use super::{
    audio_datagram::{AudioCodec, AudioJitterConfig, AudioPlayoutItem},
    configuration::NetworkTransportConfig,
    datagram::{DatagramReceiveEvent, QuicDatagramReceiver, QuicDatagramSender},
    input::MouseMovementMode,
    protocol::MessageType,
    quic::{
        negotiated_application_protocol, AuthenticatedControlChannel, QuicApplicationProtocol,
        QuicConnectionStats, QuicPeerBinding, QuicTransportError,
    },
    reliable::{
        ReliableChannel, ReliableChannelKind, ReliableChannelReceiver, ReliableChannelSender,
    },
    session::{
        decode_session_acceptance, decode_session_offer, encode_session_acceptance,
        encode_session_offer, negotiate_session, validate_session_acceptance, LatencyMode,
        SessionAgreement, SessionOffer, CAP_CLIPBOARD_RECEIVE, CAP_CLIPBOARD_SEND,
        CAP_FILE_TRANSFER, CAP_INPUT_RECEIVE, CAP_INPUT_SEND, CAP_RELIABLE_KEYFRAMES, COLOR_I420,
        COLOR_I444, COLOR_NV12, COLOR_P010,
    },
    video_datagram::{VideoCodec, VideoFrameMetadata, VideoReassemblyConfig, FLAG_KEYFRAME},
};
use crate::message_proto::{message, misc, video_frame, AudioFormat, Message, Misc, VideoFrame};
use bytes::{Bytes, BytesMut};
use protobuf::Message as ProtobufMessage;
use quinn::{Connection, Endpoint};
use std::{
    convert::TryInto,
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};

const APPLICATION_INBOUND_CAPACITY: usize = 256;
const CONTROL_OUTBOUND_CAPACITY: usize = 128;
const INPUT_OUTBOUND_CAPACITY: usize = 128;
const CLIPBOARD_OUTBOUND_CAPACITY: usize = 16;
const FILE_OUTBOUND_CAPACITY: usize = 32;
const DIAGNOSTICS_OUTBOUND_CAPACITY: usize = 64;
const AUDIO_OUTBOUND_CAPACITY: usize = 64;
const CHANNEL_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const V2_MAX_APPLICATION_DATAGRAM_SIZE: usize = 1300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationQuicRole {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationClass {
    Control,
    Input,
    Clipboard,
    File,
    Diagnostics,
    Video(VideoFrameMetadata),
    Audio,
    Mouse {
        mode: MouseMovementMode,
        x: i32,
        y: i32,
        button_state_mask: u16,
    },
}

struct ReliableOutbound {
    message_type: MessageType,
    payload: Bytes,
}

struct VideoOutbound {
    metadata: VideoFrameMetadata,
    payload: Bytes,
    ordering_epoch: u64,
}

#[derive(Default)]
struct QuicApplicationMetrics {
    video_reassembly_drops: AtomicU64,
    video_keyframe_requests: AtomicU64,
    reliable_keyframes_sent: AtomicU64,
    reliable_keyframes_received: AtomicU64,
}

impl VideoOutbound {
    fn is_keyframe(&self) -> bool {
        self.metadata.flags & FLAG_KEYFRAME != 0
    }
}

fn should_replace_pending_video(pending: &VideoOutbound, incoming: &VideoOutbound) -> bool {
    if incoming.ordering_epoch != pending.ordering_epoch {
        return incoming.ordering_epoch > pending.ordering_epoch;
    }
    !pending.is_keyframe() || incoming.is_keyframe()
}

struct AudioOutbound {
    capture_timestamp_us: u64,
    channels: u8,
    sample_rate_hz: u32,
    payload: Bytes,
}

struct MouseOutbound {
    mode: MouseMovementMode,
    x: i32,
    y: i32,
    button_state_mask: u16,
    payload: Bytes,
}

struct LatestSlot<T> {
    value: Mutex<Option<T>>,
    notify: Notify,
    replacements: AtomicU64,
}

struct VideoOrderingGate {
    requested_epoch: AtomicU64,
    acknowledged_epoch: AtomicU64,
    notify: Notify,
}

impl VideoOrderingGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            requested_epoch: AtomicU64::new(0),
            acknowledged_epoch: AtomicU64::new(0),
            notify: Notify::new(),
        })
    }

    fn next_epoch(&self) -> Result<u64, QuicTransportError> {
        self.requested_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| {
                QuicTransportError::ProtocolState("video ordering epoch exhausted".to_owned())
            })
    }

    fn current_epoch(&self) -> u64 {
        self.requested_epoch.load(Ordering::Acquire)
    }

    fn cancel_epoch(&self, epoch: u64) {
        self.acknowledge(epoch);
    }

    fn acknowledge(&self, epoch: u64) {
        self.acknowledged_epoch.fetch_max(epoch, Ordering::AcqRel);
        self.notify.notify_waiters();
    }

    fn is_open(&self, epoch: u64) -> bool {
        self.acknowledged_epoch.load(Ordering::Acquire) >= epoch
    }

    async fn wait(&self, epoch: u64) {
        while !self.is_open(epoch) {
            let notified = self.notify.notified();
            if self.is_open(epoch) {
                return;
            }
            notified.await;
        }
    }
}

impl<T> LatestSlot<T> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            value: Mutex::new(None),
            notify: Notify::new(),
            replacements: AtomicU64::new(0),
        })
    }

    fn replace(&self, value: T) {
        self.replace_when(value, |_, _| true);
    }

    fn replace_when(&self, value: T, should_replace: impl FnOnce(&T, &T) -> bool) -> bool {
        let mut slot = self.value.lock().unwrap();
        if let Some(pending) = slot.as_ref() {
            if !should_replace(pending, &value) {
                return false;
            }
            self.replacements.fetch_add(1, Ordering::Relaxed);
        }
        *slot = Some(value);
        drop(slot);
        self.notify.notify_one();
        true
    }

    async fn take(&self) -> T {
        loop {
            let notified = self.notify.notified();
            if let Some(value) = self.value.lock().unwrap().take() {
                return value;
            }
            notified.await;
        }
    }
}

pub struct QuicApplicationStream {
    connection: Connection,
    _authentication: AuthenticatedControlChannel,
    peer_binding: QuicPeerBinding,
    inbound: mpsc::Receiver<Result<BytesMut, Error>>,
    control: mpsc::Sender<ReliableOutbound>,
    input: mpsc::Sender<ReliableOutbound>,
    clipboard: mpsc::Sender<ReliableOutbound>,
    file: mpsc::Sender<ReliableOutbound>,
    diagnostics: mpsc::Sender<ReliableOutbound>,
    audio: mpsc::Sender<AudioOutbound>,
    latest_video: Arc<LatestSlot<VideoOutbound>>,
    latest_mouse: Arc<LatestSlot<MouseOutbound>>,
    audio_format: Arc<AtomicU64>,
    next_transport_frame_id: AtomicU64,
    video_ordering: Arc<VideoOrderingGate>,
    raw_mode: AtomicBool,
    agreement: SessionAgreement,
    application_protocol: QuicApplicationProtocol,
    metrics: Arc<QuicApplicationMetrics>,
    local_addr: SocketAddr,
    _endpoint_lease: Option<Endpoint>,
    tasks: Vec<JoinHandle<()>>,
}

impl QuicApplicationStream {
    pub async fn establish(
        mut authentication: AuthenticatedControlChannel,
        role: ApplicationQuicRole,
        local_addr: SocketAddr,
    ) -> Result<Self, QuicTransportError> {
        let connection = authentication.connection();
        let session_id = authentication.session_id();
        let peer_binding = QuicPeerBinding::capture(&authentication)?;
        let application_protocol = negotiated_application_protocol(&connection)?;
        let agreement =
            negotiate_application_session(&mut authentication, role, application_protocol).await?;
        let channels = tokio::time::timeout(
            CHANNEL_SETUP_TIMEOUT,
            establish_application_channels(
                &connection,
                session_id,
                role,
                agreement.reliable_keyframes,
            ),
        )
        .await
        .map_err(|_| QuicTransportError::Timeout("application channel setup"))??;

        let (inbound_tx, inbound) = mpsc::channel(APPLICATION_INBOUND_CAPACITY);
        let mut tasks = Vec::with_capacity(16);
        let video_ordering = VideoOrderingGate::new();
        let metrics = Arc::new(QuicApplicationMetrics::default());
        let (control, task_pair) = spawn_reliable_channel(
            channels.control,
            ReliableChannelKind::Control,
            CONTROL_OUTBOUND_CAPACITY,
            inbound_tx.clone(),
            connection.clone(),
            video_ordering.clone(),
            metrics.clone(),
            None,
        );
        tasks.extend(task_pair);
        let (input, task_pair) = spawn_reliable_channel(
            channels.input,
            ReliableChannelKind::Input,
            INPUT_OUTBOUND_CAPACITY,
            inbound_tx.clone(),
            connection.clone(),
            video_ordering.clone(),
            metrics.clone(),
            None,
        );
        tasks.extend(task_pair);
        let (clipboard, task_pair) = spawn_reliable_channel(
            channels.clipboard,
            ReliableChannelKind::Clipboard,
            CLIPBOARD_OUTBOUND_CAPACITY,
            inbound_tx.clone(),
            connection.clone(),
            video_ordering.clone(),
            metrics.clone(),
            None,
        );
        tasks.extend(task_pair);
        let (file, task_pair) = spawn_reliable_channel(
            channels.file,
            ReliableChannelKind::FileTransfer,
            FILE_OUTBOUND_CAPACITY,
            inbound_tx.clone(),
            connection.clone(),
            video_ordering.clone(),
            metrics.clone(),
            Some(agreement.max_file_bitrate_kbps),
        );
        tasks.extend(task_pair);
        let (diagnostics, task_pair) = spawn_reliable_channel(
            channels.diagnostics,
            ReliableChannelKind::Diagnostics,
            DIAGNOSTICS_OUTBOUND_CAPACITY,
            inbound_tx.clone(),
            connection.clone(),
            video_ordering.clone(),
            metrics.clone(),
            None,
        );
        tasks.extend(task_pair);

        let reliable_video_sender = if let Some(channel) = channels.video {
            let (sender, receiver) = channel.into_split();
            tasks.push(tokio::spawn(run_reliable_reader(
                receiver,
                ReliableChannelKind::Video,
                inbound_tx.clone(),
                connection.clone(),
                None,
                video_ordering.clone(),
                metrics.clone(),
            )));
            Some(sender)
        } else {
            None
        };

        let (audio, audio_rx) = mpsc::channel(AUDIO_OUTBOUND_CAPACITY);
        let latest_video = LatestSlot::new();
        let latest_mouse = LatestSlot::new();
        let negotiated_datagram_size = usize::from(agreement.max_datagram_payload);
        tasks.push(tokio::spawn(run_video_writer(
            QuicDatagramSender::new(connection.clone(), session_id)
                .with_max_datagram_size(negotiated_datagram_size),
            latest_video.clone(),
            video_ordering.clone(),
            inbound_tx.clone(),
            connection.clone(),
            reliable_video_sender,
            metrics.clone(),
        )));
        tasks.push(tokio::spawn(run_mouse_writer(
            QuicDatagramSender::new(connection.clone(), session_id)
                .with_max_datagram_size(negotiated_datagram_size),
            latest_mouse.clone(),
            inbound_tx.clone(),
            connection.clone(),
        )));
        tasks.push(tokio::spawn(run_audio_writer(
            QuicDatagramSender::new(connection.clone(), session_id)
                .with_max_datagram_size(negotiated_datagram_size),
            audio_rx,
            inbound_tx.clone(),
            connection.clone(),
        )));
        let video_reassembly_config = VideoReassemblyConfig {
            // Version 2 keyframes arrive on their reliable stream and therefore
            // never pass through the DATAGRAM reassembler's startup gate.
            require_initial_keyframe: !agreement.reliable_keyframes,
            ..VideoReassemblyConfig::default()
        };
        tasks.push(tokio::spawn(run_datagram_reader(
            QuicDatagramReceiver::new(
                connection.clone(),
                session_id,
                video_reassembly_config,
                AudioJitterConfig::default(),
            )?
            .with_max_datagram_size(negotiated_datagram_size),
            inbound_tx,
            control.clone(),
            connection.clone(),
            metrics.clone(),
        )));

        log::info!(
            "QUIC application channels ready: role={role:?}, protocol={application_protocol:?}, reliable_keyframes={}, local={local_addr}, peer={}, mtu={}, datagram_payload_live={:?}, datagram_payload_negotiated={}",
            agreement.reliable_keyframes,
            connection.remote_address(),
            connection.stats().path.current_mtu,
            connection.max_datagram_size(),
            agreement.max_datagram_payload,
        );
        Ok(Self {
            connection,
            _authentication: authentication,
            peer_binding,
            inbound,
            control,
            input,
            clipboard,
            file,
            diagnostics,
            audio,
            latest_video,
            latest_mouse,
            audio_format: Arc::new(AtomicU64::new(0)),
            next_transport_frame_id: AtomicU64::new(1),
            video_ordering,
            raw_mode: AtomicBool::new(false),
            agreement,
            application_protocol,
            metrics,
            local_addr,
            _endpoint_lease: None,
            tasks,
        })
    }

    pub fn enqueue(&self, payload: Bytes) -> crate::ResultType<()> {
        if self.raw_mode.load(Ordering::Acquire) {
            return self
                .control
                .try_send(ReliableOutbound {
                    message_type: MessageType::ApplicationRaw,
                    payload,
                })
                .map_err(map_try_send_error);
        }
        let message = Message::parse_from_bytes(&payload)
            .map_err(|error| Error::new(ErrorKind::InvalidData, error.to_string()))?;
        if let Some(format) = audio_format(&message) {
            self.audio_format
                .store(pack_audio_format(format), Ordering::Release);
        }
        if is_video_ordering_message(&message) {
            let epoch = self.video_ordering.next_epoch()?;
            let mut ordered_payload = Vec::with_capacity(8 + payload.len());
            ordered_payload.extend_from_slice(&epoch.to_be_bytes());
            ordered_payload.extend_from_slice(&payload);
            return match self.control.try_send(ReliableOutbound {
                message_type: MessageType::VideoOrdering,
                payload: Bytes::from(ordered_payload),
            }) {
                Ok(()) => Ok(()),
                Err(error) => {
                    self.video_ordering.cancel_epoch(epoch);
                    Err(map_try_send_error(error))
                }
            };
        }
        match classify_message(&message)? {
            ApplicationClass::Video(mut metadata) => {
                metadata.frame_id = self
                    .next_transport_frame_id
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        value.checked_add(1)
                    })
                    .map_err(|_| {
                        QuicTransportError::ProtocolState(
                            "transport video frame identifier exhausted".to_owned(),
                        )
                    })?;
                self.latest_video.replace_when(
                    VideoOutbound {
                        metadata,
                        payload,
                        ordering_epoch: self.video_ordering.current_epoch(),
                    },
                    should_replace_pending_video,
                );
                Ok(())
            }
            ApplicationClass::Audio => self.enqueue_audio(payload),
            ApplicationClass::Mouse {
                mode,
                x,
                y,
                button_state_mask,
            } => {
                self.latest_mouse.replace(MouseOutbound {
                    mode,
                    x,
                    y,
                    button_state_mask,
                    payload,
                });
                Ok(())
            }
            class => {
                let (sender, message_type) = reliable_sender(self, class);
                sender
                    .try_send(ReliableOutbound {
                        message_type,
                        payload,
                    })
                    .map_err(map_try_send_error)
            }
        }
    }

    fn enqueue_audio(&self, payload: Bytes) -> crate::ResultType<()> {
        let packed = self.audio_format.load(Ordering::Acquire);
        let Some((sample_rate_hz, channels)) = unpack_audio_format(packed) else {
            return self
                .control
                .try_send(ReliableOutbound {
                    message_type: MessageType::ApplicationControl,
                    payload,
                })
                .map_err(map_try_send_error);
        };
        let max_datagram = self
            .connection
            .max_datagram_size()
            .unwrap_or(1200)
            .min(usize::from(self.agreement.max_datagram_payload));
        if payload.len().saturating_add(80) > max_datagram {
            log::warn!(
                "Dropping oversized QUIC audio packet: payload={}, datagram_limit={}",
                payload.len(),
                max_datagram
            );
            return Ok(());
        }
        match self.audio.try_send(AudioOutbound {
            capture_timestamp_us: 0,
            channels,
            sample_rate_hz,
            payload,
        }) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(Error::new(ErrorKind::BrokenPipe, "QUIC audio writer is closed").into())
            }
        }
    }

    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        self.inbound.recv().await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn stats(&self) -> QuicConnectionStats {
        let mut stats = QuicConnectionStats::capture(&self.connection);
        stats.application_protocol = self.application_protocol as u16;
        stats.negotiated_datagram_size = Some(usize::from(self.agreement.max_datagram_payload));
        stats.reliable_keyframes = self.agreement.reliable_keyframes;
        stats.video_reassembly_drops = self.metrics.video_reassembly_drops.load(Ordering::Relaxed);
        stats.video_keyframe_requests =
            self.metrics.video_keyframe_requests.load(Ordering::Relaxed);
        stats.reliable_keyframes_sent =
            self.metrics.reliable_keyframes_sent.load(Ordering::Relaxed);
        stats.reliable_keyframes_received = self
            .metrics
            .reliable_keyframes_received
            .load(Ordering::Relaxed);
        stats
    }

    pub fn peer_binding(&self) -> &QuicPeerBinding {
        &self.peer_binding
    }

    pub fn keep_endpoint_alive(&mut self, endpoint: Endpoint) {
        self._endpoint_lease = Some(endpoint);
    }

    pub fn set_raw(&self) {
        self.raw_mode.store(true, Ordering::Release);
    }
}

impl Drop for QuicApplicationStream {
    fn drop(&mut self) {
        self.connection
            .close(0u32.into(), b"application stream dropped");
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn negotiate_application_session(
    authentication: &mut AuthenticatedControlChannel,
    role: ApplicationQuicRole,
    application_protocol: QuicApplicationProtocol,
) -> Result<SessionAgreement, QuicTransportError> {
    let local_offer =
        application_session_offer(&authentication.connection(), application_protocol)?;
    let agreement = match role {
        ApplicationQuicRole::Client => {
            let encoded = encode_session_offer(&local_offer).map_err(session_negotiation_error)?;
            authentication
                .send_control(MessageType::SessionOffer, 0, &encoded)
                .await?;
            let response = authentication.receive_control().await?;
            if response.header.message_type != MessageType::SessionAccept {
                return Err(QuicTransportError::ProtocolState(format!(
                    "expected QUIC session acceptance, received {:?}",
                    response.header.message_type
                )));
            }
            let (server_offer, agreement) =
                decode_session_acceptance(&response.payload).map_err(session_negotiation_error)?;
            validate_session_acceptance(&local_offer, &server_offer, &agreement)
                .map_err(session_negotiation_error)?;
            agreement
        }
        ApplicationQuicRole::Server => {
            let request = authentication.receive_control().await?;
            if request.header.message_type != MessageType::SessionOffer {
                return Err(QuicTransportError::ProtocolState(format!(
                    "expected QUIC session offer, received {:?}",
                    request.header.message_type
                )));
            }
            let client_offer =
                decode_session_offer(&request.payload).map_err(session_negotiation_error)?;
            let agreement = negotiate_session(&client_offer, &local_offer)
                .map_err(session_negotiation_error)?;
            let encoded = encode_session_acceptance(&local_offer, &agreement)
                .map_err(session_negotiation_error)?;
            authentication
                .send_control(MessageType::SessionAccept, 0, &encoded)
                .await?;
            agreement
        }
    };
    log::info!(
        "QUIC session negotiated: protocol={}, video={:?}, audio={:?}, color={:?}, mtu_payload={}, reliable_keyframes={}, max_fps={}, file_kbps={}",
        agreement.protocol_version,
        agreement.video_codec,
        agreement.audio_codec,
        agreement.color_format,
        agreement.max_datagram_payload,
        agreement.reliable_keyframes,
        agreement.max_fps,
        agreement.max_file_bitrate_kbps
    );
    Ok(agreement)
}

fn application_session_offer(
    connection: &Connection,
    application_protocol: QuicApplicationProtocol,
) -> Result<SessionOffer, QuicTransportError> {
    let config = NetworkTransportConfig::load()
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    let current_datagram_payload = connection
        .max_datagram_size()
        .ok_or_else(|| {
            QuicTransportError::Datagram("peer did not negotiate QUIC DATAGRAM".to_owned())
        })?
        .clamp(256, 65_000);
    let max_datagram_payload = if application_protocol.supports_reliable_keyframes() {
        current_datagram_payload
            .max(V2_MAX_APPLICATION_DATAGRAM_SIZE)
            .min(65_000)
    } else {
        current_datagram_payload
    } as u16;
    let file_kbps = if config.file_bandwidth_limit_mbps == 0 {
        1_000_000
    } else {
        config.file_bandwidth_limit_mbps.saturating_mul(1_000)
    };
    Ok(SessionOffer {
        minimum_protocol_version: application_protocol as u16,
        maximum_protocol_version: application_protocol as u16,
        capabilities: CAP_CLIPBOARD_SEND
            | CAP_CLIPBOARD_RECEIVE
            | CAP_FILE_TRANSFER
            | CAP_INPUT_SEND
            | CAP_INPUT_RECEIVE
            | if application_protocol.supports_reliable_keyframes() {
                CAP_RELIABLE_KEYFRAMES
            } else {
                0
            },
        latency_mode: LatencyMode::LowLatency,
        video_codecs: vec![
            VideoCodec::Av1,
            VideoCodec::H265,
            VideoCodec::H264,
            VideoCodec::Vp9,
            VideoCodec::Vp8,
            VideoCodec::Raw,
        ],
        audio_codecs: vec![AudioCodec::Opus],
        color_formats: COLOR_I420 | COLOR_I444 | COLOR_NV12 | COLOR_P010,
        max_width: 16_384,
        max_height: 16_384,
        max_fps: 240,
        max_datagram_payload,
        max_video_bitrate_kbps: 1_000_000,
        max_file_bitrate_kbps: file_kbps,
    })
}

fn session_negotiation_error(error: impl std::fmt::Display) -> QuicTransportError {
    QuicTransportError::ProtocolState(format!("QUIC session negotiation failed: {error}"))
}

struct ApplicationChannels {
    control: ReliableChannel,
    input: ReliableChannel,
    clipboard: ReliableChannel,
    file: ReliableChannel,
    diagnostics: ReliableChannel,
    video: Option<ReliableChannel>,
}

async fn establish_application_channels(
    connection: &Connection,
    session_id: [u8; 16],
    role: ApplicationQuicRole,
    reliable_keyframes: bool,
) -> Result<ApplicationChannels, QuicTransportError> {
    let mut control = None;
    let mut input = None;
    let mut clipboard = None;
    let mut file = None;
    let mut diagnostics = None;
    let mut video = None;
    for expected in application_channel_kinds(reliable_keyframes) {
        let channel = match role {
            ApplicationQuicRole::Client => {
                ReliableChannel::open(connection, expected, session_id).await?
            }
            ApplicationQuicRole::Server => ReliableChannel::accept(connection, session_id).await?,
        };
        let slot = match channel.kind() {
            ReliableChannelKind::Control => &mut control,
            ReliableChannelKind::Input => &mut input,
            ReliableChannelKind::Clipboard => &mut clipboard,
            ReliableChannelKind::FileTransfer => &mut file,
            ReliableChannelKind::Diagnostics => &mut diagnostics,
            ReliableChannelKind::Video => &mut video,
        };
        if slot.replace(channel).is_some() {
            return Err(QuicTransportError::ProtocolState(
                "duplicate QUIC application channel".to_owned(),
            ));
        }
    }
    Ok(ApplicationChannels {
        control: require_channel(control, "control")?,
        input: require_channel(input, "input")?,
        clipboard: require_channel(clipboard, "clipboard")?,
        file: require_channel(file, "file")?,
        diagnostics: require_channel(diagnostics, "diagnostics")?,
        video: if reliable_keyframes {
            Some(require_channel(video, "reliable video")?)
        } else {
            None
        },
    })
}

fn application_channel_kinds(reliable_keyframes: bool) -> Vec<ReliableChannelKind> {
    let mut channels = vec![
        ReliableChannelKind::Control,
        ReliableChannelKind::Input,
        ReliableChannelKind::Clipboard,
        ReliableChannelKind::FileTransfer,
        ReliableChannelKind::Diagnostics,
    ];
    if reliable_keyframes {
        channels.push(ReliableChannelKind::Video);
    }
    channels
}

fn require_channel(
    channel: Option<ReliableChannel>,
    name: &'static str,
) -> Result<ReliableChannel, QuicTransportError> {
    channel.ok_or_else(|| {
        QuicTransportError::ProtocolState(format!("missing QUIC {name} application channel"))
    })
}

fn spawn_reliable_channel(
    channel: ReliableChannel,
    kind: ReliableChannelKind,
    capacity: usize,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
    connection: Connection,
    video_ordering: Arc<VideoOrderingGate>,
    metrics: Arc<QuicApplicationMetrics>,
    bandwidth_limit_kbps: Option<u32>,
) -> (mpsc::Sender<ReliableOutbound>, [JoinHandle<()>; 2]) {
    let (sender, receiver) = channel.into_split();
    let (outbound, outbound_rx) = mpsc::channel(capacity);
    let writer_inbound = inbound.clone();
    let writer_connection = connection.clone();
    let writer = tokio::spawn(run_reliable_writer(
        sender,
        outbound_rx,
        writer_inbound,
        writer_connection,
        bandwidth_limit_kbps,
    ));
    let internal_control = (kind == ReliableChannelKind::Control).then(|| outbound.clone());
    let reader = tokio::spawn(run_reliable_reader(
        receiver,
        kind,
        inbound,
        connection,
        internal_control,
        video_ordering,
        metrics,
    ));
    (outbound, [writer, reader])
}

async fn run_reliable_writer(
    mut sender: ReliableChannelSender,
    mut outbound: mpsc::Receiver<ReliableOutbound>,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
    connection: Connection,
    bandwidth_limit_kbps: Option<u32>,
) {
    let started = Instant::now();
    while let Some(message) = outbound.recv().await {
        if let Some(kbps) = bandwidth_limit_kbps.filter(|value| *value > 0) {
            let bits = (message.payload.len() as u128).saturating_mul(8);
            let delay_us = bits
                .saturating_mul(1_000)
                .div_ceil(u128::from(kbps))
                .min(u128::from(u64::MAX)) as u64;
            tokio::time::sleep(Duration::from_micros(delay_us)).await;
        }
        let timestamp = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        if let Err(error) = sender
            .send(message.message_type, 0, timestamp, &message.payload)
            .await
        {
            report_terminal_error(&inbound, &connection, error.to_string()).await;
            return;
        }
    }
    let _ = sender.finish();
}

async fn run_reliable_reader(
    mut receiver: ReliableChannelReceiver,
    expected_kind: ReliableChannelKind,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
    connection: Connection,
    internal_control: Option<mpsc::Sender<ReliableOutbound>>,
    video_ordering: Arc<VideoOrderingGate>,
    metrics: Arc<QuicApplicationMetrics>,
) {
    loop {
        let message = match receiver.receive().await {
            Ok(message) => message,
            Err(error) => {
                report_terminal_error(&inbound, &connection, error.to_string()).await;
                return;
            }
        };
        if let Err(error) = validate_reliable_application_message(
            expected_kind,
            message.header.message_type,
            &message.payload,
        ) {
            report_terminal_error(&inbound, &connection, error.to_string()).await;
            return;
        }
        if expected_kind == ReliableChannelKind::Control {
            match message.header.message_type {
                MessageType::ApplicationRaw => {
                    if inbound
                        .send(Ok(BytesMut::from(message.payload.as_slice())))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                MessageType::VideoOrdering => {
                    let epoch = read_ordering_epoch(&message.payload).unwrap_or_default();
                    if inbound
                        .send(Ok(BytesMut::from(&message.payload[8..])))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Some(control) = internal_control.as_ref() else {
                        report_terminal_error(
                            &inbound,
                            &connection,
                            "QUIC video ordering acknowledgement channel is unavailable".to_owned(),
                        )
                        .await;
                        return;
                    };
                    if control
                        .send(ReliableOutbound {
                            message_type: MessageType::VideoOrderingAck,
                            payload: Bytes::copy_from_slice(&epoch.to_be_bytes()),
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                MessageType::VideoOrderingAck => {
                    let epoch = read_ordering_epoch(&message.payload).unwrap_or_default();
                    if epoch == 0 || epoch > video_ordering.current_epoch() {
                        report_terminal_error(
                            &inbound,
                            &connection,
                            format!("invalid QUIC video ordering acknowledgement {epoch}"),
                        )
                        .await;
                        return;
                    }
                    video_ordering.acknowledge(epoch);
                    continue;
                }
                _ => {}
            }
        }
        if expected_kind == ReliableChannelKind::Video {
            metrics
                .reliable_keyframes_received
                .fetch_add(1, Ordering::Relaxed);
        }
        if inbound
            .send(Ok(BytesMut::from(message.payload.as_slice())))
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn run_video_writer(
    mut sender: QuicDatagramSender,
    video: Arc<LatestSlot<VideoOutbound>>,
    video_ordering: Arc<VideoOrderingGate>,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
    connection: Connection,
    mut reliable_sender: Option<ReliableChannelSender>,
    metrics: Arc<QuicApplicationMetrics>,
) {
    let started = Instant::now();
    loop {
        let mut item = video.take().await;
        while !video_ordering.is_open(item.ordering_epoch) {
            tokio::select! {
                _ = video_ordering.wait(item.ordering_epoch) => {},
                newer = video.take() => {
                    if should_replace_pending_video(&item, &newer) {
                        item = newer;
                    }
                },
            }
        }
        if item.is_keyframe() {
            if let Some(reliable_sender) = reliable_sender.as_mut() {
                let timestamp = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                if let Err(error) = reliable_sender
                    .send(MessageType::ReliableVideoFrame, 0, timestamp, &item.payload)
                    .await
                {
                    report_terminal_error(&inbound, &connection, error.to_string()).await;
                    return;
                }
                metrics
                    .reliable_keyframes_sent
                    .fetch_add(1, Ordering::Relaxed);
                log::debug!(
                    "QUIC reliable keyframe sent: frame_id={}, bytes={}",
                    item.metadata.frame_id,
                    item.payload.len()
                );
                continue;
            }
        }
        if let Err(error) = sender
            .send_video_frame(item.metadata, &item.payload)
            .map(|_| ())
        {
            report_terminal_error(&inbound, &connection, error.to_string()).await;
            return;
        }
    }
}

async fn run_mouse_writer(
    mut sender: QuicDatagramSender,
    mouse: Arc<LatestSlot<MouseOutbound>>,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
    connection: Connection,
) {
    loop {
        let item = mouse.take().await;
        if let Err(error) = sender
            .send_application_mouse_movement(
                item.mode,
                item.x,
                item.y,
                0,
                item.button_state_mask,
                &item.payload,
            )
            .map(|_| ())
        {
            report_terminal_error(&inbound, &connection, error.to_string()).await;
            return;
        }
    }
}

async fn run_audio_writer(
    mut sender: QuicDatagramSender,
    mut audio: mpsc::Receiver<AudioOutbound>,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
    connection: Connection,
) {
    let started = Instant::now();
    while let Some(mut item) = audio.recv().await {
        item.capture_timestamp_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        if let Err(error) = sender
            .send_audio_packet(
                item.capture_timestamp_us,
                AudioCodec::Opus,
                item.channels,
                item.sample_rate_hz,
                &item.payload,
            )
            .map(|_| ())
        {
            report_terminal_error(&inbound, &connection, error.to_string()).await;
            return;
        }
    }
}

async fn run_datagram_reader(
    mut receiver: QuicDatagramReceiver,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
    control: mpsc::Sender<ReliableOutbound>,
    connection: Connection,
    metrics: Arc<QuicApplicationMetrics>,
) {
    let mut received_audio_format = None;
    loop {
        let event = match receiver.receive().await {
            Ok(event) => event,
            Err(error) => {
                report_terminal_error(&inbound, &connection, error.to_string()).await;
                return;
            }
        };
        match event {
            DatagramReceiveEvent::Video(outcome) => {
                let video_stats = receiver.video_stats();
                metrics.video_reassembly_drops.store(
                    video_stats
                        .expired_frames
                        .saturating_add(video_stats.evicted_frames)
                        .saturating_add(video_stats.pre_keyframe_frames),
                    Ordering::Relaxed,
                );
                if outcome.request_keyframe {
                    metrics
                        .video_keyframe_requests
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = control.try_send(ReliableOutbound {
                        message_type: MessageType::ApplicationControl,
                        payload: Bytes::from(refresh_video_message()),
                    });
                }
                if let Some(frame) = outcome.frame {
                    if validate_datagram_application_message(
                        ApplicationClassTag::Video,
                        &frame.payload,
                    )
                    .is_ok()
                    {
                        let _ = inbound.try_send(Ok(BytesMut::from(frame.payload.as_slice())));
                    }
                }
            }
            DatagramReceiveEvent::AudioAccepted => {
                while let Some(item) = receiver.pop_audio(Instant::now()) {
                    match item {
                        AudioPlayoutItem::Packet(packet) => {
                            let format = (packet.metadata.sample_rate_hz, packet.metadata.channels);
                            if received_audio_format != Some(format) {
                                let format_message = audio_format_message(format.0, format.1);
                                if inbound
                                    .send(Ok(BytesMut::from(format_message.as_slice())))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                                received_audio_format = Some(format);
                            }
                            if validate_datagram_application_message(
                                ApplicationClassTag::Audio,
                                &packet.payload,
                            )
                            .is_ok()
                                && inbound
                                    .send(Ok(BytesMut::from(packet.payload.as_slice())))
                                    .await
                                    .is_err()
                            {
                                return;
                            }
                        }
                        AudioPlayoutItem::PacketLoss { sequence_number } => {
                            log::debug!("QUIC audio packet loss: sequence={sequence_number}");
                        }
                    }
                }
            }
            DatagramReceiveEvent::ApplicationMouse(Some((_movement, payload))) => {
                if validate_datagram_application_message(ApplicationClassTag::Mouse, &payload)
                    .is_ok()
                {
                    let _ = inbound.try_send(Ok(BytesMut::from(payload.as_slice())));
                }
            }
            DatagramReceiveEvent::ApplicationMouse(None) | DatagramReceiveEvent::Mouse(_) => {}
        }
    }
}

async fn report_terminal_error(
    inbound: &mpsc::Sender<Result<BytesMut, Error>>,
    connection: &Connection,
    error: String,
) {
    log::warn!("QUIC application transport failed: {error}");
    connection.close(1u32.into(), b"application transport failed");
    let _ = inbound
        .send(Err(Error::new(ErrorKind::BrokenPipe, error)))
        .await;
}

fn reliable_sender(
    stream: &QuicApplicationStream,
    class: ApplicationClass,
) -> (&mpsc::Sender<ReliableOutbound>, MessageType) {
    match class {
        ApplicationClass::Input => (&stream.input, MessageType::ReliableInput),
        ApplicationClass::Clipboard => (&stream.clipboard, MessageType::Clipboard),
        ApplicationClass::File => (&stream.file, MessageType::FileChunk),
        ApplicationClass::Diagnostics => (&stream.diagnostics, MessageType::Diagnostics),
        _ => (&stream.control, MessageType::ApplicationControl),
    }
}

fn map_try_send_error(error: mpsc::error::TrySendError<ReliableOutbound>) -> anyhow::Error {
    let kind = match error {
        mpsc::error::TrySendError::Full(_) => ErrorKind::WouldBlock,
        mpsc::error::TrySendError::Closed(_) => ErrorKind::BrokenPipe,
    };
    Error::new(kind, "QUIC reliable application queue is unavailable").into()
}

fn validate_reliable_application_message(
    expected: ReliableChannelKind,
    message_type: MessageType,
    payload: &[u8],
) -> Result<(), QuicTransportError> {
    if expected == ReliableChannelKind::Control {
        match message_type {
            MessageType::ApplicationRaw => return Ok(()),
            MessageType::VideoOrdering => {
                let _ = read_ordering_epoch(payload)?;
                let message = Message::parse_from_bytes(&payload[8..])
                    .map_err(|error| QuicTransportError::ProtocolState(error.to_string()))?;
                if is_video_ordering_message(&message) {
                    return Ok(());
                }
                return Err(QuicTransportError::ProtocolState(
                    "QUIC video ordering message does not contain SwitchDisplay".to_owned(),
                ));
            }
            MessageType::VideoOrderingAck => {
                let _ = read_ordering_epoch(payload)?;
                return Ok(());
            }
            _ => {}
        }
    }
    let message = Message::parse_from_bytes(payload)
        .map_err(|error| QuicTransportError::ProtocolState(error.to_string()))?;
    let class = classify_message(&message)?;
    let valid = match expected {
        ReliableChannelKind::Control => message_type == MessageType::ApplicationControl,
        ReliableChannelKind::Input => {
            message_type == MessageType::ReliableInput && class == ApplicationClass::Input
        }
        ReliableChannelKind::Clipboard => {
            message_type == MessageType::Clipboard && class == ApplicationClass::Clipboard
        }
        ReliableChannelKind::FileTransfer => {
            message_type == MessageType::FileChunk && class == ApplicationClass::File
        }
        ReliableChannelKind::Diagnostics => {
            message_type == MessageType::Diagnostics && class == ApplicationClass::Diagnostics
        }
        ReliableChannelKind::Video => {
            message_type == MessageType::ReliableVideoFrame
                && matches!(class, ApplicationClass::Video(metadata) if metadata.flags & FLAG_KEYFRAME != 0)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(QuicTransportError::ProtocolState(format!(
            "protobuf message is invalid on {expected:?}"
        )))
    }
}

fn read_ordering_epoch(payload: &[u8]) -> Result<u64, QuicTransportError> {
    let encoded: [u8; 8] = payload
        .get(..8)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| {
            QuicTransportError::ProtocolState("QUIC video ordering epoch is truncated".to_owned())
        })?;
    let epoch = u64::from_be_bytes(encoded);
    if epoch == 0 {
        return Err(QuicTransportError::ProtocolState(
            "QUIC video ordering epoch must not be zero".to_owned(),
        ));
    }
    Ok(epoch)
}

#[derive(Clone, Copy)]
enum ApplicationClassTag {
    Video,
    Audio,
    Mouse,
}

fn validate_datagram_application_message(
    expected: ApplicationClassTag,
    payload: &[u8],
) -> Result<(), QuicTransportError> {
    let message = Message::parse_from_bytes(payload)
        .map_err(|error| QuicTransportError::ProtocolState(error.to_string()))?;
    let class = classify_message(&message)?;
    let valid = matches!(
        (expected, class),
        (ApplicationClassTag::Video, ApplicationClass::Video(_))
            | (ApplicationClassTag::Audio, ApplicationClass::Audio)
            | (ApplicationClassTag::Mouse, ApplicationClass::Mouse { .. })
    );
    if valid {
        Ok(())
    } else {
        Err(QuicTransportError::ProtocolState(
            "protobuf message is invalid on QUIC DATAGRAM".to_owned(),
        ))
    }
}

fn classify_message(message: &Message) -> Result<ApplicationClass, QuicTransportError> {
    let class = match message.union.as_ref() {
        Some(message::Union::VideoFrame(frame)) => ApplicationClass::Video(video_metadata(frame)?),
        Some(message::Union::AudioFrame(_)) => ApplicationClass::Audio,
        Some(message::Union::MouseEvent(event)) => match event.mask & 0x7 {
            0 => ApplicationClass::Mouse {
                mode: MouseMovementMode::Absolute,
                x: event.x,
                y: event.y,
                button_state_mask: ((event.mask >> 3) as u16) & 0x1f,
            },
            5 => ApplicationClass::Mouse {
                mode: MouseMovementMode::Relative,
                x: event.x,
                y: event.y,
                button_state_mask: ((event.mask >> 3) as u16) & 0x1f,
            },
            _ => ApplicationClass::Input,
        },
        Some(message::Union::KeyEvent(_)) | Some(message::Union::PointerDeviceEvent(_)) => {
            ApplicationClass::Input
        }
        Some(message::Union::Clipboard(_))
        | Some(message::Union::MultiClipboards(_))
        | Some(message::Union::Cliprdr(_)) => ApplicationClass::Clipboard,
        Some(message::Union::FileAction(_)) | Some(message::Union::FileResponse(_)) => {
            ApplicationClass::File
        }
        Some(message::Union::TestDelay(_)) => ApplicationClass::Diagnostics,
        Some(message::Union::Misc(value))
            if matches!(value.union, Some(misc::Union::VideoFeedback(_))) =>
        {
            ApplicationClass::Diagnostics
        }
        _ => ApplicationClass::Control,
    };
    Ok(class)
}

fn is_video_ordering_message(message: &Message) -> bool {
    matches!(
        message.union.as_ref(),
        Some(message::Union::Misc(Misc {
            union: Some(misc::Union::SwitchDisplay(_)),
            ..
        }))
    )
}

fn video_metadata(frame: &VideoFrame) -> Result<VideoFrameMetadata, QuicTransportError> {
    let (codec, keyframe) = match frame.union.as_ref() {
        Some(video_frame::Union::Vp9s(frames)) => (VideoCodec::Vp9, has_keyframe(frames)),
        Some(video_frame::Union::H264s(frames)) => (VideoCodec::H264, has_keyframe(frames)),
        Some(video_frame::Union::H265s(frames)) => (VideoCodec::H265, has_keyframe(frames)),
        Some(video_frame::Union::Vp8s(frames)) => (VideoCodec::Vp8, has_keyframe(frames)),
        Some(video_frame::Union::Av1s(frames)) => (VideoCodec::Av1, has_keyframe(frames)),
        Some(video_frame::Union::Rgb(_)) | Some(video_frame::Union::Yuv(_)) => {
            (VideoCodec::Raw, true)
        }
        None => {
            return Err(QuicTransportError::ProtocolState(
                "video protobuf has no codec payload".to_owned(),
            ))
        }
    };
    Ok(VideoFrameMetadata {
        frame_id: frame.frame_id,
        codec,
        flags: if keyframe { FLAG_KEYFRAME } else { 0 },
        presentation_timestamp_us: frame.capture_time_ms.saturating_mul(1_000),
    })
}

fn has_keyframe(frames: &crate::message_proto::EncodedVideoFrames) -> bool {
    frames.frames.iter().any(|frame| frame.key)
}

fn audio_format(message: &Message) -> Option<&AudioFormat> {
    let message::Union::Misc(value) = message.union.as_ref()? else {
        return None;
    };
    let misc::Union::AudioFormat(format) = value.union.as_ref()? else {
        return None;
    };
    Some(format)
}

fn pack_audio_format(format: &AudioFormat) -> u64 {
    if format.channels == 0 || format.channels > 8 || format.sample_rate < 8_000 {
        return 0;
    }
    (u64::from(format.channels) << 32) | u64::from(format.sample_rate)
}

fn unpack_audio_format(value: u64) -> Option<(u32, u8)> {
    if value == 0 {
        return None;
    }
    Some((value as u32, (value >> 32) as u8))
}

fn audio_format_message(sample_rate: u32, channels: u8) -> Vec<u8> {
    let mut misc = Misc::new();
    misc.set_audio_format(AudioFormat {
        sample_rate,
        channels: u32::from(channels),
        ..Default::default()
    });
    let mut message = Message::new();
    message.set_misc(misc);
    message.write_to_bytes().unwrap_or_default()
}

fn refresh_video_message() -> Vec<u8> {
    let mut misc = Misc::new();
    misc.set_refresh_video(true);
    let mut message = Message::new();
    message.set_misc(misc);
    message.write_to_bytes().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        message_proto::{
            AudioFrame, Clipboard, EncodedVideoFrame, EncodedVideoFrames, KeyEvent, MouseEvent,
            SwitchDisplay,
        },
        sodiumoxide::crypto::sign,
        transport::quic::{
            DeviceIdentity, QuicClientEndpoint, QuicServerEndpoint, QuicTransportOptions,
            TlsCredentials, PEER_SERVER_NAME,
        },
    };
    use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
    use std::net::{IpAddr, Ipv4Addr};

    struct TestCertificate {
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
    }

    impl TestCertificate {
        fn credentials(&self) -> TlsCredentials {
            TlsCredentials::new(
                vec![self.certificate.clone()],
                PrivatePkcs8KeyDer::from(self.private_key.clone()).into(),
            )
            .unwrap()
        }
    }

    fn certificate() -> TestCertificate {
        let mut params = CertificateParams::new(vec![PEER_SERVER_NAME.to_owned()]).unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        TestCertificate {
            certificate: certificate.der().clone(),
            private_key: key_pair.serialize_der(),
        }
    }

    fn device_identity() -> DeviceIdentity {
        crate::sodiumoxide::init().unwrap();
        let (public_key, secret_key) = sign::gen_keypair();
        DeviceIdentity::from_bytes(&secret_key.0, &public_key.0).unwrap()
    }

    #[test]
    fn protobuf_messages_are_classified_without_native_struct_deserialization() {
        let mut message = Message::new();
        message.set_mouse_event(MouseEvent {
            mask: 5,
            x: -3,
            y: 4,
            ..Default::default()
        });
        assert!(matches!(
            classify_message(&message).unwrap(),
            ApplicationClass::Mouse {
                mode: MouseMovementMode::Relative,
                ..
            }
        ));

        message.set_clipboard(Clipboard::new());
        assert_eq!(
            classify_message(&message).unwrap(),
            ApplicationClass::Clipboard
        );

        message.set_audio_frame(AudioFrame {
            data: Bytes::from_static(b"opus"),
            ..Default::default()
        });
        assert_eq!(classify_message(&message).unwrap(), ApplicationClass::Audio);
    }

    #[test]
    fn video_metadata_preserves_codec_keyframe_and_timestamp() {
        let mut message = Message::new();
        let mut video = VideoFrame {
            frame_id: 42,
            capture_time_ms: 17,
            ..Default::default()
        };
        video.set_h264s(EncodedVideoFrames {
            frames: vec![EncodedVideoFrame {
                data: Bytes::from_static(b"frame"),
                key: true,
                ..Default::default()
            }],
            ..Default::default()
        });
        message.set_video_frame(video);
        assert_eq!(
            classify_message(&message).unwrap(),
            ApplicationClass::Video(VideoFrameMetadata {
                frame_id: 42,
                codec: VideoCodec::H264,
                flags: FLAG_KEYFRAME,
                presentation_timestamp_us: 17_000,
            })
        );
    }

    fn outbound_video(frame_id: u64, keyframe: bool, ordering_epoch: u64) -> VideoOutbound {
        VideoOutbound {
            metadata: VideoFrameMetadata {
                frame_id,
                codec: VideoCodec::H264,
                flags: if keyframe { FLAG_KEYFRAME } else { 0 },
                presentation_timestamp_us: frame_id * 1_000,
            },
            payload: Bytes::from(vec![frame_id as u8]),
            ordering_epoch,
        }
    }

    #[tokio::test]
    async fn latest_video_slot_preserves_pending_keyframe_from_same_epoch_delta() {
        let slot = LatestSlot::new();
        assert!(slot.replace_when(outbound_video(1, true, 4), should_replace_pending_video));
        assert!(!slot.replace_when(outbound_video(2, false, 4), should_replace_pending_video));

        let pending = slot.take().await;
        assert_eq!(pending.metadata.frame_id, 1);
        assert!(pending.is_keyframe());
    }

    #[test]
    fn pending_video_selection_keeps_latency_and_ordering_semantics() {
        assert!(should_replace_pending_video(
            &outbound_video(2, false, 4),
            &outbound_video(3, false, 4)
        ));
        assert!(should_replace_pending_video(
            &outbound_video(1, true, 4),
            &outbound_video(4, true, 4)
        ));
        assert!(should_replace_pending_video(
            &outbound_video(1, true, 4),
            &outbound_video(5, false, 5)
        ));
        assert!(!should_replace_pending_video(
            &outbound_video(5, false, 5),
            &outbound_video(1, true, 4)
        ));
    }

    #[test]
    fn v1_keeps_five_channels_and_v2_adds_only_reliable_video() {
        assert_eq!(
            application_channel_kinds(false),
            vec![
                ReliableChannelKind::Control,
                ReliableChannelKind::Input,
                ReliableChannelKind::Clipboard,
                ReliableChannelKind::FileTransfer,
                ReliableChannelKind::Diagnostics,
            ]
        );
        let v2 = application_channel_kinds(true);
        assert_eq!(v2.len(), 6);
        assert_eq!(v2.last(), Some(&ReliableChannelKind::Video));
    }

    #[test]
    fn audio_format_pack_is_bounded() {
        let format = AudioFormat {
            sample_rate: 48_000,
            channels: 2,
            ..Default::default()
        };
        assert_eq!(
            unpack_audio_format(pack_audio_format(&format)),
            Some((48_000, 2))
        );
        assert_eq!(pack_audio_format(&AudioFormat::new()), 0);
    }

    #[tokio::test]
    async fn protobuf_application_stream_uses_independent_reliable_and_datagram_channels() {
        let server_certificate = certificate();
        let client_certificate = certificate();
        let server_identity = device_identity();
        let client_identity = device_identity();
        let server_identity_key = server_identity.public_key_bytes();
        let client_identity_key = client_identity.public_key_bytes();
        let options = QuicTransportOptions {
            connect_timeout: Duration::from_secs(2),
            authentication_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = match QuicServerEndpoint::bind(
            bind,
            server_certificate.credentials(),
            client_certificate.certificate.clone(),
            &options,
        ) {
            Ok(server) => server,
            Err(QuicTransportError::UdpBind(error))
                if error.contains("Operation not permitted") =>
            {
                return
            }
            Err(error) => panic!("server endpoint failed: {}", error),
        };
        let client = QuicClientEndpoint::bind(
            bind,
            client_certificate.credentials(),
            server_certificate.certificate.clone(),
            &options,
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let session_id = [7; 16];
        let auth_timeout = options.authentication_timeout;
        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            let local_addr = connection
                .local_ip()
                .map(|ip| SocketAddr::new(ip, server_address.port()))
                .unwrap_or(bind);
            let authentication = AuthenticatedControlChannel::authenticate_server_discover_session(
                connection,
                &server_identity,
                client_identity_key,
                auth_timeout,
            )
            .await
            .unwrap();
            QuicApplicationStream::establish(
                authentication,
                ApplicationQuicRole::Server,
                local_addr,
            )
            .await
            .unwrap()
        });
        let connection = client.connect(server_address).await.unwrap();
        let local_addr = client.local_addr().unwrap();
        let authentication = AuthenticatedControlChannel::authenticate_client(
            connection,
            &client_identity,
            server_identity_key,
            session_id,
            auth_timeout,
        )
        .await
        .unwrap();
        let client_stream = QuicApplicationStream::establish(
            authentication,
            ApplicationQuicRole::Client,
            local_addr,
        )
        .await
        .unwrap();
        let mut server_stream = server_task.await.unwrap();

        let mut key = Message::new();
        key.set_key_event(KeyEvent::new());
        client_stream
            .enqueue(Bytes::from(key.write_to_bytes().unwrap()))
            .unwrap();

        let mut mouse = Message::new();
        mouse.set_mouse_event(MouseEvent {
            mask: 0,
            x: 123,
            y: 456,
            ..Default::default()
        });
        client_stream
            .enqueue(Bytes::from(mouse.write_to_bytes().unwrap()))
            .unwrap();

        let mut video = Message::new();
        let mut switch = Message::new();
        let mut switch_misc = Misc::new();
        switch_misc.set_switch_display(SwitchDisplay {
            display: 0,
            width: 1920,
            height: 1080,
            ..Default::default()
        });
        switch.set_misc(switch_misc);
        client_stream
            .enqueue(Bytes::from(switch.write_to_bytes().unwrap()))
            .unwrap();

        let mut frame = VideoFrame {
            frame_id: 1,
            capture_time_ms: 3,
            ..Default::default()
        };
        frame.set_h264s(EncodedVideoFrames {
            frames: vec![EncodedVideoFrame {
                data: Bytes::from(vec![8; 4_000]),
                key: true,
                ..Default::default()
            }],
            ..Default::default()
        });
        video.set_video_frame(frame);
        client_stream
            .enqueue(Bytes::from(video.write_to_bytes().unwrap()))
            .unwrap();

        let mut format = Message::new();
        let mut misc = Misc::new();
        misc.set_audio_format(AudioFormat {
            sample_rate: 48_000,
            channels: 2,
            ..Default::default()
        });
        format.set_misc(misc);
        client_stream
            .enqueue(Bytes::from(format.write_to_bytes().unwrap()))
            .unwrap();
        for value in 1..=3 {
            let mut audio = Message::new();
            audio.set_audio_frame(AudioFrame {
                data: Bytes::from(vec![value; 80]),
                ..Default::default()
            });
            client_stream
                .enqueue(Bytes::from(audio.write_to_bytes().unwrap()))
                .unwrap();
        }

        let mut saw_key = false;
        let mut saw_mouse = false;
        let mut saw_switch = false;
        let mut saw_video = false;
        let mut saw_audio = false;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !(saw_key && saw_mouse && saw_switch && saw_video && saw_audio) {
                let bytes = server_stream.next().await.unwrap().unwrap();
                let message = Message::parse_from_bytes(&bytes).unwrap();
                match message.union {
                    Some(message::Union::KeyEvent(_)) => saw_key = true,
                    Some(message::Union::MouseEvent(event)) => {
                        saw_mouse = event.x == 123 && event.y == 456
                    }
                    Some(message::Union::Misc(value))
                        if matches!(value.union, Some(misc::Union::SwitchDisplay(_))) =>
                    {
                        saw_switch = true
                    }
                    Some(message::Union::VideoFrame(frame)) => {
                        assert!(saw_switch, "video DATAGRAM overtook SwitchDisplay");
                        saw_video = frame.frame_id == 1;
                    }
                    Some(message::Union::AudioFrame(_)) => saw_audio = true,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(client_stream.stats().application_protocol, 2);
        assert!(client_stream.stats().reliable_keyframes);
        assert!(client_stream.stats().reliable_keyframes_sent >= 1);
        assert!(server_stream.stats().reliable_keyframes_received >= 1);

        let mut delta = Message::new();
        let mut delta_frame = VideoFrame {
            frame_id: 2,
            capture_time_ms: 4,
            ..Default::default()
        };
        delta_frame.set_h264s(EncodedVideoFrames {
            frames: vec![EncodedVideoFrame {
                data: Bytes::from(vec![9; 2_000]),
                key: false,
                ..Default::default()
            }],
            ..Default::default()
        });
        delta.set_video_frame(delta_frame);
        client_stream
            .enqueue(Bytes::from(delta.write_to_bytes().unwrap()))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let bytes = server_stream.next().await.unwrap().unwrap();
                let message = Message::parse_from_bytes(&bytes).unwrap();
                if matches!(
                    message.union,
                    Some(message::Union::VideoFrame(frame)) if frame.frame_id == 2
                ) {
                    break;
                }
            }
        })
        .await
        .expect("DATAGRAM delta must follow a reliable startup keyframe");

        client_stream.set_raw();
        client_stream
            .enqueue(Bytes::from_static(b"raw-port-forward-payload"))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let raw = server_stream.next().await.unwrap().unwrap();
                if &raw[..] == b"raw-port-forward-payload" {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
}
