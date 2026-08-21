use super::{
    audio_datagram::{AudioCodec, AudioJitterConfig, AudioPlayoutItem},
    configuration::NetworkTransportConfig,
    datagram::{
        DatagramReceiveEvent, QuicDatagramReceiver, QuicDatagramSendCoordinator,
        QuicDatagramSender, VideoDatagramSendOutcome, DEFAULT_INTERACTIVE_DATAGRAM_RESERVE_BYTES,
    },
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
        CAP_FILE_TRANSFER, CAP_INPUT_RECEIVE, CAP_INPUT_SEND, CAP_RELIABLE_KEYFRAMES,
        CAP_RELIABLE_KEYFRAME_BARRIER, COLOR_I420, COLOR_I444, COLOR_NV12, COLOR_P010,
    },
    video_datagram::{VideoCodec, VideoFrameMetadata, VideoReassemblyConfig, FLAG_KEYFRAME},
};
use crate::message_proto::{
    message, misc, video_frame, AudioFormat, Message, Misc, VideoFrame, VideoReferenceRefresh,
};
use bytes::{Bytes, BytesMut};
use protobuf::Message as ProtobufMessage;
use quinn::{Connection, Endpoint};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
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
const VIDEO_RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(25);
const VIDEO_KEYFRAME_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(1);
const VIDEO_KEYFRAME_RETRY_MAX_ATTEMPTS: u8 = 3;
const VIDEO_KEYFRAME_RECOVERY_CYCLE_COOLDOWN: Duration = Duration::from_secs(10);
const VIDEO_EPOCH_HOLDBACK_TIMEOUT: Duration = Duration::from_secs(2);
const VIDEO_EPOCH_HOLDBACK_MAX_FRAMES: usize = 120;
const VIDEO_EPOCH_HOLDBACK_MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_VIDEO_EPOCH_STREAM_STATES: usize = 8;
const MAX_VIDEO_STREAM_STATES: usize = 16;

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

struct ReliableVideoReceiveContext {
    control: mpsc::Sender<ReliableOutbound>,
    scoped_reference_refresh: bool,
    keyframe_barrier: bool,
}

struct VideoOutbound {
    metadata: VideoFrameMetadata,
    source_info: Option<VideoSourceInfo>,
    payload: Bytes,
    ordering_epoch: u64,
}

enum LocalVideoRefresh {
    Legacy,
    Reference(VideoReferenceRefresh),
}

#[derive(Default)]
struct QuicApplicationMetrics {
    video_reassembly_drops: AtomicU64,
    video_reassembly_expired: AtomicU64,
    video_reassembly_evicted: AtomicU64,
    video_reassembly_obsolete: AtomicU64,
    video_reassembly_pre_keyframe: AtomicU64,
    video_reassembly_expired_keyframes: AtomicU64,
    video_reassembly_missing_fragments: AtomicU64,
    video_reassembly_last_us: AtomicU64,
    video_reassembly_max_us: AtomicU64,
    video_reassembly_max_gap_us: AtomicU64,
    video_reassembly_last_frame_bytes: AtomicU64,
    video_reassembly_last_frame_fragments: AtomicU64,
    video_keyframe_requests: AtomicU64,
    reliable_keyframes_sent: AtomicU64,
    reliable_keyframes_received: AtomicU64,
    video_source_frame_gaps: AtomicU64,
    video_recovery_suppressed_frames: AtomicU64,
    video_sender_replacements: AtomicU64,
    video_sender_reference_resets: AtomicU64,
    video_keyframe_barrier_held: AtomicU64,
    video_keyframe_barrier_released: AtomicU64,
    video_keyframe_barrier_timeouts: AtomicU64,
    video_keyframe_barrier_overflows: AtomicU64,
    video_delivery_lock: Mutex<()>,
    video_receive_recovery: Mutex<VideoReceiveRecovery>,
    video_epoch_holdback: Mutex<VideoEpochHoldback>,
}

struct VideoSendRecovery {
    state: Mutex<VideoSendRecoveryState>,
    refresh: mpsc::Sender<LocalVideoRefresh>,
    scoped_reference_refresh: bool,
    metrics: Arc<QuicApplicationMetrics>,
}

#[derive(Default)]
struct VideoSendRecoveryState {
    awaiting_keyframe: bool,
    minimum_keyframe_id: u64,
}

impl VideoSendRecovery {
    fn new(
        refresh: mpsc::Sender<LocalVideoRefresh>,
        scoped_reference_refresh: bool,
        metrics: Arc<QuicApplicationMetrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(VideoSendRecoveryState::default()),
            refresh,
            scoped_reference_refresh,
            metrics,
        })
    }

    fn enter(
        &self,
        source_info: Option<VideoSourceInfo>,
        dropped_frame_id: u64,
        reason: &'static str,
    ) {
        let first_loss = {
            let mut state = self.state.lock().unwrap();
            state.minimum_keyframe_id = state.minimum_keyframe_id.max(dropped_frame_id);
            let first_loss = !state.awaiting_keyframe;
            state.awaiting_keyframe = true;
            first_loss
        };
        if first_loss {
            self.metrics
                .video_sender_reference_resets
                .fetch_add(1, Ordering::Relaxed);
            if self.scoped_reference_refresh {
                if let Some(refresh) = source_info
                    .and_then(|info| video_reference_refresh(info, 1))
                    .map(LocalVideoRefresh::Reference)
                {
                    let _ = self.refresh.try_send(refresh);
                } else {
                    log::debug!(
                        "QUIC video sender lost an encoded reference before source metadata was available; scoped refresh suppressed"
                    );
                }
            } else {
                let _ = self.refresh.try_send(LocalVideoRefresh::Legacy);
            }
            log::warn!(
                "QUIC video sender lost an encoded reference at frame {dropped_frame_id}: {reason}; requesting a fresh keyframe"
            );
        }
    }

    fn suppress_delta(&self, frame_id: u64) -> bool {
        let suppressed = {
            let mut state = self.state.lock().unwrap();
            if !state.awaiting_keyframe {
                false
            } else {
                state.minimum_keyframe_id = state.minimum_keyframe_id.max(frame_id);
                true
            }
        };
        if !suppressed {
            return false;
        }
        self.metrics
            .video_recovery_suppressed_frames
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    fn keyframe_sent(&self, frame_id: u64) {
        let mut state = self.state.lock().unwrap();
        if frame_id > state.minimum_keyframe_id {
            state.awaiting_keyframe = false;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct VideoStreamKey {
    display: i32,
    stream_id: u64,
}

#[derive(Clone, Copy, Debug)]
struct VideoSourceInfo {
    key: VideoStreamKey,
    frame_id: u64,
    keyframe: bool,
}

struct HeldVideoFrame {
    info: VideoSourceInfo,
    payload: Bytes,
    received_at: Instant,
    counted_held: bool,
}

#[derive(Default)]
struct VideoEpochStreamState {
    current_epoch: u64,
    next_frame_id: u64,
    pending: BTreeMap<(u64, u64), HeldVideoFrame>,
    pending_bytes: usize,
    last_activity: u64,
}

#[derive(Default)]
struct VideoEpochHoldback {
    streams: BTreeMap<VideoStreamKey, VideoEpochStreamState>,
    activity_generation: u64,
}

#[derive(Default)]
struct VideoHoldbackOutcome {
    ready: Vec<(VideoSourceInfo, Bytes)>,
    held_frames: usize,
    released_frames: usize,
    recovery_required: bool,
    timed_out_frames: usize,
    overflowed_frames: usize,
}

impl VideoEpochHoldback {
    fn prepare_stream(&mut self, key: VideoStreamKey, outcome: &mut VideoHoldbackOutcome) {
        self.activity_generation = self.activity_generation.saturating_add(1);
        if !self.streams.contains_key(&key) && self.streams.len() >= MAX_VIDEO_EPOCH_STREAM_STATES {
            let oldest = self
                .streams
                .iter()
                .min_by_key(|(_, state)| state.last_activity)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                if let Some(state) = self.streams.remove(&oldest) {
                    if !state.pending.is_empty() {
                        outcome.overflowed_frames = outcome
                            .overflowed_frames
                            .saturating_add(state.pending.len());
                        outcome.recovery_required = true;
                    }
                }
            }
        }
        self.streams.entry(key).or_default().last_activity = self.activity_generation;
    }

    fn admit_delta(
        &mut self,
        info: VideoSourceInfo,
        reference_epoch: u64,
        payload: Bytes,
        now: Instant,
    ) -> VideoHoldbackOutcome {
        let mut outcome = self.expire(now);
        if reference_epoch == 0 {
            outcome.recovery_required = true;
            return outcome;
        }
        let stream_key = info.key;
        self.prepare_stream(stream_key, &mut outcome);
        {
            let state = self.streams.entry(stream_key).or_default();
            if reference_epoch < state.current_epoch
                || (reference_epoch == state.current_epoch
                    && state.next_frame_id != 0
                    && info.frame_id < state.next_frame_id)
            {
                return outcome;
            }
            let frame_key = (reference_epoch, info.frame_id);
            if state.pending.contains_key(&frame_key) {
                return outcome;
            }
            let counted_held = reference_epoch != state.current_epoch
                || state.next_frame_id == 0
                || info.frame_id != state.next_frame_id;
            state.pending_bytes = state.pending_bytes.saturating_add(payload.len());
            state.pending.insert(
                frame_key,
                HeldVideoFrame {
                    info,
                    payload,
                    received_at: now,
                    counted_held,
                },
            );
            if counted_held {
                outcome.held_frames = outcome.held_frames.saturating_add(1);
            }
        }
        let (frames, bytes) = self.pending_totals();
        if frames > VIDEO_EPOCH_HOLDBACK_MAX_FRAMES || bytes > VIDEO_EPOCH_HOLDBACK_MAX_BYTES {
            outcome.overflowed_frames = outcome.overflowed_frames.saturating_add(frames);
            outcome.recovery_required = true;
            self.clear_pending();
            return outcome;
        }
        if let Some(state) = self.streams.get_mut(&stream_key) {
            let (ready, released_frames) = Self::drain_ready(state);
            outcome.released_frames = outcome.released_frames.saturating_add(released_frames);
            outcome.ready.extend(ready);
        }
        outcome
    }

    fn accept_keyframe(
        &mut self,
        info: VideoSourceInfo,
        payload: Bytes,
        now: Instant,
    ) -> VideoHoldbackOutcome {
        let mut outcome = self.expire(now);
        self.prepare_stream(info.key, &mut outcome);
        let state = self.streams.entry(info.key).or_default();
        state.current_epoch = info.frame_id;
        state.next_frame_id = info.frame_id.saturating_add(1);
        let obsolete = state
            .pending
            .keys()
            .copied()
            .filter(|(epoch, frame_id)| *epoch < state.current_epoch || *frame_id <= info.frame_id)
            .collect::<Vec<_>>();
        for key in obsolete {
            if let Some(frame) = state.pending.remove(&key) {
                state.pending_bytes = state.pending_bytes.saturating_sub(frame.payload.len());
            }
        }
        outcome.ready.push((info, payload));
        let (ready, released_frames) = Self::drain_ready(state);
        outcome.released_frames = outcome.released_frames.saturating_add(released_frames);
        outcome.ready.extend(ready);
        outcome
    }

    fn expire(&mut self, now: Instant) -> VideoHoldbackOutcome {
        let mut outcome = VideoHoldbackOutcome::default();
        for state in self.streams.values_mut() {
            let timed_out = state.pending.values().any(|frame| {
                now.saturating_duration_since(frame.received_at) >= VIDEO_EPOCH_HOLDBACK_TIMEOUT
            });
            if timed_out {
                outcome.timed_out_frames =
                    outcome.timed_out_frames.saturating_add(state.pending.len());
                outcome.recovery_required = true;
                state.pending.clear();
                state.pending_bytes = 0;
            }
        }
        outcome
    }

    fn drain_ready(state: &mut VideoEpochStreamState) -> (Vec<(VideoSourceInfo, Bytes)>, usize) {
        let mut ready = Vec::new();
        let mut released_frames = 0usize;
        while state.current_epoch != 0 && state.next_frame_id != 0 {
            let key = (state.current_epoch, state.next_frame_id);
            let Some(frame) = state.pending.remove(&key) else {
                break;
            };
            state.pending_bytes = state.pending_bytes.saturating_sub(frame.payload.len());
            state.next_frame_id = state.next_frame_id.saturating_add(1);
            if frame.counted_held {
                released_frames = released_frames.saturating_add(1);
            }
            ready.push((frame.info, frame.payload));
        }
        (ready, released_frames)
    }

    fn pending_totals(&self) -> (usize, usize) {
        self.streams
            .values()
            .fold((0usize, 0usize), |total, state| {
                (
                    total.0.saturating_add(state.pending.len()),
                    total.1.saturating_add(state.pending_bytes),
                )
            })
    }

    fn clear_pending(&mut self) {
        for state in self.streams.values_mut() {
            state.pending.clear();
            state.pending_bytes = 0;
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct VideoReceiveState {
    last_frame_id: u64,
    awaiting_keyframe: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VideoReceiveDecision {
    Accept,
    Suppress,
    SuppressAfterGap,
}

#[derive(Clone, Copy, Debug)]
struct PendingVideoRecovery {
    source: Option<VideoSourceInfo>,
    requested_at: Instant,
    retries: u8,
}

#[derive(Debug)]
enum VideoKeyframeRequest {
    Legacy,
    Scoped(VideoReferenceRefresh),
}

#[derive(Default)]
struct VideoReceiveRecovery {
    streams: BTreeMap<VideoStreamKey, VideoReceiveState>,
    last_observed: Option<VideoSourceInfo>,
    pending_request: Option<PendingVideoRecovery>,
}

impl VideoReceiveRecovery {
    fn note_source_context(&mut self, info: VideoSourceInfo) {
        if info.key.stream_id == 0 || info.frame_id == 0 {
            return;
        }
        if !self.streams.contains_key(&info.key) && self.streams.len() >= MAX_VIDEO_STREAM_STATES {
            self.streams.pop_first();
        }
        self.last_observed = Some(info);
        self.streams.entry(info.key).or_default();
    }

    fn observe(&mut self, info: VideoSourceInfo) -> VideoReceiveDecision {
        if info.key.stream_id == 0 || info.frame_id == 0 {
            return VideoReceiveDecision::Accept;
        }
        if !self.streams.contains_key(&info.key) && self.streams.len() >= MAX_VIDEO_STREAM_STATES {
            self.streams.pop_first();
        }
        self.last_observed = Some(info);
        let state = self.streams.entry(info.key).or_default();
        if info.keyframe {
            if self.pending_request.is_some_and(|pending| {
                pending
                    .source
                    .is_some_and(|source| source.key == info.key && info.frame_id > source.frame_id)
            }) {
                self.pending_request = None;
            }
            state.last_frame_id = info.frame_id;
            state.awaiting_keyframe = false;
            return VideoReceiveDecision::Accept;
        }
        if state.awaiting_keyframe || state.last_frame_id == 0 {
            state.awaiting_keyframe = true;
            return VideoReceiveDecision::Suppress;
        }
        if info.frame_id <= state.last_frame_id {
            return VideoReceiveDecision::Suppress;
        }
        if info.frame_id != state.last_frame_id.saturating_add(1) {
            state.awaiting_keyframe = true;
            return VideoReceiveDecision::SuppressAfterGap;
        }
        state.last_frame_id = info.frame_id;
        VideoReceiveDecision::Accept
    }

    fn mark_reference_loss(&mut self) {
        for state in self.streams.values_mut() {
            state.awaiting_keyframe = true;
        }
    }

    fn latest_source(&self) -> Option<VideoSourceInfo> {
        if let Some(info) = self.last_observed {
            return Some(info);
        }
        self.streams.iter().rev().find_map(|(key, state)| {
            (state.last_frame_id > 0).then_some(VideoSourceInfo {
                key: *key,
                frame_id: state.last_frame_id,
                keyframe: false,
            })
        })
    }

    fn has_unrecovered_streams(&self) -> bool {
        self.streams.values().any(|state| state.awaiting_keyframe)
    }

    fn next_keyframe_request(
        &mut self,
        now: Instant,
        scoped_reference_refresh: bool,
        dropped_frames: u64,
    ) -> Option<VideoKeyframeRequest> {
        let source = self.latest_source();
        if scoped_reference_refresh && source.is_none() {
            return None;
        }

        let is_new_stream = self.pending_request.is_some_and(|pending| {
            pending
                .source
                .zip(source)
                .is_some_and(|(pending, source)| pending.key != source.key)
        });
        let due = match self.pending_request {
            None => true,
            Some(_) if is_new_stream => true,
            Some(pending) if pending.retries < VIDEO_KEYFRAME_RETRY_MAX_ATTEMPTS => {
                let multiplier = 1u32 << u32::from(pending.retries);
                now.saturating_duration_since(pending.requested_at)
                    >= VIDEO_KEYFRAME_RETRY_INITIAL_DELAY.saturating_mul(multiplier)
            }
            Some(pending) => {
                now.saturating_duration_since(pending.requested_at)
                    >= VIDEO_KEYFRAME_RECOVERY_CYCLE_COOLDOWN
            }
        };
        if !due {
            return None;
        }

        let retries = match self.pending_request {
            Some(pending)
                if !is_new_stream && pending.retries < VIDEO_KEYFRAME_RETRY_MAX_ATTEMPTS =>
            {
                pending.retries.saturating_add(1)
            }
            _ => 0,
        };
        self.pending_request = Some(PendingVideoRecovery {
            source,
            requested_at: now,
            retries,
        });
        match (scoped_reference_refresh, source) {
            (true, Some(source)) => {
                video_reference_refresh(source, dropped_frames).map(VideoKeyframeRequest::Scoped)
            }
            (false, _) => Some(VideoKeyframeRequest::Legacy),
            (true, None) => None,
        }
    }
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

fn apply_video_reference_epoch(
    item: &mut VideoOutbound,
    reference_epochs: &mut BTreeMap<VideoStreamKey, u64>,
    keyframe_barrier: bool,
) -> Option<u64> {
    if !keyframe_barrier {
        return None;
    }
    let info = item.source_info?;
    if item.is_keyframe() {
        reference_epochs.insert(info.key, info.frame_id);
        Some(info.frame_id)
    } else {
        item.metadata.presentation_timestamp_us =
            reference_epochs.get(&info.key).copied().unwrap_or(0);
        Some(item.metadata.presentation_timestamp_us)
    }
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
        self.replace_when_with(value, should_replace, |_, _| {})
    }

    fn replace_when_with(
        &self,
        value: T,
        should_replace: impl FnOnce(&T, &T) -> bool,
        on_replace: impl FnOnce(&T, &T),
    ) -> bool {
        let mut slot = self.value.lock().unwrap();
        if let Some(pending) = slot.as_ref() {
            if !should_replace(pending, &value) {
                return false;
            }
            on_replace(pending, &value);
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
    video_send_recovery: Arc<VideoSendRecovery>,
    latest_mouse: Arc<LatestSlot<MouseOutbound>>,
    datagram_send: Arc<QuicDatagramSendCoordinator>,
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
        let (video_refresh_tx, video_refresh_rx) = mpsc::channel(1);
        let video_send_recovery = VideoSendRecovery::new(
            video_refresh_tx,
            application_protocol.supports_scoped_video_reference_refresh(),
            metrics.clone(),
        );
        tasks.push(tokio::spawn(run_local_video_refresh(
            video_refresh_rx,
            inbound_tx.clone(),
        )));
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
                Some(ReliableVideoReceiveContext {
                    control: control.clone(),
                    scoped_reference_refresh: application_protocol
                        .supports_scoped_video_reference_refresh(),
                    keyframe_barrier: agreement.reliable_keyframe_barrier,
                }),
            )));
            Some(sender)
        } else {
            None
        };

        let (audio, audio_rx) = mpsc::channel(AUDIO_OUTBOUND_CAPACITY);
        let latest_video = LatestSlot::new();
        let latest_mouse = LatestSlot::new();
        let datagram_send = QuicDatagramSendCoordinator::new(
            DEFAULT_INTERACTIVE_DATAGRAM_RESERVE_BYTES,
            connection.datagram_send_buffer_space(),
        );
        let negotiated_datagram_size = usize::from(agreement.max_datagram_payload);
        tasks.push(tokio::spawn(run_video_writer(
            QuicDatagramSender::new(connection.clone(), session_id)
                .with_max_datagram_size(negotiated_datagram_size)
                .with_coordinator(datagram_send.clone()),
            latest_video.clone(),
            video_ordering.clone(),
            inbound_tx.clone(),
            connection.clone(),
            reliable_video_sender,
            video_send_recovery.clone(),
            agreement.reliable_keyframe_barrier,
        )));
        tasks.push(tokio::spawn(run_mouse_writer(
            QuicDatagramSender::new(connection.clone(), session_id)
                .with_max_datagram_size(negotiated_datagram_size)
                .with_coordinator(datagram_send.clone()),
            latest_mouse.clone(),
            inbound_tx.clone(),
            connection.clone(),
        )));
        tasks.push(tokio::spawn(run_audio_writer(
            QuicDatagramSender::new(connection.clone(), session_id)
                .with_max_datagram_size(negotiated_datagram_size)
                .with_coordinator(datagram_send.clone()),
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
            application_protocol.supports_scoped_video_reference_refresh(),
            agreement.reliable_keyframe_barrier,
            metrics.clone(),
        )));

        log::info!(
            "QUIC application channels ready: role={role:?}, protocol={application_protocol:?}, reliable_keyframes={}, keyframe_barrier={}, local={local_addr}, peer={}, mtu={}, datagram_payload_live={:?}, datagram_payload_negotiated={}",
            agreement.reliable_keyframes,
            agreement.reliable_keyframe_barrier,
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
            video_send_recovery,
            latest_mouse,
            datagram_send,
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
                let frame_id = metadata.frame_id;
                let keyframe = metadata.flags & FLAG_KEYFRAME != 0;
                if !keyframe && self.video_send_recovery.suppress_delta(frame_id) {
                    return Ok(());
                }
                let source_info = video_source_info(&payload).ok();
                let queued = self.latest_video.replace_when_with(
                    VideoOutbound {
                        metadata,
                        source_info,
                        payload,
                        ordering_epoch: self.video_ordering.current_epoch(),
                    },
                    should_replace_pending_video,
                    |_, incoming| {
                        self.metrics
                            .video_sender_replacements
                            .fetch_add(1, Ordering::Relaxed);
                        if !incoming.is_keyframe() {
                            self.video_send_recovery.enter(
                                incoming.source_info,
                                incoming.metadata.frame_id,
                                "a newer encoded delta replaced a pending frame",
                            );
                        }
                    },
                );
                if !queued {
                    self.metrics
                        .video_sender_replacements
                        .fetch_add(1, Ordering::Relaxed);
                    self.video_send_recovery.enter(
                        source_info,
                        frame_id,
                        "an encoded frame could not enter the latest-frame slot",
                    );
                }
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
        stats.reliable_keyframe_barrier = self.agreement.reliable_keyframe_barrier;
        stats.video_reassembly_drops = self.metrics.video_reassembly_drops.load(Ordering::Relaxed);
        stats.video_reassembly_expired = self
            .metrics
            .video_reassembly_expired
            .load(Ordering::Relaxed);
        stats.video_reassembly_evicted = self
            .metrics
            .video_reassembly_evicted
            .load(Ordering::Relaxed);
        stats.video_reassembly_obsolete = self
            .metrics
            .video_reassembly_obsolete
            .load(Ordering::Relaxed);
        stats.video_reassembly_pre_keyframe = self
            .metrics
            .video_reassembly_pre_keyframe
            .load(Ordering::Relaxed);
        stats.video_reassembly_expired_keyframes = self
            .metrics
            .video_reassembly_expired_keyframes
            .load(Ordering::Relaxed);
        stats.video_reassembly_missing_fragments = self
            .metrics
            .video_reassembly_missing_fragments
            .load(Ordering::Relaxed);
        stats.video_reassembly_last_us = self
            .metrics
            .video_reassembly_last_us
            .load(Ordering::Relaxed);
        stats.video_reassembly_max_us =
            self.metrics.video_reassembly_max_us.load(Ordering::Relaxed);
        stats.video_reassembly_max_gap_us = self
            .metrics
            .video_reassembly_max_gap_us
            .load(Ordering::Relaxed);
        stats.video_reassembly_last_frame_bytes = self
            .metrics
            .video_reassembly_last_frame_bytes
            .load(Ordering::Relaxed);
        stats.video_reassembly_last_frame_fragments = self
            .metrics
            .video_reassembly_last_frame_fragments
            .load(Ordering::Relaxed);
        stats.video_keyframe_requests =
            self.metrics.video_keyframe_requests.load(Ordering::Relaxed);
        stats.reliable_keyframes_sent =
            self.metrics.reliable_keyframes_sent.load(Ordering::Relaxed);
        stats.reliable_keyframes_received = self
            .metrics
            .reliable_keyframes_received
            .load(Ordering::Relaxed);
        stats.video_source_frame_gaps =
            self.metrics.video_source_frame_gaps.load(Ordering::Relaxed);
        stats.video_recovery_suppressed_frames = self
            .metrics
            .video_recovery_suppressed_frames
            .load(Ordering::Relaxed);
        stats.video_sender_replacements = self
            .metrics
            .video_sender_replacements
            .load(Ordering::Relaxed);
        stats.video_sender_reference_resets = self
            .metrics
            .video_sender_reference_resets
            .load(Ordering::Relaxed);
        stats.video_keyframe_barrier_held = self
            .metrics
            .video_keyframe_barrier_held
            .load(Ordering::Relaxed);
        stats.video_keyframe_barrier_released = self
            .metrics
            .video_keyframe_barrier_released
            .load(Ordering::Relaxed);
        stats.video_keyframe_barrier_timeouts = self
            .metrics
            .video_keyframe_barrier_timeouts
            .load(Ordering::Relaxed);
        stats.video_keyframe_barrier_overflows = self
            .metrics
            .video_keyframe_barrier_overflows
            .load(Ordering::Relaxed);
        let datagram_send = self.datagram_send.stats();
        stats.video_datagram_frames_sent = datagram_send.video_frames_sent;
        stats.video_datagram_frames_rejected = datagram_send.video_frames_rejected;
        stats.video_datagrams_sent = datagram_send.video_datagrams_sent;
        stats.video_datagram_frame_bytes = datagram_send.video_frame_bytes;
        stats.video_datagram_frame_bytes_peak = datagram_send.video_frame_bytes_peak;
        stats.video_datagram_frame_fragments = datagram_send.video_frame_fragments;
        stats.video_datagram_frame_fragments_peak = datagram_send.video_frame_fragments_peak;
        stats.datagram_send_buffer_space = datagram_send.send_buffer_space;
        stats.datagram_send_buffer_space_min = datagram_send.send_buffer_space_min;
        stats.datagram_send_buffer_queued = datagram_send.send_buffer_queued;
        stats.video_datagram_queue_budget = datagram_send.video_queue_budget;
        stats.video_datagram_queue_delay_us = datagram_send.video_queue_delay_us;
        stats.video_datagram_queue_target_us = datagram_send.video_queue_target_us;
        stats.audio_datagram_drops = datagram_send.audio_packets_dropped;
        stats.mouse_datagram_drops = datagram_send.mouse_updates_dropped;
        stats
    }

    pub fn peer_binding(&self) -> &QuicPeerBinding {
        &self.peer_binding
    }

    pub fn set_video_datagram_queue_policy(&self, target: Duration, minimum_bytes: usize) {
        self.datagram_send
            .set_video_queue_policy(target, minimum_bytes);
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
        "QUIC session negotiated: protocol={}, video={:?}, audio={:?}, color={:?}, mtu_payload={}, reliable_keyframes={}, keyframe_barrier={}, max_fps={}, file_kbps={}",
        agreement.protocol_version,
        agreement.video_codec,
        agreement.audio_codec,
        agreement.color_format,
        agreement.max_datagram_payload,
        agreement.reliable_keyframes,
        agreement.reliable_keyframe_barrier,
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
            }
            | if application_protocol.supports_reliable_keyframe_barrier() {
                CAP_RELIABLE_KEYFRAME_BARRIER
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
        None,
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
    video_context: Option<ReliableVideoReceiveContext>,
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
        let reliable_video = if expected_kind == ReliableChannelKind::Video {
            let info = match video_source_info(&message.payload) {
                Ok(info) if info.keyframe => info,
                Ok(_) => {
                    report_terminal_error(
                        &inbound,
                        &connection,
                        "reliable video channel received a delta frame".to_owned(),
                    )
                    .await;
                    return;
                }
                Err(error) => {
                    report_terminal_error(&inbound, &connection, error.to_string()).await;
                    return;
                }
            };
            Some(info)
        } else {
            None
        };
        if let (Some(info), Some(context)) = (reliable_video, video_context.as_ref()) {
            if context.keyframe_barrier {
                metrics
                    .reliable_keyframes_received
                    .fetch_add(1, Ordering::Relaxed);
                let _delivery_guard = metrics.video_delivery_lock.lock().unwrap();
                let outcome = metrics
                    .video_epoch_holdback
                    .lock()
                    .unwrap()
                    .accept_keyframe(
                        info,
                        Bytes::copy_from_slice(&message.payload),
                        Instant::now(),
                    );
                log::debug!(
                    "QUIC video keyframe barrier opened: display={}, stream={}, epoch={}, released_frames={}",
                    info.key.display,
                    info.key.stream_id,
                    info.frame_id,
                    outcome.released_frames,
                );
                record_video_holdback_metrics(&outcome, &metrics);
                let mut needs_keyframe = outcome.recovery_required;
                if needs_keyframe {
                    metrics
                        .video_receive_recovery
                        .lock()
                        .unwrap()
                        .mark_reference_loss();
                }
                for (ready_info, payload) in outcome.ready {
                    let (alive, frame_needs_keyframe) = deliver_video_payload(
                        ready_info,
                        payload,
                        &inbound,
                        &metrics,
                        &metrics.video_receive_recovery,
                    );
                    if !alive {
                        return;
                    }
                    needs_keyframe |= frame_needs_keyframe;
                }
                if needs_keyframe
                    && !request_video_keyframe(
                        &context.control,
                        context.scoped_reference_refresh,
                        &metrics,
                        &metrics.video_receive_recovery,
                        Instant::now(),
                        0,
                    )
                {
                    return;
                }
                continue;
            }
        }
        if inbound
            .send(Ok(BytesMut::from(message.payload.as_slice())))
            .await
            .is_err()
        {
            return;
        }
        if let Some(info) = reliable_video {
            metrics
                .reliable_keyframes_received
                .fetch_add(1, Ordering::Relaxed);
            let _ = metrics.video_receive_recovery.lock().unwrap().observe(info);
        }
    }
}

async fn run_local_video_refresh(
    mut refresh: mpsc::Receiver<LocalVideoRefresh>,
    inbound: mpsc::Sender<Result<BytesMut, Error>>,
) {
    while let Some(refresh) = refresh.recv().await {
        let message = match refresh {
            LocalVideoRefresh::Legacy => refresh_video_message(),
            LocalVideoRefresh::Reference(refresh) => video_reference_refresh_message(refresh),
        };
        if inbound
            .send(Ok(BytesMut::from(message.as_slice())))
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
    recovery: Arc<VideoSendRecovery>,
    keyframe_barrier: bool,
) {
    let started = Instant::now();
    let mut reference_epochs = BTreeMap::<VideoStreamKey, u64>::new();
    loop {
        let mut item = video.take().await;
        while !video_ordering.is_open(item.ordering_epoch) {
            tokio::select! {
                _ = video_ordering.wait(item.ordering_epoch) => {},
                newer = video.take() => {
                    if should_replace_pending_video(&item, &newer) {
                        recovery
                            .metrics
                            .video_sender_replacements
                            .fetch_add(1, Ordering::Relaxed);
                        if !newer.is_keyframe() {
                            recovery.enter(
                                newer.source_info,
                                newer.metadata.frame_id,
                                "a newer encoded delta replaced a frame waiting for display ordering",
                            );
                        }
                        item = newer;
                    } else {
                        recovery
                            .metrics
                            .video_sender_replacements
                            .fetch_add(1, Ordering::Relaxed);
                        recovery.enter(
                            newer.source_info,
                            newer.metadata.frame_id,
                            "an encoded frame was discarded while waiting for display ordering",
                        );
                    }
                },
            }
        }
        if !item.is_keyframe() && recovery.suppress_delta(item.metadata.frame_id) {
            continue;
        }
        let reference_epoch =
            apply_video_reference_epoch(&mut item, &mut reference_epochs, keyframe_barrier);
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
                recovery
                    .metrics
                    .reliable_keyframes_sent
                    .fetch_add(1, Ordering::Relaxed);
                log::debug!(
                    "QUIC reliable keyframe sent: frame_id={}, bytes={}, barrier_epoch={:?}",
                    item.metadata.frame_id,
                    item.payload.len(),
                    reference_epoch,
                );
                recovery.keyframe_sent(item.metadata.frame_id);
                continue;
            }
        }
        match sender.send_video_frame(item.metadata, &item.payload) {
            Ok(VideoDatagramSendOutcome::Sent { .. }) => {}
            Ok(VideoDatagramSendOutcome::RejectedNoSpace {
                failure,
                datagram_bytes,
                available_bytes,
                queued_bytes,
                video_queue_budget,
                interactive_reserve_bytes,
                queue_delay_us,
            }) => {
                log::warn!(
                    "QUIC video frame rejected before DATAGRAM enqueue: frame_id={}, bytes={}, reason={}, datagram_bytes={}, available_bytes={}, queued_bytes={}, queue_budget_bytes={}, interactive_reserve_bytes={}, queue_delay_us={}",
                    item.metadata.frame_id,
                    item.payload.len(),
                    failure.as_str(),
                    datagram_bytes,
                    available_bytes,
                    queued_bytes,
                    video_queue_budget,
                    interactive_reserve_bytes,
                    queue_delay_us,
                );
                recovery.enter(
                    item.source_info,
                    item.metadata.frame_id,
                    "the complete encoded frame did not fit the QUIC DATAGRAM send budget",
                );
                continue;
            }
            Err(error) => {
                report_terminal_error(&inbound, &connection, error.to_string()).await;
                return;
            }
        }
        if item.is_keyframe() {
            recovery.keyframe_sent(item.metadata.frame_id);
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
    scoped_reference_refresh: bool,
    keyframe_barrier: bool,
    metrics: Arc<QuicApplicationMetrics>,
) {
    let mut received_audio_format = None;
    let mut video_expiry = tokio::time::interval(VIDEO_RECOVERY_POLL_INTERVAL);
    video_expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    video_expiry.tick().await;
    loop {
        let event = tokio::select! {
            result = receiver.receive() => {
                match result {
                    Ok(event) => Some(event),
                    Err(error) => {
                        report_terminal_error(&inbound, &connection, error.to_string()).await;
                        return;
                    }
                }
            }
            _ = video_expiry.tick() => {
                let outcome = receiver.expire_video(Instant::now());
                if (keyframe_barrier
                    || outcome.dropped_frames > 0
                    || outcome.request_keyframe)
                    && !handle_video_outcome(
                        outcome,
                        receiver.video_stats(),
                        &inbound,
                        &control,
                        scoped_reference_refresh,
                        keyframe_barrier,
                        &metrics,
                        &metrics.video_receive_recovery,
                        Instant::now(),
                    )
                {
                    return;
                }
                None
            }
        };
        let Some(event) = event else {
            continue;
        };
        match event {
            DatagramReceiveEvent::Video(outcome) => {
                if !handle_video_outcome(
                    outcome,
                    receiver.video_stats(),
                    &inbound,
                    &control,
                    scoped_reference_refresh,
                    keyframe_barrier,
                    &metrics,
                    &metrics.video_receive_recovery,
                    Instant::now(),
                ) {
                    return;
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

fn record_video_holdback_metrics(outcome: &VideoHoldbackOutcome, metrics: &QuicApplicationMetrics) {
    metrics.video_keyframe_barrier_held.fetch_add(
        u64::try_from(outcome.held_frames).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    metrics.video_keyframe_barrier_released.fetch_add(
        u64::try_from(outcome.released_frames).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    metrics.video_keyframe_barrier_timeouts.fetch_add(
        u64::try_from(outcome.timed_out_frames).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    metrics.video_keyframe_barrier_overflows.fetch_add(
        u64::try_from(outcome.overflowed_frames).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    if outcome.timed_out_frames > 0 {
        log::warn!(
            "QUIC video keyframe barrier timed out: dropped_held_frames={}",
            outcome.timed_out_frames
        );
    }
    if outcome.overflowed_frames > 0 {
        log::warn!(
            "QUIC video keyframe barrier overflowed: dropped_held_frames={}",
            outcome.overflowed_frames
        );
    }
}

fn deliver_video_payload(
    info: VideoSourceInfo,
    payload: Bytes,
    inbound: &mpsc::Sender<Result<BytesMut, Error>>,
    metrics: &QuicApplicationMetrics,
    recovery: &Mutex<VideoReceiveRecovery>,
) -> (bool, bool) {
    let decision = {
        let mut recovery = recovery.lock().unwrap();
        recovery.observe(info)
    };
    match decision {
        VideoReceiveDecision::Accept => {
            match inbound.try_send(Ok(BytesMut::from(payload.as_ref()))) {
                Ok(()) => {
                    let needs_keyframe =
                        info.keyframe && recovery.lock().unwrap().has_unrecovered_streams();
                    (true, needs_keyframe)
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    recovery.lock().unwrap().mark_reference_loss();
                    metrics
                        .video_recovery_suppressed_frames
                        .fetch_add(1, Ordering::Relaxed);
                    (true, true)
                }
                Err(mpsc::error::TrySendError::Closed(_)) => (false, false),
            }
        }
        VideoReceiveDecision::Suppress => {
            metrics
                .video_recovery_suppressed_frames
                .fetch_add(1, Ordering::Relaxed);
            (true, true)
        }
        VideoReceiveDecision::SuppressAfterGap => {
            log::warn!(
                "QUIC video source gap: display={}, stream={}, frame={}; suppressing deltas until keyframe",
                info.key.display,
                info.key.stream_id,
                info.frame_id,
            );
            metrics
                .video_source_frame_gaps
                .fetch_add(1, Ordering::Relaxed);
            metrics
                .video_recovery_suppressed_frames
                .fetch_add(1, Ordering::Relaxed);
            (true, true)
        }
    }
}

fn request_video_keyframe(
    control: &mpsc::Sender<ReliableOutbound>,
    scoped_reference_refresh: bool,
    metrics: &QuicApplicationMetrics,
    recovery: &Mutex<VideoReceiveRecovery>,
    now: Instant,
    dropped_frames: u64,
) -> bool {
    let request = recovery.lock().unwrap().next_keyframe_request(
        now,
        scoped_reference_refresh,
        dropped_frames,
    );
    let Some(request) = request else {
        return true;
    };
    let (payload, scoped) = match request {
        VideoKeyframeRequest::Legacy => (refresh_video_message(), false),
        VideoKeyframeRequest::Scoped(refresh) => (video_reference_refresh_message(refresh), true),
    };
    match control.try_send(ReliableOutbound {
        message_type: MessageType::ApplicationControl,
        payload: Bytes::from(payload),
    }) {
        Ok(()) => {
            metrics
                .video_keyframe_requests
                .fetch_add(1, Ordering::Relaxed);
            log::debug!(
                "QUIC video recovery requested a fresh keyframe: scoped={}",
                scoped
            );
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn handle_video_outcome(
    outcome: super::video_datagram::VideoReassemblyOutcome,
    video_stats: &super::video_datagram::VideoReassemblyStats,
    inbound: &mpsc::Sender<Result<BytesMut, Error>>,
    control: &mpsc::Sender<ReliableOutbound>,
    scoped_reference_refresh: bool,
    keyframe_barrier: bool,
    metrics: &QuicApplicationMetrics,
    recovery: &Mutex<VideoReceiveRecovery>,
    now: Instant,
) -> bool {
    metrics.video_reassembly_drops.store(
        video_stats
            .expired_frames
            .saturating_add(video_stats.evicted_frames)
            .saturating_add(video_stats.obsolete_frames)
            .saturating_add(video_stats.pre_keyframe_frames),
        Ordering::Relaxed,
    );
    metrics
        .video_reassembly_expired
        .store(video_stats.expired_frames, Ordering::Relaxed);
    metrics
        .video_reassembly_evicted
        .store(video_stats.evicted_frames, Ordering::Relaxed);
    metrics
        .video_reassembly_obsolete
        .store(video_stats.obsolete_frames, Ordering::Relaxed);
    metrics
        .video_reassembly_pre_keyframe
        .store(video_stats.pre_keyframe_frames, Ordering::Relaxed);
    metrics
        .video_reassembly_expired_keyframes
        .store(video_stats.expired_keyframes, Ordering::Relaxed);
    metrics
        .video_reassembly_missing_fragments
        .store(video_stats.missing_fragments, Ordering::Relaxed);
    metrics
        .video_reassembly_last_us
        .store(video_stats.last_frame_assembly_us, Ordering::Relaxed);
    metrics
        .video_reassembly_max_us
        .store(video_stats.max_frame_assembly_us, Ordering::Relaxed);
    metrics
        .video_reassembly_max_gap_us
        .store(video_stats.max_fragment_gap_us, Ordering::Relaxed);
    metrics
        .video_reassembly_last_frame_bytes
        .store(video_stats.last_frame_bytes, Ordering::Relaxed);
    metrics
        .video_reassembly_last_frame_fragments
        .store(video_stats.last_frame_fragments, Ordering::Relaxed);
    let _delivery_guard = metrics.video_delivery_lock.lock().unwrap();
    let mut needs_keyframe = outcome.request_keyframe || outcome.dropped_frames > 0;
    if outcome.dropped_frames > 0 {
        recovery.lock().unwrap().mark_reference_loss();
    }
    let holdback_outcome = if keyframe_barrier {
        if let Some(frame) = outcome.frame {
            match video_source_info(&frame.payload) {
                Ok(info) => {
                    recovery.lock().unwrap().note_source_context(info);
                    metrics.video_epoch_holdback.lock().unwrap().admit_delta(
                        info,
                        frame.metadata.presentation_timestamp_us,
                        Bytes::from(frame.payload),
                        now,
                    )
                }
                Err(error) => {
                    log::warn!("Invalid QUIC video application payload was discarded: {error}");
                    VideoHoldbackOutcome::default()
                }
            }
        } else {
            metrics.video_epoch_holdback.lock().unwrap().expire(now)
        }
    } else {
        let mut legacy = VideoHoldbackOutcome::default();
        if let Some(frame) = outcome.frame {
            match video_source_info(&frame.payload) {
                Ok(info) => legacy.ready.push((info, Bytes::from(frame.payload))),
                Err(error) => {
                    log::warn!("Invalid QUIC video application payload was discarded: {error}");
                }
            }
        }
        legacy
    };
    record_video_holdback_metrics(&holdback_outcome, metrics);
    if holdback_outcome.recovery_required {
        recovery.lock().unwrap().mark_reference_loss();
        needs_keyframe = true;
    }
    for (info, payload) in holdback_outcome.ready {
        let (alive, frame_needs_keyframe) =
            deliver_video_payload(info, payload, inbound, metrics, recovery);
        if !alive {
            return false;
        }
        needs_keyframe |= frame_needs_keyframe;
    }
    !needs_keyframe
        || request_video_keyframe(
            control,
            scoped_reference_refresh,
            metrics,
            recovery,
            now,
            u64::from(outcome.dropped_frames),
        )
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
        (ApplicationClassTag::Audio, ApplicationClass::Audio)
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

fn video_source_info(payload: &[u8]) -> Result<VideoSourceInfo, QuicTransportError> {
    let message = Message::parse_from_bytes(payload)
        .map_err(|error| QuicTransportError::ProtocolState(error.to_string()))?;
    let Some(message::Union::VideoFrame(frame)) = message.union.as_ref() else {
        return Err(QuicTransportError::ProtocolState(
            "QUIC video payload does not contain a video frame".to_owned(),
        ));
    };
    let metadata = video_metadata(frame)?;
    Ok(VideoSourceInfo {
        key: VideoStreamKey {
            display: frame.display,
            stream_id: frame.stream_id,
        },
        frame_id: frame.frame_id,
        keyframe: metadata.flags & FLAG_KEYFRAME != 0,
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

fn video_reference_refresh(
    info: VideoSourceInfo,
    dropped_frames: u64,
) -> Option<VideoReferenceRefresh> {
    if info.key.display < 0 || info.key.stream_id == 0 || info.frame_id == 0 {
        return None;
    }
    Some(VideoReferenceRefresh {
        display: info.key.display,
        stream_id: info.key.stream_id,
        received_frame_id: info.frame_id,
        dropped_frames,
        ..Default::default()
    })
}

fn video_reference_refresh_message(refresh: VideoReferenceRefresh) -> Vec<u8> {
    let mut misc = Misc::new();
    misc.set_video_reference_refresh(refresh);
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
            source_info: Some(VideoSourceInfo {
                key: VideoStreamKey {
                    display: 0,
                    stream_id: 7,
                },
                frame_id,
                keyframe,
            }),
            payload: Bytes::from(vec![frame_id as u8]),
            ordering_epoch,
        }
    }

    #[test]
    fn v4_deltas_are_tagged_with_the_latest_source_keyframe() {
        let mut epochs = BTreeMap::new();
        let mut keyframe = outbound_video(10, true, 0);
        let mut delta = outbound_video(11, false, 0);

        assert_eq!(
            apply_video_reference_epoch(&mut keyframe, &mut epochs, true),
            Some(10)
        );
        assert_eq!(
            apply_video_reference_epoch(&mut delta, &mut epochs, true),
            Some(10)
        );
        assert_eq!(delta.metadata.presentation_timestamp_us, 10);

        let mut legacy = outbound_video(12, false, 0);
        assert_eq!(
            apply_video_reference_epoch(&mut legacy, &mut epochs, false),
            None
        );
        assert_eq!(legacy.metadata.presentation_timestamp_us, 12_000);
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

    fn source_video(stream_id: u64, frame_id: u64, keyframe: bool) -> VideoSourceInfo {
        VideoSourceInfo {
            key: VideoStreamKey {
                display: 0,
                stream_id,
            },
            frame_id,
            keyframe,
        }
    }

    #[test]
    fn receiver_suppresses_deltas_after_a_source_gap_until_keyframe() {
        let mut recovery = VideoReceiveRecovery::default();
        assert_eq!(
            recovery.observe(source_video(7, 1, true)),
            VideoReceiveDecision::Accept
        );
        assert_eq!(
            recovery.observe(source_video(7, 3, false)),
            VideoReceiveDecision::SuppressAfterGap
        );
        assert_eq!(
            recovery.observe(source_video(7, 4, false)),
            VideoReceiveDecision::Suppress
        );
        assert_eq!(
            recovery.observe(source_video(7, 5, true)),
            VideoReceiveDecision::Accept
        );
        assert_eq!(
            recovery.observe(source_video(7, 6, false)),
            VideoReceiveDecision::Accept
        );
    }

    #[test]
    fn receiver_recovery_isolated_per_video_stream() {
        let mut recovery = VideoReceiveRecovery::default();
        assert_eq!(
            recovery.observe(source_video(1, 1, true)),
            VideoReceiveDecision::Accept
        );
        assert_eq!(
            recovery.observe(source_video(2, 1, true)),
            VideoReceiveDecision::Accept
        );
        assert_eq!(
            recovery.observe(source_video(1, 3, false)),
            VideoReceiveDecision::SuppressAfterGap
        );
        assert_eq!(
            recovery.observe(source_video(2, 2, false)),
            VideoReceiveDecision::Accept
        );
    }

    #[test]
    fn legacy_unstamped_video_frames_remain_compatible() {
        let mut recovery = VideoReceiveRecovery::default();
        assert_eq!(
            recovery.observe(source_video(0, 0, false)),
            VideoReceiveDecision::Accept
        );
    }

    #[test]
    fn receiver_keyframe_recovery_uses_bounded_backoff() {
        let now = Instant::now();
        let mut recovery = VideoReceiveRecovery::default();
        recovery.observe(source_video(7, 4, true));

        assert!(matches!(
            recovery.next_keyframe_request(now, true, 1),
            Some(VideoKeyframeRequest::Scoped(_))
        ));
        assert!(recovery
            .next_keyframe_request(now + Duration::from_millis(999), true, 0)
            .is_none());
        assert!(matches!(
            recovery.next_keyframe_request(now + Duration::from_secs(1), true, 0),
            Some(VideoKeyframeRequest::Scoped(_))
        ));
        assert!(recovery
            .next_keyframe_request(now + Duration::from_secs(2), true, 0)
            .is_none());
        assert!(matches!(
            recovery.next_keyframe_request(now + Duration::from_secs(3), true, 0),
            Some(VideoKeyframeRequest::Scoped(_))
        ));
        assert!(matches!(
            recovery.next_keyframe_request(now + Duration::from_secs(7), true, 0),
            Some(VideoKeyframeRequest::Scoped(_))
        ));
        assert!(recovery
            .next_keyframe_request(now + Duration::from_secs(16), true, 0)
            .is_none());
        assert!(matches!(
            recovery.next_keyframe_request(now + Duration::from_secs(17), true, 0),
            Some(VideoKeyframeRequest::Scoped(_))
        ));
    }

    #[test]
    fn receiver_keyframe_ends_the_pending_recovery_cycle() {
        let now = Instant::now();
        let mut recovery = VideoReceiveRecovery::default();
        recovery.observe(source_video(7, 4, true));
        recovery.observe(source_video(7, 6, false));
        assert!(recovery.next_keyframe_request(now, true, 1).is_some());
        assert_eq!(
            recovery.observe(source_video(7, 7, true)),
            VideoReceiveDecision::Accept
        );
        assert!(recovery.pending_request.is_none());
    }

    #[test]
    fn keyframe_barrier_holds_future_deltas_and_releases_them_in_order() {
        let now = Instant::now();
        let mut holdback = VideoEpochHoldback::default();
        let held_11 = holdback.admit_delta(
            source_video(7, 11, false),
            10,
            Bytes::from_static(b"delta-11"),
            now,
        );
        let held_13 = holdback.admit_delta(
            source_video(7, 13, false),
            10,
            Bytes::from_static(b"delta-13"),
            now,
        );
        assert!(held_11.ready.is_empty());
        assert!(held_13.ready.is_empty());

        let keyframe = holdback.accept_keyframe(
            source_video(7, 10, true),
            Bytes::from_static(b"keyframe-10"),
            now,
        );
        assert_eq!(
            keyframe
                .ready
                .iter()
                .map(|(info, _)| info.frame_id)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );

        let filled_gap = holdback.admit_delta(
            source_video(7, 12, false),
            10,
            Bytes::from_static(b"delta-12"),
            now,
        );
        assert_eq!(
            filled_gap
                .ready
                .iter()
                .map(|(info, _)| info.frame_id)
                .collect::<Vec<_>>(),
            vec![12, 13]
        );
    }

    #[test]
    fn keyframe_barrier_times_out_without_unbounded_holdback() {
        let now = Instant::now();
        let mut holdback = VideoEpochHoldback::default();
        let held = holdback.admit_delta(
            source_video(7, 11, false),
            10,
            Bytes::from_static(b"delta-11"),
            now,
        );
        assert_eq!(held.held_frames, 1);

        let expired = holdback.expire(now + VIDEO_EPOCH_HOLDBACK_TIMEOUT);
        assert!(expired.recovery_required);
        assert_eq!(expired.timed_out_frames, 1);
        assert_eq!(holdback.pending_totals(), (0, 0));
    }

    #[test]
    fn keyframe_barrier_timeout_keeps_scoped_recovery_context() {
        let now = Instant::now();
        let mut recovery = VideoReceiveRecovery::default();
        recovery.note_source_context(source_video(7, 11, false));
        recovery.mark_reference_loss();

        match recovery.next_keyframe_request(now, true, 1) {
            Some(VideoKeyframeRequest::Scoped(refresh)) => {
                assert_eq!(refresh.display, 0);
                assert_eq!(refresh.stream_id, 7);
                assert_eq!(refresh.received_frame_id, 11);
                assert_eq!(refresh.dropped_frames, 1);
            }
            _ => panic!("expected scoped recovery for a held delta"),
        }
    }

    #[test]
    fn keyframe_barrier_rejects_unbounded_future_epochs() {
        let now = Instant::now();
        let mut holdback = VideoEpochHoldback::default();
        let mut overflow = VideoHoldbackOutcome::default();
        for frame_id in 1..=VIDEO_EPOCH_HOLDBACK_MAX_FRAMES + 1 {
            overflow = holdback.admit_delta(
                source_video(7, frame_id as u64, false),
                10,
                Bytes::from_static(b"delta"),
                now,
            );
        }
        assert!(overflow.recovery_required);
        assert!(overflow.overflowed_frames > 0);
        assert_eq!(holdback.pending_totals(), (0, 0));
    }

    #[test]
    fn keyframe_barrier_bounds_stream_states_and_evicts_least_recently_used() {
        let now = Instant::now();
        let mut holdback = VideoEpochHoldback::default();
        for display in 0..MAX_VIDEO_EPOCH_STREAM_STATES {
            let info = VideoSourceInfo {
                key: VideoStreamKey {
                    display: display as i32,
                    stream_id: display as u64 + 1,
                },
                frame_id: 1,
                keyframe: true,
            };
            holdback.accept_keyframe(info, Bytes::from_static(b"keyframe"), now);
        }

        let primary = VideoSourceInfo {
            key: VideoStreamKey {
                display: 0,
                stream_id: 1,
            },
            frame_id: 2,
            keyframe: true,
        };
        holdback.accept_keyframe(primary, Bytes::from_static(b"keyframe"), now);
        let newest = VideoSourceInfo {
            key: VideoStreamKey {
                display: MAX_VIDEO_EPOCH_STREAM_STATES as i32,
                stream_id: MAX_VIDEO_EPOCH_STREAM_STATES as u64 + 1,
            },
            frame_id: 1,
            keyframe: true,
        };
        holdback.accept_keyframe(newest, Bytes::from_static(b"keyframe"), now);

        assert_eq!(holdback.streams.len(), MAX_VIDEO_EPOCH_STREAM_STATES);
        assert!(holdback.streams.contains_key(&primary.key));
        assert!(!holdback.streams.contains_key(&VideoStreamKey {
            display: 1,
            stream_id: 2,
        }));
    }

    #[test]
    fn receiver_recovery_serializes_scoped_reference_refresh_for_v3() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let (control, mut control_rx) = mpsc::channel(1);
        let metrics = QuicApplicationMetrics::default();
        let recovery = Mutex::new(VideoReceiveRecovery::default());
        recovery.lock().unwrap().observe(source_video(7, 4, true));
        let outcome = super::super::video_datagram::VideoReassemblyOutcome {
            request_keyframe: true,
            dropped_frames: 1,
            frame: None,
        };
        assert!(handle_video_outcome(
            outcome,
            &super::super::video_datagram::VideoReassemblyStats::default(),
            &inbound,
            &control,
            true,
            false,
            &metrics,
            &recovery,
            Instant::now(),
        ));
        let outbound = control_rx.try_recv().unwrap();
        let message = Message::parse_from_bytes(&outbound.payload).unwrap();
        let Some(message::Union::Misc(misc)) = message.union else {
            panic!("expected misc message");
        };
        let Some(misc::Union::VideoReferenceRefresh(refresh)) = misc.union else {
            panic!("expected scoped video reference refresh");
        };
        assert_eq!(refresh.display, 0);
        assert_eq!(refresh.stream_id, 7);
        assert_eq!(refresh.received_frame_id, 4);
        assert_eq!(refresh.dropped_frames, 1);
    }

    #[test]
    fn receiver_recovery_keeps_legacy_refresh_for_old_quic_protocols() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let (control, mut control_rx) = mpsc::channel(1);
        let metrics = QuicApplicationMetrics::default();
        let recovery = Mutex::new(VideoReceiveRecovery::default());
        recovery.lock().unwrap().observe(source_video(7, 4, true));
        let outcome = super::super::video_datagram::VideoReassemblyOutcome {
            request_keyframe: true,
            dropped_frames: 1,
            frame: None,
        };
        assert!(handle_video_outcome(
            outcome,
            &super::super::video_datagram::VideoReassemblyStats::default(),
            &inbound,
            &control,
            false,
            false,
            &metrics,
            &recovery,
            Instant::now(),
        ));
        let outbound = control_rx.try_recv().unwrap();
        let message = Message::parse_from_bytes(&outbound.payload).unwrap();
        let Some(message::Union::Misc(misc)) = message.union else {
            panic!("expected misc message");
        };
        assert!(matches!(misc.union, Some(misc::Union::RefreshVideo(true))));
    }

    #[test]
    fn receiver_recovery_v3_never_falls_back_to_a_global_refresh_without_source_context() {
        let (inbound, _inbound_rx) = mpsc::channel(1);
        let (control, mut control_rx) = mpsc::channel(1);
        let metrics = QuicApplicationMetrics::default();
        let recovery = Mutex::new(VideoReceiveRecovery::default());
        let outcome = super::super::video_datagram::VideoReassemblyOutcome {
            request_keyframe: true,
            dropped_frames: 1,
            frame: None,
        };
        assert!(handle_video_outcome(
            outcome,
            &super::super::video_datagram::VideoReassemblyStats::default(),
            &inbound,
            &control,
            true,
            false,
            &metrics,
            &recovery,
            Instant::now(),
        ));
        assert!(control_rx.try_recv().is_err());
    }

    #[test]
    fn sender_waits_for_a_keyframe_newer_than_every_suppressed_delta() {
        let (refresh, mut refresh_rx) = mpsc::channel(1);
        let metrics = Arc::new(QuicApplicationMetrics::default());
        let recovery = VideoSendRecovery::new(refresh, true, metrics.clone());
        recovery.enter(Some(source_video(7, 2, false)), 2, "test loss");
        recovery.enter(Some(source_video(7, 3, false)), 3, "same recovery window");
        match refresh_rx.try_recv() {
            Ok(LocalVideoRefresh::Reference(refresh)) => {
                assert_eq!(refresh.display, 0);
                assert_eq!(refresh.stream_id, 7);
                assert_eq!(refresh.received_frame_id, 2);
            }
            _ => panic!("expected scoped reference refresh"),
        }
        assert!(refresh_rx.try_recv().is_err());

        assert!(recovery.suppress_delta(4));
        recovery.keyframe_sent(3);
        assert!(recovery.suppress_delta(5));
        recovery.keyframe_sent(6);
        assert!(!recovery.suppress_delta(7));
        assert_eq!(
            metrics
                .video_sender_reference_resets
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .video_recovery_suppressed_frames
                .load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn sender_reference_recovery_keeps_legacy_fallback_for_old_quic_protocols() {
        let (refresh, mut refresh_rx) = mpsc::channel(1);
        let metrics = Arc::new(QuicApplicationMetrics::default());
        let recovery = VideoSendRecovery::new(refresh, false, metrics);
        recovery.enter(Some(source_video(7, 2, false)), 2, "test loss");
        assert!(matches!(
            refresh_rx.try_recv(),
            Ok(LocalVideoRefresh::Legacy)
        ));
    }

    #[test]
    fn sender_reference_recovery_v3_never_falls_back_to_a_global_refresh_without_source_context() {
        let (refresh, mut refresh_rx) = mpsc::channel(1);
        let metrics = Arc::new(QuicApplicationMetrics::default());
        let recovery = VideoSendRecovery::new(refresh, true, metrics);
        recovery.enter(None, 2, "test loss");
        assert!(refresh_rx.try_recv().is_err());
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

        assert_eq!(client_stream.stats().application_protocol, 4);
        assert!(client_stream.stats().reliable_keyframes);
        assert!(client_stream.stats().reliable_keyframe_barrier);
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
