use super::{
    audio_datagram::{
        encode_audio_datagram, AudioCodec, AudioDatagramError, AudioJitterBuffer,
        AudioJitterConfig, AudioPacketMetadata, AudioPlayoutItem,
    },
    input::{
        encode_application_mouse_movement, encode_mouse_movement, InputProtocolError,
        MouseMovement, MouseMovementMode, MouseMovementReceiver, MOUSE_MOVEMENT_PAYLOAD_LEN,
    },
    protocol::{decode_header, MessageType, SessionId, HEADER_LEN},
    quic::QuicTransportError,
    video_datagram::{
        fragment_video_frame, VideoDatagramError, VideoFrameMetadata, VideoReassembler,
        VideoReassemblyConfig, VideoReassemblyOutcome, VideoReassemblyStats, FLAG_KEYFRAME,
    },
};
use bytes::Bytes;
use quinn::Connection;
use std::{
    convert::TryFrom,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub const DEFAULT_INTERACTIVE_DATAGRAM_RESERVE_BYTES: usize = 64 * 1024;
pub const MIN_VIDEO_DATAGRAM_QUEUE_BYTES: usize = 192 * 1024;
pub const DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET: Duration = Duration::from_millis(120);
pub const MOVIE_VIDEO_DATAGRAM_QUEUE_TARGET: Duration = Duration::from_millis(40);
pub const MOVIE_MIN_VIDEO_DATAGRAM_QUEUE_BYTES: usize = 64 * 1024;
const VIDEO_FRAME_SIZE_WINDOW: usize = 512;
const VIDEO_FRAME_PERCENTILE_PUBLISH_INTERVAL: Duration = Duration::from_millis(500);
const VIDEO_FRAME_SIZE_WINDOW_IDLE_RESET: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Default)]
struct VideoFrameSizeSample {
    datagram_bytes: u32,
    required_bytes: u32,
}

struct VideoFrameSizeWindow {
    samples: [VideoFrameSizeSample; VIDEO_FRAME_SIZE_WINDOW],
    len: usize,
    next: usize,
    last_published_at: Instant,
    last_recorded_at: Option<Instant>,
}

impl VideoFrameSizeWindow {
    fn new(now: Instant) -> Self {
        Self {
            samples: [VideoFrameSizeSample::default(); VIDEO_FRAME_SIZE_WINDOW],
            len: 0,
            next: 0,
            last_published_at: now,
            last_recorded_at: None,
        }
    }

    fn record(&mut self, now: Instant, datagram_bytes: usize, required_bytes: usize) {
        if self.last_recorded_at.is_some_and(|last| {
            now.saturating_duration_since(last) >= VIDEO_FRAME_SIZE_WINDOW_IDLE_RESET
        }) {
            self.len = 0;
            self.next = 0;
        }
        self.last_recorded_at = Some(now);
        self.samples[self.next] = VideoFrameSizeSample {
            datagram_bytes: datagram_bytes.min(u32::MAX as usize) as u32,
            required_bytes: required_bytes.min(u32::MAX as usize) as u32,
        };
        self.next = (self.next + 1) % VIDEO_FRAME_SIZE_WINDOW;
        self.len = self.len.saturating_add(1).min(VIDEO_FRAME_SIZE_WINDOW);
    }

    fn percentiles(&self) -> (u64, u64, u64, u64) {
        if self.len == 0 {
            return (0, 0, 0, 0);
        }
        let mut datagram = [0u32; VIDEO_FRAME_SIZE_WINDOW];
        let mut required = [0u32; VIDEO_FRAME_SIZE_WINDOW];
        for (index, sample) in self.samples[..self.len].iter().enumerate() {
            datagram[index] = sample.datagram_bytes;
            required[index] = sample.required_bytes;
        }
        datagram[..self.len].sort_unstable();
        required[..self.len].sort_unstable();
        let p95 = nearest_rank_index(self.len, 95);
        let p99 = nearest_rank_index(self.len, 99);
        (
            u64::from(datagram[p95]),
            u64::from(datagram[p99]),
            u64::from(required[p95]),
            u64::from(required[p99]),
        )
    }

    fn publish_if_due(&mut self, now: Instant, counters: &DatagramSendCounters) {
        if now.saturating_duration_since(self.last_published_at)
            < VIDEO_FRAME_PERCENTILE_PUBLISH_INTERVAL
        {
            return;
        }
        self.last_published_at = now;
        let (datagram_p95, datagram_p99, required_p95, required_p99) = self.percentiles();
        counters
            .video_frame_datagram_bytes_p95
            .store(datagram_p95, Ordering::Relaxed);
        counters
            .video_frame_datagram_bytes_p99
            .store(datagram_p99, Ordering::Relaxed);
        counters
            .video_frame_required_bytes_p95
            .store(required_p95, Ordering::Relaxed);
        counters
            .video_frame_required_bytes_p99
            .store(required_p99, Ordering::Relaxed);
    }
}

fn nearest_rank_index(len: usize, percentile: usize) -> usize {
    // Nearest-rank percentile over the filled sample count, not ring capacity.
    len.saturating_mul(percentile)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(len.saturating_sub(1))
}

fn record_delta_frame_size(
    window: &mut VideoFrameSizeWindow,
    metadata: VideoFrameMetadata,
    now: Instant,
    datagram_bytes: usize,
    required_bytes: usize,
) -> bool {
    if metadata.flags & FLAG_KEYFRAME != 0 {
        return false;
    }
    window.record(now, datagram_bytes, required_bytes);
    true
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatagramSendStats {
    pub video_frames_sent: u64,
    pub video_frames_rejected: u64,
    pub video_datagrams_sent: u64,
    pub video_frame_bytes: u64,
    pub video_frame_bytes_peak: u64,
    pub video_frame_fragments: u64,
    pub video_frame_fragments_peak: u64,
    pub video_frame_datagram_bytes_p95: u64,
    pub video_frame_datagram_bytes_p99: u64,
    pub video_frame_required_bytes_p95: u64,
    pub video_frame_required_bytes_p99: u64,
    pub send_buffer_space: u64,
    pub send_buffer_space_min: u64,
    pub send_buffer_queued: u64,
    pub video_queue_budget: u64,
    pub video_queue_delay_us: u64,
    pub video_queue_target_us: u64,
    pub audio_packets_dropped: u64,
    pub mouse_updates_dropped: u64,
}

#[derive(Default)]
struct DatagramSendCounters {
    video_frames_sent: AtomicU64,
    video_frames_rejected: AtomicU64,
    video_datagrams_sent: AtomicU64,
    video_frame_bytes: AtomicU64,
    video_frame_bytes_peak: AtomicU64,
    video_frame_fragments: AtomicU64,
    video_frame_fragments_peak: AtomicU64,
    video_frame_datagram_bytes_p95: AtomicU64,
    video_frame_datagram_bytes_p99: AtomicU64,
    video_frame_required_bytes_p95: AtomicU64,
    video_frame_required_bytes_p99: AtomicU64,
    send_buffer_space: AtomicU64,
    send_buffer_space_min: AtomicU64,
    send_buffer_capacity: AtomicU64,
    send_buffer_queued: AtomicU64,
    video_queue_budget: AtomicU64,
    video_queue_delay_us: AtomicU64,
    audio_packets_dropped: AtomicU64,
    mouse_updates_dropped: AtomicU64,
}

pub struct QuicDatagramSendCoordinator {
    gate: Mutex<()>,
    interactive_reserve_bytes: usize,
    video_queue_target_us: AtomicU64,
    min_video_queue_bytes: AtomicU64,
    counters: DatagramSendCounters,
}

impl QuicDatagramSendCoordinator {
    pub fn new(interactive_reserve_bytes: usize, send_buffer_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            gate: Mutex::new(()),
            interactive_reserve_bytes,
            video_queue_target_us: AtomicU64::new(
                DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64,
            ),
            min_video_queue_bytes: AtomicU64::new(MIN_VIDEO_DATAGRAM_QUEUE_BYTES as u64),
            counters: DatagramSendCounters {
                send_buffer_space_min: AtomicU64::new(u64::MAX),
                send_buffer_capacity: AtomicU64::new(
                    u64::try_from(send_buffer_capacity).unwrap_or(u64::MAX),
                ),
                ..DatagramSendCounters::default()
            },
        })
    }

    pub fn stats(&self) -> DatagramSendStats {
        let send_buffer_space_min = self.counters.send_buffer_space_min.load(Ordering::Relaxed);
        DatagramSendStats {
            video_frames_sent: self.counters.video_frames_sent.load(Ordering::Relaxed),
            video_frames_rejected: self.counters.video_frames_rejected.load(Ordering::Relaxed),
            video_datagrams_sent: self.counters.video_datagrams_sent.load(Ordering::Relaxed),
            video_frame_bytes: self.counters.video_frame_bytes.load(Ordering::Relaxed),
            video_frame_bytes_peak: self.counters.video_frame_bytes_peak.load(Ordering::Relaxed),
            video_frame_fragments: self.counters.video_frame_fragments.load(Ordering::Relaxed),
            video_frame_fragments_peak: self
                .counters
                .video_frame_fragments_peak
                .load(Ordering::Relaxed),
            video_frame_datagram_bytes_p95: self
                .counters
                .video_frame_datagram_bytes_p95
                .load(Ordering::Relaxed),
            video_frame_datagram_bytes_p99: self
                .counters
                .video_frame_datagram_bytes_p99
                .load(Ordering::Relaxed),
            video_frame_required_bytes_p95: self
                .counters
                .video_frame_required_bytes_p95
                .load(Ordering::Relaxed),
            video_frame_required_bytes_p99: self
                .counters
                .video_frame_required_bytes_p99
                .load(Ordering::Relaxed),
            send_buffer_space: self.counters.send_buffer_space.load(Ordering::Relaxed),
            send_buffer_space_min: if send_buffer_space_min == u64::MAX {
                0
            } else {
                send_buffer_space_min
            },
            send_buffer_queued: self.counters.send_buffer_queued.load(Ordering::Relaxed),
            video_queue_budget: self.counters.video_queue_budget.load(Ordering::Relaxed),
            video_queue_delay_us: self.counters.video_queue_delay_us.load(Ordering::Relaxed),
            video_queue_target_us: self.video_queue_target_us.load(Ordering::Relaxed),
            audio_packets_dropped: self.counters.audio_packets_dropped.load(Ordering::Relaxed),
            mouse_updates_dropped: self.counters.mouse_updates_dropped.load(Ordering::Relaxed),
        }
    }

    pub fn set_video_queue_policy(&self, target: Duration, minimum_bytes: usize) {
        let target_us = target.as_micros().clamp(1, u128::from(u64::MAX)) as u64;
        self.video_queue_target_us
            .store(target_us, Ordering::Relaxed);
        self.min_video_queue_bytes.store(
            u64::try_from(minimum_bytes).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn record_space(&self, available: usize) -> (usize, usize) {
        let available = u64::try_from(available).unwrap_or(u64::MAX);
        self.counters
            .send_buffer_space
            .store(available, Ordering::Relaxed);
        self.counters
            .send_buffer_space_min
            .fetch_min(available, Ordering::Relaxed);
        let previous_capacity = self
            .counters
            .send_buffer_capacity
            .fetch_max(available, Ordering::Relaxed);
        let capacity = previous_capacity.max(available);
        let queued = capacity.saturating_sub(available);
        self.counters
            .send_buffer_queued
            .store(queued, Ordering::Relaxed);
        (
            usize::try_from(queued).unwrap_or(usize::MAX),
            usize::try_from(capacity).unwrap_or(usize::MAX),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoDatagramAdmissionFailure {
    InteractiveReserve,
    VideoQueueBudget,
    InteractiveReserveAndVideoQueueBudget,
}

impl VideoDatagramAdmissionFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveReserve => "interactive-reserve",
            Self::VideoQueueBudget => "video-queue-budget",
            Self::InteractiveReserveAndVideoQueueBudget => "interactive-reserve+video-queue-budget",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoDatagramSendOutcome {
    Sent {
        fragment_count: usize,
    },
    RejectedNoSpace {
        failure: VideoDatagramAdmissionFailure,
        datagram_bytes: usize,
        available_bytes: usize,
        queued_bytes: usize,
        video_queue_budget: usize,
        interactive_reserve_bytes: usize,
        queue_delay_us: u64,
        datagram_bytes_p95: u64,
        datagram_bytes_p99: u64,
        required_bytes_p95: u64,
        required_bytes_p99: u64,
    },
}

pub struct QuicDatagramSender {
    connection: Connection,
    coordinator: Arc<QuicDatagramSendCoordinator>,
    session_id: SessionId,
    next_video_sequence: u64,
    next_audio_sequence: u64,
    next_mouse_sequence: u64,
    started: Instant,
    video_frame_sizes: VideoFrameSizeWindow,
    negotiated_max_datagram_size: usize,
}

impl QuicDatagramSender {
    pub fn new(connection: Connection, session_id: SessionId) -> Self {
        let send_buffer_capacity = connection.datagram_send_buffer_space();
        Self {
            connection,
            coordinator: QuicDatagramSendCoordinator::new(
                DEFAULT_INTERACTIVE_DATAGRAM_RESERVE_BYTES,
                send_buffer_capacity,
            ),
            session_id,
            next_video_sequence: 1,
            next_audio_sequence: 1,
            next_mouse_sequence: 1,
            started: Instant::now(),
            video_frame_sizes: VideoFrameSizeWindow::new(Instant::now()),
            negotiated_max_datagram_size: usize::MAX,
        }
    }

    pub fn with_max_datagram_size(mut self, max_datagram_size: usize) -> Self {
        self.negotiated_max_datagram_size = max_datagram_size;
        self
    }

    pub fn with_coordinator(mut self, coordinator: Arc<QuicDatagramSendCoordinator>) -> Self {
        self.coordinator = coordinator;
        self
    }

    pub fn send_video_frame(
        &mut self,
        metadata: VideoFrameMetadata,
        encoded_frame: &[u8],
    ) -> Result<VideoDatagramSendOutcome, QuicTransportError> {
        let max_datagram_size = self.max_datagram_size()?;
        let fragments = fragment_video_frame(
            self.session_id,
            self.next_video_sequence,
            elapsed_us(self.started),
            metadata,
            encoded_frame,
            max_datagram_size,
        )?;
        let fragment_count = fragments.len();
        let datagram_bytes = fragments.iter().fold(0usize, |total, fragment| {
            total.saturating_add(fragment.len())
        });
        let frame_bytes = u64::try_from(encoded_frame.len()).unwrap_or(u64::MAX);
        let fragment_count_u64 = u64::try_from(fragment_count).unwrap_or(u64::MAX);
        self.coordinator
            .counters
            .video_frame_bytes
            .store(frame_bytes, Ordering::Relaxed);
        self.coordinator
            .counters
            .video_frame_bytes_peak
            .fetch_max(frame_bytes, Ordering::Relaxed);
        self.coordinator
            .counters
            .video_frame_fragments
            .store(fragment_count_u64, Ordering::Relaxed);
        self.coordinator
            .counters
            .video_frame_fragments_peak
            .fetch_max(fragment_count_u64, Ordering::Relaxed);

        let _gate = self.coordinator.gate.lock().unwrap();
        let available_bytes = self.connection.datagram_send_buffer_space();
        let (queued_bytes, send_buffer_capacity) = self.coordinator.record_space(available_bytes);
        let path = self.connection.stats().path;
        let video_queue_budget = video_datagram_queue_budget(
            path.cwnd,
            path.rtt,
            send_buffer_capacity,
            self.coordinator.interactive_reserve_bytes,
            Duration::from_micros(
                self.coordinator
                    .video_queue_target_us
                    .load(Ordering::Relaxed),
            ),
            usize::try_from(
                self.coordinator
                    .min_video_queue_bytes
                    .load(Ordering::Relaxed),
            )
            .unwrap_or(usize::MAX),
        );
        let queue_delay_us = video_datagram_queue_delay_us(queued_bytes, path.cwnd, path.rtt);
        self.coordinator.counters.video_queue_budget.store(
            u64::try_from(video_queue_budget).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.coordinator
            .counters
            .video_queue_delay_us
            .store(queue_delay_us, Ordering::Relaxed);
        let now = Instant::now();
        if record_delta_frame_size(
            &mut self.video_frame_sizes,
            metadata,
            now,
            datagram_bytes,
            queued_bytes.saturating_add(datagram_bytes),
        ) {
            self.video_frame_sizes
                .publish_if_due(now, &self.coordinator.counters);
        }
        if let Some(failure) = video_frame_admission_failure(
            datagram_bytes,
            available_bytes,
            self.coordinator.interactive_reserve_bytes,
            queued_bytes,
            video_queue_budget,
        ) {
            self.coordinator
                .counters
                .video_frames_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Ok(VideoDatagramSendOutcome::RejectedNoSpace {
                failure,
                datagram_bytes,
                available_bytes,
                queued_bytes,
                video_queue_budget,
                interactive_reserve_bytes: self.coordinator.interactive_reserve_bytes,
                queue_delay_us,
                datagram_bytes_p95: self
                    .coordinator
                    .counters
                    .video_frame_datagram_bytes_p95
                    .load(Ordering::Relaxed),
                datagram_bytes_p99: self
                    .coordinator
                    .counters
                    .video_frame_datagram_bytes_p99
                    .load(Ordering::Relaxed),
                required_bytes_p95: self
                    .coordinator
                    .counters
                    .video_frame_required_bytes_p95
                    .load(Ordering::Relaxed),
                required_bytes_p99: self
                    .coordinator
                    .counters
                    .video_frame_required_bytes_p99
                    .load(Ordering::Relaxed),
            });
        }

        let next_video_sequence = self
            .next_video_sequence
            .checked_add(fragment_count_u64)
            .ok_or_else(|| {
                QuicTransportError::ProtocolState("video sequence exhausted".to_owned())
            })?;
        for fragment in fragments {
            self.connection
                .send_datagram(Bytes::from(fragment))
                .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        }
        self.next_video_sequence = next_video_sequence;
        self.coordinator
            .counters
            .video_frames_sent
            .fetch_add(1, Ordering::Relaxed);
        self.coordinator
            .counters
            .video_datagrams_sent
            .fetch_add(fragment_count_u64, Ordering::Relaxed);
        Ok(VideoDatagramSendOutcome::Sent { fragment_count })
    }

    pub fn send_audio_packet(
        &mut self,
        capture_timestamp_us: u64,
        codec: AudioCodec,
        channels: u8,
        sample_rate_hz: u32,
        encoded_audio: &[u8],
    ) -> Result<Option<u64>, QuicTransportError> {
        let sequence = self.next_audio_sequence;
        let datagram = encode_audio_datagram(
            self.session_id,
            elapsed_us(self.started),
            AudioPacketMetadata {
                sequence_number: sequence,
                capture_timestamp_us,
                codec,
                channels,
                sample_rate_hz,
            },
            encoded_audio,
            self.max_datagram_size()?,
        )?;
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            QuicTransportError::ProtocolState("audio sequence exhausted".to_owned())
        })?;
        let _gate = self.coordinator.gate.lock().unwrap();
        let available_bytes = self.connection.datagram_send_buffer_space();
        self.coordinator.record_space(available_bytes);
        self.next_audio_sequence = next_sequence;
        if datagram.len() > available_bytes {
            self.coordinator
                .counters
                .audio_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        self.connection
            .send_datagram(Bytes::from(datagram))
            .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        Ok(Some(sequence))
    }

    pub fn send_mouse_movement(
        &mut self,
        mode: MouseMovementMode,
        x: i32,
        y: i32,
        display_id: u32,
        button_state_mask: u16,
    ) -> Result<Option<u64>, QuicTransportError> {
        let sequence = self.next_mouse_sequence;
        let datagram = encode_mouse_movement(
            self.session_id,
            MouseMovement {
                sequence_number: sequence,
                monotonic_timestamp_us: elapsed_us(self.started),
                mode,
                x,
                y,
                display_id,
                button_state_mask,
            },
            self.max_datagram_size()?,
        )?;
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            QuicTransportError::ProtocolState("mouse sequence exhausted".to_owned())
        })?;
        let _gate = self.coordinator.gate.lock().unwrap();
        let available_bytes = self.connection.datagram_send_buffer_space();
        self.coordinator.record_space(available_bytes);
        self.next_mouse_sequence = next_sequence;
        if datagram.len() > available_bytes {
            self.coordinator
                .counters
                .mouse_updates_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        self.connection
            .send_datagram(Bytes::from(datagram))
            .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        Ok(Some(sequence))
    }

    pub fn send_application_mouse_movement(
        &mut self,
        mode: MouseMovementMode,
        x: i32,
        y: i32,
        display_id: u32,
        button_state_mask: u16,
        application_payload: &[u8],
    ) -> Result<Option<u64>, QuicTransportError> {
        let sequence = self.next_mouse_sequence;
        let datagram = encode_application_mouse_movement(
            self.session_id,
            MouseMovement {
                sequence_number: sequence,
                monotonic_timestamp_us: elapsed_us(self.started),
                mode,
                x,
                y,
                display_id,
                button_state_mask,
            },
            application_payload,
            self.max_datagram_size()?,
        )?;
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            QuicTransportError::ProtocolState("mouse sequence exhausted".to_owned())
        })?;
        let _gate = self.coordinator.gate.lock().unwrap();
        let available_bytes = self.connection.datagram_send_buffer_space();
        self.coordinator.record_space(available_bytes);
        self.next_mouse_sequence = next_sequence;
        if datagram.len() > available_bytes {
            self.coordinator
                .counters
                .mouse_updates_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        self.connection
            .send_datagram(Bytes::from(datagram))
            .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        Ok(Some(sequence))
    }

    pub fn max_datagram_size(&self) -> Result<usize, QuicTransportError> {
        self.connection
            .max_datagram_size()
            .map(|current| current.min(self.negotiated_max_datagram_size))
            .ok_or_else(|| {
                QuicTransportError::Datagram("peer does not support QUIC DATAGRAM".to_owned())
            })
    }
}

pub struct QuicDatagramReceiver {
    connection: Connection,
    session_id: SessionId,
    video: VideoReassembler,
    audio: AudioJitterBuffer,
    mouse: MouseMovementReceiver,
    negotiated_max_datagram_size: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum DatagramReceiveEvent {
    Video(VideoReassemblyOutcome),
    AudioAccepted,
    Mouse(Option<MouseMovement>),
    ApplicationMouse(Option<(MouseMovement, Vec<u8>)>),
}

impl QuicDatagramReceiver {
    pub fn new(
        connection: Connection,
        session_id: SessionId,
        video_config: VideoReassemblyConfig,
        audio_config: AudioJitterConfig,
    ) -> Result<Self, QuicTransportError> {
        Ok(Self {
            connection,
            session_id,
            video: VideoReassembler::new(video_config)?,
            audio: AudioJitterBuffer::new(audio_config)?,
            mouse: MouseMovementReceiver::new(session_id),
            negotiated_max_datagram_size: usize::MAX,
        })
    }

    pub fn with_max_datagram_size(mut self, max_datagram_size: usize) -> Self {
        self.negotiated_max_datagram_size = max_datagram_size;
        self
    }

    pub async fn receive(&mut self) -> Result<DatagramReceiveEvent, QuicTransportError> {
        let datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        let now = Instant::now();
        if datagram.len() > self.negotiated_max_datagram_size {
            return Err(QuicTransportError::ProtocolState(format!(
                "QUIC datagram length {} exceeds negotiated limit {}",
                datagram.len(),
                self.negotiated_max_datagram_size
            )));
        }
        if datagram.len() < HEADER_LEN {
            return Err(QuicTransportError::ProtocolState(
                "received truncated QUIC datagram".to_owned(),
            ));
        }
        let header = decode_header(&datagram[..HEADER_LEN])?;
        if header.session_id != self.session_id {
            return Err(QuicTransportError::ProtocolState(
                "QUIC datagram session identifier changed".to_owned(),
            ));
        }
        match header.message_type {
            MessageType::VideoFragment => Ok(DatagramReceiveEvent::Video(
                self.video.push(&datagram, now)?,
            )),
            MessageType::AudioPacket => {
                self.audio.push_datagram(&datagram, now)?;
                Ok(DatagramReceiveEvent::AudioAccepted)
            }
            MessageType::MouseMovement => {
                if header.payload_length as usize == MOUSE_MOVEMENT_PAYLOAD_LEN {
                    Ok(DatagramReceiveEvent::Mouse(self.mouse.apply(&datagram)?))
                } else {
                    Ok(DatagramReceiveEvent::ApplicationMouse(
                        self.mouse.apply_application(&datagram)?,
                    ))
                }
            }
            message_type => Err(QuicTransportError::ProtocolState(format!(
                "message {message_type:?} is invalid on QUIC DATAGRAM"
            ))),
        }
    }

    pub fn pop_audio(&mut self, now: Instant) -> Option<AudioPlayoutItem> {
        self.audio.pop_ready(now)
    }

    pub fn video_stats(&self) -> &VideoReassemblyStats {
        self.video.stats()
    }

    pub fn expire_video(&mut self, now: Instant) -> VideoReassemblyOutcome {
        self.video.expire(now)
    }

    pub fn reset(&mut self) {
        self.video.reset();
        self.audio.reset();
        self.mouse.reset();
    }
}

impl From<VideoDatagramError> for QuicTransportError {
    fn from(error: VideoDatagramError) -> Self {
        Self::Datagram(error.to_string())
    }
}

impl From<AudioDatagramError> for QuicTransportError {
    fn from(error: AudioDatagramError) -> Self {
        Self::Datagram(error.to_string())
    }
}

impl From<InputProtocolError> for QuicTransportError {
    fn from(error: InputProtocolError) -> Self {
        Self::Datagram(error.to_string())
    }
}

fn elapsed_us(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
fn video_frame_fits_send_budget(
    datagram_bytes: usize,
    available_bytes: usize,
    interactive_reserve_bytes: usize,
    queued_bytes: usize,
    video_queue_budget: usize,
) -> bool {
    video_frame_admission_failure(
        datagram_bytes,
        available_bytes,
        interactive_reserve_bytes,
        queued_bytes,
        video_queue_budget,
    )
    .is_none()
}

fn video_frame_admission_failure(
    datagram_bytes: usize,
    available_bytes: usize,
    interactive_reserve_bytes: usize,
    queued_bytes: usize,
    video_queue_budget: usize,
) -> Option<VideoDatagramAdmissionFailure> {
    let preserves_interactive_reserve = datagram_bytes
        .checked_add(interactive_reserve_bytes)
        .map(|required| required <= available_bytes)
        .unwrap_or(false);
    // Admit one complete frame while the existing queue is still within its
    // latency budget. The physical reserve remains a hard limit, and the next
    // frame is rejected if this bounded overshoot has not drained.
    let stays_within_video_queue = queued_bytes <= video_queue_budget;
    match (preserves_interactive_reserve, stays_within_video_queue) {
        (true, true) => None,
        (false, true) => Some(VideoDatagramAdmissionFailure::InteractiveReserve),
        (true, false) => Some(VideoDatagramAdmissionFailure::VideoQueueBudget),
        (false, false) => {
            Some(VideoDatagramAdmissionFailure::InteractiveReserveAndVideoQueueBudget)
        }
    }
}

fn video_datagram_queue_delay_us(
    queued_bytes: usize,
    congestion_window_bytes: u64,
    rtt: Duration,
) -> u64 {
    if queued_bytes == 0 || congestion_window_bytes == 0 {
        return 0;
    }
    let delay_us = (queued_bytes as u128)
        .saturating_mul(rtt.as_micros())
        .checked_div(u128::from(congestion_window_bytes))
        .unwrap_or(u128::from(u64::MAX));
    delay_us.min(u128::from(u64::MAX)) as u64
}

fn video_datagram_queue_budget(
    congestion_window_bytes: u64,
    rtt: Duration,
    send_buffer_capacity: usize,
    interactive_reserve_bytes: usize,
    target_latency: Duration,
    minimum_video_queue_bytes: usize,
) -> usize {
    let rtt_us = rtt.as_micros().max(5_000);
    let target_us = target_latency.as_micros().max(1);
    let latency_budget = u128::from(congestion_window_bytes)
        .saturating_mul(target_us)
        .checked_div(rtt_us)
        .unwrap_or(0);
    let preferred_budget = usize::try_from(latency_budget)
        .unwrap_or(usize::MAX)
        .max(minimum_video_queue_bytes);
    preferred_budget.min(send_buffer_capacity.saturating_sub(interactive_reserve_bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        record_delta_frame_size, video_datagram_queue_budget, video_datagram_queue_delay_us,
        video_frame_admission_failure, video_frame_fits_send_budget, QuicDatagramSendCoordinator,
        VideoDatagramAdmissionFailure, VideoFrameMetadata, VideoFrameSizeWindow,
        DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET, FLAG_KEYFRAME, MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
        MOVIE_MIN_VIDEO_DATAGRAM_QUEUE_BYTES, MOVIE_VIDEO_DATAGRAM_QUEUE_TARGET,
    };
    use crate::transport::video_datagram::VideoCodec;
    use std::time::{Duration, Instant};

    #[test]
    fn video_frame_size_percentiles_use_filled_nearest_rank_samples() {
        let mut window = VideoFrameSizeWindow::new(Instant::now());
        assert_eq!(window.percentiles(), (0, 0, 0, 0));
        let now = Instant::now();
        for value in 1..=100 {
            window.record(now, value, value + 100);
        }
        assert_eq!(window.percentiles(), (95, 99, 195, 199));
    }

    #[test]
    fn video_frame_size_percentiles_keep_only_the_latest_ring_window() {
        let mut window = VideoFrameSizeWindow::new(Instant::now());
        let now = Instant::now();
        for value in 0..600 {
            window.record(now, value, value + 1_000);
        }
        assert_eq!(window.percentiles(), (574, 594, 1_574, 1_594));
    }

    #[test]
    fn rejected_delta_is_measured_but_keyframe_is_excluded() {
        let mut window = VideoFrameSizeWindow::new(Instant::now());
        let now = Instant::now();
        let delta = VideoFrameMetadata {
            frame_id: 1,
            codec: VideoCodec::H264,
            flags: 0,
            presentation_timestamp_us: 0,
        };
        assert!(record_delta_frame_size(
            &mut window,
            delta,
            now,
            56_000,
            91_000
        ));
        assert!(video_frame_admission_failure(56_000, 512_000, 64_000, 65_537, 65_536).is_some());
        assert_eq!(window.percentiles(), (56_000, 56_000, 91_000, 91_000));

        assert!(!record_delta_frame_size(
            &mut window,
            VideoFrameMetadata {
                frame_id: 2,
                codec: VideoCodec::H264,
                flags: FLAG_KEYFRAME,
                presentation_timestamp_us: 0,
            },
            now,
            80_000,
            115_000,
        ));
        assert_eq!(window.percentiles(), (56_000, 56_000, 91_000, 91_000));
    }

    #[test]
    fn video_frame_size_window_discards_samples_after_idle_gap() {
        let start = Instant::now();
        let mut window = VideoFrameSizeWindow::new(start);
        window.record(start, 80_000, 120_000);
        window.record(
            start + super::VIDEO_FRAME_SIZE_WINDOW_IDLE_RESET,
            10_000,
            20_000,
        );
        assert_eq!(window.percentiles(), (10_000, 10_000, 20_000, 20_000));
    }

    #[test]
    fn video_admission_preserves_the_complete_interactive_reserve() {
        assert!(video_frame_fits_send_budget(
            128_000, 192_000, 64_000, 0, 192_000,
        ));
        assert!(!video_frame_fits_send_budget(
            128_001, 192_000, 64_000, 0, 192_000,
        ));
    }

    #[test]
    fn video_admission_allows_one_complete_frame_at_the_queue_age_boundary() {
        assert!(video_frame_fits_send_budget(
            64_000, 512_000, 64_000, 192_000, 192_000,
        ));
        assert!(!video_frame_fits_send_budget(
            1, 512_000, 64_000, 192_001, 192_000,
        ));
    }

    #[test]
    fn video_admission_rejects_overflowed_size_calculations() {
        assert!(!video_frame_fits_send_budget(
            usize::MAX,
            usize::MAX,
            1,
            0,
            usize::MAX,
        ));
    }

    #[test]
    fn video_queue_budget_scales_with_path_and_is_bounded() {
        assert_eq!(
            video_datagram_queue_budget(
                16 * 1024,
                Duration::from_millis(200),
                2 * 1024 * 1024,
                64 * 1024,
                DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET,
                MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
            ),
            MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
        );
        assert_eq!(
            video_datagram_queue_budget(
                4 * 1024 * 1024,
                Duration::from_millis(5),
                2 * 1024 * 1024,
                64 * 1024,
                DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET,
                MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
            ),
            (2 * 1024 * 1024) - (64 * 1024),
        );
        assert_eq!(
            video_datagram_queue_budget(
                128 * 1024,
                Duration::from_millis(80),
                2 * 1024 * 1024,
                64 * 1024,
                DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET,
                MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
            ),
            192 * 1024,
        );
    }

    #[test]
    fn video_queue_budget_handles_a_buffer_smaller_than_the_preferred_floor() {
        assert_eq!(
            video_datagram_queue_budget(
                16 * 1024,
                Duration::from_millis(200),
                96 * 1024,
                64 * 1024,
                DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET,
                MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
            ),
            32 * 1024,
        );
    }

    #[test]
    fn high_bandwidth_path_admits_frame_beyond_the_old_static_ceiling() {
        let capacity = 2 * 1024 * 1024;
        let reserve = 64 * 1024;
        let queued = 503_566;
        let frame = 24_348;
        let available = capacity - queued;
        let budget = video_datagram_queue_budget(
            512 * 1024,
            Duration::from_millis(18),
            capacity,
            reserve,
            DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET,
            MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
        );

        assert!(budget > 512 * 1024);
        assert!(video_frame_fits_send_budget(
            frame, available, reserve, queued, budget,
        ));
    }

    #[test]
    fn video_admission_reports_the_limiting_budget() {
        assert_eq!(
            video_frame_admission_failure(128_001, 192_000, 64_000, 0, 192_000),
            Some(VideoDatagramAdmissionFailure::InteractiveReserve)
        );
        assert_eq!(
            video_frame_admission_failure(1, 512_000, 64_000, 192_001, 192_000),
            Some(VideoDatagramAdmissionFailure::VideoQueueBudget)
        );
    }

    #[test]
    fn video_queue_delay_uses_quic_path_rate_without_wall_clock_time() {
        assert_eq!(
            video_datagram_queue_delay_us(128 * 1024, 256 * 1024, Duration::from_millis(20)),
            10_000
        );
        assert_eq!(
            video_datagram_queue_delay_us(128 * 1024, 0, Duration::from_millis(20)),
            0
        );
    }

    #[test]
    fn movie_queue_policy_uses_a_lower_latency_budget_and_floor() {
        let standard = video_datagram_queue_budget(
            512 * 1024,
            Duration::from_millis(40),
            2 * 1024 * 1024,
            64 * 1024,
            DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET,
            MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
        );
        let movie = video_datagram_queue_budget(
            512 * 1024,
            Duration::from_millis(40),
            2 * 1024 * 1024,
            64 * 1024,
            MOVIE_VIDEO_DATAGRAM_QUEUE_TARGET,
            MOVIE_MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
        );

        assert!(movie < standard);
        assert_eq!(movie, 512 * 1024);
    }

    #[test]
    fn coordinator_switches_queue_target_without_recreation() {
        let coordinator = QuicDatagramSendCoordinator::new(64 * 1024, 2 * 1024 * 1024);
        assert_eq!(
            coordinator.stats().video_queue_target_us,
            DEFAULT_VIDEO_DATAGRAM_QUEUE_TARGET.as_micros() as u64
        );

        coordinator.set_video_queue_policy(
            MOVIE_VIDEO_DATAGRAM_QUEUE_TARGET,
            MOVIE_MIN_VIDEO_DATAGRAM_QUEUE_BYTES,
        );
        assert_eq!(
            coordinator.stats().video_queue_target_us,
            MOVIE_VIDEO_DATAGRAM_QUEUE_TARGET.as_micros() as u64
        );
    }
}
