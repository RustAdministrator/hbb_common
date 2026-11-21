use super::protocol::{
    decode_message, encode_message, MessageHeader, MessageType, ProtocolError, SessionId,
    HEADER_LEN,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::{TryFrom, TryInto},
    time::{Duration, Instant},
};

pub const VIDEO_FRAGMENT_HEADER_LEN: usize = 28;
pub const FLAG_KEYFRAME: u8 = 1 << 0;
pub const FLAG_CODEC_CONFIG: u8 = 1 << 1;
pub const KNOWN_FRAME_FLAGS: u8 = FLAG_KEYFRAME | FLAG_CODEC_CONFIG;
pub const MAX_VIDEO_FRAME_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_VIDEO_FRAGMENTS: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VideoCodec {
    H264 = 1,
    H265 = 2,
    Vp8 = 3,
    Vp9 = 4,
    Av1 = 5,
    Raw = 6,
}

impl VideoCodec {
    pub fn is_reference_sensitive(self) -> bool {
        matches!(self, Self::H264 | Self::H265 | Self::Av1)
    }
}

impl TryFrom<u8> for VideoCodec {
    type Error = VideoDatagramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::H264),
            2 => Ok(Self::H265),
            3 => Ok(Self::Vp8),
            4 => Ok(Self::Vp9),
            5 => Ok(Self::Av1),
            6 => Ok(Self::Raw),
            _ => Err(VideoDatagramError::UnknownCodec(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VideoFrameMetadata {
    pub frame_id: u64,
    pub codec: VideoCodec,
    pub flags: u8,
    pub presentation_timestamp_us: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteVideoFrame {
    pub metadata: VideoFrameMetadata,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct VideoReassemblyConfig {
    pub max_frame_bytes: usize,
    pub max_pending_frames: usize,
    pub max_memory_bytes: usize,
    /// Maximum time without a new fragment before an incomplete delta frame expires.
    pub fragment_deadline: Duration,
    /// Maximum time without a new fragment before an incomplete keyframe expires.
    pub keyframe_fragment_deadline: Duration,
    /// Hard upper bound for an incomplete delta frame, even while fragments arrive.
    pub frame_lifetime: Duration,
    /// Hard upper bound for an incomplete keyframe, even while fragments arrive.
    pub keyframe_lifetime: Duration,
    pub require_initial_keyframe: bool,
    pub keyframe_request_after_drops: u32,
    pub keyframe_request_interval: Duration,
    /// How long after a frame was completed a frame with a lower id may still arrive and be
    /// assembled. All streams of a connection share one sequence of ids and the datagrams of
    /// two frames can arrive in either order; zero is "a completed frame closes everything
    /// below it at once".
    pub reorder_grace: Duration,
    /// An incomplete delta frame below a completed one is given up before the grace is over
    /// once nothing has arrived for it for this long. The datagrams of one frame are sent in
    /// one run, before those of the next frame: what has not arrived by the time a later
    /// frame is complete and the run has gone quiet is lost, not late. Waiting the whole
    /// grace for it would only delay the request for a keyframe.
    pub reorder_idle: Duration,
}

impl Default for VideoReassemblyConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: MAX_VIDEO_FRAME_BYTES,
            max_pending_frames: 8,
            max_memory_bytes: 64 * 1024 * 1024,
            fragment_deadline: Duration::from_millis(120),
            keyframe_fragment_deadline: Duration::from_millis(500),
            frame_lifetime: Duration::from_secs(1),
            keyframe_lifetime: Duration::from_secs(3),
            require_initial_keyframe: true,
            keyframe_request_after_drops: 1,
            keyframe_request_interval: Duration::from_millis(500),
            reorder_grace: Duration::from_millis(100),
            reorder_idle: Duration::from_millis(10),
        }
    }
}

/// The most completions that are remembered while their grace runs. Far above what any frame
/// rate reaches in the grace time; a bound for a peer that sends nothing but tiny frames.
const MAX_REMEMBERED_COMPLETIONS: usize = 256;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VideoReassemblyStats {
    pub completed_frames: u64,
    pub expired_frames: u64,
    pub evicted_frames: u64,
    pub obsolete_frames: u64,
    pub duplicate_fragments: u64,
    pub obsolete_fragments: u64,
    pub malformed_fragments: u64,
    pub pre_keyframe_frames: u64,
    pub expired_keyframes: u64,
    pub missing_fragments: u64,
    pub last_frame_assembly_us: u64,
    pub max_frame_assembly_us: u64,
    pub max_fragment_gap_us: u64,
    pub last_frame_bytes: u64,
    pub last_frame_fragments: u64,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VideoReassemblyOutcome {
    pub frame: Option<CompleteVideoFrame>,
    pub dropped_frames: u32,
    pub request_keyframe: bool,
    /// The highest `presentation_timestamp_us` among the `dropped_frames` that were dropped
    /// incomplete. A sender that puts the id of the keyframe a delta follows into that field
    /// lets the receiver tell a frame lost before its current keyframe from one lost after.
    pub dropped_newest_timestamp_us: Option<u64>,
    /// One of the `dropped_frames` was a keyframe.
    pub dropped_keyframe: bool,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VideoDatagramError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("video frame identifier must not be zero")]
    ZeroFrameId,
    #[error("unknown video codec {0}")]
    UnknownCodec(u8),
    #[error("unknown video frame flags 0x{0:02x}")]
    UnknownFlags(u8),
    #[error("video fragment header is truncated")]
    HeaderTruncated,
    #[error("video fragment reserved field is not zero")]
    ReservedField,
    #[error("video fragment index {index} is invalid for {count} fragments")]
    InvalidFragmentIndex { index: usize, count: usize },
    #[error("video fragment count {0} is invalid")]
    InvalidFragmentCount(usize),
    #[error("encoded video frame size {0} is invalid")]
    InvalidFrameSize(usize),
    #[error("video fragment payload must not be empty")]
    EmptyFragment,
    #[error("QUIC datagram size {0} leaves no room for a video payload")]
    DatagramTooSmall(usize),
    #[error("video sequence number overflow")]
    SequenceOverflow,
    #[error("video fragments for one frame have inconsistent metadata")]
    InconsistentMetadata,
    #[error("duplicate video fragment has different contents")]
    ConflictingDuplicate,
    #[error("video frame exceeds the configured reassembly memory limit")]
    MemoryLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FragmentHeader {
    metadata: VideoFrameMetadata,
    fragment_index: usize,
    fragment_count: usize,
    frame_size: usize,
}

impl FragmentHeader {
    fn belongs_to_same_frame(self, other: Self) -> bool {
        self.metadata == other.metadata
            && self.fragment_count == other.fragment_count
            && self.frame_size == other.frame_size
    }
}

struct PendingFrame {
    header: FragmentHeader,
    fragments: Vec<Option<Vec<u8>>>,
    received_fragments: usize,
    received_bytes: usize,
    created_at: Instant,
    last_progress_at: Instant,
    max_fragment_gap: Duration,
}

pub fn fragment_video_frame(
    session_id: SessionId,
    first_sequence_number: u64,
    monotonic_timestamp_us: u64,
    metadata: VideoFrameMetadata,
    encoded_frame: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>, VideoDatagramError> {
    validate_frame_metadata(metadata)?;
    if encoded_frame.is_empty() || encoded_frame.len() > MAX_VIDEO_FRAME_BYTES {
        return Err(VideoDatagramError::InvalidFrameSize(encoded_frame.len()));
    }
    let overhead = HEADER_LEN + VIDEO_FRAGMENT_HEADER_LEN;
    let fragment_payload_size = max_datagram_size
        .checked_sub(overhead)
        .filter(|size| *size > 0)
        .ok_or(VideoDatagramError::DatagramTooSmall(max_datagram_size))?;
    let fragment_count = encoded_frame.len().div_ceil(fragment_payload_size);
    if fragment_count == 0 || fragment_count > MAX_VIDEO_FRAGMENTS {
        return Err(VideoDatagramError::InvalidFragmentCount(fragment_count));
    }
    first_sequence_number
        .checked_add(fragment_count as u64 - 1)
        .ok_or(VideoDatagramError::SequenceOverflow)?;

    let mut datagrams = Vec::with_capacity(fragment_count);
    for (fragment_index, fragment) in encoded_frame.chunks(fragment_payload_size).enumerate() {
        let payload = encode_fragment_payload(
            FragmentHeader {
                metadata,
                fragment_index,
                fragment_count,
                frame_size: encoded_frame.len(),
            },
            fragment,
        )?;
        let header = MessageHeader::new(
            MessageType::VideoFragment,
            0,
            session_id,
            first_sequence_number + fragment_index as u64,
            payload.len(),
            monotonic_timestamp_us,
        )?;
        let datagram = encode_message(&header, &payload)?;
        debug_assert!(datagram.len() <= max_datagram_size);
        datagrams.push(datagram);
    }
    Ok(datagrams)
}

pub struct VideoReassembler {
    config: VideoReassemblyConfig,
    pending: BTreeMap<u64, PendingFrame>,
    pending_bytes: usize,
    last_completed_frame_id: u64,
    /// Every frame up to this id is finished with: completed, dropped or given up.
    closed_frame_id: u64,
    /// Frames above `closed_frame_id` that were completed, and when; in order of completion.
    recent_completions: VecDeque<(Instant, u64)>,
    /// Frames above `closed_frame_id` that are finished with already: completed, or given up.
    finished_above_closed: BTreeSet<u64>,
    /// The highest `presentation_timestamp_us` of the frames dropped incomplete since the
    /// last `expire`.
    dropped_newest_timestamp_us: Option<u64>,
    /// Whether one of them was a keyframe.
    dropped_keyframe: bool,
    has_completed_keyframe: bool,
    consecutive_dropped_frames: u32,
    last_keyframe_request: Option<Instant>,
    stats: VideoReassemblyStats,
}

impl VideoReassembler {
    pub fn new(config: VideoReassemblyConfig) -> Result<Self, VideoDatagramError> {
        if config.max_frame_bytes == 0 || config.max_frame_bytes > MAX_VIDEO_FRAME_BYTES {
            return Err(VideoDatagramError::InvalidFrameSize(config.max_frame_bytes));
        }
        if config.max_pending_frames == 0 || config.max_memory_bytes < config.max_frame_bytes {
            return Err(VideoDatagramError::MemoryLimit);
        }
        let has_completed_keyframe = !config.require_initial_keyframe;
        Ok(Self {
            config,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            last_completed_frame_id: 0,
            closed_frame_id: 0,
            recent_completions: VecDeque::new(),
            finished_above_closed: BTreeSet::new(),
            dropped_newest_timestamp_us: None,
            dropped_keyframe: false,
            has_completed_keyframe,
            consecutive_dropped_frames: 0,
            last_keyframe_request: None,
            stats: VideoReassemblyStats::default(),
        })
    }

    pub fn push(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<VideoReassemblyOutcome, VideoDatagramError> {
        let mut outcome = self.push_fragment(datagram, now)?;
        if outcome.dropped_frames > 0 {
            outcome.dropped_newest_timestamp_us = self.dropped_newest_timestamp_us;
            outcome.dropped_keyframe = self.dropped_keyframe;
        }
        Ok(outcome)
    }

    fn push_fragment(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<VideoReassemblyOutcome, VideoDatagramError> {
        let mut outcome = self.expire(now);
        let message = decode_message(datagram)?;
        if message.header.message_type != MessageType::VideoFragment {
            return Err(ProtocolError::ChannelMismatch {
                message_type: message.header.message_type,
                channel: message.header.channel,
            }
            .into());
        }
        let (fragment_header, fragment_payload) = decode_fragment_payload(message.payload)?;
        self.validate_fragment_header(fragment_header)?;

        // Finished with: below the closed mark, or completed or given up while its
        // neighbours' grace runs.
        if fragment_header.metadata.frame_id <= self.closed_frame_id
            || self
                .finished_above_closed
                .contains(&fragment_header.metadata.frame_id)
        {
            self.stats.obsolete_fragments = self.stats.obsolete_fragments.saturating_add(1);
            return Ok(outcome);
        }

        if !self
            .pending
            .contains_key(&fragment_header.metadata.frame_id)
        {
            while self.pending.len() >= self.config.max_pending_frames {
                if self.evict_oldest() {
                    outcome.dropped_frames = outcome.dropped_frames.saturating_add(1);
                }
            }
            self.pending.insert(
                fragment_header.metadata.frame_id,
                PendingFrame {
                    header: fragment_header,
                    fragments: vec![None; fragment_header.fragment_count],
                    received_fragments: 0,
                    received_bytes: 0,
                    created_at: now,
                    last_progress_at: now,
                    max_fragment_gap: Duration::from_secs(0),
                },
            );
        }

        let pending = self
            .pending
            .get_mut(&fragment_header.metadata.frame_id)
            .expect("pending frame was inserted");
        if !pending.header.belongs_to_same_frame(fragment_header) {
            self.drop_frame(fragment_header.metadata.frame_id, false);
            self.stats.malformed_fragments = self.stats.malformed_fragments.saturating_add(1);
            return Err(VideoDatagramError::InconsistentMetadata);
        }
        if let Some(existing) = &pending.fragments[fragment_header.fragment_index] {
            if existing == fragment_payload {
                self.stats.duplicate_fragments = self.stats.duplicate_fragments.saturating_add(1);
                return Ok(outcome);
            }
            self.drop_frame(fragment_header.metadata.frame_id, false);
            self.stats.malformed_fragments = self.stats.malformed_fragments.saturating_add(1);
            return Err(VideoDatagramError::ConflictingDuplicate);
        }
        if self.pending_bytes.saturating_add(fragment_payload.len()) > self.config.max_memory_bytes
        {
            self.drop_frame(fragment_header.metadata.frame_id, false);
            return Err(VideoDatagramError::MemoryLimit);
        }
        pending.max_fragment_gap = pending
            .max_fragment_gap
            .max(now.saturating_duration_since(pending.last_progress_at));
        pending.fragments[fragment_header.fragment_index] = Some(fragment_payload.to_vec());
        pending.received_fragments += 1;
        pending.received_bytes += fragment_payload.len();
        pending.last_progress_at = now;
        self.pending_bytes += fragment_payload.len();

        if pending.received_bytes > fragment_header.frame_size {
            let received_bytes = pending.received_bytes;
            self.drop_frame(fragment_header.metadata.frame_id, false);
            self.stats.malformed_fragments = self.stats.malformed_fragments.saturating_add(1);
            return Err(VideoDatagramError::InvalidFrameSize(received_bytes));
        }
        if pending.received_fragments != fragment_header.fragment_count {
            outcome.request_keyframe |= self.should_request_keyframe(now);
            return Ok(outcome);
        }
        if pending.received_bytes != fragment_header.frame_size {
            let received_bytes = pending.received_bytes;
            self.drop_frame(fragment_header.metadata.frame_id, false);
            self.stats.malformed_fragments = self.stats.malformed_fragments.saturating_add(1);
            return Err(VideoDatagramError::InvalidFrameSize(received_bytes));
        }

        let is_keyframe = fragment_header.metadata.flags & FLAG_KEYFRAME != 0;
        if !self.has_completed_keyframe && !is_keyframe {
            let dropped = self
                .pending
                .remove(&fragment_header.metadata.frame_id)
                .expect("complete pending frame exists");
            self.pending_bytes = self.pending_bytes.saturating_sub(dropped.received_bytes);
            self.stats.pre_keyframe_frames = self.stats.pre_keyframe_frames.saturating_add(1);
            self.record_drops(1);
            outcome.dropped_frames = outcome.dropped_frames.saturating_add(1);
            outcome.request_keyframe |= self.should_request_keyframe(now);
            return Ok(outcome);
        }

        let complete = self
            .pending
            .remove(&fragment_header.metadata.frame_id)
            .expect("complete pending frame exists");
        self.pending_bytes = self.pending_bytes.saturating_sub(complete.received_bytes);
        let assembly_us = duration_us(now.saturating_duration_since(complete.created_at));
        self.stats.last_frame_assembly_us = assembly_us;
        self.stats.max_frame_assembly_us = self.stats.max_frame_assembly_us.max(assembly_us);
        self.stats.max_fragment_gap_us = self
            .stats
            .max_fragment_gap_us
            .max(duration_us(complete.max_fragment_gap));
        self.stats.last_frame_bytes = u64::try_from(complete.received_bytes).unwrap_or(u64::MAX);
        self.stats.last_frame_fragments =
            u64::try_from(complete.received_fragments).unwrap_or(u64::MAX);
        let mut payload = Vec::with_capacity(complete.header.frame_size);
        for fragment in complete.fragments {
            payload.extend_from_slice(fragment.as_deref().expect("all fragments are present"));
        }
        let completed_frame_id = complete.header.metadata.frame_id;
        self.last_completed_frame_id = self.last_completed_frame_id.max(completed_frame_id);
        self.finished_above_closed.insert(completed_frame_id);
        self.recent_completions.push_back((now, completed_frame_id));
        if is_keyframe {
            self.has_completed_keyframe = true;
        }
        // A frame with a lower id is not given up at once: its datagrams may be right behind.
        let obsolete_frames = self.close_completed(now);
        if obsolete_frames > 0 {
            self.record_drops(obsolete_frames);
            outcome.dropped_frames = outcome.dropped_frames.saturating_add(obsolete_frames);
            outcome.request_keyframe |= self.should_request_keyframe(now);
        }
        if is_keyframe || outcome.dropped_frames == 0 {
            self.consecutive_dropped_frames = 0;
        }
        self.stats.completed_frames = self.stats.completed_frames.saturating_add(1);
        outcome.frame = Some(CompleteVideoFrame {
            metadata: complete.header.metadata,
            payload,
        });
        Ok(outcome)
    }

    pub fn expire(&mut self, now: Instant) -> VideoReassemblyOutcome {
        self.dropped_newest_timestamp_us = None;
        self.dropped_keyframe = false;
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter_map(|(frame_id, frame)| {
                let is_keyframe = frame.header.metadata.flags & FLAG_KEYFRAME != 0;
                let (idle_deadline, lifetime) = if is_keyframe {
                    (
                        self.config.keyframe_fragment_deadline,
                        self.config.keyframe_lifetime,
                    )
                } else {
                    (self.config.fragment_deadline, self.config.frame_lifetime)
                };
                if now.saturating_duration_since(frame.last_progress_at) >= idle_deadline
                    || now.saturating_duration_since(frame.created_at) >= lifetime
                {
                    Some(*frame_id)
                } else {
                    None
                }
            })
            .collect();
        let dropped_frames = u32::try_from(expired.len()).unwrap_or(u32::MAX);
        for frame_id in expired {
            if self
                .pending
                .get(&frame_id)
                .is_some_and(|frame| frame.header.metadata.flags & FLAG_KEYFRAME != 0)
            {
                self.stats.expired_keyframes = self.stats.expired_keyframes.saturating_add(1);
            }
            self.drop_frame(frame_id, false);
            self.stats.expired_frames = self.stats.expired_frames.saturating_add(1);
        }
        // Frames that stayed incomplete below a completed one: until its grace was over, or
        // until nothing arrived for them any more.
        let obsolete_frames = self.close_completed(now);
        let dropped_frames = dropped_frames.saturating_add(obsolete_frames);
        self.record_drops(dropped_frames);
        VideoReassemblyOutcome {
            frame: None,
            dropped_frames,
            request_keyframe: self.should_request_keyframe(now),
            dropped_newest_timestamp_us: self
                .dropped_newest_timestamp_us
                .filter(|_| dropped_frames > 0),
            dropped_keyframe: self.dropped_keyframe && dropped_frames > 0,
        }
    }

    pub fn reset(&mut self) {
        self.pending.clear();
        self.pending_bytes = 0;
        self.last_completed_frame_id = 0;
        self.closed_frame_id = 0;
        self.recent_completions.clear();
        self.finished_above_closed.clear();
        self.dropped_newest_timestamp_us = None;
        self.dropped_keyframe = false;
        self.has_completed_keyframe = !self.config.require_initial_keyframe;
        self.consecutive_dropped_frames = 0;
        self.last_keyframe_request = None;
    }

    pub fn stats(&self) -> &VideoReassemblyStats {
        &self.stats
    }

    pub fn pending_memory_bytes(&self) -> usize {
        self.pending_bytes
    }

    fn validate_fragment_header(
        &self,
        fragment_header: FragmentHeader,
    ) -> Result<(), VideoDatagramError> {
        validate_frame_metadata(fragment_header.metadata)?;
        if fragment_header.fragment_count == 0
            || fragment_header.fragment_count > MAX_VIDEO_FRAGMENTS
        {
            return Err(VideoDatagramError::InvalidFragmentCount(
                fragment_header.fragment_count,
            ));
        }
        if fragment_header.fragment_index >= fragment_header.fragment_count {
            return Err(VideoDatagramError::InvalidFragmentIndex {
                index: fragment_header.fragment_index,
                count: fragment_header.fragment_count,
            });
        }
        if fragment_header.frame_size == 0
            || fragment_header.frame_size > self.config.max_frame_bytes
        {
            return Err(VideoDatagramError::InvalidFrameSize(
                fragment_header.frame_size,
            ));
        }
        Ok(())
    }

    fn evict_oldest(&mut self) -> bool {
        let frame_id = match self
            .pending
            .iter()
            .find_map(|(frame_id, frame)| {
                (frame.header.metadata.flags & FLAG_KEYFRAME == 0).then_some(*frame_id)
            })
            .or_else(|| self.pending.keys().next().copied())
        {
            Some(frame_id) => frame_id,
            None => return false,
        };
        self.drop_frame(frame_id, false);
        self.stats.evicted_frames = self.stats.evicted_frames.saturating_add(1);
        self.record_drops(1);
        true
    }

    fn drop_frame(&mut self, frame_id: u64, record_drop: bool) {
        if let Some(frame) = self.pending.remove(&frame_id) {
            self.pending_bytes = self.pending_bytes.saturating_sub(frame.received_bytes);
            let timestamp_us = frame.header.metadata.presentation_timestamp_us;
            self.dropped_newest_timestamp_us = Some(
                self.dropped_newest_timestamp_us
                    .map_or(timestamp_us, |newest| newest.max(timestamp_us)),
            );
            self.dropped_keyframe |= frame.header.metadata.flags & FLAG_KEYFRAME != 0;
            let missing = frame
                .header
                .fragment_count
                .saturating_sub(frame.received_fragments);
            self.stats.missing_fragments = self
                .stats
                .missing_fragments
                .saturating_add(u64::try_from(missing).unwrap_or(u64::MAX));
            if record_drop {
                self.record_drops(1);
            }
        }
    }

    /// Moves the closed mark up to the frames that were completed at least the grace time
    /// ago, and drops what is still incomplete below it; then gives up the delta frames below
    /// a completed one for which nothing arrives any more. Returns how many frames that was.
    fn close_completed(&mut self, now: Instant) -> u32 {
        let mut closed = self.closed_frame_id;
        while let Some((completed_at, frame_id)) = self.recent_completions.front().copied() {
            if self.recent_completions.len() <= MAX_REMEMBERED_COMPLETIONS
                && now.saturating_duration_since(completed_at) < self.config.reorder_grace
            {
                break;
            }
            closed = closed.max(frame_id);
            self.recent_completions.pop_front();
        }
        let mut dropped = 0;
        if closed != self.closed_frame_id {
            self.closed_frame_id = closed;
            self.finished_above_closed = self.finished_above_closed.split_off(&(closed + 1));
            dropped = self.drop_obsolete_pending();
        }
        dropped.saturating_add(self.give_up_idle_below_completed(now))
    }

    /// A delta frame below a completed one whose datagrams stopped arriving is lost: it is
    /// reported now, not when the grace of the completed frame is over. What arrives for it
    /// later is ignored, so it is reported once.
    ///
    /// A keyframe waits for the whole grace: it is large, and nothing replaces it.
    fn give_up_idle_below_completed(&mut self, now: Instant) -> u32 {
        let idle: Vec<u64> = self
            .pending
            .range(..self.last_completed_frame_id)
            .filter_map(|(frame_id, frame)| {
                (frame.header.metadata.flags & FLAG_KEYFRAME == 0
                    && now.saturating_duration_since(frame.last_progress_at)
                        >= self.config.reorder_idle)
                    .then_some(*frame_id)
            })
            .collect();
        for frame_id in &idle {
            self.drop_frame(*frame_id, false);
            self.finished_above_closed.insert(*frame_id);
        }
        let count = u32::try_from(idle.len()).unwrap_or(u32::MAX);
        self.stats.obsolete_frames = self.stats.obsolete_frames.saturating_add(u64::from(count));
        count
    }

    fn drop_obsolete_pending(&mut self) -> u32 {
        let obsolete: Vec<u64> = self
            .pending
            .range(..=self.closed_frame_id)
            .map(|(frame_id, _)| *frame_id)
            .collect();
        for frame_id in &obsolete {
            self.drop_frame(*frame_id, false);
            self.stats.obsolete_fragments = self.stats.obsolete_fragments.saturating_add(1);
        }
        let count = u32::try_from(obsolete.len()).unwrap_or(u32::MAX);
        self.stats.obsolete_frames = self.stats.obsolete_frames.saturating_add(u64::from(count));
        count
    }

    fn record_drops(&mut self, count: u32) {
        self.consecutive_dropped_frames = self.consecutive_dropped_frames.saturating_add(count);
    }

    fn should_request_keyframe(&mut self, now: Instant) -> bool {
        if self.consecutive_dropped_frames < self.config.keyframe_request_after_drops {
            return false;
        }
        if self
            .last_keyframe_request
            .map(|last| now.saturating_duration_since(last) < self.config.keyframe_request_interval)
            .unwrap_or(false)
        {
            return false;
        }
        self.last_keyframe_request = Some(now);
        true
    }
}

fn validate_frame_metadata(metadata: VideoFrameMetadata) -> Result<(), VideoDatagramError> {
    if metadata.frame_id == 0 {
        return Err(VideoDatagramError::ZeroFrameId);
    }
    if metadata.flags & !KNOWN_FRAME_FLAGS != 0 {
        return Err(VideoDatagramError::UnknownFlags(metadata.flags));
    }
    Ok(())
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn encode_fragment_payload(
    header: FragmentHeader,
    fragment: &[u8],
) -> Result<Vec<u8>, VideoDatagramError> {
    if fragment.is_empty() {
        return Err(VideoDatagramError::EmptyFragment);
    }
    let fragment_index = u16::try_from(header.fragment_index).map_err(|_| {
        VideoDatagramError::InvalidFragmentIndex {
            index: header.fragment_index,
            count: header.fragment_count,
        }
    })?;
    let fragment_count = u16::try_from(header.fragment_count)
        .map_err(|_| VideoDatagramError::InvalidFragmentCount(header.fragment_count))?;
    let frame_size = u32::try_from(header.frame_size)
        .map_err(|_| VideoDatagramError::InvalidFrameSize(header.frame_size))?;
    let mut payload = Vec::with_capacity(VIDEO_FRAGMENT_HEADER_LEN + fragment.len());
    payload.extend_from_slice(&header.metadata.frame_id.to_be_bytes());
    payload.extend_from_slice(&fragment_index.to_be_bytes());
    payload.extend_from_slice(&fragment_count.to_be_bytes());
    payload.push(header.metadata.codec as u8);
    payload.push(header.metadata.flags);
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&header.metadata.presentation_timestamp_us.to_be_bytes());
    payload.extend_from_slice(&frame_size.to_be_bytes());
    payload.extend_from_slice(fragment);
    Ok(payload)
}

fn decode_fragment_payload(payload: &[u8]) -> Result<(FragmentHeader, &[u8]), VideoDatagramError> {
    if payload.len() <= VIDEO_FRAGMENT_HEADER_LEN {
        return Err(if payload.len() < VIDEO_FRAGMENT_HEADER_LEN {
            VideoDatagramError::HeaderTruncated
        } else {
            VideoDatagramError::EmptyFragment
        });
    }
    if read_u16(payload, 14) != 0 {
        return Err(VideoDatagramError::ReservedField);
    }
    let fragment_header = FragmentHeader {
        metadata: VideoFrameMetadata {
            frame_id: read_u64(payload, 0),
            codec: VideoCodec::try_from(payload[12])?,
            flags: payload[13],
            presentation_timestamp_us: read_u64(payload, 16),
        },
        fragment_index: read_u16(payload, 8) as usize,
        fragment_count: read_u16(payload, 10) as usize,
        frame_size: read_u32(payload, 24) as usize,
    };
    Ok((fragment_header, &payload[VIDEO_FRAGMENT_HEADER_LEN..]))
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(input[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::robustness::exercise_decoder;

    #[test]
    fn random_and_mutated_fragments_never_panic_or_exceed_limits() {
        let frame: Vec<u8> = (0..3000).map(|index| index as u8).collect();
        let mut samples = datagrams(1, &frame, 800);
        samples.extend(datagrams_with_flags(2, 0, &frame[..500], 1200));
        let config = VideoReassemblyConfig::default();
        let mut reassembler = VideoReassembler::new(config).unwrap();
        let start = Instant::now();
        let mut step = 0u64;
        exercise_decoder(0x7669_6465, &samples, 1500, |input| {
            step += 1;
            let _ = reassembler.push(input, start + Duration::from_millis(step % 5_000));
            assert!(reassembler.pending.len() <= config.max_pending_frames);
            assert!(reassembler.pending_bytes <= config.max_memory_bytes);
        });
    }

    fn metadata(frame_id: u64) -> VideoFrameMetadata {
        VideoFrameMetadata {
            frame_id,
            codec: VideoCodec::H264,
            flags: FLAG_KEYFRAME,
            presentation_timestamp_us: 99,
        }
    }

    fn datagrams_with_flags(
        frame_id: u64,
        flags: u8,
        bytes: &[u8],
        max_size: usize,
    ) -> Vec<Vec<u8>> {
        let mut metadata = metadata(frame_id);
        metadata.flags = flags;
        fragment_video_frame([7; 16], 1, 42, metadata, bytes, max_size).unwrap()
    }

    fn datagrams(frame_id: u64, bytes: &[u8], max_size: usize) -> Vec<Vec<u8>> {
        fragment_video_frame([7; 16], 1, 42, metadata(frame_id), bytes, max_size).unwrap()
    }

    /// A delta frame in datagrams of at most 700 bytes; `timestamp_us` is what a sender with
    /// the keyframe barrier uses for the id of the keyframe the delta follows.
    fn delta_datagrams(frame_id: u64, timestamp_us: u64, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut metadata = metadata(frame_id);
        metadata.flags = 0;
        metadata.presentation_timestamp_us = timestamp_us;
        fragment_video_frame([7; 16], 1, 42, metadata, bytes, 700).unwrap()
    }

    fn reassembler_without_initial_keyframe(config: VideoReassemblyConfig) -> VideoReassembler {
        VideoReassembler::new(VideoReassemblyConfig {
            require_initial_keyframe: false,
            // Long enough not to expire an incomplete frame by itself in these tests.
            fragment_deadline: Duration::from_secs(5),
            ..config
        })
        .unwrap()
    }

    #[test]
    fn fragments_respect_negotiated_datagram_size() {
        let frame = vec![9; 4096];
        let packets = datagrams(1, &frame, 1200);
        assert!(packets.len() > 1);
        assert!(packets.iter().all(|packet| packet.len() <= 1200));
    }

    #[test]
    fn reassembles_out_of_order_and_ignores_duplicate() {
        let frame: Vec<u8> = (0..5000).map(|index| index as u8).collect();
        let mut packets = datagrams(1, &frame, 800);
        packets.reverse();
        packets.insert(1, packets[0].clone());
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig::default()).unwrap();
        let mut completed = None;
        for packet in packets {
            if let Some(frame) = reassembler.push(&packet, now).unwrap().frame {
                completed = Some(frame);
            }
        }
        assert_eq!(completed.unwrap().payload, frame);
        assert_eq!(reassembler.stats().duplicate_fragments, 1);
    }

    #[test]
    fn incomplete_frame_expires_without_blocking_newer_frame() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            fragment_deadline: Duration::from_millis(10),
            keyframe_fragment_deadline: Duration::from_millis(10),
            keyframe_request_after_drops: 1,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let old = datagrams(1, &[1; 3000], 700);
        reassembler.push(&old[0], now).unwrap();
        let expired = reassembler.expire(now + Duration::from_millis(11));
        assert_eq!(expired.dropped_frames, 1);
        assert!(expired.request_keyframe);

        let mut complete = None;
        for packet in datagrams(2, &[2; 1000], 700) {
            complete = reassembler
                .push(&packet, now + Duration::from_millis(12))
                .unwrap()
                .frame
                .or(complete);
        }
        assert_eq!(complete.unwrap().metadata.frame_id, 2);
    }

    #[test]
    fn active_fragment_progress_extends_idle_deadline() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            fragment_deadline: Duration::from_millis(10),
            frame_lifetime: Duration::from_millis(100),
            require_initial_keyframe: false,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let packets = datagrams_with_flags(1, 0, &[1; 3_000], 700);

        reassembler.push(&packets[0], now).unwrap();
        reassembler
            .push(&packets[1], now + Duration::from_millis(8))
            .unwrap();
        assert_eq!(
            reassembler
                .expire(now + Duration::from_millis(11))
                .dropped_frames,
            0
        );
        reassembler
            .push(&packets[2], now + Duration::from_millis(16))
            .unwrap();
        assert_eq!(
            reassembler
                .expire(now + Duration::from_millis(25))
                .dropped_frames,
            0
        );
        assert_eq!(
            reassembler
                .expire(now + Duration::from_millis(27))
                .dropped_frames,
            1
        );
    }

    #[test]
    fn hard_frame_lifetime_bounds_continuous_progress() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            fragment_deadline: Duration::from_millis(20),
            frame_lifetime: Duration::from_millis(25),
            require_initial_keyframe: false,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let packets = datagrams_with_flags(1, 0, &[1; 5_000], 700);

        reassembler.push(&packets[0], now).unwrap();
        reassembler
            .push(&packets[1], now + Duration::from_millis(9))
            .unwrap();
        reassembler
            .push(&packets[2], now + Duration::from_millis(18))
            .unwrap();
        assert_eq!(
            reassembler
                .expire(now + Duration::from_millis(24))
                .dropped_frames,
            0
        );
        assert_eq!(
            reassembler
                .expire(now + Duration::from_millis(25))
                .dropped_frames,
            1
        );
    }

    #[test]
    fn expiry_keyframe_request_is_not_overwritten_by_the_next_fragment() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            fragment_deadline: Duration::from_millis(10),
            keyframe_fragment_deadline: Duration::from_millis(10),
            keyframe_request_after_drops: 1,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let old = datagrams(1, &[1; 3_000], 700);
        reassembler.push(&old[0], now).unwrap();

        let newer = datagrams(2, &[2; 3_000], 700);
        let outcome = reassembler
            .push(&newer[0], now + Duration::from_millis(11))
            .unwrap();
        assert_eq!(outcome.dropped_frames, 1);
        assert!(outcome.request_keyframe);
    }

    #[test]
    fn startup_delta_does_not_obsolete_partial_keyframe() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            keyframe_request_after_drops: 1,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let keyframe = datagrams_with_flags(1, FLAG_KEYFRAME, &[1; 4_000], 700);
        reassembler.push(&keyframe[0], now).unwrap();

        let mut delta_outcome = VideoReassemblyOutcome::default();
        for packet in datagrams_with_flags(2, 0, &[2; 1_000], 700) {
            delta_outcome = reassembler.push(&packet, now).unwrap();
        }
        assert!(delta_outcome.frame.is_none());
        assert!(delta_outcome.request_keyframe);
        assert_eq!(reassembler.stats().pre_keyframe_frames, 1);

        let mut completed = None;
        for packet in keyframe.into_iter().skip(1) {
            completed = reassembler.push(&packet, now).unwrap().frame.or(completed);
        }
        assert_eq!(completed.unwrap().metadata.frame_id, 1);
    }

    #[test]
    fn external_reliable_keyframe_mode_accepts_datagram_delta() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            require_initial_keyframe: false,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let mut completed = None;
        for packet in datagrams_with_flags(2, 0, &[2; 1_000], 700) {
            completed = reassembler.push(&packet, now).unwrap().frame.or(completed);
        }
        assert_eq!(completed.unwrap().metadata.frame_id, 2);
        assert_eq!(reassembler.stats().pre_keyframe_frames, 0);
    }

    #[test]
    fn keyframe_uses_longer_fragment_deadline() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            fragment_deadline: Duration::from_millis(10),
            keyframe_fragment_deadline: Duration::from_millis(100),
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let keyframe = datagrams(1, &[1; 3_000], 700);
        reassembler.push(&keyframe[0], now).unwrap();
        assert_eq!(
            reassembler
                .expire(now + Duration::from_millis(11))
                .dropped_frames,
            0
        );
        assert_eq!(
            reassembler
                .expire(now + Duration::from_millis(101))
                .dropped_frames,
            1
        );
        assert_eq!(reassembler.stats().expired_keyframes, 1);
    }

    #[test]
    fn completing_new_frame_discards_old_partial_frame_after_the_grace() {
        let now = Instant::now();
        let config = VideoReassemblyConfig::default();
        let after_grace = now + config.reorder_grace;
        let mut reassembler = VideoReassembler::new(config).unwrap();
        let old = datagrams(1, &[1; 3000], 700);
        reassembler.push(&old[0], now).unwrap();
        for packet in datagrams(2, &[2; 100], 700) {
            reassembler.push(&packet, now).unwrap();
        }
        // Not at once: the rest of its datagrams may be right behind those of the newer frame.
        assert!(reassembler.pending_memory_bytes() > 0);
        assert_eq!(reassembler.push(&old[1], after_grace).unwrap().frame, None);
        assert_eq!(reassembler.pending_memory_bytes(), 0);
        assert_eq!(reassembler.stats().obsolete_frames, 1);
        assert_eq!(reassembler.stats().obsolete_fragments, 2);
    }

    #[test]
    fn bounded_pending_frames_evict_oldest() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            max_pending_frames: 2,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        for frame_id in 1..=3 {
            let packets = datagrams(frame_id, &[frame_id as u8; 3000], 700);
            reassembler.push(&packets[0], now).unwrap();
        }
        assert_eq!(reassembler.pending.len(), 2);
        assert_eq!(reassembler.stats().evicted_frames, 1);
    }

    #[test]
    fn rejects_conflicting_duplicate_and_releases_memory() {
        let now = Instant::now();
        let mut packets = datagrams(1, &[1; 3000], 700);
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig::default()).unwrap();
        reassembler.push(&packets[0], now).unwrap();
        *packets[0].last_mut().unwrap() ^= 1;
        assert_eq!(
            reassembler.push(&packets[0], now),
            Err(VideoDatagramError::ConflictingDuplicate)
        );
        assert_eq!(reassembler.pending_memory_bytes(), 0);
    }

    #[test]
    fn rejects_datagram_too_small_and_sequence_overflow() {
        let frame = [1; 100];
        assert_eq!(
            fragment_video_frame([1; 16], 1, 1, metadata(1), &frame, 76),
            Err(VideoDatagramError::DatagramTooSmall(76))
        );
        assert_eq!(
            fragment_video_frame([1; 16], u64::MAX, 1, metadata(1), &frame, 100),
            Err(VideoDatagramError::SequenceOverflow)
        );
    }

    /// A frame with a lower id whose datagrams arrive right after a frame with a higher id has
    /// been completed: two displays share one sequence, and an older sender, or the network,
    /// can deliver them in this order. Both are whole frames and both must be handed on; which
    /// of them can be decoded is decided per stream by the layer above.
    #[test]
    fn frame_arriving_right_after_a_newer_one_is_still_delivered() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            require_initial_keyframe: false,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let mut delivered = Vec::new();
        let mut dropped = 0;
        let mut push_all = |frame_id: u64, at: Instant, reassembler: &mut VideoReassembler| {
            for packet in datagrams(frame_id, &[frame_id as u8; 2000], 700) {
                let outcome = reassembler.push(&packet, at).unwrap();
                dropped += outcome.dropped_frames;
                if let Some(frame) = outcome.frame {
                    delivered.push(frame.metadata.frame_id);
                }
            }
        };
        push_all(9, now, &mut reassembler);
        push_all(11, now + Duration::from_millis(1), &mut reassembler);
        push_all(10, now + Duration::from_millis(3), &mut reassembler);
        assert_eq!(delivered, vec![9, 11, 10]);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn frame_left_incomplete_below_a_completed_one_is_dropped_when_the_grace_is_over() {
        let now = Instant::now();
        let config = VideoReassemblyConfig {
            require_initial_keyframe: false,
            // Long enough not to expire the incomplete frame by itself in this test.
            fragment_deadline: Duration::from_secs(5),
            ..VideoReassemblyConfig::default()
        };
        let grace = config.reorder_grace;
        let mut reassembler = VideoReassembler::new(config).unwrap();
        let old = datagrams(10, &[1; 3000], 700);
        reassembler.push(&old[0], now).unwrap();
        let mut completed = None;
        for packet in datagrams(11, &[2; 1000], 700) {
            let outcome = reassembler.push(&packet, now).unwrap();
            assert_eq!(outcome.dropped_frames, 0, "not given up at once");
            completed = outcome.frame.or(completed);
        }
        assert_eq!(completed.unwrap().metadata.frame_id, 11);

        // Within the grace the rest of the older frame still completes it.
        let mut late = None;
        for packet in &old[1..] {
            late = reassembler
                .push(packet, now + grace / 2)
                .unwrap()
                .frame
                .or(late);
        }
        assert_eq!(late.unwrap().metadata.frame_id, 10);

        // Another one stays incomplete: when the grace of the newer frame is over it is
        // dropped and reported, as before.
        let stuck = datagrams(12, &[3; 3000], 700);
        reassembler.push(&stuck[0], now + grace / 2).unwrap();
        for packet in datagrams(13, &[4; 1000], 700) {
            reassembler.push(&packet, now + grace / 2).unwrap();
        }
        let outcome = reassembler.expire(now + grace * 2);
        assert_eq!(outcome.dropped_frames, 1);
        assert!(outcome.request_keyframe);
        // Its remaining datagrams are now too late.
        let before = reassembler.stats().obsolete_fragments;
        assert!(reassembler
            .push(&stuck[1], now + grace * 2)
            .unwrap()
            .frame
            .is_none());
        assert!(reassembler.stats().obsolete_fragments > before);
    }

    #[test]
    fn datagram_of_a_completed_frame_is_ignored_during_the_grace() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            require_initial_keyframe: false,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let packets = datagrams(5, &[7; 2000], 700);
        let mut completions = 0;
        for packet in packets.iter().chain(packets.iter()) {
            if reassembler.push(packet, now).unwrap().frame.is_some() {
                completions += 1;
            }
        }
        assert_eq!(
            completions, 1,
            "a repeated datagram must not rebuild the frame"
        );
        assert_eq!(reassembler.stats().obsolete_fragments, packets.len() as u64);
    }

    #[test]
    fn without_a_grace_a_completed_frame_closes_everything_below_it() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig {
            require_initial_keyframe: false,
            reorder_grace: Duration::ZERO,
            ..VideoReassemblyConfig::default()
        })
        .unwrap();
        let mut delivered = Vec::new();
        for frame_id in [9u64, 11, 10] {
            for packet in datagrams(frame_id, &[frame_id as u8; 2000], 700) {
                if let Some(frame) = reassembler.push(&packet, now).unwrap().frame {
                    delivered.push(frame.metadata.frame_id);
                }
            }
        }
        assert_eq!(delivered, vec![9, 11]);
    }

    /// One stream at thirty frames a second. A datagram of frame 10 is lost; frame 11
    /// arrives a frame time later. Nothing has come for frame 10 since: it is reported with
    /// the completion of frame 11, not a grace time later, when the keyframe that was asked
    /// for because of the gap may already be here.
    #[test]
    fn delta_that_stopped_arriving_is_given_up_when_a_later_frame_is_complete() {
        let now = Instant::now();
        let config = VideoReassemblyConfig::default();
        let grace = config.reorder_grace;
        let mut reassembler = reassembler_without_initial_keyframe(config);
        let lost = delta_datagrams(10, 4, &[1; 3000]);
        for packet in &lost[..lost.len() - 1] {
            assert_eq!(reassembler.push(packet, now).unwrap().dropped_frames, 0);
        }
        let frame_time = Duration::from_millis(33);
        let mut completed = None;
        let mut dropped = 0;
        let mut dropped_timestamp = None;
        for packet in delta_datagrams(11, 4, &[2; 1000]) {
            let outcome = reassembler.push(&packet, now + frame_time).unwrap();
            dropped += outcome.dropped_frames;
            dropped_timestamp = outcome.dropped_newest_timestamp_us.or(dropped_timestamp);
            if outcome.frame.is_some() {
                assert_eq!(outcome.dropped_frames, 1, "reported with the completion");
                assert!(outcome.request_keyframe);
            }
            completed = outcome.frame.or(completed);
        }
        assert_eq!(completed.unwrap().metadata.frame_id, 11);
        assert_eq!(dropped, 1);
        assert_eq!(
            dropped_timestamp,
            Some(4),
            "the keyframe the lost delta followed"
        );
        assert_eq!(reassembler.pending_memory_bytes(), 0);

        // Its last datagram, should it still come, is ignored, and the frame is not
        // reported a second time when the grace is over.
        let before = reassembler.stats().obsolete_fragments;
        let late = reassembler
            .push(
                &lost[lost.len() - 1],
                now + frame_time + Duration::from_millis(1),
            )
            .unwrap();
        assert!(late.frame.is_none());
        assert_eq!(late.dropped_frames, 0);
        assert_eq!(reassembler.stats().obsolete_fragments, before + 1);
        assert_eq!(reassembler.pending_memory_bytes(), 0);
        let after_grace = reassembler.expire(now + frame_time + grace * 2);
        assert_eq!(after_grace.dropped_frames, 0);
        assert_eq!(after_grace.dropped_newest_timestamp_us, None);
    }

    /// Two frames sent one right after the other, their datagrams mixed on the way: the
    /// frame with the lower id is still arriving when the one above it is complete. It is
    /// not given up, and it is delivered.
    #[test]
    fn delta_that_is_still_arriving_below_a_completed_frame_is_waited_for() {
        let now = Instant::now();
        let mut reassembler =
            reassembler_without_initial_keyframe(VideoReassemblyConfig::default());
        let lower = delta_datagrams(10, 4, &[1; 3000]);
        for packet in &lower[..lower.len() - 1] {
            reassembler.push(packet, now).unwrap();
        }
        let mut delivered = Vec::new();
        for packet in delta_datagrams(11, 4, &[2; 1000]) {
            let outcome = reassembler
                .push(&packet, now + Duration::from_millis(1))
                .unwrap();
            assert_eq!(outcome.dropped_frames, 0);
            delivered.extend(outcome.frame.map(|frame| frame.metadata.frame_id));
        }
        let outcome = reassembler
            .push(&lower[lower.len() - 1], now + Duration::from_millis(3))
            .unwrap();
        assert_eq!(outcome.dropped_frames, 0);
        delivered.extend(outcome.frame.map(|frame| frame.metadata.frame_id));
        assert_eq!(delivered, vec![11, 10]);
    }

    /// A frame below a completed one for which a datagram keeps coming every few
    /// milliseconds is never idle; the grace of the completed frame still bounds the wait.
    #[test]
    fn delta_that_keeps_arriving_below_a_completed_frame_is_given_up_after_the_grace() {
        let now = Instant::now();
        let config = VideoReassemblyConfig::default();
        let grace = config.reorder_grace;
        let step = config.reorder_idle / 2;
        let mut reassembler = reassembler_without_initial_keyframe(config);
        let slow = delta_datagrams(10, 4, &[1; 40_000]);
        reassembler.push(&slow[0], now).unwrap();
        for packet in delta_datagrams(11, 4, &[2; 500]) {
            assert_eq!(reassembler.push(&packet, now).unwrap().dropped_frames, 0);
        }
        let mut dropped_at = None;
        for (index, packet) in slow[1..slow.len() - 1].iter().enumerate() {
            let at = now + step * (index as u32 + 1);
            if reassembler.push(packet, at).unwrap().dropped_frames > 0 {
                dropped_at = Some(at);
                break;
            }
        }
        let dropped_at = dropped_at.expect("given up when the grace was over");
        assert!(
            dropped_at >= now + grace,
            "given up while it was still arriving"
        );
        assert!(dropped_at < now + grace + step * 2);
    }

    /// A keyframe sent in datagrams is large and nothing replaces it: below a completed
    /// frame it waits for the whole grace, quiet or not.
    #[test]
    fn keyframe_below_a_completed_frame_waits_for_the_whole_grace() {
        let now = Instant::now();
        let config = VideoReassemblyConfig {
            keyframe_fragment_deadline: Duration::from_secs(5),
            ..VideoReassemblyConfig::default()
        };
        let grace = config.reorder_grace;
        let mut reassembler = reassembler_without_initial_keyframe(config);
        let keyframe = datagrams(10, &[1; 3000], 700);
        for packet in &keyframe[..keyframe.len() - 1] {
            reassembler.push(packet, now).unwrap();
        }
        for packet in delta_datagrams(11, 4, &[2; 500]) {
            assert_eq!(reassembler.push(&packet, now).unwrap().dropped_frames, 0);
        }
        assert_eq!(reassembler.expire(now + grace / 2).dropped_frames, 0);
        let outcome = reassembler
            .push(&keyframe[keyframe.len() - 1], now + grace / 2)
            .unwrap();
        assert_eq!(outcome.frame.unwrap().metadata.frame_id, 10);
    }

    /// Of several frames dropped together the report names the newest timestamp.
    #[test]
    fn report_of_dropped_frames_names_the_newest_timestamp() {
        let now = Instant::now();
        let mut reassembler =
            reassembler_without_initial_keyframe(VideoReassemblyConfig::default());
        reassembler
            .push(&delta_datagrams(10, 4, &[1; 3000])[0], now)
            .unwrap();
        reassembler
            .push(&delta_datagrams(11, 9, &[1; 3000])[0], now)
            .unwrap();
        let mut dropped = 0;
        let mut timestamp = None;
        for packet in delta_datagrams(12, 9, &[2; 500]) {
            let outcome = reassembler
                .push(&packet, now + Duration::from_millis(33))
                .unwrap();
            dropped += outcome.dropped_frames;
            timestamp = outcome.dropped_newest_timestamp_us.or(timestamp);
        }
        assert_eq!(dropped, 2);
        assert_eq!(timestamp, Some(9));
    }

    /// A dropped keyframe is named as one: its timestamp field is not the id of a keyframe
    /// it follows, and the receiver must not read it as that.
    #[test]
    fn report_of_a_dropped_keyframe_says_so() {
        let now = Instant::now();
        let config = VideoReassemblyConfig::default();
        let deadline = config.keyframe_fragment_deadline;
        let mut reassembler = VideoReassembler::new(config).unwrap();
        let first = reassembler
            .push(&datagrams(10, &[1; 3000], 700)[0], now)
            .unwrap();
        assert!(!first.dropped_keyframe);
        let expired = reassembler.expire(now + deadline);
        assert_eq!(expired.dropped_frames, 1);
        assert!(expired.dropped_keyframe);
        assert!(!reassembler.expire(now + deadline * 2).dropped_keyframe);
    }
}
