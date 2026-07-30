use super::protocol::{
    decode_message, encode_message, MessageHeader, MessageType, ProtocolError, SessionId,
    HEADER_LEN,
};
use std::{
    collections::BTreeMap,
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
    pub fragment_deadline: Duration,
    pub keyframe_request_after_drops: u32,
    pub keyframe_request_interval: Duration,
}

impl Default for VideoReassemblyConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: MAX_VIDEO_FRAME_BYTES,
            max_pending_frames: 8,
            max_memory_bytes: 64 * 1024 * 1024,
            fragment_deadline: Duration::from_millis(80),
            keyframe_request_after_drops: 3,
            keyframe_request_interval: Duration::from_millis(500),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VideoReassemblyStats {
    pub completed_frames: u64,
    pub expired_frames: u64,
    pub evicted_frames: u64,
    pub duplicate_fragments: u64,
    pub obsolete_fragments: u64,
    pub malformed_fragments: u64,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VideoReassemblyOutcome {
    pub frame: Option<CompleteVideoFrame>,
    pub dropped_frames: u32,
    pub request_keyframe: bool,
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
        Ok(Self {
            config,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            last_completed_frame_id: 0,
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

        if fragment_header.metadata.frame_id <= self.last_completed_frame_id {
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
        pending.fragments[fragment_header.fragment_index] = Some(fragment_payload.to_vec());
        pending.received_fragments += 1;
        pending.received_bytes += fragment_payload.len();
        self.pending_bytes += fragment_payload.len();

        if pending.received_bytes > fragment_header.frame_size {
            let received_bytes = pending.received_bytes;
            self.drop_frame(fragment_header.metadata.frame_id, false);
            self.stats.malformed_fragments = self.stats.malformed_fragments.saturating_add(1);
            return Err(VideoDatagramError::InvalidFrameSize(received_bytes));
        }
        if pending.received_fragments != fragment_header.fragment_count {
            outcome.request_keyframe = self.should_request_keyframe(now);
            return Ok(outcome);
        }
        if pending.received_bytes != fragment_header.frame_size {
            let received_bytes = pending.received_bytes;
            self.drop_frame(fragment_header.metadata.frame_id, false);
            self.stats.malformed_fragments = self.stats.malformed_fragments.saturating_add(1);
            return Err(VideoDatagramError::InvalidFrameSize(received_bytes));
        }

        let complete = self
            .pending
            .remove(&fragment_header.metadata.frame_id)
            .expect("complete pending frame exists");
        self.pending_bytes = self.pending_bytes.saturating_sub(complete.received_bytes);
        let mut payload = Vec::with_capacity(complete.header.frame_size);
        for fragment in complete.fragments {
            payload.extend_from_slice(fragment.as_deref().expect("all fragments are present"));
        }
        self.last_completed_frame_id = complete.header.metadata.frame_id;
        self.drop_obsolete_pending();
        self.consecutive_dropped_frames = 0;
        self.stats.completed_frames = self.stats.completed_frames.saturating_add(1);
        outcome.frame = Some(CompleteVideoFrame {
            metadata: complete.header.metadata,
            payload,
        });
        Ok(outcome)
    }

    pub fn expire(&mut self, now: Instant) -> VideoReassemblyOutcome {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter_map(|(frame_id, frame)| {
                if now.saturating_duration_since(frame.created_at) >= self.config.fragment_deadline
                {
                    Some(*frame_id)
                } else {
                    None
                }
            })
            .collect();
        let dropped_frames = u32::try_from(expired.len()).unwrap_or(u32::MAX);
        for frame_id in expired {
            self.drop_frame(frame_id, false);
            self.stats.expired_frames = self.stats.expired_frames.saturating_add(1);
        }
        self.record_drops(dropped_frames);
        VideoReassemblyOutcome {
            frame: None,
            dropped_frames,
            request_keyframe: self.should_request_keyframe(now),
        }
    }

    pub fn reset(&mut self) {
        self.pending.clear();
        self.pending_bytes = 0;
        self.last_completed_frame_id = 0;
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
        let frame_id = match self.pending.keys().next().copied() {
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
            if record_drop {
                self.record_drops(1);
            }
        }
    }

    fn drop_obsolete_pending(&mut self) {
        let obsolete: Vec<u64> = self
            .pending
            .range(..=self.last_completed_frame_id)
            .map(|(frame_id, _)| *frame_id)
            .collect();
        for frame_id in obsolete {
            self.drop_frame(frame_id, false);
            self.stats.obsolete_fragments = self.stats.obsolete_fragments.saturating_add(1);
        }
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

    fn metadata(frame_id: u64) -> VideoFrameMetadata {
        VideoFrameMetadata {
            frame_id,
            codec: VideoCodec::H264,
            flags: 0,
            presentation_timestamp_us: 99,
        }
    }

    fn datagrams(frame_id: u64, bytes: &[u8], max_size: usize) -> Vec<Vec<u8>> {
        fragment_video_frame([7; 16], 1, 42, metadata(frame_id), bytes, max_size).unwrap()
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
    fn completing_new_frame_discards_old_partial_frame() {
        let now = Instant::now();
        let mut reassembler = VideoReassembler::new(VideoReassemblyConfig::default()).unwrap();
        let old = datagrams(1, &[1; 3000], 700);
        reassembler.push(&old[0], now).unwrap();
        for packet in datagrams(2, &[2; 100], 700) {
            reassembler.push(&packet, now).unwrap();
        }
        assert_eq!(reassembler.pending_memory_bytes(), 0);
        assert_eq!(reassembler.push(&old[1], now).unwrap().frame, None);
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
}
