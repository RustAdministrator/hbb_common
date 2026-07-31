use super::protocol::{
    decode_message, encode_message, MessageHeader, MessageType, ProtocolError, SessionId,
    HEADER_LEN,
};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    time::{Duration, Instant},
};

pub const AUDIO_PACKET_HEADER_LEN: usize = 20;
pub const MAX_AUDIO_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_AUDIO_SEQUENCE_AHEAD: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AudioCodec {
    Opus = 1,
}

impl TryFrom<u8> for AudioCodec {
    type Error = AudioDatagramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Opus),
            _ => Err(AudioDatagramError::UnknownCodec(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AudioPacketMetadata {
    pub sequence_number: u64,
    pub capture_timestamp_us: u64,
    pub codec: AudioCodec,
    pub channels: u8,
    pub sample_rate_hz: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudioPacket {
    pub metadata: AudioPacketMetadata,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct AudioJitterConfig {
    pub playout_delay: Duration,
    pub max_packet_age: Duration,
    pub max_packets: usize,
    pub max_memory_bytes: usize,
    pub start_packets: usize,
}

impl Default for AudioJitterConfig {
    fn default() -> Self {
        Self {
            playout_delay: Duration::from_millis(30),
            max_packet_age: Duration::from_millis(120),
            max_packets: 64,
            max_memory_bytes: 2 * 1024 * 1024,
            start_packets: 3,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AudioJitterStats {
    pub accepted_packets: u64,
    pub played_packets: u64,
    pub duplicate_packets: u64,
    pub late_packets: u64,
    pub lost_packets: u64,
    pub evicted_packets: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AudioJitterState {
    pub queue_depth: usize,
    pub buffered_bytes: usize,
    pub buffered_capture_span_us: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AudioPlayoutItem {
    Packet(AudioPacket),
    PacketLoss { sequence_number: u64 },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AudioDatagramError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("unknown audio codec {0}")]
    UnknownCodec(u8),
    #[error("audio packet header is truncated")]
    HeaderTruncated,
    #[error("audio packet reserved field is not zero")]
    ReservedField,
    #[error("audio sequence number must not be zero")]
    ZeroSequence,
    #[error("audio channel count {0} is invalid")]
    InvalidChannelCount(u8),
    #[error("audio sample rate {0} Hz is invalid")]
    InvalidSampleRate(u32),
    #[error("audio payload size {0} is invalid")]
    InvalidPayloadSize(usize),
    #[error("QUIC datagram size {0} is too small for audio")]
    DatagramTooSmall(usize),
    #[error("audio jitter-buffer configuration is invalid")]
    InvalidJitterConfig,
    #[error("audio jitter buffer memory limit exceeded")]
    MemoryLimit,
    #[error("audio sequence gap exceeds the jitter-buffer limit")]
    SequenceGap,
}

struct BufferedAudioPacket {
    packet: AudioPacket,
    arrived_at: Instant,
}

pub fn encode_audio_datagram(
    session_id: SessionId,
    monotonic_timestamp_us: u64,
    metadata: AudioPacketMetadata,
    encoded_audio: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<u8>, AudioDatagramError> {
    validate_metadata(metadata)?;
    if encoded_audio.is_empty() || encoded_audio.len() > MAX_AUDIO_PAYLOAD_BYTES {
        return Err(AudioDatagramError::InvalidPayloadSize(encoded_audio.len()));
    }
    let required_size = HEADER_LEN
        .checked_add(AUDIO_PACKET_HEADER_LEN)
        .and_then(|size| size.checked_add(encoded_audio.len()))
        .ok_or(AudioDatagramError::InvalidPayloadSize(encoded_audio.len()))?;
    if required_size > max_datagram_size {
        return Err(AudioDatagramError::DatagramTooSmall(max_datagram_size));
    }

    let payload_len = u32::try_from(encoded_audio.len())
        .map_err(|_| AudioDatagramError::InvalidPayloadSize(encoded_audio.len()))?;
    let mut payload = Vec::with_capacity(AUDIO_PACKET_HEADER_LEN + encoded_audio.len());
    payload.extend_from_slice(&metadata.capture_timestamp_us.to_be_bytes());
    payload.push(metadata.codec as u8);
    payload.push(metadata.channels);
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&metadata.sample_rate_hz.to_be_bytes());
    payload.extend_from_slice(&payload_len.to_be_bytes());
    payload.extend_from_slice(encoded_audio);
    let header = MessageHeader::new(
        MessageType::AudioPacket,
        0,
        session_id,
        metadata.sequence_number,
        payload.len(),
        monotonic_timestamp_us,
    )?;
    Ok(encode_message(&header, &payload)?)
}

pub fn decode_audio_datagram(datagram: &[u8]) -> Result<AudioPacket, AudioDatagramError> {
    let message = decode_message(datagram)?;
    if message.header.message_type != MessageType::AudioPacket {
        return Err(ProtocolError::ChannelMismatch {
            message_type: message.header.message_type,
            channel: message.header.channel,
        }
        .into());
    }
    if message.payload.len() < AUDIO_PACKET_HEADER_LEN {
        return Err(AudioDatagramError::HeaderTruncated);
    }
    if read_u16(message.payload, 10) != 0 {
        return Err(AudioDatagramError::ReservedField);
    }
    let declared_payload_len = read_u32(message.payload, 16) as usize;
    let encoded_audio = &message.payload[AUDIO_PACKET_HEADER_LEN..];
    if encoded_audio.is_empty()
        || encoded_audio.len() > MAX_AUDIO_PAYLOAD_BYTES
        || encoded_audio.len() != declared_payload_len
    {
        return Err(AudioDatagramError::InvalidPayloadSize(declared_payload_len));
    }
    let metadata = AudioPacketMetadata {
        sequence_number: message.header.sequence_number,
        capture_timestamp_us: read_u64(message.payload, 0),
        codec: AudioCodec::try_from(message.payload[8])?,
        channels: message.payload[9],
        sample_rate_hz: read_u32(message.payload, 12),
    };
    validate_metadata(metadata)?;
    Ok(AudioPacket {
        metadata,
        payload: encoded_audio.to_vec(),
    })
}

pub struct AudioJitterBuffer {
    config: AudioJitterConfig,
    packets: BTreeMap<u64, BufferedAudioPacket>,
    next_sequence: Option<u64>,
    playout_started: bool,
    buffered_bytes: usize,
    stats: AudioJitterStats,
}

impl AudioJitterBuffer {
    pub fn new(config: AudioJitterConfig) -> Result<Self, AudioDatagramError> {
        if config.max_packets == 0
            || config.max_memory_bytes == 0
            || config.start_packets == 0
            || config.start_packets > config.max_packets
            || config.playout_delay > config.max_packet_age
        {
            return Err(AudioDatagramError::InvalidJitterConfig);
        }
        Ok(Self {
            config,
            packets: BTreeMap::new(),
            next_sequence: None,
            playout_started: false,
            buffered_bytes: 0,
            stats: AudioJitterStats::default(),
        })
    }

    pub fn push_datagram(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<bool, AudioDatagramError> {
        let packet = decode_audio_datagram(datagram)?;
        self.push(packet, now)
    }

    pub fn push(&mut self, packet: AudioPacket, now: Instant) -> Result<bool, AudioDatagramError> {
        validate_metadata(packet.metadata)?;
        if packet.payload.is_empty() || packet.payload.len() > MAX_AUDIO_PAYLOAD_BYTES {
            return Err(AudioDatagramError::InvalidPayloadSize(packet.payload.len()));
        }
        if self.playout_started
            && self
                .next_sequence
                .map(|next| packet.metadata.sequence_number < next)
                .unwrap_or(false)
        {
            self.stats.late_packets = self.stats.late_packets.saturating_add(1);
            return Ok(false);
        }
        if self.packets.contains_key(&packet.metadata.sequence_number) {
            self.stats.duplicate_packets = self.stats.duplicate_packets.saturating_add(1);
            return Ok(false);
        }
        let minimum_sequence = self
            .next_sequence
            .map(|sequence| sequence.min(packet.metadata.sequence_number))
            .unwrap_or(packet.metadata.sequence_number);
        let maximum_sequence = self
            .packets
            .keys()
            .next_back()
            .copied()
            .unwrap_or(packet.metadata.sequence_number)
            .max(packet.metadata.sequence_number);
        if maximum_sequence.saturating_sub(minimum_sequence) > MAX_AUDIO_SEQUENCE_AHEAD {
            return Err(AudioDatagramError::SequenceGap);
        }
        if packet.payload.len() > self.config.max_memory_bytes {
            return Err(AudioDatagramError::MemoryLimit);
        }
        while self.packets.len() >= self.config.max_packets
            || self.buffered_bytes.saturating_add(packet.payload.len())
                > self.config.max_memory_bytes
        {
            if !self.evict_oldest() {
                return Err(AudioDatagramError::MemoryLimit);
            }
        }
        self.next_sequence = Some(
            self.next_sequence
                .map(|next| next.min(packet.metadata.sequence_number))
                .unwrap_or(packet.metadata.sequence_number),
        );
        self.buffered_bytes += packet.payload.len();
        self.packets.insert(
            packet.metadata.sequence_number,
            BufferedAudioPacket {
                packet,
                arrived_at: now,
            },
        );
        self.stats.accepted_packets = self.stats.accepted_packets.saturating_add(1);
        Ok(true)
    }

    pub fn pop_ready(&mut self, now: Instant) -> Option<AudioPlayoutItem> {
        self.discard_expired(now);
        let next_sequence = self.next_sequence?;
        if let Some(packet) = self.packets.get(&next_sequence) {
            let ready = self.packets.len() >= self.config.start_packets
                || now.saturating_duration_since(packet.arrived_at) >= self.config.playout_delay;
            if !ready {
                return None;
            }
            let packet = self.packets.remove(&next_sequence).unwrap().packet;
            self.buffered_bytes = self.buffered_bytes.saturating_sub(packet.payload.len());
            self.next_sequence = next_sequence.checked_add(1);
            self.playout_started = true;
            self.stats.played_packets = self.stats.played_packets.saturating_add(1);
            return Some(AudioPlayoutItem::Packet(packet));
        }

        let first_buffered = self.packets.values().next()?;
        let gap_expired = self.packets.len() >= self.config.start_packets
            || now.saturating_duration_since(first_buffered.arrived_at)
                >= self.config.playout_delay;
        if !gap_expired {
            return None;
        }
        self.next_sequence = next_sequence.checked_add(1);
        self.playout_started = true;
        self.stats.lost_packets = self.stats.lost_packets.saturating_add(1);
        Some(AudioPlayoutItem::PacketLoss {
            sequence_number: next_sequence,
        })
    }

    pub fn state(&self) -> AudioJitterState {
        let first_timestamp = self
            .packets
            .values()
            .next()
            .map(|packet| packet.packet.metadata.capture_timestamp_us);
        let last_timestamp = self
            .packets
            .values()
            .next_back()
            .map(|packet| packet.packet.metadata.capture_timestamp_us);
        AudioJitterState {
            queue_depth: self.packets.len(),
            buffered_bytes: self.buffered_bytes,
            buffered_capture_span_us: first_timestamp
                .zip(last_timestamp)
                .map(|(first, last)| last.saturating_sub(first))
                .unwrap_or(0),
        }
    }

    pub fn stats(&self) -> &AudioJitterStats {
        &self.stats
    }

    pub fn reset(&mut self) {
        self.packets.clear();
        self.next_sequence = None;
        self.playout_started = false;
        self.buffered_bytes = 0;
    }

    fn evict_oldest(&mut self) -> bool {
        let sequence = match self.packets.keys().next().copied() {
            Some(sequence) => sequence,
            None => return false,
        };
        if let Some(packet) = self.packets.remove(&sequence) {
            self.buffered_bytes = self
                .buffered_bytes
                .saturating_sub(packet.packet.payload.len());
            if self.next_sequence == Some(sequence) {
                self.next_sequence = sequence.checked_add(1);
            }
            self.stats.evicted_packets = self.stats.evicted_packets.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn discard_expired(&mut self, now: Instant) {
        let expired: Vec<u64> = self
            .packets
            .iter()
            .filter_map(|(sequence, packet)| {
                if now.saturating_duration_since(packet.arrived_at) >= self.config.max_packet_age {
                    Some(*sequence)
                } else {
                    None
                }
            })
            .collect();
        for sequence in expired {
            if let Some(packet) = self.packets.remove(&sequence) {
                self.buffered_bytes = self
                    .buffered_bytes
                    .saturating_sub(packet.packet.payload.len());
                self.stats.late_packets = self.stats.late_packets.saturating_add(1);
            }
        }
    }
}

fn validate_metadata(metadata: AudioPacketMetadata) -> Result<(), AudioDatagramError> {
    if metadata.sequence_number == 0 {
        return Err(AudioDatagramError::ZeroSequence);
    }
    if metadata.channels == 0 || metadata.channels > 8 {
        return Err(AudioDatagramError::InvalidChannelCount(metadata.channels));
    }
    if !(8_000..=192_000).contains(&metadata.sample_rate_hz) {
        return Err(AudioDatagramError::InvalidSampleRate(
            metadata.sample_rate_hz,
        ));
    }
    Ok(())
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

    fn metadata(sequence_number: u64) -> AudioPacketMetadata {
        AudioPacketMetadata {
            sequence_number,
            capture_timestamp_us: sequence_number * 20_000,
            codec: AudioCodec::Opus,
            channels: 2,
            sample_rate_hz: 48_000,
        }
    }

    fn packet(sequence_number: u64) -> AudioPacket {
        AudioPacket {
            metadata: metadata(sequence_number),
            payload: vec![sequence_number as u8; 20],
        }
    }

    #[test]
    fn audio_datagram_round_trip() {
        let datagram = encode_audio_datagram([3; 16], 7, metadata(5), &[1, 2, 3], 1200).unwrap();
        assert_eq!(
            decode_audio_datagram(&datagram).unwrap(),
            AudioPacket {
                metadata: metadata(5),
                payload: vec![1, 2, 3],
            }
        );
    }

    #[test]
    fn jitter_buffer_orders_packets_and_detects_duplicate() {
        let now = Instant::now();
        let mut buffer = AudioJitterBuffer::new(AudioJitterConfig::default()).unwrap();
        assert!(buffer.push(packet(2), now).unwrap());
        assert!(buffer.push(packet(1), now).unwrap());
        assert!(!buffer.push(packet(1), now).unwrap());
        assert!(buffer.push(packet(3), now).unwrap());
        assert_eq!(
            buffer.pop_ready(now),
            Some(AudioPlayoutItem::Packet(packet(1)))
        );
        assert_eq!(buffer.stats().duplicate_packets, 1);
    }

    #[test]
    fn missing_packet_produces_loss_concealment_event() {
        let now = Instant::now();
        let mut buffer = AudioJitterBuffer::new(AudioJitterConfig {
            start_packets: 2,
            ..AudioJitterConfig::default()
        })
        .unwrap();
        buffer.push(packet(1), now).unwrap();
        buffer.push(packet(3), now).unwrap();
        assert_eq!(
            buffer.pop_ready(now),
            Some(AudioPlayoutItem::Packet(packet(1)))
        );
        assert_eq!(buffer.pop_ready(now), None);
        assert_eq!(
            buffer.pop_ready(now + Duration::from_millis(31)),
            Some(AudioPlayoutItem::PacketLoss { sequence_number: 2 })
        );
    }

    #[test]
    fn late_packet_is_discarded() {
        let now = Instant::now();
        let mut buffer = AudioJitterBuffer::new(AudioJitterConfig {
            start_packets: 1,
            ..AudioJitterConfig::default()
        })
        .unwrap();
        buffer.push(packet(1), now).unwrap();
        buffer.pop_ready(now);
        assert!(!buffer.push(packet(1), now).unwrap());
        assert_eq!(buffer.stats().late_packets, 1);
    }

    #[test]
    fn queue_is_bounded_and_exposes_drift_state() {
        let now = Instant::now();
        let mut buffer = AudioJitterBuffer::new(AudioJitterConfig {
            max_packets: 2,
            start_packets: 2,
            ..AudioJitterConfig::default()
        })
        .unwrap();
        buffer.push(packet(1), now).unwrap();
        buffer.push(packet(2), now).unwrap();
        buffer.push(packet(3), now).unwrap();
        assert_eq!(buffer.state().queue_depth, 2);
        assert_eq!(buffer.state().buffered_capture_span_us, 20_000);
        assert_eq!(buffer.stats().evicted_packets, 1);
    }

    #[test]
    fn oversized_audio_packet_is_rejected() {
        assert_eq!(
            encode_audio_datagram([3; 16], 7, metadata(1), &[1; 2000], 1200),
            Err(AudioDatagramError::DatagramTooSmall(1200))
        );
    }

    #[test]
    fn malicious_sequence_jump_is_rejected() {
        let now = Instant::now();
        let mut buffer = AudioJitterBuffer::new(AudioJitterConfig::default()).unwrap();
        buffer.push(packet(1), now).unwrap();
        assert_eq!(
            buffer.push(packet(MAX_AUDIO_SEQUENCE_AHEAD + 2), now),
            Err(AudioDatagramError::SequenceGap)
        );
    }
}
