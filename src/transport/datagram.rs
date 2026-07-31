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
        VideoReassemblyConfig, VideoReassemblyOutcome, VideoReassemblyStats,
    },
};
use bytes::Bytes;
use quinn::Connection;
use std::time::Instant;

pub struct QuicDatagramSender {
    connection: Connection,
    session_id: SessionId,
    next_video_sequence: u64,
    next_audio_sequence: u64,
    next_mouse_sequence: u64,
    started: Instant,
    negotiated_max_datagram_size: usize,
}

impl QuicDatagramSender {
    pub fn new(connection: Connection, session_id: SessionId) -> Self {
        Self {
            connection,
            session_id,
            next_video_sequence: 1,
            next_audio_sequence: 1,
            next_mouse_sequence: 1,
            started: Instant::now(),
            negotiated_max_datagram_size: usize::MAX,
        }
    }

    pub fn with_max_datagram_size(mut self, max_datagram_size: usize) -> Self {
        self.negotiated_max_datagram_size = max_datagram_size;
        self
    }

    pub fn send_video_frame(
        &mut self,
        metadata: VideoFrameMetadata,
        encoded_frame: &[u8],
    ) -> Result<usize, QuicTransportError> {
        let max_datagram_size = self.max_datagram_size()?;
        let fragments = fragment_video_frame(
            self.session_id,
            self.next_video_sequence,
            elapsed_us(self.started),
            metadata,
            encoded_frame,
            max_datagram_size,
        )?;
        self.next_video_sequence = self
            .next_video_sequence
            .checked_add(fragments.len() as u64)
            .ok_or_else(|| {
                QuicTransportError::ProtocolState("video sequence exhausted".to_owned())
            })?;
        let fragment_count = fragments.len();
        for fragment in fragments {
            self.connection
                .send_datagram(Bytes::from(fragment))
                .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        }
        Ok(fragment_count)
    }

    pub fn send_audio_packet(
        &mut self,
        capture_timestamp_us: u64,
        codec: AudioCodec,
        channels: u8,
        sample_rate_hz: u32,
        encoded_audio: &[u8],
    ) -> Result<u64, QuicTransportError> {
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
        self.connection
            .send_datagram(Bytes::from(datagram))
            .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        self.next_audio_sequence = sequence.checked_add(1).ok_or_else(|| {
            QuicTransportError::ProtocolState("audio sequence exhausted".to_owned())
        })?;
        Ok(sequence)
    }

    pub fn send_mouse_movement(
        &mut self,
        mode: MouseMovementMode,
        x: i32,
        y: i32,
        display_id: u32,
        button_state_mask: u16,
    ) -> Result<u64, QuicTransportError> {
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
        self.connection
            .send_datagram(Bytes::from(datagram))
            .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        self.next_mouse_sequence = sequence.checked_add(1).ok_or_else(|| {
            QuicTransportError::ProtocolState("mouse sequence exhausted".to_owned())
        })?;
        Ok(sequence)
    }

    pub fn send_application_mouse_movement(
        &mut self,
        mode: MouseMovementMode,
        x: i32,
        y: i32,
        display_id: u32,
        button_state_mask: u16,
        application_payload: &[u8],
    ) -> Result<u64, QuicTransportError> {
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
        self.connection
            .send_datagram(Bytes::from(datagram))
            .map_err(|error| QuicTransportError::Datagram(error.to_string()))?;
        self.next_mouse_sequence = sequence.checked_add(1).ok_or_else(|| {
            QuicTransportError::ProtocolState("mouse sequence exhausted".to_owned())
        })?;
        Ok(sequence)
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
