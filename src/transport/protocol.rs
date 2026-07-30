use std::convert::TryFrom;

pub const MAGIC: u32 = 0x5241_5131;
pub const PROTOCOL_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 48;
pub const FLAG_ACK_REQUIRED: u16 = 1 << 0;
pub const FLAG_RESPONSE: u16 = 1 << 1;
pub const KNOWN_FLAGS: u16 = FLAG_ACK_REQUIRED | FLAG_RESPONSE;

pub type SessionId = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChannelId {
    Control = 1,
    ReliableInput = 2,
    Clipboard = 3,
    FileTransfer = 4,
    Diagnostics = 5,
    VideoDatagram = 16,
    AudioDatagram = 17,
    MouseDatagram = 18,
}

impl TryFrom<u8> for ChannelId {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::ReliableInput),
            3 => Ok(Self::Clipboard),
            4 => Ok(Self::FileTransfer),
            5 => Ok(Self::Diagnostics),
            16 => Ok(Self::VideoDatagram),
            17 => Ok(Self::AudioDatagram),
            18 => Ok(Self::MouseDatagram),
            _ => Err(ProtocolError::UnknownChannel(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MessageType {
    ClientHello = 1,
    ServerHello = 2,
    Ping = 3,
    Pong = 4,
    Error = 5,
    KeyframeRequest = 6,
    SessionClose = 7,
    SessionOffer = 8,
    SessionAccept = 9,
    ApplicationControl = 10,
    ApplicationRaw = 11,
    VideoOrdering = 12,
    VideoOrderingAck = 13,
    ReliableInput = 16,
    Clipboard = 32,
    FileMetadata = 48,
    FileChunk = 49,
    FileCancel = 50,
    Diagnostics = 64,
    VideoFragment = 128,
    AudioPacket = 129,
    MouseMovement = 130,
}

impl TryFrom<u16> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::Ping),
            4 => Ok(Self::Pong),
            5 => Ok(Self::Error),
            6 => Ok(Self::KeyframeRequest),
            7 => Ok(Self::SessionClose),
            8 => Ok(Self::SessionOffer),
            9 => Ok(Self::SessionAccept),
            10 => Ok(Self::ApplicationControl),
            11 => Ok(Self::ApplicationRaw),
            12 => Ok(Self::VideoOrdering),
            13 => Ok(Self::VideoOrderingAck),
            16 => Ok(Self::ReliableInput),
            32 => Ok(Self::Clipboard),
            48 => Ok(Self::FileMetadata),
            49 => Ok(Self::FileChunk),
            50 => Ok(Self::FileCancel),
            64 => Ok(Self::Diagnostics),
            128 => Ok(Self::VideoFragment),
            129 => Ok(Self::AudioPacket),
            130 => Ok(Self::MouseMovement),
            _ => Err(ProtocolError::UnknownMessageType(value)),
        }
    }
}

impl MessageType {
    pub fn channel(self) -> ChannelId {
        match self {
            Self::ClientHello
            | Self::ServerHello
            | Self::Ping
            | Self::Pong
            | Self::Error
            | Self::KeyframeRequest
            | Self::SessionClose
            | Self::SessionOffer
            | Self::SessionAccept
            | Self::ApplicationControl
            | Self::ApplicationRaw
            | Self::VideoOrdering
            | Self::VideoOrderingAck => ChannelId::Control,
            Self::ReliableInput => ChannelId::ReliableInput,
            Self::Clipboard => ChannelId::Clipboard,
            Self::FileMetadata | Self::FileChunk | Self::FileCancel => ChannelId::FileTransfer,
            Self::Diagnostics => ChannelId::Diagnostics,
            Self::VideoFragment => ChannelId::VideoDatagram,
            Self::AudioPacket => ChannelId::AudioDatagram,
            Self::MouseMovement => ChannelId::MouseDatagram,
        }
    }

    pub fn max_payload_len(self) -> usize {
        match self {
            Self::ClientHello | Self::ServerHello => 512,
            Self::Ping | Self::Pong => 64,
            Self::Error | Self::SessionClose => 16 * 1024,
            Self::SessionOffer | Self::SessionAccept => 4 * 1024,
            Self::ApplicationControl | Self::ApplicationRaw => 32 * 1024 * 1024,
            Self::VideoOrdering => 1024 * 1024,
            Self::VideoOrderingAck => 8,
            Self::KeyframeRequest => 64,
            Self::ReliableInput => 4 * 1024,
            Self::Clipboard => 16 * 1024 * 1024,
            Self::FileMetadata => 64 * 1024,
            Self::FileChunk => 1024 * 1024,
            Self::FileCancel => 4 * 1024,
            Self::Diagnostics => 64 * 1024,
            Self::VideoFragment | Self::AudioPacket | Self::MouseMovement => 64 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    pub message_type: MessageType,
    pub flags: u16,
    pub channel: ChannelId,
    pub session_id: SessionId,
    pub sequence_number: u64,
    pub payload_length: u32,
    pub monotonic_timestamp_us: u64,
}

impl MessageHeader {
    pub fn new(
        message_type: MessageType,
        flags: u16,
        session_id: SessionId,
        sequence_number: u64,
        payload_length: usize,
        monotonic_timestamp_us: u64,
    ) -> Result<Self, ProtocolError> {
        validate_fields(
            message_type,
            flags,
            message_type.channel(),
            &session_id,
            sequence_number,
            payload_length,
        )?;
        let payload_length = u32::try_from(payload_length)
            .map_err(|_| ProtocolError::PayloadTooLarge(payload_length))?;
        Ok(Self {
            message_type,
            flags,
            channel: message_type.channel(),
            session_id,
            sequence_number,
            payload_length,
            monotonic_timestamp_us,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParsedMessage<'a> {
    pub header: MessageHeader,
    pub payload: &'a [u8],
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("packet is shorter than the protocol header")]
    HeaderTruncated,
    #[error("invalid protocol magic 0x{0:08x}")]
    InvalidMagic(u32),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("unknown message type {0}")]
    UnknownMessageType(u16),
    #[error("unknown channel {0}")]
    UnknownChannel(u8),
    #[error("unknown protocol flags 0x{0:04x}")]
    UnknownFlags(u16),
    #[error("reserved protocol header byte is not zero")]
    ReservedByte,
    #[error("message type {message_type:?} is invalid on channel {channel:?}")]
    ChannelMismatch {
        message_type: MessageType,
        channel: ChannelId,
    },
    #[error("session identifier must not be all zero")]
    ZeroSessionId,
    #[error("sequence number must not be zero")]
    ZeroSequence,
    #[error("payload length {0} exceeds its message limit")]
    PayloadTooLarge(usize),
    #[error("packet length does not match the declared payload length")]
    LengthMismatch,
}

pub fn encode_message(header: &MessageHeader, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    validate_fields(
        header.message_type,
        header.flags,
        header.channel,
        &header.session_id,
        header.sequence_number,
        payload.len(),
    )?;
    if header.payload_length as usize != payload.len() {
        return Err(ProtocolError::LengthMismatch);
    }

    let mut output = Vec::with_capacity(HEADER_LEN + payload.len());
    output.extend_from_slice(&MAGIC.to_be_bytes());
    output.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    output.extend_from_slice(&(header.message_type as u16).to_be_bytes());
    output.extend_from_slice(&header.flags.to_be_bytes());
    output.push(header.channel as u8);
    output.push(0);
    output.extend_from_slice(&header.session_id);
    output.extend_from_slice(&header.sequence_number.to_be_bytes());
    output.extend_from_slice(&header.payload_length.to_be_bytes());
    output.extend_from_slice(&header.monotonic_timestamp_us.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_message(packet: &[u8]) -> Result<ParsedMessage<'_>, ProtocolError> {
    if packet.len() < HEADER_LEN {
        return Err(ProtocolError::HeaderTruncated);
    }

    let header = decode_header(&packet[..HEADER_LEN])?;
    let expected_len = HEADER_LEN
        .checked_add(header.payload_length as usize)
        .ok_or(ProtocolError::PayloadTooLarge(
            header.payload_length as usize,
        ))?;
    if packet.len() != expected_len {
        return Err(ProtocolError::LengthMismatch);
    }

    Ok(ParsedMessage {
        header,
        payload: &packet[HEADER_LEN..],
    })
}

pub fn decode_header(packet: &[u8]) -> Result<MessageHeader, ProtocolError> {
    if packet.len() != HEADER_LEN {
        return Err(ProtocolError::HeaderTruncated);
    }

    let magic = read_u32(packet, 0);
    if magic != MAGIC {
        return Err(ProtocolError::InvalidMagic(magic));
    }
    let version = read_u16(packet, 4);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let message_type = MessageType::try_from(read_u16(packet, 6))?;
    let flags = read_u16(packet, 8);
    let channel = ChannelId::try_from(packet[10])?;
    if packet[11] != 0 {
        return Err(ProtocolError::ReservedByte);
    }
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&packet[12..28]);
    let sequence_number = read_u64(packet, 28);
    let payload_length = read_u32(packet, 36);
    let monotonic_timestamp_us = read_u64(packet, 40);
    validate_fields(
        message_type,
        flags,
        channel,
        &session_id,
        sequence_number,
        payload_length as usize,
    )?;

    Ok(MessageHeader {
        message_type,
        flags,
        channel,
        session_id,
        sequence_number,
        payload_length,
        monotonic_timestamp_us,
    })
}

fn validate_fields(
    message_type: MessageType,
    flags: u16,
    channel: ChannelId,
    session_id: &SessionId,
    sequence_number: u64,
    payload_length: usize,
) -> Result<(), ProtocolError> {
    if flags & !KNOWN_FLAGS != 0 {
        return Err(ProtocolError::UnknownFlags(flags & !KNOWN_FLAGS));
    }
    if channel != message_type.channel() {
        return Err(ProtocolError::ChannelMismatch {
            message_type,
            channel,
        });
    }
    if session_id.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::ZeroSessionId);
    }
    if sequence_number == 0 {
        return Err(ProtocolError::ZeroSequence);
    }
    if payload_length > message_type.max_payload_len() {
        return Err(ProtocolError::PayloadTooLarge(payload_length));
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_id() -> SessionId {
        [7; 16]
    }

    fn ping(payload_len: usize) -> (MessageHeader, Vec<u8>) {
        let payload = vec![3; payload_len];
        let header = MessageHeader::new(
            MessageType::Ping,
            FLAG_ACK_REQUIRED,
            session_id(),
            9,
            payload.len(),
            123,
        )
        .unwrap();
        (header, payload)
    }

    #[test]
    fn protocol_header_is_fixed_width_and_round_trips() {
        let (header, payload) = ping(8);
        let encoded = encode_message(&header, &payload).unwrap();
        assert_eq!(encoded.len(), HEADER_LEN + payload.len());

        let parsed = decode_message(&encoded).unwrap();
        assert_eq!(parsed.header, header);
        assert_eq!(parsed.payload, payload.as_slice());
    }

    #[test]
    fn rejects_version_flags_channel_and_reserved_byte() {
        let (header, payload) = ping(8);
        let encoded = encode_message(&header, &payload).unwrap();

        let mut invalid = encoded.clone();
        invalid[5] = 2;
        assert_eq!(
            decode_message(&invalid),
            Err(ProtocolError::UnsupportedVersion(2))
        );

        let mut invalid = encoded.clone();
        invalid[8] = 0x80;
        assert_eq!(
            decode_message(&invalid),
            Err(ProtocolError::UnknownFlags(0x8000))
        );

        let mut invalid = encoded.clone();
        invalid[10] = ChannelId::Diagnostics as u8;
        assert_eq!(
            decode_message(&invalid),
            Err(ProtocolError::ChannelMismatch {
                message_type: MessageType::Ping,
                channel: ChannelId::Diagnostics,
            })
        );

        let mut invalid = encoded;
        invalid[11] = 1;
        assert_eq!(decode_message(&invalid), Err(ProtocolError::ReservedByte));
    }

    #[test]
    fn rejects_zero_session_zero_sequence_and_length_mismatch() {
        assert_eq!(
            MessageHeader::new(MessageType::Ping, 0, [0; 16], 1, 0, 0),
            Err(ProtocolError::ZeroSessionId)
        );
        assert_eq!(
            MessageHeader::new(MessageType::Ping, 0, session_id(), 0, 0, 0),
            Err(ProtocolError::ZeroSequence)
        );

        let (header, payload) = ping(8);
        let mut encoded = encode_message(&header, &payload).unwrap();
        encoded.push(0);
        assert_eq!(decode_message(&encoded), Err(ProtocolError::LengthMismatch));
    }

    #[test]
    fn enforces_per_message_payload_limits_before_allocation() {
        assert_eq!(
            MessageHeader::new(MessageType::Ping, 0, session_id(), 1, 65, 0),
            Err(ProtocolError::PayloadTooLarge(65))
        );

        let (mut header, payload) = ping(8);
        header.payload_length = 65;
        assert_eq!(
            encode_message(&header, &payload),
            Err(ProtocolError::LengthMismatch)
        );
    }
}
