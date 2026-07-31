use super::{
    protocol::{
        decode_message, encode_message, ChannelId, MessageHeader, MessageType, SessionId,
        HEADER_LEN, PROTOCOL_VERSION,
    },
    quic::QuicTransportError,
};
use quinn::{Connection, RecvStream, SendStream};
use std::convert::{TryFrom, TryInto};
use tokio::io::AsyncReadExt;

const STREAM_MAGIC: u32 = 0x5241_5153;
const STREAM_PREFACE_LEN: usize = 8;
const MAX_CONTROL_STREAM_MESSAGE: usize = HEADER_LEN + 32 * 1024 * 1024;
const MAX_CLIPBOARD_STREAM_MESSAGE: usize = HEADER_LEN + 16 * 1024 * 1024;
const MAX_FILE_STREAM_MESSAGE: usize = HEADER_LEN + 1024 * 1024;
const MAX_INPUT_STREAM_MESSAGE: usize = HEADER_LEN + 4 * 1024;
const MAX_DIAGNOSTICS_STREAM_MESSAGE: usize = HEADER_LEN + 64 * 1024;
const MAX_VIDEO_STREAM_MESSAGE: usize = HEADER_LEN + 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReliableChannelKind {
    Control,
    Input,
    Clipboard,
    FileTransfer,
    Diagnostics,
    Video,
}

impl ReliableChannelKind {
    pub fn channel_id(self) -> ChannelId {
        match self {
            Self::Control => ChannelId::Control,
            Self::Input => ChannelId::ReliableInput,
            Self::Clipboard => ChannelId::Clipboard,
            Self::FileTransfer => ChannelId::FileTransfer,
            Self::Diagnostics => ChannelId::Diagnostics,
            Self::Video => ChannelId::ReliableVideo,
        }
    }

    fn priority(self) -> i32 {
        match self {
            Self::Control => 1_000,
            Self::Input => 900,
            Self::Clipboard => 200,
            Self::FileTransfer => 100,
            Self::Diagnostics => 0,
            Self::Video => 700,
        }
    }

    fn max_message_size(self) -> usize {
        match self {
            Self::Control => MAX_CONTROL_STREAM_MESSAGE,
            Self::Input => MAX_INPUT_STREAM_MESSAGE,
            Self::Clipboard => MAX_CLIPBOARD_STREAM_MESSAGE,
            Self::FileTransfer => MAX_FILE_STREAM_MESSAGE,
            Self::Diagnostics => MAX_DIAGNOSTICS_STREAM_MESSAGE,
            Self::Video => MAX_VIDEO_STREAM_MESSAGE,
        }
    }
}

impl TryFrom<ChannelId> for ReliableChannelKind {
    type Error = QuicTransportError;

    fn try_from(channel: ChannelId) -> Result<Self, Self::Error> {
        match channel {
            ChannelId::Control => Ok(Self::Control),
            ChannelId::ReliableInput => Ok(Self::Input),
            ChannelId::Clipboard => Ok(Self::Clipboard),
            ChannelId::FileTransfer => Ok(Self::FileTransfer),
            ChannelId::Diagnostics => Ok(Self::Diagnostics),
            ChannelId::ReliableVideo => Ok(Self::Video),
            _ => Err(QuicTransportError::ProtocolState(format!(
                "channel {channel:?} is not a reliable application stream"
            ))),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReliableMessage {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

pub struct ReliableChannel {
    send: SendStream,
    receive: RecvStream,
    kind: ReliableChannelKind,
    session_id: SessionId,
    next_outgoing_sequence: u64,
    last_incoming_sequence: u64,
}

pub struct ReliableChannelSender {
    send: SendStream,
    kind: ReliableChannelKind,
    session_id: SessionId,
    next_outgoing_sequence: u64,
}

pub struct ReliableChannelReceiver {
    receive: RecvStream,
    kind: ReliableChannelKind,
    session_id: SessionId,
    last_incoming_sequence: u64,
}

impl ReliableChannel {
    pub async fn open(
        connection: &Connection,
        kind: ReliableChannelKind,
        session_id: SessionId,
    ) -> Result<Self, QuicTransportError> {
        let (mut send, receive) = connection
            .open_bi()
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        send.set_priority(kind.priority())
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        send.write_all(&encode_stream_preface(kind))
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        Ok(Self::new(send, receive, kind, session_id))
    }

    pub async fn accept(
        connection: &Connection,
        session_id: SessionId,
    ) -> Result<Self, QuicTransportError> {
        let (send, mut receive) = connection
            .accept_bi()
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        let mut preface = [0u8; STREAM_PREFACE_LEN];
        receive
            .read_exact(&mut preface)
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        let kind = decode_stream_preface(&preface)?;
        send.set_priority(kind.priority())
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        Ok(Self::new(send, receive, kind, session_id))
    }

    pub fn kind(&self) -> ReliableChannelKind {
        self.kind
    }

    pub fn into_split(self) -> (ReliableChannelSender, ReliableChannelReceiver) {
        (
            ReliableChannelSender {
                send: self.send,
                kind: self.kind,
                session_id: self.session_id,
                next_outgoing_sequence: self.next_outgoing_sequence,
            },
            ReliableChannelReceiver {
                receive: self.receive,
                kind: self.kind,
                session_id: self.session_id,
                last_incoming_sequence: self.last_incoming_sequence,
            },
        )
    }

    pub async fn send(
        &mut self,
        message_type: MessageType,
        flags: u16,
        monotonic_timestamp_us: u64,
        payload: &[u8],
    ) -> Result<u64, QuicTransportError> {
        if message_type.channel() != self.kind.channel_id() {
            return Err(QuicTransportError::ProtocolState(format!(
                "message {message_type:?} is invalid on {:?}",
                self.kind
            )));
        }
        let sequence = self.next_outgoing_sequence;
        self.next_outgoing_sequence = sequence.checked_add(1).ok_or_else(|| {
            QuicTransportError::ProtocolState("reliable sequence exhausted".to_owned())
        })?;
        let header = MessageHeader::new(
            message_type,
            flags,
            self.session_id,
            sequence,
            payload.len(),
            monotonic_timestamp_us,
        )?;
        let message = encode_message(&header, payload)?;
        if message.len() > self.kind.max_message_size() {
            return Err(QuicTransportError::ProtocolState(format!(
                "reliable {:?} message exceeds {} bytes",
                self.kind,
                self.kind.max_message_size()
            )));
        }
        let length = u32::try_from(message.len()).map_err(|_| {
            QuicTransportError::ProtocolState("reliable message length overflow".to_owned())
        })?;
        self.send
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        self.send
            .write_all(&message)
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        Ok(sequence)
    }

    pub async fn receive(&mut self) -> Result<ReliableMessage, QuicTransportError> {
        let length = self
            .receive
            .read_u32()
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?
            as usize;
        if length < HEADER_LEN || length > self.kind.max_message_size() {
            return Err(QuicTransportError::ProtocolState(format!(
                "invalid reliable {:?} message length {length}",
                self.kind
            )));
        }
        let mut encoded = vec![0u8; length];
        self.receive
            .read_exact(&mut encoded)
            .await
            .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
        let parsed = decode_message(&encoded)?;
        if parsed.header.channel != self.kind.channel_id()
            || parsed.header.session_id != self.session_id
        {
            return Err(QuicTransportError::ProtocolState(
                "reliable message channel or session changed".to_owned(),
            ));
        }
        if parsed.header.sequence_number <= self.last_incoming_sequence {
            return Err(QuicTransportError::ProtocolState(
                "duplicate or out-of-order reliable sequence".to_owned(),
            ));
        }
        self.last_incoming_sequence = parsed.header.sequence_number;
        Ok(ReliableMessage {
            header: parsed.header,
            payload: parsed.payload.to_vec(),
        })
    }

    pub fn finish(&mut self) -> Result<(), QuicTransportError> {
        self.send
            .finish()
            .map_err(|error| QuicTransportError::Stream(error.to_string()))
    }

    fn new(
        send: SendStream,
        receive: RecvStream,
        kind: ReliableChannelKind,
        session_id: SessionId,
    ) -> Self {
        Self {
            send,
            receive,
            kind,
            session_id,
            next_outgoing_sequence: 1,
            last_incoming_sequence: 0,
        }
    }
}

impl ReliableChannelSender {
    pub fn kind(&self) -> ReliableChannelKind {
        self.kind
    }

    pub async fn send(
        &mut self,
        message_type: MessageType,
        flags: u16,
        monotonic_timestamp_us: u64,
        payload: &[u8],
    ) -> Result<u64, QuicTransportError> {
        send_reliable(
            &mut self.send,
            self.kind,
            self.session_id,
            &mut self.next_outgoing_sequence,
            message_type,
            flags,
            monotonic_timestamp_us,
            payload,
        )
        .await
    }

    pub fn finish(&mut self) -> Result<(), QuicTransportError> {
        self.send
            .finish()
            .map_err(|error| QuicTransportError::Stream(error.to_string()))
    }
}

impl ReliableChannelReceiver {
    pub fn kind(&self) -> ReliableChannelKind {
        self.kind
    }

    pub async fn receive(&mut self) -> Result<ReliableMessage, QuicTransportError> {
        receive_reliable(
            &mut self.receive,
            self.kind,
            self.session_id,
            &mut self.last_incoming_sequence,
        )
        .await
    }
}

async fn send_reliable(
    send: &mut SendStream,
    kind: ReliableChannelKind,
    session_id: SessionId,
    next_outgoing_sequence: &mut u64,
    message_type: MessageType,
    flags: u16,
    monotonic_timestamp_us: u64,
    payload: &[u8],
) -> Result<u64, QuicTransportError> {
    if message_type.channel() != kind.channel_id() {
        return Err(QuicTransportError::ProtocolState(format!(
            "message {message_type:?} is invalid on {kind:?}"
        )));
    }
    let sequence = *next_outgoing_sequence;
    *next_outgoing_sequence = sequence.checked_add(1).ok_or_else(|| {
        QuicTransportError::ProtocolState("reliable sequence exhausted".to_owned())
    })?;
    let header = MessageHeader::new(
        message_type,
        flags,
        session_id,
        sequence,
        payload.len(),
        monotonic_timestamp_us,
    )?;
    let message = encode_message(&header, payload)?;
    if message.len() > kind.max_message_size() {
        return Err(QuicTransportError::ProtocolState(format!(
            "reliable {kind:?} message exceeds {} bytes",
            kind.max_message_size()
        )));
    }
    let length = u32::try_from(message.len()).map_err(|_| {
        QuicTransportError::ProtocolState("reliable message length overflow".to_owned())
    })?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    send.write_all(&message)
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    Ok(sequence)
}

async fn receive_reliable(
    receive: &mut RecvStream,
    kind: ReliableChannelKind,
    session_id: SessionId,
    last_incoming_sequence: &mut u64,
) -> Result<ReliableMessage, QuicTransportError> {
    let length = receive
        .read_u32()
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))? as usize;
    if length < HEADER_LEN || length > kind.max_message_size() {
        return Err(QuicTransportError::ProtocolState(format!(
            "invalid reliable {kind:?} message length {length}"
        )));
    }
    let mut encoded = vec![0u8; length];
    receive
        .read_exact(&mut encoded)
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    let parsed = decode_message(&encoded)?;
    if parsed.header.channel != kind.channel_id() || parsed.header.session_id != session_id {
        return Err(QuicTransportError::ProtocolState(
            "reliable message channel or session changed".to_owned(),
        ));
    }
    if parsed.header.sequence_number <= *last_incoming_sequence {
        return Err(QuicTransportError::ProtocolState(
            "duplicate or out-of-order reliable sequence".to_owned(),
        ));
    }
    *last_incoming_sequence = parsed.header.sequence_number;
    Ok(ReliableMessage {
        header: parsed.header,
        payload: parsed.payload.to_vec(),
    })
}

fn encode_stream_preface(kind: ReliableChannelKind) -> [u8; STREAM_PREFACE_LEN] {
    let mut preface = [0u8; STREAM_PREFACE_LEN];
    preface[..4].copy_from_slice(&STREAM_MAGIC.to_be_bytes());
    preface[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    preface[6] = kind.channel_id() as u8;
    preface
}

fn decode_stream_preface(
    preface: &[u8; STREAM_PREFACE_LEN],
) -> Result<ReliableChannelKind, QuicTransportError> {
    let magic = u32::from_be_bytes(preface[..4].try_into().unwrap());
    let version = u16::from_be_bytes(preface[4..6].try_into().unwrap());
    if magic != STREAM_MAGIC || version != PROTOCOL_VERSION || preface[7] != 0 {
        return Err(QuicTransportError::ProtocolState(
            "invalid reliable stream preface".to_owned(),
        ));
    }
    let channel = ChannelId::try_from(preface[6])?;
    ReliableChannelKind::try_from(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_prefaces_round_trip() {
        for kind in [
            ReliableChannelKind::Control,
            ReliableChannelKind::Input,
            ReliableChannelKind::Clipboard,
            ReliableChannelKind::FileTransfer,
            ReliableChannelKind::Diagnostics,
            ReliableChannelKind::Video,
        ] {
            assert_eq!(
                decode_stream_preface(&encode_stream_preface(kind)).unwrap(),
                kind
            );
        }
    }

    #[test]
    fn rejects_datagram_stream_prefaces() {
        for channel in [
            ChannelId::VideoDatagram,
            ChannelId::AudioDatagram,
            ChannelId::MouseDatagram,
        ] {
            let mut preface = encode_stream_preface(ReliableChannelKind::Input);
            preface[6] = channel as u8;
            assert!(decode_stream_preface(&preface).is_err());
        }
    }
}
