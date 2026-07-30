use super::{audio_datagram::AudioCodec, video_datagram::VideoCodec};
use std::{
    collections::BTreeSet,
    convert::{TryFrom, TryInto},
};

pub const SESSION_OFFER_HEADER_LEN: usize = 32;
pub const SESSION_AGREEMENT_LEN: usize = 28;
pub const SESSION_ACCEPTANCE_HEADER_LEN: usize = 4;
pub const MAX_OFFERED_VIDEO_CODECS: usize = 8;
pub const MAX_OFFERED_AUDIO_CODECS: usize = 4;
pub const COLOR_I420: u16 = 1 << 0;
pub const COLOR_I444: u16 = 1 << 1;
pub const COLOR_NV12: u16 = 1 << 2;
pub const COLOR_P010: u16 = 1 << 3;
pub const KNOWN_COLOR_FORMATS: u16 = COLOR_I420 | COLOR_I444 | COLOR_NV12 | COLOR_P010;
pub const CAP_HDR: u16 = 1 << 0;
pub const CAP_CLIPBOARD_SEND: u16 = 1 << 1;
pub const CAP_CLIPBOARD_RECEIVE: u16 = 1 << 2;
pub const CAP_FILE_TRANSFER: u16 = 1 << 3;
pub const CAP_INPUT_SEND: u16 = 1 << 4;
pub const CAP_INPUT_RECEIVE: u16 = 1 << 5;
pub const CAP_RELIABLE_KEYFRAMES: u16 = 1 << 6;
pub const KNOWN_CAPABILITIES: u16 = CAP_HDR
    | CAP_CLIPBOARD_SEND
    | CAP_CLIPBOARD_RECEIVE
    | CAP_FILE_TRANSFER
    | CAP_INPUT_SEND
    | CAP_INPUT_RECEIVE
    | CAP_RELIABLE_KEYFRAMES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LatencyMode {
    Balanced = 1,
    LowLatency = 2,
    Quality = 3,
}

impl TryFrom<u8> for LatencyMode {
    type Error = SessionNegotiationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Balanced),
            2 => Ok(Self::LowLatency),
            3 => Ok(Self::Quality),
            _ => Err(SessionNegotiationError::InvalidLatencyMode(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColorFormat {
    I420,
    I444,
    Nv12,
    P010,
}

impl TryFrom<u8> for ColorFormat {
    type Error = SessionNegotiationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::I420),
            2 => Ok(Self::I444),
            3 => Ok(Self::Nv12),
            4 => Ok(Self::P010),
            _ => Err(SessionNegotiationError::UnknownColorFormat(value)),
        }
    }
}

impl ColorFormat {
    fn mask(self) -> u16 {
        match self {
            Self::I420 => COLOR_I420,
            Self::I444 => COLOR_I444,
            Self::Nv12 => COLOR_NV12,
            Self::P010 => COLOR_P010,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionOffer {
    pub minimum_protocol_version: u16,
    pub maximum_protocol_version: u16,
    pub capabilities: u16,
    pub latency_mode: LatencyMode,
    pub video_codecs: Vec<VideoCodec>,
    pub audio_codecs: Vec<AudioCodec>,
    pub color_formats: u16,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u16,
    pub max_datagram_payload: u16,
    pub max_video_bitrate_kbps: u32,
    pub max_file_bitrate_kbps: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAgreement {
    pub protocol_version: u16,
    pub video_codec: VideoCodec,
    pub audio_codec: AudioCodec,
    pub color_format: ColorFormat,
    pub hdr: bool,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u16,
    pub max_datagram_payload: u16,
    pub max_video_bitrate_kbps: u32,
    pub max_file_bitrate_kbps: u32,
    pub latency_mode: LatencyMode,
    pub local_may_send_clipboard: bool,
    pub remote_may_send_clipboard: bool,
    pub file_transfer_enabled: bool,
    pub local_may_send_input: bool,
    pub remote_may_send_input: bool,
    pub reliable_keyframes: bool,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum SessionNegotiationError {
    #[error("session offer header is truncated")]
    HeaderTruncated,
    #[error("session offer length is invalid")]
    LengthMismatch,
    #[error("session offer flags or reserved fields are invalid")]
    InvalidReservedField,
    #[error("session offer protocol range is invalid")]
    InvalidProtocolRange,
    #[error("session peers have no compatible protocol version")]
    IncompatibleProtocol,
    #[error("session capability flags 0x{0:04x} are invalid")]
    InvalidCapabilities(u16),
    #[error("session color-format mask 0x{0:04x} is invalid")]
    InvalidColorFormats(u16),
    #[error("session video codec list is invalid")]
    InvalidVideoCodecs,
    #[error("session audio codec list is invalid")]
    InvalidAudioCodecs,
    #[error("session peers have no compatible video codec")]
    IncompatibleVideoCodec,
    #[error("session peers have no compatible audio codec")]
    IncompatibleAudioCodec,
    #[error("session peers have no compatible color format")]
    IncompatibleColorFormat,
    #[error("session geometry or frame-rate limit is invalid")]
    InvalidGeometry,
    #[error("session datagram payload limit is invalid")]
    InvalidDatagramSize,
    #[error("session bitrate limit is invalid")]
    InvalidBitrate,
    #[error("unknown video codec {0}")]
    UnknownVideoCodec(u8),
    #[error("unknown audio codec {0}")]
    UnknownAudioCodec(u8),
    #[error("unknown color format {0}")]
    UnknownColorFormat(u8),
    #[error("invalid latency mode {0}")]
    InvalidLatencyMode(u8),
    #[error("session agreement is invalid or exceeds the local offer")]
    InvalidAgreement,
}

pub fn encode_session_offer(offer: &SessionOffer) -> Result<Vec<u8>, SessionNegotiationError> {
    validate_offer(offer)?;
    let mut payload = Vec::with_capacity(
        SESSION_OFFER_HEADER_LEN + offer.video_codecs.len() + offer.audio_codecs.len(),
    );
    payload.extend_from_slice(&offer.minimum_protocol_version.to_be_bytes());
    payload.extend_from_slice(&offer.maximum_protocol_version.to_be_bytes());
    payload.extend_from_slice(&offer.capabilities.to_be_bytes());
    payload.push(offer.latency_mode as u8);
    payload.push(offer.video_codecs.len() as u8);
    payload.push(offer.audio_codecs.len() as u8);
    payload.push(0);
    payload.extend_from_slice(&offer.color_formats.to_be_bytes());
    payload.extend_from_slice(&offer.max_width.to_be_bytes());
    payload.extend_from_slice(&offer.max_height.to_be_bytes());
    payload.extend_from_slice(&offer.max_fps.to_be_bytes());
    payload.extend_from_slice(&offer.max_datagram_payload.to_be_bytes());
    payload.extend_from_slice(&offer.max_video_bitrate_kbps.to_be_bytes());
    payload.extend_from_slice(&offer.max_file_bitrate_kbps.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend(offer.video_codecs.iter().map(|codec| *codec as u8));
    payload.extend(offer.audio_codecs.iter().map(|codec| *codec as u8));
    Ok(payload)
}

pub fn decode_session_offer(payload: &[u8]) -> Result<SessionOffer, SessionNegotiationError> {
    if payload.len() < SESSION_OFFER_HEADER_LEN {
        return Err(SessionNegotiationError::HeaderTruncated);
    }
    if payload[9] != 0 || read_u16(payload, 28) != 0 || read_u16(payload, 30) != 0 {
        return Err(SessionNegotiationError::InvalidReservedField);
    }
    let video_count = payload[7] as usize;
    let audio_count = payload[8] as usize;
    if payload.len() != SESSION_OFFER_HEADER_LEN + video_count + audio_count {
        return Err(SessionNegotiationError::LengthMismatch);
    }
    let video_start = SESSION_OFFER_HEADER_LEN;
    let audio_start = video_start + video_count;
    let mut video_codecs = Vec::with_capacity(video_count);
    for value in &payload[video_start..audio_start] {
        video_codecs.push(
            VideoCodec::try_from(*value)
                .map_err(|_| SessionNegotiationError::UnknownVideoCodec(*value))?,
        );
    }
    let mut audio_codecs = Vec::with_capacity(audio_count);
    for value in &payload[audio_start..] {
        audio_codecs.push(
            AudioCodec::try_from(*value)
                .map_err(|_| SessionNegotiationError::UnknownAudioCodec(*value))?,
        );
    }
    let offer = SessionOffer {
        minimum_protocol_version: read_u16(payload, 0),
        maximum_protocol_version: read_u16(payload, 2),
        capabilities: read_u16(payload, 4),
        latency_mode: LatencyMode::try_from(payload[6])?,
        video_codecs,
        audio_codecs,
        color_formats: read_u16(payload, 10),
        max_width: read_u16(payload, 12),
        max_height: read_u16(payload, 14),
        max_fps: read_u16(payload, 16),
        max_datagram_payload: read_u16(payload, 18),
        max_video_bitrate_kbps: read_u32(payload, 20),
        max_file_bitrate_kbps: read_u32(payload, 24),
    };
    validate_offer(&offer)?;
    Ok(offer)
}

pub fn negotiate_session(
    local: &SessionOffer,
    remote: &SessionOffer,
) -> Result<SessionAgreement, SessionNegotiationError> {
    validate_offer(local)?;
    validate_offer(remote)?;
    let minimum_version = local
        .minimum_protocol_version
        .max(remote.minimum_protocol_version);
    let protocol_version = local
        .maximum_protocol_version
        .min(remote.maximum_protocol_version);
    if protocol_version < minimum_version {
        return Err(SessionNegotiationError::IncompatibleProtocol);
    }
    let video_codec = local
        .video_codecs
        .iter()
        .copied()
        .find(|codec| remote.video_codecs.contains(codec))
        .ok_or(SessionNegotiationError::IncompatibleVideoCodec)?;
    let audio_codec = local
        .audio_codecs
        .iter()
        .copied()
        .find(|codec| remote.audio_codecs.contains(codec))
        .ok_or(SessionNegotiationError::IncompatibleAudioCodec)?;
    let common_colors = local.color_formats & remote.color_formats;
    let hdr = local.capabilities & remote.capabilities & CAP_HDR != 0;
    let color_format = [
        (ColorFormat::P010, hdr),
        (ColorFormat::I444, true),
        (ColorFormat::Nv12, true),
        (ColorFormat::I420, true),
    ]
    .iter()
    .copied()
    .find_map(|(format, allowed)| (allowed && common_colors & format.mask() != 0).then_some(format))
    .ok_or(SessionNegotiationError::IncompatibleColorFormat)?;
    Ok(SessionAgreement {
        protocol_version,
        video_codec,
        audio_codec,
        color_format,
        hdr: hdr && color_format == ColorFormat::P010,
        max_width: local.max_width.min(remote.max_width),
        max_height: local.max_height.min(remote.max_height),
        max_fps: local.max_fps.min(remote.max_fps),
        max_datagram_payload: local.max_datagram_payload.min(remote.max_datagram_payload),
        max_video_bitrate_kbps: local
            .max_video_bitrate_kbps
            .min(remote.max_video_bitrate_kbps),
        max_file_bitrate_kbps: local
            .max_file_bitrate_kbps
            .min(remote.max_file_bitrate_kbps),
        latency_mode: if local.latency_mode == LatencyMode::LowLatency
            || remote.latency_mode == LatencyMode::LowLatency
        {
            LatencyMode::LowLatency
        } else {
            local.latency_mode
        },
        local_may_send_clipboard: local.capabilities & CAP_CLIPBOARD_SEND != 0
            && remote.capabilities & CAP_CLIPBOARD_RECEIVE != 0,
        remote_may_send_clipboard: remote.capabilities & CAP_CLIPBOARD_SEND != 0
            && local.capabilities & CAP_CLIPBOARD_RECEIVE != 0,
        file_transfer_enabled: local.capabilities & remote.capabilities & CAP_FILE_TRANSFER != 0,
        local_may_send_input: local.capabilities & CAP_INPUT_SEND != 0
            && remote.capabilities & CAP_INPUT_RECEIVE != 0,
        remote_may_send_input: remote.capabilities & CAP_INPUT_SEND != 0
            && local.capabilities & CAP_INPUT_RECEIVE != 0,
        reliable_keyframes: local.capabilities & remote.capabilities & CAP_RELIABLE_KEYFRAMES != 0,
    })
}

pub fn encode_session_agreement(
    agreement: &SessionAgreement,
) -> Result<[u8; SESSION_AGREEMENT_LEN], SessionNegotiationError> {
    validate_agreement_fields(agreement)?;
    let mut payload = [0u8; SESSION_AGREEMENT_LEN];
    payload[0..2].copy_from_slice(&agreement.protocol_version.to_be_bytes());
    payload[2] = agreement.video_codec as u8;
    payload[3] = agreement.audio_codec as u8;
    payload[4] = match agreement.color_format {
        ColorFormat::I420 => 1,
        ColorFormat::I444 => 2,
        ColorFormat::Nv12 => 3,
        ColorFormat::P010 => 4,
    };
    payload[5] = agreement.latency_mode as u8;
    payload[6..8].copy_from_slice(&agreement_flags(agreement).to_be_bytes());
    payload[8..10].copy_from_slice(&agreement.max_width.to_be_bytes());
    payload[10..12].copy_from_slice(&agreement.max_height.to_be_bytes());
    payload[12..14].copy_from_slice(&agreement.max_fps.to_be_bytes());
    payload[14..16].copy_from_slice(&agreement.max_datagram_payload.to_be_bytes());
    payload[16..20].copy_from_slice(&agreement.max_video_bitrate_kbps.to_be_bytes());
    payload[20..24].copy_from_slice(&agreement.max_file_bitrate_kbps.to_be_bytes());
    Ok(payload)
}

pub fn decode_session_agreement(
    payload: &[u8],
) -> Result<SessionAgreement, SessionNegotiationError> {
    if payload.len() != SESSION_AGREEMENT_LEN {
        return Err(SessionNegotiationError::LengthMismatch);
    }
    if read_u32(payload, 24) != 0 {
        return Err(SessionNegotiationError::InvalidReservedField);
    }
    let flags = read_u16(payload, 6);
    if flags & !KNOWN_CAPABILITIES != 0 {
        return Err(SessionNegotiationError::InvalidAgreement);
    }
    let color_format = ColorFormat::try_from(payload[4])?;
    let agreement = SessionAgreement {
        protocol_version: read_u16(payload, 0),
        video_codec: VideoCodec::try_from(payload[2])
            .map_err(|_| SessionNegotiationError::UnknownVideoCodec(payload[2]))?,
        audio_codec: AudioCodec::try_from(payload[3])
            .map_err(|_| SessionNegotiationError::UnknownAudioCodec(payload[3]))?,
        color_format,
        hdr: flags & CAP_HDR != 0,
        max_width: read_u16(payload, 8),
        max_height: read_u16(payload, 10),
        max_fps: read_u16(payload, 12),
        max_datagram_payload: read_u16(payload, 14),
        max_video_bitrate_kbps: read_u32(payload, 16),
        max_file_bitrate_kbps: read_u32(payload, 20),
        latency_mode: LatencyMode::try_from(payload[5])?,
        local_may_send_clipboard: flags & CAP_CLIPBOARD_SEND != 0,
        remote_may_send_clipboard: flags & CAP_CLIPBOARD_RECEIVE != 0,
        file_transfer_enabled: flags & CAP_FILE_TRANSFER != 0,
        local_may_send_input: flags & CAP_INPUT_SEND != 0,
        remote_may_send_input: flags & CAP_INPUT_RECEIVE != 0,
        reliable_keyframes: flags & CAP_RELIABLE_KEYFRAMES != 0,
    };
    validate_agreement_fields(&agreement)?;
    Ok(agreement)
}

pub fn validate_agreement_for_offer(
    agreement: &SessionAgreement,
    local_offer: &SessionOffer,
) -> Result<(), SessionNegotiationError> {
    validate_offer(local_offer)?;
    validate_agreement_fields(agreement)?;
    if !(local_offer.minimum_protocol_version..=local_offer.maximum_protocol_version)
        .contains(&agreement.protocol_version)
        || !local_offer.video_codecs.contains(&agreement.video_codec)
        || !local_offer.audio_codecs.contains(&agreement.audio_codec)
        || local_offer.color_formats & agreement.color_format.mask() == 0
        || agreement.max_width > local_offer.max_width
        || agreement.max_height > local_offer.max_height
        || agreement.max_fps > local_offer.max_fps
        || agreement.max_datagram_payload > local_offer.max_datagram_payload
        || agreement.max_video_bitrate_kbps > local_offer.max_video_bitrate_kbps
        || agreement.max_file_bitrate_kbps > local_offer.max_file_bitrate_kbps
        || (agreement.hdr && local_offer.capabilities & CAP_HDR == 0)
        || (agreement.local_may_send_clipboard
            && local_offer.capabilities & CAP_CLIPBOARD_SEND == 0)
        || (agreement.remote_may_send_clipboard
            && local_offer.capabilities & CAP_CLIPBOARD_RECEIVE == 0)
        || (agreement.file_transfer_enabled && local_offer.capabilities & CAP_FILE_TRANSFER == 0)
        || (agreement.local_may_send_input && local_offer.capabilities & CAP_INPUT_SEND == 0)
        || (agreement.remote_may_send_input && local_offer.capabilities & CAP_INPUT_RECEIVE == 0)
        || (agreement.reliable_keyframes && local_offer.capabilities & CAP_RELIABLE_KEYFRAMES == 0)
    {
        return Err(SessionNegotiationError::InvalidAgreement);
    }
    Ok(())
}

pub fn encode_session_acceptance(
    server_offer: &SessionOffer,
    agreement: &SessionAgreement,
) -> Result<Vec<u8>, SessionNegotiationError> {
    let encoded_offer = encode_session_offer(server_offer)?;
    let encoded_agreement = encode_session_agreement(agreement)?;
    let offer_len =
        u16::try_from(encoded_offer.len()).map_err(|_| SessionNegotiationError::LengthMismatch)?;
    let mut payload = Vec::with_capacity(
        SESSION_ACCEPTANCE_HEADER_LEN + encoded_offer.len() + encoded_agreement.len(),
    );
    payload.extend_from_slice(&offer_len.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&encoded_offer);
    payload.extend_from_slice(&encoded_agreement);
    Ok(payload)
}

pub fn decode_session_acceptance(
    payload: &[u8],
) -> Result<(SessionOffer, SessionAgreement), SessionNegotiationError> {
    if payload.len() < SESSION_ACCEPTANCE_HEADER_LEN + SESSION_AGREEMENT_LEN {
        return Err(SessionNegotiationError::HeaderTruncated);
    }
    if read_u16(payload, 2) != 0 {
        return Err(SessionNegotiationError::InvalidReservedField);
    }
    let offer_len = read_u16(payload, 0) as usize;
    let expected_len = SESSION_ACCEPTANCE_HEADER_LEN
        .checked_add(offer_len)
        .and_then(|length| length.checked_add(SESSION_AGREEMENT_LEN))
        .ok_or(SessionNegotiationError::LengthMismatch)?;
    if offer_len < SESSION_OFFER_HEADER_LEN || payload.len() != expected_len {
        return Err(SessionNegotiationError::LengthMismatch);
    }
    let offer_end = SESSION_ACCEPTANCE_HEADER_LEN + offer_len;
    let offer = decode_session_offer(&payload[SESSION_ACCEPTANCE_HEADER_LEN..offer_end])?;
    let agreement = decode_session_agreement(&payload[offer_end..])?;
    Ok((offer, agreement))
}

pub fn validate_session_acceptance(
    client_offer: &SessionOffer,
    server_offer: &SessionOffer,
    agreement: &SessionAgreement,
) -> Result<(), SessionNegotiationError> {
    let expected = negotiate_session(client_offer, server_offer)?;
    if &expected != agreement {
        return Err(SessionNegotiationError::InvalidAgreement);
    }
    validate_agreement_for_offer(agreement, client_offer)
}

fn validate_agreement_fields(agreement: &SessionAgreement) -> Result<(), SessionNegotiationError> {
    if agreement.protocol_version == 0
        || !(320..=16_384).contains(&agreement.max_width)
        || !(200..=16_384).contains(&agreement.max_height)
        || !(1..=240).contains(&agreement.max_fps)
        || !(256..=65_000).contains(&agreement.max_datagram_payload)
        || agreement.max_video_bitrate_kbps == 0
        || agreement.max_video_bitrate_kbps > 1_000_000
        || (agreement.file_transfer_enabled && agreement.max_file_bitrate_kbps == 0)
        || (agreement.hdr && agreement.color_format != ColorFormat::P010)
    {
        return Err(SessionNegotiationError::InvalidAgreement);
    }
    Ok(())
}

fn agreement_flags(agreement: &SessionAgreement) -> u16 {
    let mut flags = 0;
    for (enabled, flag) in [
        (agreement.hdr, CAP_HDR),
        (agreement.local_may_send_clipboard, CAP_CLIPBOARD_SEND),
        (agreement.remote_may_send_clipboard, CAP_CLIPBOARD_RECEIVE),
        (agreement.file_transfer_enabled, CAP_FILE_TRANSFER),
        (agreement.local_may_send_input, CAP_INPUT_SEND),
        (agreement.remote_may_send_input, CAP_INPUT_RECEIVE),
        (agreement.reliable_keyframes, CAP_RELIABLE_KEYFRAMES),
    ] {
        if enabled {
            flags |= flag;
        }
    }
    flags
}

fn validate_offer(offer: &SessionOffer) -> Result<(), SessionNegotiationError> {
    if offer.minimum_protocol_version == 0
        || offer.maximum_protocol_version < offer.minimum_protocol_version
    {
        return Err(SessionNegotiationError::InvalidProtocolRange);
    }
    if offer.capabilities & !KNOWN_CAPABILITIES != 0 {
        return Err(SessionNegotiationError::InvalidCapabilities(
            offer.capabilities,
        ));
    }
    if offer.color_formats == 0 || offer.color_formats & !KNOWN_COLOR_FORMATS != 0 {
        return Err(SessionNegotiationError::InvalidColorFormats(
            offer.color_formats,
        ));
    }
    if offer.video_codecs.is_empty()
        || offer.video_codecs.len() > MAX_OFFERED_VIDEO_CODECS
        || contains_duplicates(offer.video_codecs.iter().map(|codec| *codec as u8))
    {
        return Err(SessionNegotiationError::InvalidVideoCodecs);
    }
    if offer.audio_codecs.is_empty()
        || offer.audio_codecs.len() > MAX_OFFERED_AUDIO_CODECS
        || contains_duplicates(offer.audio_codecs.iter().map(|codec| *codec as u8))
    {
        return Err(SessionNegotiationError::InvalidAudioCodecs);
    }
    if !(320..=16_384).contains(&offer.max_width)
        || !(200..=16_384).contains(&offer.max_height)
        || !(1..=240).contains(&offer.max_fps)
    {
        return Err(SessionNegotiationError::InvalidGeometry);
    }
    if !(256..=65_000).contains(&offer.max_datagram_payload) {
        return Err(SessionNegotiationError::InvalidDatagramSize);
    }
    if offer.max_video_bitrate_kbps == 0 || offer.max_video_bitrate_kbps > 1_000_000 {
        return Err(SessionNegotiationError::InvalidBitrate);
    }
    if offer.capabilities & CAP_FILE_TRANSFER != 0 && offer.max_file_bitrate_kbps == 0 {
        return Err(SessionNegotiationError::InvalidBitrate);
    }
    Ok(())
}

fn contains_duplicates(mut values: impl Iterator<Item = u8>) -> bool {
    let mut seen = BTreeSet::new();
    values.any(|value| !seen.insert(value))
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> SessionOffer {
        SessionOffer {
            minimum_protocol_version: 1,
            maximum_protocol_version: 2,
            capabilities: CAP_CLIPBOARD_SEND
                | CAP_CLIPBOARD_RECEIVE
                | CAP_FILE_TRANSFER
                | CAP_INPUT_SEND
                | CAP_INPUT_RECEIVE
                | CAP_RELIABLE_KEYFRAMES,
            latency_mode: LatencyMode::LowLatency,
            video_codecs: vec![VideoCodec::H265, VideoCodec::H264],
            audio_codecs: vec![AudioCodec::Opus],
            color_formats: COLOR_I444 | COLOR_I420,
            max_width: 3840,
            max_height: 2160,
            max_fps: 60,
            max_datagram_payload: 1200,
            max_video_bitrate_kbps: 50_000,
            max_file_bitrate_kbps: 20_000,
        }
    }

    #[test]
    fn offer_round_trip() {
        let offer = offer();
        assert_eq!(
            decode_session_offer(&encode_session_offer(&offer).unwrap()),
            Ok(offer)
        );
    }

    #[test]
    fn agreement_round_trip_and_offer_validation() {
        let local = offer();
        let agreement = negotiate_session(&local, &local).unwrap();
        let encoded = encode_session_agreement(&agreement).unwrap();
        let decoded = decode_session_agreement(&encoded).unwrap();
        assert_eq!(decoded, agreement);
        assert!(validate_agreement_for_offer(&decoded, &local).is_ok());

        let mut downgraded = decoded;
        downgraded.protocol_version = 3;
        assert_eq!(
            validate_agreement_for_offer(&downgraded, &local),
            Err(SessionNegotiationError::InvalidAgreement)
        );
    }

    #[test]
    fn acceptance_carries_server_offer_and_prevents_downgrade() {
        let client_offer = offer();
        let mut server_offer = offer();
        server_offer.maximum_protocol_version = 1;
        let agreement = negotiate_session(&client_offer, &server_offer).unwrap();
        let encoded = encode_session_acceptance(&server_offer, &agreement).unwrap();
        let (decoded_offer, decoded_agreement) = decode_session_acceptance(&encoded).unwrap();
        assert_eq!(decoded_offer, server_offer);
        assert_eq!(decoded_agreement, agreement);
        assert!(
            validate_session_acceptance(&client_offer, &decoded_offer, &decoded_agreement).is_ok()
        );

        let mut downgraded = decoded_agreement;
        downgraded.max_fps = downgraded.max_fps.saturating_sub(1);
        assert_eq!(
            validate_session_acceptance(&client_offer, &decoded_offer, &downgraded),
            Err(SessionNegotiationError::InvalidAgreement)
        );
    }

    #[test]
    fn negotiation_selects_intersection_and_directional_permissions() {
        let local = offer();
        let mut remote = offer();
        remote.maximum_protocol_version = 1;
        remote.video_codecs = vec![VideoCodec::H264];
        remote.color_formats = COLOR_I420;
        remote.max_width = 1920;
        remote.max_fps = 30;
        remote.capabilities &= !CAP_CLIPBOARD_SEND;
        let agreement = negotiate_session(&local, &remote).unwrap();
        assert_eq!(agreement.protocol_version, 1);
        assert_eq!(agreement.video_codec, VideoCodec::H264);
        assert_eq!(agreement.color_format, ColorFormat::I420);
        assert_eq!((agreement.max_width, agreement.max_fps), (1920, 30));
        assert!(agreement.local_may_send_clipboard);
        assert!(!agreement.remote_may_send_clipboard);
    }

    #[test]
    fn incompatible_protocol_and_codec_fail_cleanly() {
        let local = offer();
        let mut remote = offer();
        remote.minimum_protocol_version = 3;
        remote.maximum_protocol_version = 3;
        assert_eq!(
            negotiate_session(&local, &remote),
            Err(SessionNegotiationError::IncompatibleProtocol)
        );
        remote = offer();
        remote.video_codecs = vec![VideoCodec::Av1];
        assert_eq!(
            negotiate_session(&local, &remote),
            Err(SessionNegotiationError::IncompatibleVideoCodec)
        );
    }

    #[test]
    fn malformed_limits_and_duplicate_codecs_are_rejected() {
        let mut invalid = offer();
        invalid.max_datagram_payload = 100;
        assert_eq!(
            encode_session_offer(&invalid),
            Err(SessionNegotiationError::InvalidDatagramSize)
        );
        invalid = offer();
        invalid.video_codecs.push(VideoCodec::H265);
        assert_eq!(
            encode_session_offer(&invalid),
            Err(SessionNegotiationError::InvalidVideoCodecs)
        );
    }
}
