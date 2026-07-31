use std::{collections::BTreeMap, convert::TryInto};

pub const CLIPBOARD_HEADER_LEN: usize = 32;
pub const DEFAULT_MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
const MAX_TRACKED_ORIGINS: usize = 8;
const FORMAT_UTF8_TEXT: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardPermission {
    Disabled,
    ReceiveOnly,
    SendOnly,
    Bidirectional,
}

impl ClipboardPermission {
    fn can_send(self) -> bool {
        matches!(self, Self::SendOnly | Self::Bidirectional)
    }

    fn can_receive(self) -> bool {
        matches!(self, Self::ReceiveOnly | Self::Bidirectional)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClipboardText {
    pub origin_id: [u8; 16],
    pub change_sequence: u64,
    pub text: String,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ClipboardError {
    #[error("clipboard synchronization is not permitted in this direction")]
    PermissionDenied,
    #[error("clipboard origin identifier must not be all zero")]
    ZeroOrigin,
    #[error("clipboard change sequence must not be zero")]
    ZeroSequence,
    #[error("clipboard payload header is truncated")]
    HeaderTruncated,
    #[error("unsupported clipboard format {0}")]
    UnsupportedFormat(u8),
    #[error("clipboard flags or reserved fields are invalid")]
    InvalidReservedField,
    #[error("clipboard payload size {0} is invalid")]
    InvalidSize(usize),
    #[error("clipboard text is not valid UTF-8")]
    InvalidUtf8,
    #[error("clipboard message uses too many independent origins")]
    TooManyOrigins,
    #[error("clipboard local sequence is exhausted")]
    SequenceExhausted,
}

pub fn encode_clipboard_text(
    origin_id: [u8; 16],
    change_sequence: u64,
    text: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, ClipboardError> {
    validate_origin_and_sequence(&origin_id, change_sequence)?;
    if text.len() > max_bytes || text.len() > u32::MAX as usize {
        return Err(ClipboardError::InvalidSize(text.len()));
    }
    let mut payload = Vec::with_capacity(CLIPBOARD_HEADER_LEN + text.len());
    payload.extend_from_slice(&origin_id);
    payload.extend_from_slice(&change_sequence.to_be_bytes());
    payload.push(FORMAT_UTF8_TEXT);
    payload.push(0);
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
    payload.extend_from_slice(text.as_bytes());
    Ok(payload)
}

pub fn decode_clipboard_text(
    payload: &[u8],
    max_bytes: usize,
) -> Result<ClipboardText, ClipboardError> {
    if payload.len() < CLIPBOARD_HEADER_LEN {
        return Err(ClipboardError::HeaderTruncated);
    }
    let mut origin_id = [0u8; 16];
    origin_id.copy_from_slice(&payload[..16]);
    let change_sequence = read_u64(payload, 16);
    validate_origin_and_sequence(&origin_id, change_sequence)?;
    if payload[24] != FORMAT_UTF8_TEXT {
        return Err(ClipboardError::UnsupportedFormat(payload[24]));
    }
    if payload[25] != 0 || read_u16(payload, 26) != 0 {
        return Err(ClipboardError::InvalidReservedField);
    }
    let declared_len = read_u32(payload, 28) as usize;
    let text_bytes = &payload[CLIPBOARD_HEADER_LEN..];
    if declared_len != text_bytes.len() || declared_len > max_bytes {
        return Err(ClipboardError::InvalidSize(declared_len));
    }
    let text = std::str::from_utf8(text_bytes)
        .map_err(|_| ClipboardError::InvalidUtf8)?
        .to_owned();
    Ok(ClipboardText {
        origin_id,
        change_sequence,
        text,
    })
}

pub struct ClipboardState {
    permission: ClipboardPermission,
    local_origin_id: [u8; 16],
    next_local_sequence: u64,
    remote_sequences: BTreeMap<[u8; 16], u64>,
    max_bytes: usize,
}

impl ClipboardState {
    pub fn new(
        permission: ClipboardPermission,
        local_origin_id: [u8; 16],
        max_bytes: usize,
    ) -> Result<Self, ClipboardError> {
        validate_origin_and_sequence(&local_origin_id, 1)?;
        if max_bytes == 0 || max_bytes > DEFAULT_MAX_CLIPBOARD_BYTES {
            return Err(ClipboardError::InvalidSize(max_bytes));
        }
        Ok(Self {
            permission,
            local_origin_id,
            next_local_sequence: 1,
            remote_sequences: BTreeMap::new(),
            max_bytes,
        })
    }

    pub fn prepare_local_text(&mut self, text: &str) -> Result<Vec<u8>, ClipboardError> {
        if !self.permission.can_send() {
            return Err(ClipboardError::PermissionDenied);
        }
        let sequence = self.next_local_sequence;
        let payload = encode_clipboard_text(self.local_origin_id, sequence, text, self.max_bytes)?;
        self.next_local_sequence = sequence
            .checked_add(1)
            .ok_or(ClipboardError::SequenceExhausted)?;
        Ok(payload)
    }

    pub fn receive(&mut self, payload: &[u8]) -> Result<Option<ClipboardText>, ClipboardError> {
        if !self.permission.can_receive() {
            return Err(ClipboardError::PermissionDenied);
        }
        let clipboard = decode_clipboard_text(payload, self.max_bytes)?;
        if clipboard.origin_id == self.local_origin_id {
            return Ok(None);
        }
        if let Some(last_sequence) = self.remote_sequences.get_mut(&clipboard.origin_id) {
            if clipboard.change_sequence <= *last_sequence {
                return Ok(None);
            }
            *last_sequence = clipboard.change_sequence;
            return Ok(Some(clipboard));
        }
        if self.remote_sequences.len() >= MAX_TRACKED_ORIGINS {
            return Err(ClipboardError::TooManyOrigins);
        }
        self.remote_sequences
            .insert(clipboard.origin_id, clipboard.change_sequence);
        Ok(Some(clipboard))
    }

    pub fn reset_remote_state(&mut self) {
        self.remote_sequences.clear();
    }
}

fn validate_origin_and_sequence(
    origin_id: &[u8; 16],
    change_sequence: u64,
) -> Result<(), ClipboardError> {
    if origin_id.iter().all(|byte| *byte == 0) {
        return Err(ClipboardError::ZeroOrigin);
    }
    if change_sequence == 0 {
        return Err(ClipboardError::ZeroSequence);
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

    #[test]
    fn utf8_clipboard_round_trip() {
        let payload = encode_clipboard_text([1; 16], 7, "hello", 1024).unwrap();
        assert_eq!(
            decode_clipboard_text(&payload, 1024).unwrap(),
            ClipboardText {
                origin_id: [1; 16],
                change_sequence: 7,
                text: "hello".to_owned(),
            }
        );
    }

    #[test]
    fn loop_and_duplicate_changes_are_suppressed() {
        let mut state =
            ClipboardState::new(ClipboardPermission::Bidirectional, [1; 16], 1024).unwrap();
        let own = encode_clipboard_text([1; 16], 1, "own", 1024).unwrap();
        assert_eq!(state.receive(&own).unwrap(), None);
        let peer = encode_clipboard_text([2; 16], 4, "peer", 1024).unwrap();
        assert!(state.receive(&peer).unwrap().is_some());
        assert_eq!(state.receive(&peer).unwrap(), None);
        let stale = encode_clipboard_text([2; 16], 3, "stale", 1024).unwrap();
        assert_eq!(state.receive(&stale).unwrap(), None);
    }

    #[test]
    fn directional_permissions_are_enforced() {
        let mut receive_only =
            ClipboardState::new(ClipboardPermission::ReceiveOnly, [1; 16], 1024).unwrap();
        assert_eq!(
            receive_only.prepare_local_text("blocked"),
            Err(ClipboardError::PermissionDenied)
        );
        let mut send_only =
            ClipboardState::new(ClipboardPermission::SendOnly, [1; 16], 1024).unwrap();
        let peer = encode_clipboard_text([2; 16], 1, "peer", 1024).unwrap();
        assert_eq!(
            send_only.receive(&peer),
            Err(ClipboardError::PermissionDenied)
        );
    }

    #[test]
    fn malformed_and_oversized_payloads_are_rejected() {
        assert_eq!(
            encode_clipboard_text([1; 16], 1, "too large", 2),
            Err(ClipboardError::InvalidSize(9))
        );
        let mut payload = encode_clipboard_text([1; 16], 1, "ok", 1024).unwrap();
        payload[31] = 9;
        assert_eq!(
            decode_clipboard_text(&payload, 1024),
            Err(ClipboardError::InvalidSize(9))
        );
    }
}
