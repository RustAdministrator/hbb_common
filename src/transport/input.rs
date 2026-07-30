use super::protocol::{
    decode_message, encode_message, MessageHeader, MessageType, ProtocolError, SessionId,
    HEADER_LEN,
};
use std::{
    collections::BTreeSet,
    convert::{TryFrom, TryInto},
};

pub const MOUSE_MOVEMENT_PAYLOAD_LEN: usize = 20;
pub const RELIABLE_INPUT_PAYLOAD_LEN: usize = 24;
pub const MAX_DISPLAY_ID: u32 = 255;
pub const KNOWN_BUTTON_MASK: u16 = 0x001f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MouseMovementMode {
    Absolute = 1,
    Relative = 2,
}

impl TryFrom<u8> for MouseMovementMode {
    type Error = InputProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Absolute),
            2 => Ok(Self::Relative),
            _ => Err(InputProtocolError::UnknownMouseMode(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MouseMovement {
    pub sequence_number: u64,
    pub monotonic_timestamp_us: u64,
    pub mode: MouseMovementMode,
    pub x: i32,
    pub y: i32,
    pub display_id: u32,
    pub button_state_mask: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum MouseButton {
    Left = 1,
    Right = 2,
    Middle = 3,
    Back = 4,
    Forward = 5,
}

impl TryFrom<u8> for MouseButton {
    type Error = InputProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Left),
            2 => Ok(Self::Right),
            3 => Ok(Self::Middle),
            4 => Ok(Self::Back),
            5 => Ok(Self::Forward),
            _ => Err(InputProtocolError::UnknownMouseButton(value)),
        }
    }
}

impl MouseButton {
    fn mask(self) -> u16 {
        1 << (self as u8 - 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReliableInputEvent {
    Key {
        key_code: u32,
        pressed: bool,
        modifiers: u32,
    },
    MouseButton {
        button: MouseButton,
        pressed: bool,
        x: i32,
        y: i32,
        display_id: u32,
    },
    Wheel {
        delta_x: i32,
        delta_y: i32,
        display_id: u32,
    },
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum InputProtocolError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("mouse movement payload has an invalid size")]
    InvalidMousePayloadSize,
    #[error("reliable input payload has an invalid size")]
    InvalidReliablePayloadSize,
    #[error("unknown mouse movement mode {0}")]
    UnknownMouseMode(u8),
    #[error("unknown reliable input event {0}")]
    UnknownInputEvent(u8),
    #[error("unknown mouse button {0}")]
    UnknownMouseButton(u8),
    #[error("unknown input flags 0x{0:02x}")]
    UnknownFlags(u8),
    #[error("input reserved field is not zero")]
    ReservedField,
    #[error("display identifier {0} exceeds the protocol limit")]
    InvalidDisplayId(u32),
    #[error("mouse button-state mask 0x{0:04x} is invalid")]
    InvalidButtonMask(u16),
    #[error("mouse coordinates or deltas exceed the protocol limit")]
    InvalidCoordinates,
    #[error("keyboard code must not be zero")]
    InvalidKeyCode,
    #[error("reliable input sequence {received} does not follow {previous}")]
    InvalidSequence { previous: u64, received: u64 },
    #[error("input session identifier does not match the active session")]
    SessionMismatch,
}

pub fn encode_mouse_movement(
    session_id: SessionId,
    movement: MouseMovement,
    max_datagram_size: usize,
) -> Result<Vec<u8>, InputProtocolError> {
    validate_mouse_movement(movement)?;
    if HEADER_LEN + MOUSE_MOVEMENT_PAYLOAD_LEN > max_datagram_size {
        return Err(InputProtocolError::InvalidMousePayloadSize);
    }
    let mut payload = Vec::with_capacity(MOUSE_MOVEMENT_PAYLOAD_LEN);
    payload.push(movement.mode as u8);
    payload.push(0);
    payload.extend_from_slice(&movement.button_state_mask.to_be_bytes());
    payload.extend_from_slice(&movement.display_id.to_be_bytes());
    payload.extend_from_slice(&movement.x.to_be_bytes());
    payload.extend_from_slice(&movement.y.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    let header = MessageHeader::new(
        MessageType::MouseMovement,
        0,
        session_id,
        movement.sequence_number,
        payload.len(),
        movement.monotonic_timestamp_us,
    )?;
    Ok(encode_message(&header, &payload)?)
}

pub fn decode_mouse_movement(datagram: &[u8]) -> Result<MouseMovement, InputProtocolError> {
    let message = decode_message(datagram)?;
    if message.header.message_type != MessageType::MouseMovement {
        return Err(ProtocolError::ChannelMismatch {
            message_type: message.header.message_type,
            channel: message.header.channel,
        }
        .into());
    }
    if message.payload.len() != MOUSE_MOVEMENT_PAYLOAD_LEN {
        return Err(InputProtocolError::InvalidMousePayloadSize);
    }
    if message.payload[1] != 0 || read_u32(message.payload, 16) != 0 {
        return Err(InputProtocolError::ReservedField);
    }
    let movement = MouseMovement {
        sequence_number: message.header.sequence_number,
        monotonic_timestamp_us: message.header.monotonic_timestamp_us,
        mode: MouseMovementMode::try_from(message.payload[0])?,
        button_state_mask: read_u16(message.payload, 2),
        display_id: read_u32(message.payload, 4),
        x: read_i32(message.payload, 8),
        y: read_i32(message.payload, 12),
    };
    validate_mouse_movement(movement)?;
    Ok(movement)
}

pub fn encode_reliable_input(event: ReliableInputEvent) -> Vec<u8> {
    let mut payload = vec![0u8; RELIABLE_INPUT_PAYLOAD_LEN];
    match event {
        ReliableInputEvent::Key {
            key_code,
            pressed,
            modifiers,
        } => {
            payload[0] = 1;
            payload[1] = u8::from(pressed);
            payload[4..8].copy_from_slice(&key_code.to_be_bytes());
            payload[16..20].copy_from_slice(&modifiers.to_be_bytes());
        }
        ReliableInputEvent::MouseButton {
            button,
            pressed,
            x,
            y,
            display_id,
        } => {
            payload[0] = 2;
            payload[1] = u8::from(pressed);
            payload[4] = button as u8;
            payload[8..12].copy_from_slice(&x.to_be_bytes());
            payload[12..16].copy_from_slice(&y.to_be_bytes());
            payload[16..20].copy_from_slice(&display_id.to_be_bytes());
        }
        ReliableInputEvent::Wheel {
            delta_x,
            delta_y,
            display_id,
        } => {
            payload[0] = 3;
            payload[8..12].copy_from_slice(&delta_x.to_be_bytes());
            payload[12..16].copy_from_slice(&delta_y.to_be_bytes());
            payload[16..20].copy_from_slice(&display_id.to_be_bytes());
        }
    }
    payload
}

pub fn decode_reliable_input(payload: &[u8]) -> Result<ReliableInputEvent, InputProtocolError> {
    if payload.len() != RELIABLE_INPUT_PAYLOAD_LEN {
        return Err(InputProtocolError::InvalidReliablePayloadSize);
    }
    if read_u16(payload, 2) != 0 || read_u32(payload, 20) != 0 {
        return Err(InputProtocolError::ReservedField);
    }
    if payload[1] & !1 != 0 {
        return Err(InputProtocolError::UnknownFlags(payload[1]));
    }
    let event = match payload[0] {
        1 => {
            if read_u32(payload, 4) == 0 || read_i32(payload, 8) != 0 || read_i32(payload, 12) != 0
            {
                return Err(InputProtocolError::InvalidKeyCode);
            }
            ReliableInputEvent::Key {
                key_code: read_u32(payload, 4),
                pressed: payload[1] != 0,
                modifiers: read_u32(payload, 16),
            }
        }
        2 => {
            if payload[5..8] != [0; 3] {
                return Err(InputProtocolError::ReservedField);
            }
            let display_id = read_u32(payload, 16);
            validate_display_id(display_id)?;
            let x = read_i32(payload, 8);
            let y = read_i32(payload, 12);
            validate_absolute_coordinates(x, y)?;
            ReliableInputEvent::MouseButton {
                button: MouseButton::try_from(payload[4])?,
                pressed: payload[1] != 0,
                x,
                y,
                display_id,
            }
        }
        3 => {
            if payload[1] != 0 || read_u32(payload, 4) != 0 {
                return Err(InputProtocolError::ReservedField);
            }
            let display_id = read_u32(payload, 16);
            validate_display_id(display_id)?;
            let delta_x = read_i32(payload, 8);
            let delta_y = read_i32(payload, 12);
            validate_relative_coordinates(delta_x, delta_y)?;
            ReliableInputEvent::Wheel {
                delta_x,
                delta_y,
                display_id,
            }
        }
        value => return Err(InputProtocolError::UnknownInputEvent(value)),
    };
    Ok(event)
}

pub struct MouseMovementReceiver {
    session_id: SessionId,
    last_sequence: u64,
}

impl MouseMovementReceiver {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            last_sequence: 0,
        }
    }

    pub fn apply(&mut self, datagram: &[u8]) -> Result<Option<MouseMovement>, InputProtocolError> {
        let message = decode_message(datagram)?;
        if message.header.session_id != self.session_id {
            return Err(InputProtocolError::SessionMismatch);
        }
        let movement = decode_mouse_movement(datagram)?;
        if movement.sequence_number <= self.last_sequence {
            return Ok(None);
        }
        self.last_sequence = movement.sequence_number;
        Ok(Some(movement))
    }

    pub fn reset(&mut self) {
        self.last_sequence = 0;
    }
}

pub struct ReliableInputReceiver {
    last_sequence: u64,
    pressed_keys: BTreeSet<u32>,
    pressed_buttons: u16,
}

impl ReliableInputReceiver {
    pub fn new() -> Self {
        Self {
            last_sequence: 0,
            pressed_keys: BTreeSet::new(),
            pressed_buttons: 0,
        }
    }

    pub fn apply(
        &mut self,
        sequence_number: u64,
        payload: &[u8],
    ) -> Result<Option<ReliableInputEvent>, InputProtocolError> {
        let expected = self.last_sequence.saturating_add(1);
        if sequence_number != expected {
            return Err(InputProtocolError::InvalidSequence {
                previous: self.last_sequence,
                received: sequence_number,
            });
        }
        let event = decode_reliable_input(payload)?;
        self.last_sequence = sequence_number;
        let changed = match event {
            ReliableInputEvent::Key {
                key_code, pressed, ..
            } => {
                if pressed {
                    self.pressed_keys.insert(key_code)
                } else {
                    self.pressed_keys.remove(&key_code)
                }
            }
            ReliableInputEvent::MouseButton {
                button, pressed, ..
            } => {
                let mask = button.mask();
                let was_pressed = self.pressed_buttons & mask != 0;
                if pressed {
                    self.pressed_buttons |= mask;
                } else {
                    self.pressed_buttons &= !mask;
                }
                was_pressed != pressed
            }
            ReliableInputEvent::Wheel { .. } => true,
        };
        Ok(changed.then_some(event))
    }

    pub fn release_all(&mut self) -> Vec<ReliableInputEvent> {
        let mut releases = Vec::with_capacity(self.pressed_keys.len() + 5);
        for key_code in std::mem::take(&mut self.pressed_keys) {
            releases.push(ReliableInputEvent::Key {
                key_code,
                pressed: false,
                modifiers: 0,
            });
        }
        for button in [
            MouseButton::Left,
            MouseButton::Right,
            MouseButton::Middle,
            MouseButton::Back,
            MouseButton::Forward,
        ] {
            if self.pressed_buttons & button.mask() != 0 {
                releases.push(ReliableInputEvent::MouseButton {
                    button,
                    pressed: false,
                    x: 0,
                    y: 0,
                    display_id: 0,
                });
            }
        }
        self.pressed_buttons = 0;
        self.last_sequence = 0;
        releases
    }
}

impl Default for ReliableInputReceiver {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_mouse_movement(movement: MouseMovement) -> Result<(), InputProtocolError> {
    validate_display_id(movement.display_id)?;
    if movement.button_state_mask & !KNOWN_BUTTON_MASK != 0 {
        return Err(InputProtocolError::InvalidButtonMask(
            movement.button_state_mask,
        ));
    }
    match movement.mode {
        MouseMovementMode::Absolute => validate_absolute_coordinates(movement.x, movement.y),
        MouseMovementMode::Relative => validate_relative_coordinates(movement.x, movement.y),
    }
}

fn validate_display_id(display_id: u32) -> Result<(), InputProtocolError> {
    if display_id > MAX_DISPLAY_ID {
        return Err(InputProtocolError::InvalidDisplayId(display_id));
    }
    Ok(())
}

fn validate_absolute_coordinates(x: i32, y: i32) -> Result<(), InputProtocolError> {
    if x < 0 || y < 0 || x > 1_000_000 || y > 1_000_000 {
        return Err(InputProtocolError::InvalidCoordinates);
    }
    Ok(())
}

fn validate_relative_coordinates(x: i32, y: i32) -> Result<(), InputProtocolError> {
    if !(-100_000..=100_000).contains(&x) || !(-100_000..=100_000).contains(&y) {
        return Err(InputProtocolError::InvalidCoordinates);
    }
    Ok(())
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn read_i32(input: &[u8], offset: usize) -> i32 {
    i32::from_be_bytes(input[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_mouse_movement_wins() {
        let session = [5; 16];
        let movement = |sequence_number, x| MouseMovement {
            sequence_number,
            monotonic_timestamp_us: sequence_number * 10,
            mode: MouseMovementMode::Absolute,
            x,
            y: 20,
            display_id: 0,
            button_state_mask: 1,
        };
        let newer = encode_mouse_movement(session, movement(2, 200), 1200).unwrap();
        let older = encode_mouse_movement(session, movement(1, 100), 1200).unwrap();
        let mut receiver = MouseMovementReceiver::new(session);
        assert_eq!(receiver.apply(&newer).unwrap(), Some(movement(2, 200)));
        assert_eq!(receiver.apply(&older).unwrap(), None);
    }

    #[test]
    fn reliable_events_round_trip() {
        let events = [
            ReliableInputEvent::Key {
                key_code: 42,
                pressed: true,
                modifiers: 3,
            },
            ReliableInputEvent::MouseButton {
                button: MouseButton::Right,
                pressed: true,
                x: 100,
                y: 200,
                display_id: 1,
            },
            ReliableInputEvent::Wheel {
                delta_x: -120,
                delta_y: 240,
                display_id: 1,
            },
        ];
        for event in events {
            assert_eq!(
                decode_reliable_input(&encode_reliable_input(event)),
                Ok(event)
            );
        }
    }

    #[test]
    fn duplicate_state_changes_are_not_applied_twice() {
        let event = ReliableInputEvent::Key {
            key_code: 42,
            pressed: true,
            modifiers: 0,
        };
        let payload = encode_reliable_input(event);
        let mut receiver = ReliableInputReceiver::new();
        assert_eq!(receiver.apply(1, &payload).unwrap(), Some(event));
        assert_eq!(receiver.apply(2, &payload).unwrap(), None);
        assert!(matches!(
            receiver.apply(2, &payload),
            Err(InputProtocolError::InvalidSequence { .. })
        ));
    }

    #[test]
    fn disconnect_releases_pressed_keys_and_buttons() {
        let mut receiver = ReliableInputReceiver::new();
        receiver
            .apply(
                1,
                &encode_reliable_input(ReliableInputEvent::Key {
                    key_code: 7,
                    pressed: true,
                    modifiers: 0,
                }),
            )
            .unwrap();
        receiver
            .apply(
                2,
                &encode_reliable_input(ReliableInputEvent::MouseButton {
                    button: MouseButton::Left,
                    pressed: true,
                    x: 10,
                    y: 20,
                    display_id: 0,
                }),
            )
            .unwrap();
        let releases = receiver.release_all();
        assert_eq!(releases.len(), 2);
        assert!(releases.iter().all(|event| matches!(
            event,
            ReliableInputEvent::Key { pressed: false, .. }
                | ReliableInputEvent::MouseButton { pressed: false, .. }
        )));
    }

    #[test]
    fn malformed_coordinates_and_masks_are_rejected() {
        assert!(encode_mouse_movement(
            [1; 16],
            MouseMovement {
                sequence_number: 1,
                monotonic_timestamp_us: 1,
                mode: MouseMovementMode::Absolute,
                x: -1,
                y: 0,
                display_id: 0,
                button_state_mask: 0,
            },
            1200,
        )
        .is_err());
        assert!(encode_mouse_movement(
            [1; 16],
            MouseMovement {
                sequence_number: 1,
                monotonic_timestamp_us: 1,
                mode: MouseMovementMode::Relative,
                x: 0,
                y: 0,
                display_id: 0,
                button_state_mask: 0x8000,
            },
            1200,
        )
        .is_err());
    }
}
