use std::{fmt, slice::Iter, str::FromStr};

use crate::protos::message::{keyboard_input, KeyboardInput, KeyboardMode};

pub const KEYBOARD_INPUT_PROTOCOL_VERSION: u32 = 1;
pub const MAX_COMMITTED_TEXT_BYTES: usize = 2 * 1024;
pub const MAX_TEXT_DELETE_GRAPHEMES: u32 = 64;
pub const MAX_SOURCE_LANGUAGE_TAG_BYTES: usize = 64;
pub const MAX_SOURCE_LAYOUT_TYPE_BYTES: usize = 64;
pub const KEYBOARD_MODIFIER_SHIFT: u32 = 1 << 0;
pub const KEYBOARD_MODIFIER_CONTROL: u32 = 1 << 1;
pub const KEYBOARD_MODIFIER_ALT: u32 = 1 << 2;
pub const KEYBOARD_MODIFIER_META: u32 = 1 << 3;
pub const KNOWN_KEYBOARD_MODIFIER_MASK: u32 = KEYBOARD_MODIFIER_SHIFT
    | KEYBOARD_MODIFIER_CONTROL
    | KEYBOARD_MODIFIER_ALT
    | KEYBOARD_MODIFIER_META;
pub const KEYBOARD_LOCK_CAPS: u32 = 1 << 0;
pub const KEYBOARD_LOCK_NUM: u32 = 1 << 1;
pub const KEYBOARD_LOCK_SCROLL: u32 = 1 << 2;
pub const KNOWN_KEYBOARD_LOCK_MASK: u32 =
    KEYBOARD_LOCK_CAPS | KEYBOARD_LOCK_NUM | KEYBOARD_LOCK_SCROLL;
pub const MIN_USB_HID_KEYBOARD_USAGE: u32 = 0x04;
pub const MAX_USB_HID_KEYBOARD_USAGE: u32 = 0xe7;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum KeyboardInputError {
    #[error("unsupported keyboard input protocol version {0}")]
    UnsupportedVersion(u32),
    #[error("keyboard input epoch must not be zero")]
    MissingEpoch,
    #[error("keyboard input sequence must not be zero")]
    MissingSequence,
    #[error("keyboard input payload is missing")]
    MissingPayload,
    #[error("committed text payload is empty")]
    EmptyCommittedText,
    #[error("committed text payload exceeds {MAX_COMMITTED_TEXT_BYTES} bytes")]
    CommittedTextTooLarge,
    #[error("committed text deletion exceeds {MAX_TEXT_DELETE_GRAPHEMES} graphemes")]
    TextDeletionTooLarge,
    #[error("keyboard source language tag is invalid")]
    InvalidSourceLanguageTag,
    #[error("keyboard source layout type is invalid")]
    InvalidSourceLayoutType,
    #[error("USB HID keyboard usage 0x{0:x} is outside usage page 0x07")]
    InvalidUsbHidUsage(u32),
    #[error("physical-key repeat requires a key-down event")]
    RepeatWithoutKeyDown,
    #[error("keyboard modifier mask contains unknown bits 0x{0:x}")]
    InvalidModifierMask(u32),
    #[error("keyboard lock mask contains unknown bits 0x{0:x}")]
    InvalidLockMask(u32),
}

pub fn validate_keyboard_input(input: &KeyboardInput) -> Result<(), KeyboardInputError> {
    if input.protocol_version != KEYBOARD_INPUT_PROTOCOL_VERSION {
        return Err(KeyboardInputError::UnsupportedVersion(
            input.protocol_version,
        ));
    }
    if input.input_epoch == 0 {
        return Err(KeyboardInputError::MissingEpoch);
    }
    if input.sequence == 0 {
        return Err(KeyboardInputError::MissingSequence);
    }

    match input.union.as_ref() {
        Some(keyboard_input::Union::CommittedText(text)) => {
            if text.text.is_empty()
                && text.delete_before_graphemes == 0
                && text.delete_after_graphemes == 0
            {
                return Err(KeyboardInputError::EmptyCommittedText);
            }
            if text.text.len() > MAX_COMMITTED_TEXT_BYTES {
                return Err(KeyboardInputError::CommittedTextTooLarge);
            }
            if text.delete_before_graphemes > MAX_TEXT_DELETE_GRAPHEMES
                || text.delete_after_graphemes > MAX_TEXT_DELETE_GRAPHEMES
            {
                return Err(KeyboardInputError::TextDeletionTooLarge);
            }
            if !text.source_language_tag.is_empty()
                && !valid_source_metadata(&text.source_language_tag, MAX_SOURCE_LANGUAGE_TAG_BYTES)
            {
                return Err(KeyboardInputError::InvalidSourceLanguageTag);
            }
            if !text.source_layout_type.is_empty()
                && !valid_source_metadata(&text.source_layout_type, MAX_SOURCE_LAYOUT_TYPE_BYTES)
            {
                return Err(KeyboardInputError::InvalidSourceLayoutType);
            }
            if text.prefer_physical && text.source_language_tag.is_empty() {
                return Err(KeyboardInputError::InvalidSourceLanguageTag);
            }
        }
        Some(keyboard_input::Union::PhysicalKey(key)) => {
            if !(MIN_USB_HID_KEYBOARD_USAGE..=MAX_USB_HID_KEYBOARD_USAGE)
                .contains(&key.usb_hid_usage)
            {
                return Err(KeyboardInputError::InvalidUsbHidUsage(key.usb_hid_usage));
            }
            if key.repeat && !key.down {
                return Err(KeyboardInputError::RepeatWithoutKeyDown);
            }
            validate_masks(key.modifier_mask, key.lock_mask)?;
        }
        Some(keyboard_input::Union::ModifierSync(sync)) => {
            validate_masks(sync.modifier_mask, sync.lock_mask)?;
        }
        None => return Err(KeyboardInputError::MissingPayload),
    }
    Ok(())
}

pub fn validate_source_layout_metadata(language_tag: &str, layout_type: &str) -> bool {
    !language_tag.is_empty()
        && valid_source_metadata(language_tag, MAX_SOURCE_LANGUAGE_TAG_BYTES)
        && (layout_type.is_empty()
            || valid_source_metadata(layout_type, MAX_SOURCE_LAYOUT_TYPE_BYTES))
}

fn valid_source_metadata(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'.'))
}

fn validate_masks(modifier_mask: u32, lock_mask: u32) -> Result<(), KeyboardInputError> {
    let unknown_modifiers = modifier_mask & !KNOWN_KEYBOARD_MODIFIER_MASK;
    if unknown_modifiers != 0 {
        return Err(KeyboardInputError::InvalidModifierMask(unknown_modifiers));
    }
    let unknown_locks = lock_mask & !KNOWN_KEYBOARD_LOCK_MASK;
    if unknown_locks != 0 {
        return Err(KeyboardInputError::InvalidLockMask(unknown_locks));
    }
    Ok(())
}

impl fmt::Display for KeyboardMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyboardMode::Legacy => write!(f, "legacy"),
            KeyboardMode::Map => write!(f, "map"),
            KeyboardMode::Translate => write!(f, "translate"),
            KeyboardMode::Auto => write!(f, "auto"),
        }
    }
}

impl FromStr for KeyboardMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "legacy" => Ok(KeyboardMode::Legacy),
            "map" => Ok(KeyboardMode::Map),
            "translate" => Ok(KeyboardMode::Translate),
            "auto" => Ok(KeyboardMode::Auto),
            _ => Err(()),
        }
    }
}

impl KeyboardMode {
    pub fn iter() -> Iter<'static, KeyboardMode> {
        static KEYBOARD_MODES: [KeyboardMode; 4] = [
            KeyboardMode::Legacy,
            KeyboardMode::Map,
            KeyboardMode::Translate,
            KeyboardMode::Auto,
        ];
        KEYBOARD_MODES.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        message_proto::{keyboard_input, CommittedText, ModifierSync, PhysicalKey},
        protobuf::Message as _,
    };

    fn base_input() -> KeyboardInput {
        KeyboardInput {
            protocol_version: KEYBOARD_INPUT_PROTOCOL_VERSION,
            input_epoch: 7,
            sequence: 1,
            ..Default::default()
        }
    }

    #[test]
    fn validates_committed_text_and_bounded_edits() {
        let mut input = base_input();
        input.set_committed_text(CommittedText {
            text: "Ahoj \u{43c}\u{438}\u{440}".to_owned(),
            delete_before_graphemes: 2,
            ..Default::default()
        });
        assert_eq!(validate_keyboard_input(&input), Ok(()));

        input.mut_committed_text().text = "x".repeat(MAX_COMMITTED_TEXT_BYTES + 1);
        assert_eq!(
            validate_keyboard_input(&input),
            Err(KeyboardInputError::CommittedTextTooLarge)
        );
    }

    #[test]
    fn validates_source_layout_metadata_without_accepting_unbounded_values() {
        let mut input = base_input();
        input.set_committed_text(CommittedText {
            text: "text".to_owned(),
            source_language_tag: "ru-RU".to_owned(),
            source_layout_type: "qwerty".to_owned(),
            prefer_physical: true,
            ..Default::default()
        });
        assert_eq!(validate_keyboard_input(&input), Ok(()));

        input.mut_committed_text().source_language_tag = "ru RU".to_owned();
        assert_eq!(
            validate_keyboard_input(&input),
            Err(KeyboardInputError::InvalidSourceLanguageTag)
        );

        input.mut_committed_text().source_language_tag = "ru-RU".to_owned();
        input.mut_committed_text().source_layout_type =
            "x".repeat(MAX_SOURCE_LAYOUT_TYPE_BYTES + 1);
        assert_eq!(
            validate_keyboard_input(&input),
            Err(KeyboardInputError::InvalidSourceLayoutType)
        );
    }

    #[test]
    fn rejects_invalid_physical_key_fields() {
        let mut input = base_input();
        input.set_physical_key(PhysicalKey {
            usb_hid_usage: 0x04,
            down: true,
            modifier_mask: KEYBOARD_MODIFIER_SHIFT,
            lock_mask: KEYBOARD_LOCK_CAPS,
            ..Default::default()
        });
        assert_eq!(validate_keyboard_input(&input), Ok(()));

        input.mut_physical_key().usb_hid_usage = 0x100;
        assert_eq!(
            validate_keyboard_input(&input),
            Err(KeyboardInputError::InvalidUsbHidUsage(0x100))
        );
    }

    #[test]
    fn modifier_sync_can_release_all_modifiers() {
        let mut input = base_input();
        input.set_modifier_sync(ModifierSync::new());
        assert_eq!(validate_keyboard_input(&input), Ok(()));
    }

    #[test]
    fn keyboard_input_round_trips_without_native_struct_deserialization() {
        let mut input = base_input();
        input.set_committed_text(CommittedText {
            text: "\u{65e5}\u{672c}\u{8a9e} \u{1f642}".to_owned(),
            delete_before_graphemes: 1,
            source_language_tag: "ja-JP".to_owned(),
            source_layout_type: "qwerty".to_owned(),
            prefer_physical: true,
            ..Default::default()
        });

        let encoded = input.write_to_bytes().unwrap();
        let decoded = KeyboardInput::parse_from_bytes(&encoded).unwrap();
        assert_eq!(validate_keyboard_input(&decoded), Ok(()));
        let Some(keyboard_input::Union::CommittedText(text)) = decoded.union else {
            panic!("missing committed text");
        };
        assert_eq!(text.text, "\u{65e5}\u{672c}\u{8a9e} \u{1f642}");
        assert_eq!(text.delete_before_graphemes, 1);
        assert_eq!(text.source_language_tag, "ja-JP");
        assert_eq!(text.source_layout_type, "qwerty");
        assert!(text.prefer_physical);
    }
}
