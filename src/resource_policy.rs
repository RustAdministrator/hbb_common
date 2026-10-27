use std::time::Duration;

use crate::{
    message_proto::{option_message, OptionMessage},
    protobuf::EnumOrUnknown,
};

pub const OPTION_HOST_RESOURCE_MODE: &str = "host-resource-mode";
pub const OPTION_VIEWER_RESOURCE_MODE: &str = "viewer-resource-mode";
pub const OPTION_REMOTE_RESOURCE_MODE: &str = "remote-resource-mode";

/// The resource policy requested by a local setting or a connected session.
///
/// The declaration order is the policy strength order. Keep `Normal` as the
/// default so omitted and unknown wire/config values remain compatible.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceMode {
    #[default]
    Normal,
    LowPower,
    MinimizeGpu,
}

impl ResourceMode {
    /// Parse persisted values; unknown values retain the normal default.
    pub fn from_config(value: &str) -> Self {
        match value.trim() {
            value if value.eq_ignore_ascii_case("normal") => Self::Normal,
            value if value.eq_ignore_ascii_case("low-power") => Self::LowPower,
            value if value.eq_ignore_ascii_case("minimize-gpu") => Self::MinimizeGpu,
            _ => Self::Normal,
        }
    }

    pub const fn config_value(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::LowPower => "low-power",
            Self::MinimizeGpu => "minimize-gpu",
        }
    }

    pub const fn strongest(self, other: Self) -> Self {
        match (self, other) {
            (Self::MinimizeGpu, _) | (_, Self::MinimizeGpu) => Self::MinimizeGpu,
            (Self::LowPower, _) | (_, Self::LowPower) => Self::LowPower,
            _ => Self::Normal,
        }
    }

    pub const fn active_fps_cap(self) -> Option<u32> {
        match self {
            Self::Normal => None,
            Self::LowPower | Self::MinimizeGpu => Some(10),
        }
    }

    pub const fn idle_fps(self) -> Option<u32> {
        match self {
            Self::Normal => None,
            Self::LowPower | Self::MinimizeGpu => Some(2),
        }
    }

    pub const fn idle_after(self) -> Duration {
        Duration::from_secs(2)
    }

    pub const fn hardware_allowed(self) -> bool {
        !matches!(self, Self::MinimizeGpu)
    }

    pub fn write_option(self, option: &mut OptionMessage) {
        option.resource_mode = self.wire_value().into();
    }

    pub const fn wire_value(self) -> option_message::ResourceMode {
        match self {
            Self::Normal => option_message::ResourceMode::ResourceModeNormal,
            Self::LowPower => option_message::ResourceMode::ResourceModeLowPower,
            Self::MinimizeGpu => option_message::ResourceMode::ResourceModeMinimizeGpu,
        }
    }

    pub fn from_wire_update(value: EnumOrUnknown<option_message::ResourceMode>) -> Option<Self> {
        match value.enum_value() {
            Ok(option_message::ResourceMode::ResourceModeNotSet) => None,
            Ok(option_message::ResourceMode::ResourceModeNormal) => Some(Self::Normal),
            Ok(option_message::ResourceMode::ResourceModeLowPower) => Some(Self::LowPower),
            Ok(option_message::ResourceMode::ResourceModeMinimizeGpu) => {
                Some(Self::MinimizeGpu)
            }
            Err(_) => Some(Self::Normal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf::Message as _;

    #[test]
    fn config_values_are_canonical_and_invalid_values_are_normal() {
        for (value, expected, canonical) in [
            ("normal", ResourceMode::Normal, "normal"),
            (" low-power ", ResourceMode::LowPower, "low-power"),
            ("minimize-gpu", ResourceMode::MinimizeGpu, "minimize-gpu"),
            ("LOW-POWER", ResourceMode::LowPower, "low-power"),
            ("invalid", ResourceMode::Normal, "normal"),
        ] {
            assert_eq!(ResourceMode::from_config(value), expected);
            assert_eq!(expected.config_value(), canonical);
        }
    }

    #[test]
    fn strongest_policy_and_limits_are_deterministic() {
        assert_eq!(
            ResourceMode::Normal.strongest(ResourceMode::LowPower),
            ResourceMode::LowPower
        );
        assert_eq!(
            ResourceMode::LowPower.strongest(ResourceMode::MinimizeGpu),
            ResourceMode::MinimizeGpu
        );
        assert_eq!(ResourceMode::Normal.active_fps_cap(), None);
        assert_eq!(ResourceMode::LowPower.active_fps_cap(), Some(10));
        assert_eq!(ResourceMode::MinimizeGpu.idle_fps(), Some(2));
        assert_eq!(
            ResourceMode::MinimizeGpu.idle_after(),
            Duration::from_secs(2)
        );
        assert!(ResourceMode::Normal.hardware_allowed());
        assert!(ResourceMode::LowPower.hardware_allowed());
        assert!(!ResourceMode::MinimizeGpu.hardware_allowed());
    }

    #[test]
    fn resource_mode_wire_mapping_round_trips_and_defaults_safely() {
        for mode in [
            ResourceMode::Normal,
            ResourceMode::LowPower,
            ResourceMode::MinimizeGpu,
        ] {
            let mut option = OptionMessage::new();
            mode.write_option(&mut option);
            let encoded = option.write_to_bytes().expect("resource option encodes");
            let decoded =
                OptionMessage::parse_from_bytes(&encoded).expect("resource option decodes");
            assert_eq!(
                ResourceMode::from_wire_update(decoded.resource_mode),
                Some(mode)
            );
        }

        let omitted = OptionMessage::new();
        assert_eq!(ResourceMode::from_wire_update(omitted.resource_mode), None);

        let unknown = OptionMessage::parse_from_bytes(&[0xb0, 0x01, 99])
            .expect("unknown resource enum remains wire-compatible");
        assert_eq!(
            ResourceMode::from_wire_update(unknown.resource_mode),
            Some(ResourceMode::Normal)
        );
    }
}
