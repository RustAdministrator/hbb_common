use crate::config::{keys, Config};
use std::{collections::HashMap, net::IpAddr, path::PathBuf, str::FromStr, time::Duration};

pub const DEFAULT_QUIC_PORT: u16 = 48100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteTransportMode {
    Tcp,
    QuicPreferred,
    QuicOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkTransportConfig {
    pub mode: RemoteTransportMode,
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub connect_timeout: Duration,
    pub keepalive_interval: Duration,
    pub enable_ipv6: bool,
    pub file_bandwidth_limit_mbps: u32,
    pub trusted_peer_store: PathBuf,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NetworkConfigError {
    #[error("unknown remote transport mode {0}")]
    InvalidMode(String),
    #[error("invalid QUIC listen address {0}")]
    InvalidListenAddress(String),
    #[error("invalid QUIC UDP port {0}")]
    InvalidPort(String),
    #[error("invalid QUIC connect timeout {0}")]
    InvalidConnectTimeout(String),
    #[error("invalid QUIC keepalive interval {0}")]
    InvalidKeepalive(String),
    #[error("invalid QUIC file-transfer bandwidth limit {0}")]
    InvalidFileBandwidth(String),
}

impl NetworkTransportConfig {
    pub fn load() -> Result<Self, NetworkConfigError> {
        let mut values = HashMap::new();
        for key in [
            keys::OPTION_DISABLE_UDP,
            keys::OPTION_REMOTE_TRANSPORT,
            keys::OPTION_QUIC_LISTEN_ADDRESS,
            keys::OPTION_QUIC_LISTEN_PORT,
            keys::OPTION_QUIC_CONNECT_TIMEOUT_MS,
            keys::OPTION_QUIC_KEEPALIVE_INTERVAL_MS,
            keys::OPTION_QUIC_ENABLE_IPV6,
            keys::OPTION_QUIC_FILE_BANDWIDTH_MBPS,
        ] {
            values.insert(key.to_owned(), Config::get_option(key));
        }
        let trusted_peer_store = Config::file()
            .parent()
            .map(|parent| parent.join("trusted-peers-quic"))
            .unwrap_or_else(|| PathBuf::from("trusted-peers-quic"));
        Self::from_values(&values, trusted_peer_store)
    }

    pub fn from_values(
        values: &HashMap<String, String>,
        trusted_peer_store: PathBuf,
    ) -> Result<Self, NetworkConfigError> {
        let value = |key: &str| values.get(key).map(String::as_str).unwrap_or("");
        let udp_disabled = value(keys::OPTION_DISABLE_UDP) == "Y";
        let configured_mode = match value(keys::OPTION_REMOTE_TRANSPORT) {
            "" | "quic-preferred" => RemoteTransportMode::QuicPreferred,
            "tcp" => RemoteTransportMode::Tcp,
            "quic-only" => RemoteTransportMode::QuicOnly,
            invalid => return Err(NetworkConfigError::InvalidMode(invalid.to_owned())),
        };
        let mode = if udp_disabled {
            RemoteTransportMode::Tcp
        } else {
            configured_mode
        };
        let listen_address_value = value(keys::OPTION_QUIC_LISTEN_ADDRESS);
        let listen_address = if listen_address_value.is_empty() {
            IpAddr::from([0, 0, 0, 0])
        } else {
            IpAddr::from_str(listen_address_value).map_err(|_| {
                NetworkConfigError::InvalidListenAddress(listen_address_value.to_owned())
            })?
        };
        let listen_port = parse_or_default::<u16>(
            value(keys::OPTION_QUIC_LISTEN_PORT),
            DEFAULT_QUIC_PORT,
            NetworkConfigError::InvalidPort,
        )?;
        if listen_port == 0 {
            return Err(NetworkConfigError::InvalidPort("0".to_owned()));
        }
        let connect_timeout_ms = parse_or_default::<u64>(
            value(keys::OPTION_QUIC_CONNECT_TIMEOUT_MS),
            5_000,
            NetworkConfigError::InvalidConnectTimeout,
        )?;
        if !(250..=60_000).contains(&connect_timeout_ms) {
            return Err(NetworkConfigError::InvalidConnectTimeout(
                connect_timeout_ms.to_string(),
            ));
        }
        let keepalive_interval_ms = parse_or_default::<u64>(
            value(keys::OPTION_QUIC_KEEPALIVE_INTERVAL_MS),
            5_000,
            NetworkConfigError::InvalidKeepalive,
        )?;
        if keepalive_interval_ms != 0 && !(1_000..=60_000).contains(&keepalive_interval_ms) {
            return Err(NetworkConfigError::InvalidKeepalive(
                keepalive_interval_ms.to_string(),
            ));
        }
        let file_bandwidth_limit_mbps = parse_or_default::<u32>(
            value(keys::OPTION_QUIC_FILE_BANDWIDTH_MBPS),
            20,
            NetworkConfigError::InvalidFileBandwidth,
        )?;
        if file_bandwidth_limit_mbps > 10_000 {
            return Err(NetworkConfigError::InvalidFileBandwidth(
                file_bandwidth_limit_mbps.to_string(),
            ));
        }
        let enable_ipv6 = value(keys::OPTION_QUIC_ENABLE_IPV6) != "N";
        if !enable_ipv6 && listen_address.is_ipv6() {
            return Err(NetworkConfigError::InvalidListenAddress(
                listen_address.to_string(),
            ));
        }
        Ok(Self {
            mode,
            listen_address,
            listen_port,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            keepalive_interval: Duration::from_millis(keepalive_interval_ms),
            enable_ipv6,
            file_bandwidth_limit_mbps,
            trusted_peer_store,
        })
    }
}

fn parse_or_default<T: FromStr>(
    value: &str,
    default: T,
    error: fn(String) -> NetworkConfigError,
) -> Result<T, NetworkConfigError> {
    if value.is_empty() {
        return Ok(default);
    }
    value.parse().map_err(|_| error(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_quic_with_automatic_tcp_fallback() {
        let config =
            NetworkTransportConfig::from_values(&HashMap::new(), PathBuf::from("trusted")).unwrap();
        assert_eq!(config.mode, RemoteTransportMode::QuicPreferred);
        assert_eq!(config.listen_port, DEFAULT_QUIC_PORT);
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn disable_udp_is_an_emergency_kill_switch() {
        let values = HashMap::from([
            (
                keys::OPTION_REMOTE_TRANSPORT.to_owned(),
                "quic-only".to_owned(),
            ),
            (keys::OPTION_DISABLE_UDP.to_owned(), "Y".to_owned()),
        ]);
        let config =
            NetworkTransportConfig::from_values(&values, PathBuf::from("trusted")).unwrap();
        assert_eq!(config.mode, RemoteTransportMode::Tcp);
    }

    #[test]
    fn quic_options_are_strictly_validated() {
        let values = HashMap::from([
            (
                keys::OPTION_REMOTE_TRANSPORT.to_owned(),
                "quic-preferred".to_owned(),
            ),
            (
                keys::OPTION_QUIC_LISTEN_ADDRESS.to_owned(),
                "10.20.30.2".to_owned(),
            ),
            (keys::OPTION_QUIC_LISTEN_PORT.to_owned(), "48101".to_owned()),
        ]);
        let config =
            NetworkTransportConfig::from_values(&values, PathBuf::from("trusted")).unwrap();
        assert_eq!(config.mode, RemoteTransportMode::QuicPreferred);
        assert_eq!(config.listen_address, IpAddr::from([10, 20, 30, 2]));
        assert_eq!(config.listen_port, 48101);
    }

    #[test]
    fn ipv6_disabled_rejects_ipv6_listener() {
        let values = HashMap::from([
            (keys::OPTION_QUIC_LISTEN_ADDRESS.to_owned(), "::".to_owned()),
            (keys::OPTION_QUIC_ENABLE_IPV6.to_owned(), "N".to_owned()),
        ]);
        assert!(matches!(
            NetworkTransportConfig::from_values(&values, PathBuf::from("trusted")),
            Err(NetworkConfigError::InvalidListenAddress(_))
        ));
    }
}
