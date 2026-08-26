use super::protocol::{
    decode_header, decode_message, encode_message, MessageHeader, MessageType, ProtocolError,
    SessionId, FLAG_ACK_REQUIRED, FLAG_RESPONSE, HEADER_LEN,
};
use crate::{
    config::{keys, Config},
    rand::{rngs::OsRng, RngCore},
    sha2::{Digest, Sha256},
    sodiumoxide::crypto::sign,
};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
        server::danger::{ClientCertVerified, ClientCertVerifier},
        DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
    },
    ClientConfig, Connection, ConnectionError, Endpoint, MtuDiscoveryConfig, RecvStream,
    SendStream, ServerConfig, TransportConfig, VarInt,
};
use std::{
    convert::{TryFrom, TryInto},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

pub const ALPN_V1: &[u8] = b"rustadmin-quic-v1";
pub const ALPN_V2: &[u8] = b"rustadmin-quic-v2";
pub const ALPN_V3: &[u8] = b"rustadmin-quic-v3";
pub const ALPN_V4: &[u8] = b"rustadmin-quic-v4";
pub const ALPN: &[u8] = ALPN_V1;
pub const DEFAULT_QUIC_PORT: u16 = 48100;
pub const DEFAULT_INITIAL_MTU: u16 = 1200;
pub const DEFAULT_MAX_MTU: u16 = 1360;
pub const DEFAULT_DATAGRAM_BUFFER_BYTES: usize = 2 * 1024 * 1024;
pub const PEER_SERVER_NAME: &str = "rustadmin-peer";
pub const MAX_PEER_CERTIFICATE_BYTES: usize = 16 * 1024;

const EXPORTER_LABEL: &[u8] = b"EXPORTER-RustAdmin-QUIC-v1";
const EXPORTER_LEN: usize = 32;
const IDENTITY_PUBLIC_KEY_LEN: usize = sign::PUBLICKEYBYTES;
const IDENTITY_SIGNATURE_LEN: usize = sign::SIGNATUREBYTES;
const NONCE_LEN: usize = 32;
const CLIENT_HELLO_LEN: usize = 4 + IDENTITY_PUBLIC_KEY_LEN + NONCE_LEN + IDENTITY_SIGNATURE_LEN;
const SERVER_HELLO_LEN: usize =
    4 + IDENTITY_PUBLIC_KEY_LEN + NONCE_LEN + NONCE_LEN + IDENTITY_SIGNATURE_LEN;
const ROLE_CLIENT: u8 = 1;
const ROLE_SERVER: u8 = 2;
const AUTH_CLOSE_CODE: u32 = 0x100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum QuicApplicationProtocol {
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
}

impl QuicApplicationProtocol {
    pub fn supports_reliable_keyframes(self) -> bool {
        matches!(self, Self::V2 | Self::V3 | Self::V4)
    }

    pub fn supports_scoped_video_reference_refresh(self) -> bool {
        matches!(self, Self::V3 | Self::V4)
    }

    pub fn supports_reliable_keyframe_barrier(self) -> bool {
        matches!(self, Self::V4)
    }
}

fn provisional_signature_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
    ]
}

fn validate_provisional_certificate(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<(), TlsError> {
    if end_entity.is_empty()
        || end_entity.len() > MAX_PEER_CERTIFICATE_BYTES
        || intermediates
            .iter()
            .any(|certificate| certificate.len() > MAX_PEER_CERTIFICATE_BYTES)
    {
        return Err(TlsError::General(
            "invalid provisional peer certificate chain".to_owned(),
        ));
    }
    Ok(())
}

// Provisional TLS grants no application trust. The exporter-bound device proof and
// the existing pairing handshake must bind this exact certificate before use.
#[derive(Debug)]
struct ProvisionalServerCertificateVerifier;

impl ServerCertVerifier for ProvisionalServerCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        validate_provisional_certificate(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provisional_signature_schemes()
    }
}

#[derive(Debug, Default)]
struct ProvisionalClientCertificateVerifier {
    root_hints: Vec<DistinguishedName>,
}

impl ClientCertVerifier for ProvisionalClientCertificateVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        validate_provisional_certificate(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provisional_signature_schemes()
    }
}

#[derive(Clone, Debug)]
pub struct QuicTransportOptions {
    pub connect_timeout: Duration,
    pub authentication_timeout: Duration,
    pub idle_timeout: Duration,
    pub keepalive_interval: Duration,
    pub initial_mtu: u16,
    pub max_mtu: u16,
    pub datagram_receive_buffer_size: usize,
    pub datagram_send_buffer_size: usize,
    pub enable_application_protocol_v2: bool,
}

impl Default for QuicTransportOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            authentication_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(15),
            keepalive_interval: Duration::from_secs(5),
            initial_mtu: DEFAULT_INITIAL_MTU,
            max_mtu: DEFAULT_MAX_MTU,
            datagram_receive_buffer_size: DEFAULT_DATAGRAM_BUFFER_BYTES,
            datagram_send_buffer_size: DEFAULT_DATAGRAM_BUFFER_BYTES,
            enable_application_protocol_v2: true,
        }
    }
}

pub struct TlsCredentials {
    pub certificate_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl TlsCredentials {
    pub fn new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, QuicTransportError> {
        if certificate_chain.is_empty() {
            return Err(QuicTransportError::Configuration(
                "TLS certificate chain is empty".to_owned(),
            ));
        }
        Ok(Self {
            certificate_chain,
            private_key,
        })
    }
}

pub struct DeviceIdentity {
    secret_key: sign::SecretKey,
    public_key: sign::PublicKey,
}

impl DeviceIdentity {
    pub fn from_config() -> Result<Self, QuicTransportError> {
        let (secret_key, public_key) = Config::get_key_pair();
        Self::from_bytes(&secret_key, &public_key)
    }

    pub fn from_bytes(secret_key: &[u8], public_key: &[u8]) -> Result<Self, QuicTransportError> {
        sodiumoxide_init()?;
        let secret_key = sign::SecretKey::from_slice(secret_key).ok_or_else(|| {
            QuicTransportError::Configuration("invalid device signing secret key".to_owned())
        })?;
        let public_key = sign::PublicKey::from_slice(public_key).ok_or_else(|| {
            QuicTransportError::Configuration("invalid device signing public key".to_owned())
        })?;
        if secret_key.public_key() != public_key {
            return Err(QuicTransportError::Configuration(
                "device signing keypair does not match".to_owned(),
            ));
        }
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn public_key_bytes(&self) -> [u8; IDENTITY_PUBLIC_KEY_LEN] {
        self.public_key.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificatePin(pub [u8; 32]);

impl CertificatePin {
    pub fn from_certificate(certificate: &CertificateDer<'_>) -> Self {
        let digest = Sha256::digest(certificate.as_ref());
        let mut pin = [0u8; 32];
        pin.copy_from_slice(&digest);
        Self(pin)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReliableKeyframeMark {
    pub display: i32,
    pub stream_id: u64,
    pub barrier_epoch: u64,
    pub age_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicConnectionStats {
    pub rtt_us: u64,
    pub congestion_window_bytes: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub sent_packets: u64,
    pub current_mtu: u16,
    pub max_datagram_size: Option<usize>,
    pub black_holes_detected: u64,
    pub application_protocol: u16,
    pub negotiated_datagram_size: Option<usize>,
    pub reliable_keyframes: bool,
    pub reliable_keyframe_barrier: bool,
    pub video_reassembly_drops: u64,
    pub video_reassembly_expired: u64,
    pub video_reassembly_evicted: u64,
    pub video_reassembly_obsolete: u64,
    pub video_reassembly_pre_keyframe: u64,
    pub video_reassembly_expired_keyframes: u64,
    pub video_reassembly_missing_fragments: u64,
    pub video_reassembly_last_us: u64,
    pub video_reassembly_max_us: u64,
    pub video_reassembly_max_gap_us: u64,
    pub video_reassembly_last_frame_bytes: u64,
    pub video_reassembly_last_frame_fragments: u64,
    pub video_keyframe_requests: u64,
    pub reliable_keyframes_sent: u64,
    pub reliable_keyframe_last_bytes: u64,
    pub reliable_keyframe_last_mark: Option<ReliableKeyframeMark>,
    pub reliable_keyframes_received: u64,
    pub video_source_frame_gaps: u64,
    pub video_recovery_suppressed_frames: u64,
    pub video_sender_replacements: u64,
    pub video_sender_reference_resets: u64,
    pub video_keyframe_barrier_held: u64,
    pub video_keyframe_barrier_released: u64,
    pub video_keyframe_barrier_timeouts: u64,
    pub video_keyframe_barrier_overflows: u64,
    pub video_keyframe_barrier_gap_events: u64,
    pub video_keyframe_barrier_gap_skipped_frames: u64,
    pub video_datagram_frames_sent: u64,
    pub video_datagram_frames_rejected: u64,
    pub video_datagram_frames_rejected_active: u64,
    pub video_datagram_frames_rejected_teardown: u64,
    pub video_frames_discarded_teardown: u64,
    pub video_datagrams_sent: u64,
    pub video_datagram_frame_bytes: u64,
    pub video_datagram_frame_bytes_peak: u64,
    pub video_datagram_frame_fragments: u64,
    pub video_datagram_frame_fragments_peak: u64,
    pub video_datagram_frame_bytes_p95: u64,
    pub video_datagram_frame_bytes_p99: u64,
    pub video_datagram_required_bytes_p95: u64,
    pub video_datagram_required_bytes_p99: u64,
    pub datagram_send_buffer_space: u64,
    pub datagram_send_buffer_space_min: u64,
    pub datagram_send_buffer_queued: u64,
    pub video_datagram_queue_budget: u64,
    pub video_datagram_queue_delay_us: u64,
    pub video_datagram_queue_target_us: u64,
    pub audio_datagram_drops: u64,
    pub mouse_datagram_drops: u64,
}

impl QuicConnectionStats {
    pub fn capture(connection: &Connection) -> Self {
        let stats = connection.stats();
        Self {
            rtt_us: stats.path.rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            congestion_window_bytes: stats.path.cwnd,
            lost_packets: stats.path.lost_packets,
            lost_bytes: stats.path.lost_bytes,
            sent_packets: stats.path.sent_packets,
            current_mtu: stats.path.current_mtu,
            max_datagram_size: connection.max_datagram_size(),
            black_holes_detected: stats.path.black_holes_detected,
            application_protocol: 0,
            negotiated_datagram_size: None,
            reliable_keyframes: false,
            reliable_keyframe_barrier: false,
            video_reassembly_drops: 0,
            video_reassembly_expired: 0,
            video_reassembly_evicted: 0,
            video_reassembly_obsolete: 0,
            video_reassembly_pre_keyframe: 0,
            video_reassembly_expired_keyframes: 0,
            video_reassembly_missing_fragments: 0,
            video_reassembly_last_us: 0,
            video_reassembly_max_us: 0,
            video_reassembly_max_gap_us: 0,
            video_reassembly_last_frame_bytes: 0,
            video_reassembly_last_frame_fragments: 0,
            video_keyframe_requests: 0,
            reliable_keyframes_sent: 0,
            reliable_keyframe_last_bytes: 0,
            reliable_keyframe_last_mark: None,
            reliable_keyframes_received: 0,
            video_source_frame_gaps: 0,
            video_recovery_suppressed_frames: 0,
            video_sender_replacements: 0,
            video_sender_reference_resets: 0,
            video_keyframe_barrier_held: 0,
            video_keyframe_barrier_released: 0,
            video_keyframe_barrier_timeouts: 0,
            video_keyframe_barrier_overflows: 0,
            video_keyframe_barrier_gap_events: 0,
            video_keyframe_barrier_gap_skipped_frames: 0,
            video_datagram_frames_sent: 0,
            video_datagram_frames_rejected: 0,
            video_datagram_frames_rejected_active: 0,
            video_datagram_frames_rejected_teardown: 0,
            video_frames_discarded_teardown: 0,
            video_datagrams_sent: 0,
            video_datagram_frame_bytes: 0,
            video_datagram_frame_bytes_peak: 0,
            video_datagram_frame_fragments: 0,
            video_datagram_frame_fragments_peak: 0,
            video_datagram_frame_bytes_p95: 0,
            video_datagram_frame_bytes_p99: 0,
            video_datagram_required_bytes_p95: 0,
            video_datagram_required_bytes_p99: 0,
            datagram_send_buffer_space: 0,
            datagram_send_buffer_space_min: 0,
            datagram_send_buffer_queued: 0,
            video_datagram_queue_budget: 0,
            video_datagram_queue_delay_us: 0,
            video_datagram_queue_target_us: 0,
            audio_datagram_drops: 0,
            mouse_datagram_drops: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicPeerBinding {
    pub identity_key: [u8; IDENTITY_PUBLIC_KEY_LEN],
    pub certificate_der: Vec<u8>,
    pub certificate_pin: CertificatePin,
}

impl QuicPeerBinding {
    pub fn capture(
        authentication: &AuthenticatedControlChannel,
    ) -> Result<Self, QuicTransportError> {
        let certificate = peer_certificate_der(&authentication.connection())?;
        Ok(Self {
            identity_key: authentication.peer_identity_key(),
            certificate_pin: CertificatePin::from_certificate(&certificate),
            certificate_der: certificate.as_ref().to_vec(),
        })
    }

    pub fn verify_signed_identity(
        &self,
        identity_key: &[u8],
        certificate_der: &[u8],
    ) -> Result<(), QuicTransportError> {
        if self.identity_key.as_slice() != identity_key
            || self.certificate_der.as_slice() != certificate_der
        {
            return Err(QuicTransportError::Authentication(
                "signed identity does not match the TLS peer and exporter proof".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct QuicServerEndpoint {
    endpoint: Endpoint,
    expected_client_certificates: Option<Vec<CertificatePin>>,
    connect_timeout: Duration,
}

impl QuicServerEndpoint {
    pub fn bind(
        bind_address: SocketAddr,
        credentials: TlsCredentials,
        trusted_client_certificate: CertificateDer<'static>,
        options: &QuicTransportOptions,
    ) -> Result<Self, QuicTransportError> {
        ensure_udp_enabled()?;
        Self::bind_trusted_certificates(
            bind_address,
            credentials,
            vec![trusted_client_certificate],
            options,
        )
    }

    pub fn bind_trusted_certificates(
        bind_address: SocketAddr,
        credentials: TlsCredentials,
        trusted_client_certificates: Vec<CertificateDer<'static>>,
        options: &QuicTransportOptions,
    ) -> Result<Self, QuicTransportError> {
        ensure_udp_enabled()?;
        if trusted_client_certificates.is_empty() {
            return Err(QuicTransportError::Configuration(
                "at least one trusted QUIC client certificate is required".to_owned(),
            ));
        }
        let expected_client_certificates = trusted_client_certificates
            .iter()
            .map(CertificatePin::from_certificate)
            .collect();
        let server_config = build_server_config(credentials, trusted_client_certificates, options)?;
        let endpoint = Endpoint::server(server_config, bind_address)
            .map_err(|error| QuicTransportError::UdpBind(error.to_string()))?;
        log::info!(
            "QUIC UDP listener active: address={}, initial_mtu={}, max_mtu={}, datagram_receive_buffer={}, datagram_send_buffer={}",
            endpoint
                .local_addr()
                .map(|address| address.to_string())
                .unwrap_or_else(|_| bind_address.to_string()),
            options.initial_mtu,
            options.max_mtu,
            options.datagram_receive_buffer_size,
            options.datagram_send_buffer_size
        );
        Ok(Self {
            endpoint,
            expected_client_certificates: Some(expected_client_certificates),
            connect_timeout: options.connect_timeout,
        })
    }

    pub fn bind_provisional(
        bind_address: SocketAddr,
        credentials: TlsCredentials,
        options: &QuicTransportOptions,
    ) -> Result<Self, QuicTransportError> {
        ensure_udp_enabled()?;
        let server_config = build_provisional_server_config(credentials, options)?;
        let endpoint = Endpoint::server(server_config, bind_address)
            .map_err(|error| QuicTransportError::UdpBind(error.to_string()))?;
        log::info!(
            "QUIC UDP listener active: address={}, initial_mtu={}, max_mtu={}, datagram_receive_buffer={}, datagram_send_buffer={}, first_contact=bounded",
            endpoint
                .local_addr()
                .map(|address| address.to_string())
                .unwrap_or_else(|_| bind_address.to_string()),
            options.initial_mtu,
            options.max_mtu,
            options.datagram_receive_buffer_size,
            options.datagram_send_buffer_size
        );
        Ok(Self {
            endpoint,
            expected_client_certificates: None,
            connect_timeout: options.connect_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicTransportError> {
        self.endpoint
            .local_addr()
            .map_err(|error| QuicTransportError::UdpBind(error.to_string()))
    }

    pub async fn accept(&self) -> Result<Connection, QuicTransportError> {
        let incoming = tokio::time::timeout(self.connect_timeout, self.endpoint.accept())
            .await
            .map_err(|_| QuicTransportError::Timeout("accept"))?
            .ok_or(QuicTransportError::EndpointClosed)?;
        let connection = tokio::time::timeout(self.connect_timeout, incoming)
            .await
            .map_err(|_| QuicTransportError::Timeout("handshake"))?
            .map_err(|error| QuicTransportError::Handshake(error.to_string()))?;
        if let Some(expected) = self.expected_client_certificates.as_ref() {
            let actual = peer_certificate_pin(&connection)?;
            if !expected.contains(&actual) {
                return Err(QuicTransportError::CertificatePinMismatch);
            }
        } else {
            peer_certificate_der(&connection)?;
        }
        log_connection("accepted", &connection);
        Ok(connection)
    }

    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"endpoint closed");
    }

    pub async fn close_and_wait(&self) {
        self.close();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
    }
}

pub struct QuicClientEndpoint {
    endpoint: Endpoint,
    expected_server_certificate: Option<CertificatePin>,
    connect_timeout: Duration,
}

impl QuicClientEndpoint {
    pub fn bind(
        bind_address: SocketAddr,
        credentials: TlsCredentials,
        trusted_server_certificate: CertificateDer<'static>,
        options: &QuicTransportOptions,
    ) -> Result<Self, QuicTransportError> {
        ensure_udp_enabled()?;
        let expected_server_certificate =
            CertificatePin::from_certificate(&trusted_server_certificate);
        let client_config = build_client_config(credentials, trusted_server_certificate, options)?;
        let mut endpoint = Endpoint::client(bind_address)
            .map_err(|error| QuicTransportError::UdpBind(error.to_string()))?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            expected_server_certificate: Some(expected_server_certificate),
            connect_timeout: options.connect_timeout,
        })
    }

    pub fn bind_provisional(
        bind_address: SocketAddr,
        credentials: TlsCredentials,
        options: &QuicTransportOptions,
    ) -> Result<Self, QuicTransportError> {
        ensure_udp_enabled()?;
        let client_config = build_provisional_client_config(credentials, options)?;
        let mut endpoint = Endpoint::client(bind_address)
            .map_err(|error| QuicTransportError::UdpBind(error.to_string()))?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            expected_server_certificate: None,
            connect_timeout: options.connect_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicTransportError> {
        self.endpoint
            .local_addr()
            .map_err(|error| QuicTransportError::UdpBind(error.to_string()))
    }

    pub async fn connect(
        &self,
        peer_address: SocketAddr,
    ) -> Result<Connection, QuicTransportError> {
        let connecting = self
            .endpoint
            .connect(peer_address, PEER_SERVER_NAME)
            .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
        let connection = tokio::time::timeout(self.connect_timeout, connecting)
            .await
            .map_err(|_| QuicTransportError::Timeout("connect"))?
            .map_err(|error| match error {
                ConnectionError::TimedOut | ConnectionError::Reset => {
                    QuicTransportError::Unreachable(error.to_string())
                }
                _ => QuicTransportError::Handshake(error.to_string()),
            })?;
        if let Some(expected) = self.expected_server_certificate {
            verify_peer_certificate(&connection, expected)?;
        } else {
            peer_certificate_der(&connection)?;
        }
        log_connection("connected", &connection);
        Ok(connection)
    }

    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"endpoint closed");
    }

    pub fn lease(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

pub struct AuthenticatedControlChannel {
    connection: Connection,
    send: SendStream,
    receive: RecvStream,
    session_id: SessionId,
    next_outgoing_sequence: u64,
    last_incoming_sequence: u64,
    started: Instant,
    peer_identity_key: [u8; IDENTITY_PUBLIC_KEY_LEN],
}

impl AuthenticatedControlChannel {
    pub async fn authenticate_client(
        connection: Connection,
        identity: &DeviceIdentity,
        expected_server_identity_key: [u8; IDENTITY_PUBLIC_KEY_LEN],
        session_id: SessionId,
        timeout: Duration,
    ) -> Result<Self, QuicTransportError> {
        let result = tokio::time::timeout(
            timeout,
            authenticate_client_inner(
                connection.clone(),
                identity,
                Some(expected_server_identity_key),
                session_id,
            ),
        )
        .await
        .map_err(|_| QuicTransportError::Timeout("application authentication"))?;
        if result.is_err() {
            connection.close(
                VarInt::from_u32(AUTH_CLOSE_CODE),
                b"application authentication failed",
            );
        }
        result
    }

    pub async fn authenticate_client_discover_peer(
        connection: Connection,
        identity: &DeviceIdentity,
        session_id: SessionId,
        timeout: Duration,
    ) -> Result<Self, QuicTransportError> {
        let result = tokio::time::timeout(
            timeout,
            authenticate_client_inner(connection.clone(), identity, None, session_id),
        )
        .await
        .map_err(|_| QuicTransportError::Timeout("provisional application authentication"))?;
        if result.is_err() {
            connection.close(
                VarInt::from_u32(AUTH_CLOSE_CODE),
                b"provisional application authentication failed",
            );
        }
        result
    }

    pub async fn authenticate_server(
        connection: Connection,
        identity: &DeviceIdentity,
        expected_client_identity_key: [u8; IDENTITY_PUBLIC_KEY_LEN],
        session_id: SessionId,
        timeout: Duration,
    ) -> Result<Self, QuicTransportError> {
        let result = tokio::time::timeout(
            timeout,
            authenticate_server_inner(
                connection.clone(),
                identity,
                Some(expected_client_identity_key),
                session_id,
            ),
        )
        .await
        .map_err(|_| QuicTransportError::Timeout("application authentication"))?;
        if result.is_err() {
            connection.close(
                VarInt::from_u32(AUTH_CLOSE_CODE),
                b"application authentication failed",
            );
        }
        result
    }

    pub async fn authenticate_server_discover_session(
        connection: Connection,
        identity: &DeviceIdentity,
        expected_client_identity_key: [u8; IDENTITY_PUBLIC_KEY_LEN],
        timeout: Duration,
    ) -> Result<Self, QuicTransportError> {
        let result = tokio::time::timeout(
            timeout,
            authenticate_server_discover_session_inner(
                connection.clone(),
                identity,
                Some(expected_client_identity_key),
            ),
        )
        .await
        .map_err(|_| QuicTransportError::Timeout("application authentication"))?;
        if result.is_err() {
            connection.close(
                VarInt::from_u32(AUTH_CLOSE_CODE),
                b"application authentication failed",
            );
        }
        result
    }

    pub async fn authenticate_server_discover_peer(
        connection: Connection,
        identity: &DeviceIdentity,
        timeout: Duration,
    ) -> Result<Self, QuicTransportError> {
        let result = tokio::time::timeout(
            timeout,
            authenticate_server_discover_session_inner(connection.clone(), identity, None),
        )
        .await
        .map_err(|_| QuicTransportError::Timeout("provisional application authentication"))?;
        if result.is_err() {
            connection.close(
                VarInt::from_u32(AUTH_CLOSE_CODE),
                b"provisional application authentication failed",
            );
        }
        result
    }

    pub fn peer_identity_key(&self) -> [u8; IDENTITY_PUBLIC_KEY_LEN] {
        self.peer_identity_key
    }

    pub fn stats(&self) -> QuicConnectionStats {
        QuicConnectionStats::capture(&self.connection)
    }

    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub async fn send_control(
        &mut self,
        message_type: MessageType,
        flags: u16,
        payload: &[u8],
    ) -> Result<u64, QuicTransportError> {
        if message_type.channel() != super::protocol::ChannelId::Control
            || matches!(
                message_type,
                MessageType::ClientHello | MessageType::ServerHello
            )
        {
            return Err(QuicTransportError::ProtocolState(format!(
                "message {message_type:?} is invalid after control authentication"
            )));
        }
        let sequence = self.take_sequence()?;
        let header = MessageHeader::new(
            message_type,
            flags,
            self.session_id,
            sequence,
            payload.len(),
            elapsed_us(self.started),
        )?;
        write_message(&mut self.send, &header, payload).await?;
        Ok(sequence)
    }

    pub async fn receive_control(&mut self) -> Result<ControlMessage, QuicTransportError> {
        self.read_control_message().await
    }

    pub async fn ping(&mut self) -> Result<Duration, QuicTransportError> {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let sequence = self.take_sequence()?;
        let header = MessageHeader::new(
            MessageType::Ping,
            FLAG_ACK_REQUIRED,
            self.session_id,
            sequence,
            nonce.len(),
            elapsed_us(self.started),
        )?;
        let started = Instant::now();
        write_message(&mut self.send, &header, &nonce).await?;
        let response = self.read_control_message().await?;
        if response.header.message_type != MessageType::Pong
            || response.header.flags & FLAG_RESPONSE == 0
            || response.payload != nonce
        {
            return Err(QuicTransportError::Authentication(
                "invalid ping response".to_owned(),
            ));
        }
        Ok(started.elapsed())
    }

    pub async fn respond_to_ping(&mut self) -> Result<(), QuicTransportError> {
        let request = self.read_control_message().await?;
        if request.header.message_type != MessageType::Ping || request.payload.len() != 8 {
            return Err(QuicTransportError::Authentication(
                "expected a bounded ping request".to_owned(),
            ));
        }
        let sequence = self.take_sequence()?;
        let header = MessageHeader::new(
            MessageType::Pong,
            FLAG_RESPONSE,
            self.session_id,
            sequence,
            request.payload.len(),
            elapsed_us(self.started),
        )?;
        write_message(&mut self.send, &header, &request.payload).await
    }

    pub fn close(&self, reason: &[u8]) {
        let reason = &reason[..reason.len().min(256)];
        self.connection.close(VarInt::from_u32(0), reason);
    }

    fn take_sequence(&mut self) -> Result<u64, QuicTransportError> {
        let sequence = self.next_outgoing_sequence;
        self.next_outgoing_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| QuicTransportError::ProtocolState("sequence exhausted".to_owned()))?;
        Ok(sequence)
    }

    async fn read_control_message(&mut self) -> Result<ControlMessage, QuicTransportError> {
        let message = read_message(&mut self.receive).await?;
        if message.header.session_id != self.session_id {
            return Err(QuicTransportError::ProtocolState(
                "control message session identifier changed".to_owned(),
            ));
        }
        if message.header.sequence_number <= self.last_incoming_sequence {
            return Err(QuicTransportError::ProtocolState(
                "duplicate or out-of-order control sequence".to_owned(),
            ));
        }
        self.last_incoming_sequence = message.header.sequence_number;
        Ok(message)
    }
}

#[derive(Debug)]
pub struct ControlMessage {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum QuicTransportError {
    #[error("UDP is disabled by the global transport setting")]
    UdpDisabled,
    #[error("QUIC configuration error: {0}")]
    Configuration(String),
    #[error("failed to bind QUIC UDP socket: {0}")]
    UdpBind(String),
    #[error("QUIC endpoint is closed")]
    EndpointClosed,
    #[error("QUIC {0} timed out")]
    Timeout(&'static str),
    #[error("QUIC peer is unreachable: {0}")]
    Unreachable(String),
    #[error("QUIC TLS handshake failed: {0}")]
    Handshake(String),
    #[error("QUIC peer certificate pin mismatch")]
    CertificatePinMismatch,
    #[error("QUIC peer certificate is unavailable")]
    MissingPeerCertificate,
    #[error("QUIC application authentication failed: {0}")]
    Authentication(String),
    #[error("QUIC stream error: {0}")]
    Stream(String),
    #[error("QUIC datagram error: {0}")]
    Datagram(String),
    #[error("QUIC protocol state error: {0}")]
    ProtocolState(String),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

fn ensure_udp_enabled() -> Result<(), QuicTransportError> {
    if Config::get_option(keys::OPTION_DISABLE_UDP) == "Y" {
        Err(QuicTransportError::UdpDisabled)
    } else {
        Ok(())
    }
}

fn supported_alpn_protocols(options: &QuicTransportOptions) -> Vec<Vec<u8>> {
    if options.enable_application_protocol_v2 {
        vec![
            ALPN_V4.to_vec(),
            ALPN_V3.to_vec(),
            ALPN_V2.to_vec(),
            ALPN_V1.to_vec(),
        ]
    } else {
        vec![ALPN_V1.to_vec()]
    }
}

pub fn negotiated_application_protocol(
    connection: &Connection,
) -> Result<QuicApplicationProtocol, QuicTransportError> {
    let handshake = connection
        .handshake_data()
        .ok_or_else(|| {
            QuicTransportError::Handshake("TLS handshake metadata is unavailable".to_owned())
        })?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| {
            QuicTransportError::Handshake("unexpected TLS handshake metadata".to_owned())
        })?;
    match handshake.protocol.as_deref() {
        Some(ALPN_V4) => Ok(QuicApplicationProtocol::V4),
        Some(ALPN_V3) => Ok(QuicApplicationProtocol::V3),
        Some(ALPN_V2) => Ok(QuicApplicationProtocol::V2),
        Some(ALPN_V1) => Ok(QuicApplicationProtocol::V1),
        Some(protocol) => Err(QuicTransportError::Handshake(format!(
            "unsupported negotiated ALPN {}",
            String::from_utf8_lossy(protocol)
        ))),
        None => Err(QuicTransportError::Handshake(
            "TLS peer did not negotiate an ALPN".to_owned(),
        )),
    }
}

fn build_server_config(
    credentials: TlsCredentials,
    trusted_client_certificates: Vec<CertificateDer<'static>>,
    options: &QuicTransportOptions,
) -> Result<ServerConfig, QuicTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for certificate in trusted_client_certificates {
        roots
            .add(certificate)
            .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    }
    let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(credentials.certificate_chain, credentials.private_key)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    crypto.alpn_protocols = supported_alpn_protocols(options);
    let crypto = QuicServerConfig::try_from(crypto)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(build_transport_config(options)?);
    Ok(config)
}

fn build_provisional_server_config(
    credentials: TlsCredentials,
    options: &QuicTransportOptions,
) -> Result<ServerConfig, QuicTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?
        .with_client_cert_verifier(Arc::new(ProvisionalClientCertificateVerifier::default()))
        .with_single_cert(credentials.certificate_chain, credentials.private_key)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    crypto.alpn_protocols = supported_alpn_protocols(options);
    let crypto = QuicServerConfig::try_from(crypto)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(build_transport_config(options)?);
    Ok(config)
}

fn build_client_config(
    credentials: TlsCredentials,
    trusted_server_certificate: CertificateDer<'static>,
    options: &QuicTransportOptions,
) -> Result<ClientConfig, QuicTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(trusted_server_certificate)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?
        .with_root_certificates(roots)
        .with_client_auth_cert(credentials.certificate_chain, credentials.private_key)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    crypto.alpn_protocols = supported_alpn_protocols(options);
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(build_transport_config(options)?);
    Ok(config)
}

fn build_provisional_client_config(
    credentials: TlsCredentials,
    options: &QuicTransportOptions,
) -> Result<ClientConfig, QuicTransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProvisionalServerCertificateVerifier))
        .with_client_auth_cert(credentials.certificate_chain, credentials.private_key)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    crypto.alpn_protocols = supported_alpn_protocols(options);
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(build_transport_config(options)?);
    Ok(config)
}

fn build_transport_config(
    options: &QuicTransportOptions,
) -> Result<Arc<TransportConfig>, QuicTransportError> {
    if options.initial_mtu < DEFAULT_INITIAL_MTU {
        return Err(QuicTransportError::Configuration(format!(
            "QUIC initial MTU {} is below the required minimum {}",
            options.initial_mtu, DEFAULT_INITIAL_MTU
        )));
    }
    if options.max_mtu < options.initial_mtu {
        return Err(QuicTransportError::Configuration(format!(
            "QUIC maximum MTU {} is below initial MTU {}",
            options.max_mtu, options.initial_mtu
        )));
    }
    let idle_timeout =
        options
            .idle_timeout
            .try_into()
            .map_err(|error: quinn::VarIntBoundsExceeded| {
                QuicTransportError::Configuration(error.to_string())
            })?;
    let mut mtu_discovery = MtuDiscoveryConfig::default();
    mtu_discovery.upper_bound(options.max_mtu);
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(
            (!options.keepalive_interval.is_zero()).then_some(options.keepalive_interval),
        )
        .max_concurrent_bidi_streams(32_u32.into())
        .max_concurrent_uni_streams(32_u32.into())
        .initial_mtu(options.initial_mtu)
        .min_mtu(DEFAULT_INITIAL_MTU)
        .mtu_discovery_config(Some(mtu_discovery))
        .datagram_receive_buffer_size(Some(options.datagram_receive_buffer_size))
        .datagram_send_buffer_size(options.datagram_send_buffer_size);
    Ok(Arc::new(transport))
}

fn verify_peer_certificate(
    connection: &Connection,
    expected: CertificatePin,
) -> Result<(), QuicTransportError> {
    let certificate = peer_certificate_der(connection)?;
    if CertificatePin::from_certificate(&certificate) != expected {
        return Err(QuicTransportError::CertificatePinMismatch);
    }
    Ok(())
}

pub fn peer_certificate_der(
    connection: &Connection,
) -> Result<CertificateDer<'static>, QuicTransportError> {
    let identity = connection
        .peer_identity()
        .ok_or(QuicTransportError::MissingPeerCertificate)?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| QuicTransportError::MissingPeerCertificate)?;
    let certificate = certificates
        .first()
        .ok_or(QuicTransportError::MissingPeerCertificate)?;
    if certificate.is_empty() || certificate.len() > MAX_PEER_CERTIFICATE_BYTES {
        return Err(QuicTransportError::Handshake(
            "peer certificate is empty or oversized".to_owned(),
        ));
    }
    Ok(certificate.clone())
}

pub fn peer_certificate_pin(connection: &Connection) -> Result<CertificatePin, QuicTransportError> {
    Ok(CertificatePin::from_certificate(&peer_certificate_der(
        connection,
    )?))
}

fn log_connection(action: &str, connection: &Connection) {
    let stats = QuicConnectionStats::capture(connection);
    log::info!(
        "QUIC connection {}: peer={}, rtt_us={}, mtu={}, max_datagram_size={:?}, lost_packets={}, black_holes={}",
        action,
        connection.remote_address(),
        stats.rtt_us,
        stats.current_mtu,
        stats.max_datagram_size,
        stats.lost_packets,
        stats.black_holes_detected
    );
}

async fn authenticate_client_inner(
    connection: Connection,
    identity: &DeviceIdentity,
    expected_server_identity_key: Option<[u8; IDENTITY_PUBLIC_KEY_LEN]>,
    session_id: SessionId,
) -> Result<AuthenticatedControlChannel, QuicTransportError> {
    let started = Instant::now();
    let exporter = export_keying_material(&connection, &session_id)?;
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    send.set_priority(i32::MAX)
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    let mut client_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut client_nonce);
    let client_payload = encode_client_hello(identity, &session_id, &exporter, &client_nonce);
    let header = MessageHeader::new(
        MessageType::ClientHello,
        FLAG_ACK_REQUIRED,
        session_id,
        1,
        client_payload.len(),
        elapsed_us(started),
    )?;
    write_message(&mut send, &header, &client_payload).await?;

    let response = read_message(&mut receive).await?;
    if response.header.message_type != MessageType::ServerHello
        || response.header.session_id != session_id
        || response.header.sequence_number != 1
        || response.header.flags & FLAG_RESPONSE == 0
    {
        return Err(QuicTransportError::Authentication(
            "invalid server hello header".to_owned(),
        ));
    }
    let (server_key, server_nonce) = parse_server_hello(
        &response.payload,
        &session_id,
        &exporter,
        &client_nonce,
        &identity.public_key_bytes(),
    )?;
    if expected_server_identity_key.is_some_and(|expected| server_key != expected) {
        return Err(QuicTransportError::Authentication(
            "server device identity key is not trusted".to_owned(),
        ));
    }
    let _ = server_nonce;

    Ok(AuthenticatedControlChannel {
        connection,
        send,
        receive,
        session_id,
        next_outgoing_sequence: 2,
        last_incoming_sequence: 1,
        started,
        peer_identity_key: server_key,
    })
}

async fn authenticate_server_inner(
    connection: Connection,
    identity: &DeviceIdentity,
    expected_client_identity_key: Option<[u8; IDENTITY_PUBLIC_KEY_LEN]>,
    session_id: SessionId,
) -> Result<AuthenticatedControlChannel, QuicTransportError> {
    let started = Instant::now();
    let exporter = export_keying_material(&connection, &session_id)?;
    let (mut send, mut receive) = connection
        .accept_bi()
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    send.set_priority(i32::MAX)
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    let request = read_message(&mut receive).await?;
    if request.header.message_type != MessageType::ClientHello
        || request.header.session_id != session_id
        || request.header.sequence_number != 1
        || request.header.flags & FLAG_ACK_REQUIRED == 0
    {
        return Err(QuicTransportError::Authentication(
            "invalid client hello header".to_owned(),
        ));
    }
    let (client_key, client_nonce) = parse_client_hello(&request.payload, &session_id, &exporter)?;
    if expected_client_identity_key.is_some_and(|expected| client_key != expected) {
        return Err(QuicTransportError::Authentication(
            "client device identity key is not trusted".to_owned(),
        ));
    }

    let mut server_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut server_nonce);
    let server_payload = encode_server_hello(
        identity,
        &session_id,
        &exporter,
        &client_key,
        &client_nonce,
        &server_nonce,
    );
    let header = MessageHeader::new(
        MessageType::ServerHello,
        FLAG_RESPONSE,
        session_id,
        1,
        server_payload.len(),
        elapsed_us(started),
    )?;
    write_message(&mut send, &header, &server_payload).await?;

    Ok(AuthenticatedControlChannel {
        connection,
        send,
        receive,
        session_id,
        next_outgoing_sequence: 2,
        last_incoming_sequence: 1,
        started,
        peer_identity_key: client_key,
    })
}

async fn authenticate_server_discover_session_inner(
    connection: Connection,
    identity: &DeviceIdentity,
    expected_client_identity_key: Option<[u8; IDENTITY_PUBLIC_KEY_LEN]>,
) -> Result<AuthenticatedControlChannel, QuicTransportError> {
    let started = Instant::now();
    let (mut send, mut receive) = connection
        .accept_bi()
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    send.set_priority(i32::MAX)
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    let request = read_message(&mut receive).await?;
    if request.header.message_type != MessageType::ClientHello
        || request.header.sequence_number != 1
        || request.header.flags & FLAG_ACK_REQUIRED == 0
    {
        return Err(QuicTransportError::Authentication(
            "invalid client hello header".to_owned(),
        ));
    }
    let session_id = request.header.session_id;
    let exporter = export_keying_material(&connection, &session_id)?;
    let (client_key, client_nonce) = parse_client_hello(&request.payload, &session_id, &exporter)?;
    if expected_client_identity_key.is_some_and(|expected| client_key != expected) {
        return Err(QuicTransportError::Authentication(
            "client device identity key is not trusted".to_owned(),
        ));
    }
    let mut server_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut server_nonce);
    let server_payload = encode_server_hello(
        identity,
        &session_id,
        &exporter,
        &client_key,
        &client_nonce,
        &server_nonce,
    );
    let header = MessageHeader::new(
        MessageType::ServerHello,
        FLAG_RESPONSE,
        session_id,
        1,
        server_payload.len(),
        elapsed_us(started),
    )?;
    write_message(&mut send, &header, &server_payload).await?;
    Ok(AuthenticatedControlChannel {
        connection,
        send,
        receive,
        session_id,
        next_outgoing_sequence: 2,
        last_incoming_sequence: 1,
        started,
        peer_identity_key: client_key,
    })
}

fn export_keying_material(
    connection: &Connection,
    session_id: &SessionId,
) -> Result<[u8; EXPORTER_LEN], QuicTransportError> {
    let mut exporter = [0u8; EXPORTER_LEN];
    connection
        .export_keying_material(&mut exporter, EXPORTER_LABEL, session_id)
        .map_err(|_| {
            QuicTransportError::Authentication(
                "TLS exporter keying material is unavailable".to_owned(),
            )
        })?;
    Ok(exporter)
}

fn encode_client_hello(
    identity: &DeviceIdentity,
    session_id: &SessionId,
    exporter: &[u8; EXPORTER_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let public_key = identity.public_key_bytes();
    let transcript = client_transcript(session_id, exporter, &public_key, nonce);
    let signature = sign::sign_detached(&transcript, &identity.secret_key);
    let mut payload = Vec::with_capacity(CLIENT_HELLO_LEN);
    payload.extend_from_slice(&[ROLE_CLIENT, 0, 0, 0]);
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(signature.as_ref());
    payload
}

fn parse_client_hello(
    payload: &[u8],
    session_id: &SessionId,
    exporter: &[u8; EXPORTER_LEN],
) -> Result<([u8; IDENTITY_PUBLIC_KEY_LEN], [u8; NONCE_LEN]), QuicTransportError> {
    if payload.len() != CLIENT_HELLO_LEN || payload[..4] != [ROLE_CLIENT, 0, 0, 0] {
        return Err(QuicTransportError::Authentication(
            "malformed client hello".to_owned(),
        ));
    }
    let public_key = copy_array::<IDENTITY_PUBLIC_KEY_LEN>(&payload[4..36]);
    let nonce = copy_array::<NONCE_LEN>(&payload[36..68]);
    let signature_bytes = copy_array::<IDENTITY_SIGNATURE_LEN>(&payload[68..132]);
    let public_key_value = sign::PublicKey::from_slice(&public_key).ok_or_else(|| {
        QuicTransportError::Authentication("invalid client identity key".to_owned())
    })?;
    let signature = sign::Signature::from_bytes(&signature_bytes).map_err(|_| {
        QuicTransportError::Authentication("invalid client signature encoding".to_owned())
    })?;
    let transcript = client_transcript(session_id, exporter, &public_key, &nonce);
    if !sign::verify_detached(&signature, &transcript, &public_key_value) {
        return Err(QuicTransportError::Authentication(
            "client identity signature verification failed".to_owned(),
        ));
    }
    Ok((public_key, nonce))
}

fn encode_server_hello(
    identity: &DeviceIdentity,
    session_id: &SessionId,
    exporter: &[u8; EXPORTER_LEN],
    client_key: &[u8; IDENTITY_PUBLIC_KEY_LEN],
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let public_key = identity.public_key_bytes();
    let transcript = server_transcript(
        session_id,
        exporter,
        client_key,
        client_nonce,
        &public_key,
        server_nonce,
    );
    let signature = sign::sign_detached(&transcript, &identity.secret_key);
    let mut payload = Vec::with_capacity(SERVER_HELLO_LEN);
    payload.extend_from_slice(&[ROLE_SERVER, 0, 0, 0]);
    payload.extend_from_slice(&public_key);
    payload.extend_from_slice(server_nonce);
    payload.extend_from_slice(client_nonce);
    payload.extend_from_slice(signature.as_ref());
    payload
}

fn parse_server_hello(
    payload: &[u8],
    session_id: &SessionId,
    exporter: &[u8; EXPORTER_LEN],
    client_nonce: &[u8; NONCE_LEN],
    client_key: &[u8; IDENTITY_PUBLIC_KEY_LEN],
) -> Result<([u8; IDENTITY_PUBLIC_KEY_LEN], [u8; NONCE_LEN]), QuicTransportError> {
    if payload.len() != SERVER_HELLO_LEN || payload[..4] != [ROLE_SERVER, 0, 0, 0] {
        return Err(QuicTransportError::Authentication(
            "malformed server hello".to_owned(),
        ));
    }
    let public_key = copy_array::<IDENTITY_PUBLIC_KEY_LEN>(&payload[4..36]);
    let server_nonce = copy_array::<NONCE_LEN>(&payload[36..68]);
    let echoed_client_nonce = copy_array::<NONCE_LEN>(&payload[68..100]);
    if &echoed_client_nonce != client_nonce {
        return Err(QuicTransportError::Authentication(
            "server hello client nonce mismatch".to_owned(),
        ));
    }
    let signature_bytes = copy_array::<IDENTITY_SIGNATURE_LEN>(&payload[100..164]);
    let public_key_value = sign::PublicKey::from_slice(&public_key).ok_or_else(|| {
        QuicTransportError::Authentication("invalid server identity key".to_owned())
    })?;
    let signature = sign::Signature::from_bytes(&signature_bytes).map_err(|_| {
        QuicTransportError::Authentication("invalid server signature encoding".to_owned())
    })?;
    let transcript = server_transcript(
        session_id,
        exporter,
        client_key,
        client_nonce,
        &public_key,
        &server_nonce,
    );
    if !sign::verify_detached(&signature, &transcript, &public_key_value) {
        return Err(QuicTransportError::Authentication(
            "server identity signature verification failed".to_owned(),
        ));
    }
    Ok((public_key, server_nonce))
}

fn client_transcript(
    session_id: &SessionId,
    exporter: &[u8; EXPORTER_LEN],
    public_key: &[u8; IDENTITY_PUBLIC_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(32 + EXPORTER_LEN + 16 + 32 + 32);
    transcript.extend_from_slice(b"rustadmin-quic-client-auth-v1");
    transcript.extend_from_slice(exporter);
    transcript.extend_from_slice(session_id);
    transcript.extend_from_slice(public_key);
    transcript.extend_from_slice(nonce);
    transcript
}

fn server_transcript(
    session_id: &SessionId,
    exporter: &[u8; EXPORTER_LEN],
    client_key: &[u8; IDENTITY_PUBLIC_KEY_LEN],
    client_nonce: &[u8; NONCE_LEN],
    server_key: &[u8; IDENTITY_PUBLIC_KEY_LEN],
    server_nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(32 + EXPORTER_LEN + 16 + 32 + 32 + 32 + 32);
    transcript.extend_from_slice(b"rustadmin-quic-server-auth-v1");
    transcript.extend_from_slice(exporter);
    transcript.extend_from_slice(session_id);
    transcript.extend_from_slice(client_key);
    transcript.extend_from_slice(client_nonce);
    transcript.extend_from_slice(server_key);
    transcript.extend_from_slice(server_nonce);
    transcript
}

async fn write_message(
    stream: &mut SendStream,
    header: &MessageHeader,
    payload: &[u8],
) -> Result<(), QuicTransportError> {
    let packet = encode_message(header, payload)?;
    stream
        .write_all(&packet)
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))
}

async fn read_message(stream: &mut RecvStream) -> Result<ControlMessage, QuicTransportError> {
    let mut encoded_header = [0u8; HEADER_LEN];
    stream
        .read_exact(&mut encoded_header)
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    let header = decode_header(&encoded_header)?;
    let mut payload = vec![0u8; header.payload_length as usize];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|error| QuicTransportError::Stream(error.to_string()))?;
    let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
    packet.extend_from_slice(&encoded_header);
    packet.extend_from_slice(&payload);
    let parsed = decode_message(&packet)?;
    Ok(ControlMessage {
        header: parsed.header,
        payload,
    })
}

fn sodiumoxide_init() -> Result<(), QuicTransportError> {
    crate::sodiumoxide::init()
        .map_err(|_| QuicTransportError::Configuration("failed to initialize libsodium".to_owned()))
}

fn elapsed_us(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

fn copy_array<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut output = [0u8; N];
    output.copy_from_slice(input);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{
        audio_datagram::{AudioCodec, AudioJitterConfig, AudioPlayoutItem},
        datagram::{
            DatagramReceiveEvent, QuicDatagramReceiver, QuicDatagramSender,
            VideoDatagramSendOutcome,
        },
        input::{MouseMovement, MouseMovementMode},
        reliable::{ReliableChannel, ReliableChannelKind},
        session::{
            decode_session_acceptance, decode_session_offer, encode_session_acceptance,
            encode_session_offer, negotiate_session, validate_session_acceptance, LatencyMode,
            SessionOffer, CAP_CLIPBOARD_RECEIVE, CAP_CLIPBOARD_SEND, CAP_FILE_TRANSFER,
            CAP_INPUT_RECEIVE, CAP_INPUT_SEND, COLOR_I420,
        },
        video_datagram::{VideoCodec, VideoFrameMetadata, VideoReassemblyConfig},
    };
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
    use std::net::{IpAddr, Ipv4Addr};

    struct TestCertificate {
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
    }

    impl TestCertificate {
        fn credentials(&self) -> TlsCredentials {
            TlsCredentials::new(
                vec![self.certificate.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(self.private_key.clone()).into(),
            )
            .unwrap()
        }
    }

    fn certificate() -> TestCertificate {
        let mut params = CertificateParams::new(vec![PEER_SERVER_NAME.to_owned()]).unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key_pair = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key_pair).unwrap();
        TestCertificate {
            certificate: certificate.der().clone(),
            private_key: key_pair.serialize_der(),
        }
    }

    fn device_identity() -> DeviceIdentity {
        sodiumoxide_init().unwrap();
        let (public_key, secret_key) = sign::gen_keypair();
        DeviceIdentity::from_bytes(&secret_key.0, &public_key.0).unwrap()
    }

    async fn negotiate_test_alpn(
        server_v2: bool,
        client_v2: bool,
    ) -> Option<(QuicApplicationProtocol, QuicApplicationProtocol)> {
        let server_certificate = certificate();
        let client_certificate = certificate();
        let server_options = QuicTransportOptions {
            connect_timeout: Duration::from_secs(2),
            enable_application_protocol_v2: server_v2,
            ..Default::default()
        };
        let client_options = QuicTransportOptions {
            connect_timeout: Duration::from_secs(2),
            enable_application_protocol_v2: client_v2,
            ..Default::default()
        };
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = match QuicServerEndpoint::bind(
            bind,
            server_certificate.credentials(),
            client_certificate.certificate.clone(),
            &server_options,
        ) {
            Ok(server) => server,
            Err(QuicTransportError::UdpBind(error))
                if error.contains("Operation not permitted") =>
            {
                return None
            }
            Err(error) => panic!("server endpoint failed: {}", error),
        };
        let client = QuicClientEndpoint::bind(
            bind,
            client_certificate.credentials(),
            server_certificate.certificate.clone(),
            &client_options,
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            let protocol = negotiated_application_protocol(&connection).unwrap();
            connection.close(0u32.into(), b"ALPN test complete");
            protocol
        });
        let connection = client.connect(server_address).await.unwrap();
        let client_protocol = negotiated_application_protocol(&connection).unwrap();
        let server_protocol = server_task.await.unwrap();
        client.close();
        Some((client_protocol, server_protocol))
    }

    #[tokio::test]
    async fn alpn_v4_is_preferred_and_older_peers_remain_compatible() {
        let Some(v4) = negotiate_test_alpn(true, true).await else {
            return;
        };
        assert_eq!(
            v4,
            (QuicApplicationProtocol::V4, QuicApplicationProtocol::V4)
        );
        assert_eq!(
            negotiate_test_alpn(false, true).await,
            Some((QuicApplicationProtocol::V1, QuicApplicationProtocol::V1))
        );
        assert_eq!(
            negotiate_test_alpn(true, false).await,
            Some((QuicApplicationProtocol::V1, QuicApplicationProtocol::V1))
        );
    }

    fn session_offer() -> SessionOffer {
        SessionOffer {
            minimum_protocol_version: 1,
            maximum_protocol_version: 1,
            capabilities: CAP_CLIPBOARD_SEND
                | CAP_CLIPBOARD_RECEIVE
                | CAP_FILE_TRANSFER
                | CAP_INPUT_SEND
                | CAP_INPUT_RECEIVE,
            latency_mode: LatencyMode::LowLatency,
            video_codecs: vec![VideoCodec::H264],
            audio_codecs: vec![AudioCodec::Opus],
            color_formats: COLOR_I420,
            max_width: 1920,
            max_height: 1080,
            max_fps: 60,
            max_datagram_payload: 1200,
            max_video_bitrate_kbps: 50_000,
            max_file_bitrate_kbps: 20_000,
        }
    }

    #[tokio::test]
    async fn mutual_tls_identity_binding_and_ping_round_trip() {
        let server_certificate = certificate();
        let client_certificate = certificate();
        let server_identity = device_identity();
        let client_identity = device_identity();
        let server_identity_key = server_identity.public_key_bytes();
        let client_identity_key = client_identity.public_key_bytes();
        let options = QuicTransportOptions {
            connect_timeout: Duration::from_secs(2),
            authentication_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = match QuicServerEndpoint::bind(
            bind,
            server_certificate.credentials(),
            client_certificate.certificate.clone(),
            &options,
        ) {
            Ok(server) => server,
            Err(QuicTransportError::UdpBind(error))
                if error.contains("Operation not permitted") =>
            {
                return
            }
            Err(error) => panic!("server endpoint failed: {}", error),
        };
        let client = QuicClientEndpoint::bind(
            bind,
            client_certificate.credentials(),
            server_certificate.certificate.clone(),
            &options,
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let session_id = [9; 16];
        let authentication_timeout = options.authentication_timeout;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let (datagram_ready_tx, datagram_ready_rx) = tokio::sync::oneshot::channel();
        let idle_gap =
            VideoReassemblyConfig::default().fragment_deadline + Duration::from_millis(50);

        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            let mut channel = AuthenticatedControlChannel::authenticate_server(
                connection,
                &server_identity,
                client_identity_key,
                session_id,
                authentication_timeout,
            )
            .await
            .unwrap();
            assert_eq!(channel.peer_identity_key(), client_identity_key);
            channel.respond_to_ping().await.unwrap();
            let offer_message = channel.receive_control().await.unwrap();
            assert_eq!(offer_message.header.message_type, MessageType::SessionOffer);
            let client_offer = decode_session_offer(&offer_message.payload).unwrap();
            let server_offer = session_offer();
            let agreement = negotiate_session(&client_offer, &server_offer).unwrap();
            channel
                .send_control(
                    MessageType::SessionAccept,
                    0,
                    &encode_session_acceptance(&server_offer, &agreement).unwrap(),
                )
                .await
                .unwrap();
            let mut input = ReliableChannel::accept(&channel.connection(), session_id)
                .await
                .unwrap();
            assert_eq!(input.kind(), ReliableChannelKind::Input);
            let input_message = input.receive().await.unwrap();
            assert_eq!(
                input_message.header.message_type,
                MessageType::ReliableInput
            );
            assert_eq!(input_message.payload, b"key-down");
            input
                .send(MessageType::ReliableInput, 0, 1, b"input-ack")
                .await
                .unwrap();

            let mut file = ReliableChannel::accept(&channel.connection(), session_id)
                .await
                .unwrap();
            assert_eq!(file.kind(), ReliableChannelKind::FileTransfer);
            let file_message = file.receive().await.unwrap();
            assert_eq!(file_message.header.message_type, MessageType::FileChunk);
            assert_eq!(file_message.payload, vec![7; 4096]);

            let mut datagrams = QuicDatagramReceiver::new(
                channel.connection(),
                session_id,
                VideoReassemblyConfig::default(),
                AudioJitterConfig::default(),
            )
            .unwrap();
            let _ = datagram_ready_tx.send(());
            let mut video_frame = None;
            let mut audio_received = false;
            let mut mouse_movement = None;
            tokio::time::timeout(Duration::from_secs(2), async {
                while video_frame.is_none() || !audio_received || mouse_movement.is_none() {
                    match datagrams.receive().await.unwrap() {
                        DatagramReceiveEvent::Video(outcome) => {
                            video_frame = outcome.frame;
                        }
                        DatagramReceiveEvent::AudioAccepted => audio_received = true,
                        DatagramReceiveEvent::Mouse(movement) => mouse_movement = movement,
                        DatagramReceiveEvent::ApplicationMouse(_) => {}
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(video_frame.unwrap().payload, vec![8; 5000]);
            assert_eq!(datagrams.video_stats().expired_frames, 0);
            let mouse_movement: MouseMovement = mouse_movement.unwrap();
            assert_eq!(mouse_movement.mode, MouseMovementMode::Absolute);
            assert_eq!((mouse_movement.x, mouse_movement.y), (640, 480));
            assert_eq!(
                datagrams.pop_audio(Instant::now() + Duration::from_millis(31)),
                Some(AudioPlayoutItem::Packet(
                    crate::transport::audio_datagram::AudioPacket {
                        metadata: crate::transport::audio_datagram::AudioPacketMetadata {
                            sequence_number: 1,
                            capture_timestamp_us: 123,
                            codec: AudioCodec::Opus,
                            channels: 2,
                            sample_rate_hz: 48_000,
                        },
                        payload: vec![9; 120],
                    }
                ))
            );
            let _ = done_rx.await;
            channel.close(b"test complete");
        });

        let connection = client.connect(server_address).await.unwrap();
        let mut channel = AuthenticatedControlChannel::authenticate_client(
            connection,
            &client_identity,
            server_identity_key,
            session_id,
            authentication_timeout,
        )
        .await
        .unwrap();
        assert_eq!(channel.peer_identity_key(), server_identity_key);
        let rtt = channel.ping().await.unwrap();
        assert!(rtt < Duration::from_secs(2));
        assert!(channel.stats().current_mtu >= DEFAULT_INITIAL_MTU);

        let offer = session_offer();
        channel
            .send_control(
                MessageType::SessionOffer,
                0,
                &encode_session_offer(&offer).unwrap(),
            )
            .await
            .unwrap();
        let agreement_message = channel.receive_control().await.unwrap();
        assert_eq!(
            agreement_message.header.message_type,
            MessageType::SessionAccept
        );
        let (server_offer, agreement) =
            decode_session_acceptance(&agreement_message.payload).unwrap();
        validate_session_acceptance(&offer, &server_offer, &agreement).unwrap();

        let mut input = ReliableChannel::open(
            &channel.connection(),
            ReliableChannelKind::Input,
            session_id,
        )
        .await
        .unwrap();
        input
            .send(MessageType::ReliableInput, 0, 1, b"key-down")
            .await
            .unwrap();
        let input_ack = input.receive().await.unwrap();
        assert_eq!(input_ack.payload, b"input-ack");

        let mut file = ReliableChannel::open(
            &channel.connection(),
            ReliableChannelKind::FileTransfer,
            session_id,
        )
        .await
        .unwrap();
        file.send(MessageType::FileChunk, 0, 2, &vec![7; 4096])
            .await
            .unwrap();

        let _ = datagram_ready_rx.await;
        // An idle display must not age the first fragment by time spent waiting for it.
        tokio::time::sleep(idle_gap).await;
        let mut datagrams = QuicDatagramSender::new(channel.connection(), session_id);
        let video_fragments = datagrams
            .send_video_frame(
                VideoFrameMetadata {
                    frame_id: 1,
                    codec: VideoCodec::H264,
                    flags: crate::transport::video_datagram::FLAG_KEYFRAME,
                    presentation_timestamp_us: 100,
                },
                &vec![8; 5000],
            )
            .unwrap();
        assert!(matches!(
            video_fragments,
            VideoDatagramSendOutcome::Sent { fragment_count } if fragment_count > 1
        ));
        datagrams
            .send_audio_packet(123, AudioCodec::Opus, 2, 48_000, &vec![9; 120])
            .unwrap();
        datagrams
            .send_mouse_movement(MouseMovementMode::Absolute, 640, 480, 0, 1)
            .unwrap();
        let _ = done_tx.send(());
        server_task.await.unwrap();
        client.close();
    }

    #[tokio::test]
    async fn provisional_tls_is_bound_to_discovered_device_identities() {
        let server_certificate = certificate();
        let client_certificate = certificate();
        let server_certificate_der = server_certificate.certificate.as_ref().to_vec();
        let client_certificate_der = client_certificate.certificate.as_ref().to_vec();
        let server_identity = device_identity();
        let client_identity = device_identity();
        let server_identity_key = server_identity.public_key_bytes();
        let client_identity_key = client_identity.public_key_bytes();
        let options = QuicTransportOptions {
            connect_timeout: Duration::from_secs(2),
            authentication_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = match QuicServerEndpoint::bind_provisional(
            bind,
            server_certificate.credentials(),
            &options,
        ) {
            Ok(server) => server,
            Err(QuicTransportError::UdpBind(error))
                if error.contains("Operation not permitted") =>
            {
                return
            }
            Err(error) => panic!("server endpoint failed: {}", error),
        };
        let client =
            QuicClientEndpoint::bind_provisional(bind, client_certificate.credentials(), &options)
                .unwrap();
        let server_address = server.local_addr().unwrap();
        let session_id = [7; 16];
        let authentication_timeout = options.authentication_timeout;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            let mut channel = AuthenticatedControlChannel::authenticate_server_discover_peer(
                connection,
                &server_identity,
                authentication_timeout,
            )
            .await
            .unwrap();
            let binding = QuicPeerBinding::capture(&channel).unwrap();
            assert_eq!(binding.identity_key, client_identity_key);
            assert_eq!(binding.certificate_der, client_certificate_der);
            binding
                .verify_signed_identity(&client_identity_key, &client_certificate_der)
                .unwrap();
            assert!(binding
                .verify_signed_identity(&server_identity_key, &client_certificate_der)
                .is_err());
            channel.respond_to_ping().await.unwrap();
            let _ = done_rx.await;
        });

        let connection = client.connect(server_address).await.unwrap();
        let mut channel = AuthenticatedControlChannel::authenticate_client_discover_peer(
            connection,
            &client_identity,
            session_id,
            authentication_timeout,
        )
        .await
        .unwrap();
        let binding = QuicPeerBinding::capture(&channel).unwrap();
        assert_eq!(binding.identity_key, server_identity_key);
        assert_eq!(binding.certificate_der, server_certificate_der);
        channel.ping().await.unwrap();
        let _ = done_tx.send(());
        server_task.await.unwrap();
        client.close();
    }

    #[test]
    fn identity_binding_rejects_mismatched_keypair() {
        sodiumoxide_init().unwrap();
        let (public_key, secret_key) = sign::gen_keypair();
        let (other_public_key, _) = sign::gen_keypair();
        assert!(DeviceIdentity::from_bytes(&secret_key.0, &public_key.0).is_ok());
        assert!(DeviceIdentity::from_bytes(&secret_key.0, &other_public_key.0).is_err());
    }

    #[test]
    fn transport_rejects_mtu_below_quic_minimum() {
        let options = QuicTransportOptions {
            initial_mtu: DEFAULT_INITIAL_MTU - 1,
            ..Default::default()
        };
        assert!(build_transport_config(&options).is_err());

        let options = QuicTransportOptions {
            initial_mtu: DEFAULT_MAX_MTU,
            max_mtu: DEFAULT_INITIAL_MTU,
            ..Default::default()
        };
        assert!(build_transport_config(&options).is_err());
    }
}
