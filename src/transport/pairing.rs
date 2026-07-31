use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const MAX_PEER_ID_BYTES: usize = 128;
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingCandidate {
    pub peer_id: String,
    pub identity_key: [u8; 32],
    pub certificate_der: Vec<u8>,
    pub certificate_pin: [u8; 32],
}

impl PairingCandidate {
    pub fn new(
        peer_id: String,
        identity_key: [u8; 32],
        certificate_der: Vec<u8>,
    ) -> Result<Self, PairingError> {
        validate_peer_id(&peer_id)?;
        if identity_key.iter().all(|byte| *byte == 0) {
            return Err(PairingError::InvalidIdentityKey);
        }
        if certificate_der.is_empty() || certificate_der.len() > MAX_CERTIFICATE_BYTES {
            return Err(PairingError::InvalidCertificate);
        }
        let certificate_pin = sha256_array(&certificate_der);
        Ok(Self {
            peer_id,
            identity_key,
            certificate_der,
            certificate_pin,
        })
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"rustadmin-peer-pairing-v1");
        hasher.update(self.identity_key);
        hasher.update(self.certificate_pin);
        format_fingerprint(&hasher.finalize())
    }

    pub fn confirm(
        self,
        confirmed_fingerprint: &str,
        confirmed_at_unix_ms: u64,
    ) -> Result<TrustedPeerRecord, PairingError> {
        if !constant_time_ascii_case_equal(&self.fingerprint(), confirmed_fingerprint) {
            return Err(PairingError::FingerprintMismatch);
        }
        Ok(TrustedPeerRecord {
            peer_id: self.peer_id,
            identity_key: self.identity_key,
            certificate_der: self.certificate_der,
            certificate_pin: self.certificate_pin,
            confirmed_at_unix_ms,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPeerRecord {
    pub peer_id: String,
    pub identity_key: [u8; 32],
    pub certificate_der: Vec<u8>,
    pub certificate_pin: [u8; 32],
    pub confirmed_at_unix_ms: u64,
}

impl TrustedPeerRecord {
    pub fn validate(&self) -> Result<(), PairingError> {
        validate_peer_id(&self.peer_id)?;
        if self.identity_key.iter().all(|byte| *byte == 0) {
            return Err(PairingError::InvalidIdentityKey);
        }
        if self.certificate_der.is_empty()
            || self.certificate_der.len() > MAX_CERTIFICATE_BYTES
            || sha256_array(&self.certificate_der) != self.certificate_pin
        {
            return Err(PairingError::InvalidCertificate);
        }
        Ok(())
    }
}

pub trait TrustedPeerStore {
    fn load(&self, peer_id: &str) -> Result<Option<TrustedPeerRecord>, PairingError>;
    fn insert(&mut self, record: TrustedPeerRecord) -> Result<(), PairingError>;
}

#[derive(Default)]
pub struct MemoryTrustedPeerStore {
    records: BTreeMap<String, TrustedPeerRecord>,
}

impl TrustedPeerStore for MemoryTrustedPeerStore {
    fn load(&self, peer_id: &str) -> Result<Option<TrustedPeerRecord>, PairingError> {
        validate_peer_id(peer_id)?;
        Ok(self.records.get(peer_id).cloned())
    }

    fn insert(&mut self, record: TrustedPeerRecord) -> Result<(), PairingError> {
        record.validate()?;
        if self.records.contains_key(&record.peer_id) {
            return Err(PairingError::AlreadyPaired);
        }
        self.records.insert(record.peer_id.clone(), record);
        Ok(())
    }
}

pub struct FileTrustedPeerStore {
    directory: PathBuf,
}

impl FileTrustedPeerStore {
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, PairingError> {
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(PairingError::Io)?;
        set_private_directory_permissions(&directory)?;
        Ok(Self { directory })
    }

    fn record_path(&self, peer_id: &str) -> Result<PathBuf, PairingError> {
        validate_peer_id(peer_id)?;
        let digest = Sha256::digest(peer_id.as_bytes());
        Ok(self.directory.join(format!("{}.json", hex_lower(&digest))))
    }

    pub fn load_all(&self) -> Result<Vec<TrustedPeerRecord>, PairingError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(PairingError::Io)? {
            let entry = entry.map_err(PairingError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            if records.len() >= 4_096 {
                return Err(PairingError::InvalidRecord);
            }
            let encoded = fs::read(&path).map_err(PairingError::Io)?;
            records.push(decode_record(&encoded)?);
        }
        records.sort_by(|left, right| left.peer_id.cmp(&right.peer_id));
        Ok(records)
    }
}

impl TrustedPeerStore for FileTrustedPeerStore {
    fn load(&self, peer_id: &str) -> Result<Option<TrustedPeerRecord>, PairingError> {
        let path = self.record_path(peer_id)?;
        let encoded = match fs::read(&path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(PairingError::Io(error)),
        };
        let record = decode_record(&encoded)?;
        if record.peer_id != peer_id {
            return Err(PairingError::InvalidRecord);
        }
        record.validate()?;
        Ok(Some(record))
    }

    fn insert(&mut self, record: TrustedPeerRecord) -> Result<(), PairingError> {
        record.validate()?;
        let path = self.record_path(&record.peer_id)?;
        if path.exists() {
            return Err(PairingError::AlreadyPaired);
        }
        let persisted = PersistedTrustedPeer::from_record(&record);
        let encoded =
            serde_json::to_vec_pretty(&persisted).map_err(|_| PairingError::InvalidRecord)?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(PairingError::Io)?;
        set_private_file_permissions(&temporary)?;
        if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(PairingError::Io(error));
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(PairingError::Io(error));
        }
        Ok(())
    }
}

fn decode_record(encoded: &[u8]) -> Result<TrustedPeerRecord, PairingError> {
    if encoded.len() > 64 * 1024 {
        return Err(PairingError::InvalidRecord);
    }
    let persisted: PersistedTrustedPeer =
        serde_json::from_slice(encoded).map_err(|_| PairingError::InvalidRecord)?;
    let record = persisted.into_record()?;
    record.validate()?;
    Ok(record)
}

#[derive(Serialize, Deserialize)]
struct PersistedTrustedPeer {
    version: u16,
    peer_id: String,
    identity_key_base64: String,
    certificate_der_base64: String,
    certificate_pin_base64: String,
    confirmed_at_unix_ms: u64,
}

impl PersistedTrustedPeer {
    fn from_record(record: &TrustedPeerRecord) -> Self {
        Self {
            version: 1,
            peer_id: record.peer_id.clone(),
            identity_key_base64: BASE64.encode(record.identity_key),
            certificate_der_base64: BASE64.encode(&record.certificate_der),
            certificate_pin_base64: BASE64.encode(record.certificate_pin),
            confirmed_at_unix_ms: record.confirmed_at_unix_ms,
        }
    }

    fn into_record(self) -> Result<TrustedPeerRecord, PairingError> {
        if self.version != 1 {
            return Err(PairingError::InvalidRecord);
        }
        let identity_key = decode_array::<32>(&self.identity_key_base64)?;
        let certificate_der = BASE64
            .decode(self.certificate_der_base64)
            .map_err(|_| PairingError::InvalidRecord)?;
        let certificate_pin = decode_array::<32>(&self.certificate_pin_base64)?;
        Ok(TrustedPeerRecord {
            peer_id: self.peer_id,
            identity_key,
            certificate_der,
            certificate_pin,
            confirmed_at_unix_ms: self.confirmed_at_unix_ms,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("peer identifier is invalid")]
    InvalidPeerId,
    #[error("peer identity key is invalid")]
    InvalidIdentityKey,
    #[error("peer TLS certificate or pin is invalid")]
    InvalidCertificate,
    #[error("pairing fingerprint does not match")]
    FingerprintMismatch,
    #[error("peer is already paired; explicit replacement is required")]
    AlreadyPaired,
    #[error("trusted-peer record is invalid")]
    InvalidRecord,
    #[error("trusted-peer storage failed: {0}")]
    Io(#[source] std::io::Error),
}

fn validate_peer_id(peer_id: &str) -> Result<(), PairingError> {
    if peer_id.is_empty()
        || peer_id.len() > MAX_PEER_ID_BYTES
        || peer_id.chars().any(|character| character.is_control())
    {
        return Err(PairingError::InvalidPeerId);
    }
    Ok(())
}

fn sha256_array(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn format_fingerprint(input: &[u8]) -> String {
    input
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn hex_lower(input: &[u8]) -> String {
    input.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn constant_time_ascii_case_equal(expected: &str, received: &str) -> bool {
    if expected.len() != received.len() {
        return false;
    }
    expected
        .bytes()
        .zip(received.bytes())
        .fold(0u8, |difference, (left, right)| {
            difference | (left.to_ascii_uppercase() ^ right.to_ascii_uppercase())
        })
        == 0
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], PairingError> {
    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| PairingError::InvalidRecord)?;
    decoded.try_into().map_err(|_| PairingError::InvalidRecord)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), PairingError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(PairingError::Io)
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), PairingError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), PairingError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(PairingError::Io)
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), PairingError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> PairingCandidate {
        PairingCandidate::new("peer-1".to_owned(), [7; 32], vec![1, 2, 3, 4]).unwrap()
    }

    #[test]
    fn pairing_requires_exact_explicit_fingerprint_confirmation() {
        let candidate = candidate();
        let fingerprint = candidate.fingerprint();
        assert_eq!(fingerprint.len(), 95);
        assert!(candidate.clone().confirm("00:11", 1).is_err());
        let record = candidate
            .confirm(&fingerprint.to_ascii_lowercase(), 1)
            .unwrap();
        assert_eq!(record.peer_id, "peer-1");
        assert!(record.validate().is_ok());
    }

    #[test]
    fn trust_store_refuses_silent_identity_replacement() {
        let candidate = candidate();
        let record = candidate
            .clone()
            .confirm(&candidate.fingerprint(), 1)
            .unwrap();
        let mut store = MemoryTrustedPeerStore::default();
        store.insert(record.clone()).unwrap();
        assert_eq!(store.load("peer-1").unwrap(), Some(record.clone()));
        assert!(matches!(
            store.insert(record),
            Err(PairingError::AlreadyPaired)
        ));
    }

    #[test]
    fn corrupted_certificate_pin_is_rejected() {
        let candidate = candidate();
        let mut record = candidate
            .clone()
            .confirm(&candidate.fingerprint(), 1)
            .unwrap();
        record.certificate_pin[0] ^= 1;
        assert!(matches!(
            record.validate(),
            Err(PairingError::InvalidCertificate)
        ));
    }

    #[test]
    fn file_store_lists_only_valid_bounded_records() {
        let directory = std::env::temp_dir().join(format!(
            "rustadmin-quic-trust-{}-{}",
            std::process::id(),
            crate::rand::random::<u64>()
        ));
        let mut store = FileTrustedPeerStore::new(&directory).unwrap();
        let candidate = candidate();
        store
            .insert(
                candidate
                    .clone()
                    .confirm(&candidate.fingerprint(), 1)
                    .unwrap(),
            )
            .unwrap();
        let records = store.load_all().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].peer_id, "peer-1");
        fs::remove_dir_all(directory).unwrap();
    }
}
