use super::quic::{QuicTransportError, TlsCredentials, PEER_SERVER_NAME};
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const CERTIFICATE_FILE: &str = "certificate.der";
const PRIVATE_KEY_FILE: &str = "private-key.pk8";
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;

pub struct LocalTlsIdentity {
    certificate: CertificateDer<'static>,
    private_key_pkcs8: Vec<u8>,
}

impl LocalTlsIdentity {
    pub fn load_or_create(directory: impl AsRef<Path>) -> Result<Self, QuicTransportError> {
        // The direct server and the first certificate request create the identity at the same
        // start-up: one creates it, the other loads it.
        static CREATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _creating = CREATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let directory = directory.as_ref();
        fs::create_dir_all(directory)
            .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
        set_private_directory_permissions(directory)?;
        let certificate_path = directory.join(CERTIFICATE_FILE);
        let private_key_path = directory.join(PRIVATE_KEY_FILE);
        match (certificate_path.exists(), private_key_path.exists()) {
            (true, true) => Self::load(&certificate_path, &private_key_path),
            (false, false) => Self::generate(directory, &certificate_path, &private_key_path),
            _ => Err(QuicTransportError::Configuration(
                "QUIC TLS identity is incomplete; refusing silent key replacement".to_owned(),
            )),
        }
    }

    pub fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }

    pub fn certificate_bytes(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    pub fn credentials(&self) -> Result<TlsCredentials, QuicTransportError> {
        TlsCredentials::new(
            vec![self.certificate.clone()],
            PrivatePkcs8KeyDer::from(self.private_key_pkcs8.clone()).into(),
        )
    }

    fn load(certificate_path: &Path, private_key_path: &Path) -> Result<Self, QuicTransportError> {
        let certificate = read_bounded(certificate_path, MAX_CERTIFICATE_BYTES)?;
        let private_key_pkcs8 = read_bounded(private_key_path, MAX_PRIVATE_KEY_BYTES)?;
        if certificate.is_empty() || private_key_pkcs8.is_empty() {
            return Err(QuicTransportError::Configuration(
                "QUIC TLS identity file is empty".to_owned(),
            ));
        }
        set_private_file_permissions(private_key_path)?;
        Ok(Self {
            certificate: CertificateDer::from(certificate),
            private_key_pkcs8,
        })
    }

    fn generate(
        directory: &Path,
        certificate_path: &Path,
        private_key_path: &Path,
    ) -> Result<Self, QuicTransportError> {
        let mut params = CertificateParams::new(vec![PEER_SERVER_NAME.to_owned()])
            .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key_pair = KeyPair::generate()
            .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
        let certificate_der = certificate.der().to_vec();
        let private_key_pkcs8 = key_pair.serialize_der();

        write_atomic(directory, private_key_path, &private_key_pkcs8, true)?;
        if let Err(error) = write_atomic(directory, certificate_path, &certificate_der, false) {
            let _ = fs::remove_file(private_key_path);
            return Err(error);
        }
        log::info!(
            "Generated persistent QUIC TLS identity in {}",
            directory.display()
        );
        Ok(Self {
            certificate: CertificateDer::from(certificate_der),
            private_key_pkcs8,
        })
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, QuicTransportError> {
    let metadata =
        fs::metadata(path).map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    if metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(QuicTransportError::Configuration(format!(
            "QUIC TLS identity file {} has an invalid size",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| QuicTransportError::Configuration(error.to_string()))
}

fn write_atomic(
    directory: &Path,
    destination: &Path,
    contents: &[u8],
    private: bool,
) -> Result<(), QuicTransportError> {
    // A name of its own for every write: a file left by one that died must not refuse it.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temporary = directory.join(format!(
        ".{}.tmp-{}-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("identity"),
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))?;
    if private {
        set_private_file_permissions(&temporary)?;
    }
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(QuicTransportError::Configuration(error.to_string()));
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(QuicTransportError::Configuration(error.to_string()));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), QuicTransportError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), QuicTransportError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), QuicTransportError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| QuicTransportError::Configuration(error.to_string()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), QuicTransportError> {
    Ok(())
}

pub fn default_identity_directory(config_file: &Path) -> PathBuf {
    config_file
        .parent()
        .map(|parent| parent.join("quic-identity"))
        .unwrap_or_else(|| PathBuf::from("quic-identity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_persistent_and_partial_identity_is_rejected() {
        let directory = std::env::temp_dir().join(format!(
            "rustadmin-quic-identity-{}-{}",
            std::process::id(),
            crate::rand::random::<u64>()
        ));
        let first = LocalTlsIdentity::load_or_create(&directory).unwrap();
        let first_certificate = first.certificate_bytes().to_vec();
        let second = LocalTlsIdentity::load_or_create(&directory).unwrap();
        assert_eq!(second.certificate_bytes(), first_certificate);
        fs::remove_file(directory.join(CERTIFICATE_FILE)).unwrap();
        assert!(LocalTlsIdentity::load_or_create(&directory).is_err());
        fs::remove_dir_all(&directory).unwrap();
    }

    /// A file left by a write that died, under the name this process would use, made the
    /// identity impossible to create.
    #[test]
    fn a_left_temporary_file_does_not_block_the_identity() {
        let directory = std::env::temp_dir().join(format!(
            "rustadmin-quic-identity-{}-{}",
            std::process::id(),
            crate::rand::random::<u64>()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(format!(".{}.tmp-{}", CERTIFICATE_FILE, std::process::id())),
            b"left",
        )
        .unwrap();
        assert!(LocalTlsIdentity::load_or_create(&directory).is_ok());
        fs::remove_dir_all(&directory).unwrap();
    }

    /// The direct server and the first certificate request create the identity at the same
    /// start-up. Both must get the one that ends up on disk.
    #[test]
    fn identities_created_at_once_are_the_same() {
        let directory = std::env::temp_dir().join(format!(
            "rustadmin-quic-identity-{}-{}",
            std::process::id(),
            crate::rand::random::<u64>()
        ));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let directory = directory.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    LocalTlsIdentity::load_or_create(&directory)
                        .map(|identity| identity.certificate_bytes().to_vec())
                })
            })
            .collect();
        let certificates: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect();
        assert!(certificates.windows(2).all(|pair| pair[0] == pair[1]));
        let on_disk = LocalTlsIdentity::load_or_create(&directory).unwrap();
        assert_eq!(on_disk.certificate_bytes(), certificates[0]);
        fs::remove_dir_all(&directory).unwrap();
    }
}
