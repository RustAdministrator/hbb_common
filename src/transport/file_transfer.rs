use sha2::{Digest, Sha256};
use std::{
    convert::{TryFrom, TryInto},
    time::{Duration, Instant},
};

pub const FILE_METADATA_HEADER_LEN: usize = 68;
pub const FILE_CHUNK_HEADER_LEN: usize = 28;
pub const FILE_CANCEL_PAYLOAD_LEN: usize = 20;
pub const MAX_FILE_NAME_BYTES: usize = 255;
pub const MAX_FILE_CHUNK_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_FILE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTransferMetadata {
    pub transfer_id: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub resume_offset: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileChunk {
    pub transfer_id: [u8; 16],
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum FileCancelReason {
    User = 1,
    PermissionDenied = 2,
    InvalidData = 3,
    IntegrityFailure = 4,
    SessionClosed = 5,
}

impl TryFrom<u16> for FileCancelReason {
    type Error = FileTransferError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::User),
            2 => Ok(Self::PermissionDenied),
            3 => Ok(Self::InvalidData),
            4 => Ok(Self::IntegrityFailure),
            5 => Ok(Self::SessionClosed),
            _ => Err(FileTransferError::UnknownCancelReason(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileTransferProgress {
    pub completed_bytes: u64,
    pub total_bytes: u64,
}

pub struct FileResumeState {
    pub offset: u64,
    pub hasher: Sha256,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FileTransferError {
    #[error("file transfer requires explicit user permission")]
    PermissionDenied,
    #[error("file transfer identifier must not be all zero")]
    ZeroTransferId,
    #[error("file name is invalid or unsafe")]
    InvalidFileName,
    #[error("file size {0} exceeds the configured policy")]
    FileTooLarge(u64),
    #[error("file resume offset {offset} exceeds file size {size}")]
    InvalidResumeOffset { offset: u64, size: u64 },
    #[error("file hash must be present")]
    MissingHash,
    #[error("file metadata payload is truncated")]
    MetadataTruncated,
    #[error("file metadata flags or reserved fields are invalid")]
    InvalidReservedField,
    #[error("file metadata name length is invalid")]
    InvalidNameLength,
    #[error("file name is not valid UTF-8")]
    InvalidUtf8,
    #[error("file chunk payload is truncated")]
    ChunkTruncated,
    #[error("file chunk size {0} is invalid")]
    InvalidChunkSize(usize),
    #[error("file chunk transfer identifier changed")]
    TransferIdMismatch,
    #[error("file chunk offset {received} does not match expected offset {expected}")]
    UnexpectedOffset { expected: u64, received: u64 },
    #[error("file chunk exceeds the declared file size")]
    ChunkExceedsFileSize,
    #[error("file transfer is incomplete")]
    Incomplete,
    #[error("file SHA-256 verification failed")]
    HashMismatch,
    #[error("file transfer is cancelled")]
    Cancelled,
    #[error("resume hashing state is missing or inconsistent")]
    InvalidResumeState,
    #[error("unknown file cancellation reason {0}")]
    UnknownCancelReason(u16),
    #[error("file transfer rate limit is invalid")]
    InvalidRateLimit,
}

pub fn encode_file_metadata(
    metadata: &FileTransferMetadata,
    max_file_bytes: u64,
) -> Result<Vec<u8>, FileTransferError> {
    validate_metadata(metadata, max_file_bytes)?;
    let name = metadata.file_name.as_bytes();
    let mut payload = Vec::with_capacity(FILE_METADATA_HEADER_LEN + name.len());
    payload.extend_from_slice(&metadata.transfer_id);
    payload.extend_from_slice(&metadata.file_size.to_be_bytes());
    payload.extend_from_slice(&metadata.resume_offset.to_be_bytes());
    payload.extend_from_slice(&metadata.sha256);
    payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(name);
    Ok(payload)
}

pub fn decode_file_metadata(
    payload: &[u8],
    max_file_bytes: u64,
) -> Result<FileTransferMetadata, FileTransferError> {
    if payload.len() < FILE_METADATA_HEADER_LEN {
        return Err(FileTransferError::MetadataTruncated);
    }
    if read_u16(payload, 66) != 0 {
        return Err(FileTransferError::InvalidReservedField);
    }
    let name_len = read_u16(payload, 64) as usize;
    if name_len == 0
        || name_len > MAX_FILE_NAME_BYTES
        || payload.len() != FILE_METADATA_HEADER_LEN + name_len
    {
        return Err(FileTransferError::InvalidNameLength);
    }
    let file_name = std::str::from_utf8(&payload[FILE_METADATA_HEADER_LEN..])
        .map_err(|_| FileTransferError::InvalidUtf8)?
        .to_owned();
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&payload[..16]);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&payload[32..64]);
    let metadata = FileTransferMetadata {
        transfer_id,
        file_name,
        file_size: read_u64(payload, 16),
        resume_offset: read_u64(payload, 24),
        sha256,
    };
    validate_metadata(&metadata, max_file_bytes)?;
    Ok(metadata)
}

pub fn encode_file_chunk(chunk: &FileChunk) -> Result<Vec<u8>, FileTransferError> {
    validate_transfer_id(&chunk.transfer_id)?;
    if chunk.data.is_empty() || chunk.data.len() > MAX_FILE_CHUNK_BYTES {
        return Err(FileTransferError::InvalidChunkSize(chunk.data.len()));
    }
    let mut payload = Vec::with_capacity(FILE_CHUNK_HEADER_LEN + chunk.data.len());
    payload.extend_from_slice(&chunk.transfer_id);
    payload.extend_from_slice(&chunk.offset.to_be_bytes());
    payload.extend_from_slice(&(chunk.data.len() as u32).to_be_bytes());
    payload.extend_from_slice(&chunk.data);
    Ok(payload)
}

pub fn decode_file_chunk(payload: &[u8]) -> Result<FileChunk, FileTransferError> {
    if payload.len() < FILE_CHUNK_HEADER_LEN {
        return Err(FileTransferError::ChunkTruncated);
    }
    let declared_len = read_u32(payload, 24) as usize;
    let data = &payload[FILE_CHUNK_HEADER_LEN..];
    if declared_len == 0 || declared_len > MAX_FILE_CHUNK_BYTES || data.len() != declared_len {
        return Err(FileTransferError::InvalidChunkSize(declared_len));
    }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&payload[..16]);
    validate_transfer_id(&transfer_id)?;
    Ok(FileChunk {
        transfer_id,
        offset: read_u64(payload, 16),
        data: data.to_vec(),
    })
}

pub fn encode_file_cancel(
    transfer_id: [u8; 16],
    reason: FileCancelReason,
) -> Result<[u8; FILE_CANCEL_PAYLOAD_LEN], FileTransferError> {
    validate_transfer_id(&transfer_id)?;
    let mut payload = [0u8; FILE_CANCEL_PAYLOAD_LEN];
    payload[..16].copy_from_slice(&transfer_id);
    payload[16..18].copy_from_slice(&(reason as u16).to_be_bytes());
    Ok(payload)
}

pub fn decode_file_cancel(
    payload: &[u8],
) -> Result<([u8; 16], FileCancelReason), FileTransferError> {
    if payload.len() != FILE_CANCEL_PAYLOAD_LEN {
        return Err(FileTransferError::ChunkTruncated);
    }
    if read_u16(payload, 18) != 0 {
        return Err(FileTransferError::InvalidReservedField);
    }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&payload[..16]);
    validate_transfer_id(&transfer_id)?;
    Ok((
        transfer_id,
        FileCancelReason::try_from(read_u16(payload, 16))?,
    ))
}

pub struct FileTransferReceiver {
    metadata: FileTransferMetadata,
    expected_offset: u64,
    hasher: Sha256,
    cancelled: bool,
}

impl FileTransferReceiver {
    pub fn start(
        metadata: FileTransferMetadata,
        max_file_bytes: u64,
        user_permitted: bool,
        resume_state: Option<FileResumeState>,
    ) -> Result<Self, FileTransferError> {
        if !user_permitted {
            return Err(FileTransferError::PermissionDenied);
        }
        validate_metadata(&metadata, max_file_bytes)?;
        let hasher = if metadata.resume_offset == 0 {
            if resume_state.is_some() {
                return Err(FileTransferError::InvalidResumeState);
            }
            Sha256::new()
        } else {
            let resume_state = resume_state.ok_or(FileTransferError::InvalidResumeState)?;
            if resume_state.offset != metadata.resume_offset {
                return Err(FileTransferError::InvalidResumeState);
            }
            resume_state.hasher
        };
        Ok(Self {
            expected_offset: metadata.resume_offset,
            metadata,
            hasher,
            cancelled: false,
        })
    }

    pub fn accept_chunk(
        &mut self,
        chunk: &FileChunk,
    ) -> Result<FileTransferProgress, FileTransferError> {
        if self.cancelled {
            return Err(FileTransferError::Cancelled);
        }
        if chunk.transfer_id != self.metadata.transfer_id {
            return Err(FileTransferError::TransferIdMismatch);
        }
        if chunk.offset != self.expected_offset {
            return Err(FileTransferError::UnexpectedOffset {
                expected: self.expected_offset,
                received: chunk.offset,
            });
        }
        if chunk.data.is_empty() || chunk.data.len() > MAX_FILE_CHUNK_BYTES {
            return Err(FileTransferError::InvalidChunkSize(chunk.data.len()));
        }
        let next_offset = self
            .expected_offset
            .checked_add(chunk.data.len() as u64)
            .ok_or(FileTransferError::ChunkExceedsFileSize)?;
        if next_offset > self.metadata.file_size {
            return Err(FileTransferError::ChunkExceedsFileSize);
        }
        self.hasher.update(&chunk.data);
        self.expected_offset = next_offset;
        Ok(self.progress())
    }

    pub fn progress(&self) -> FileTransferProgress {
        FileTransferProgress {
            completed_bytes: self.expected_offset,
            total_bytes: self.metadata.file_size,
        }
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn finish(self) -> Result<FileTransferMetadata, FileTransferError> {
        if self.cancelled {
            return Err(FileTransferError::Cancelled);
        }
        if self.expected_offset != self.metadata.file_size {
            return Err(FileTransferError::Incomplete);
        }
        let digest = self.hasher.finalize();
        if digest.as_slice() != self.metadata.sha256 {
            return Err(FileTransferError::HashMismatch);
        }
        Ok(self.metadata)
    }
}

pub struct FileTransferRateLimiter {
    bytes_per_second: u64,
    burst_bytes: u64,
    available_bytes: f64,
    updated_at: Instant,
}

impl FileTransferRateLimiter {
    pub fn new(
        bytes_per_second: u64,
        burst_bytes: u64,
        now: Instant,
    ) -> Result<Self, FileTransferError> {
        if bytes_per_second == 0 || burst_bytes == 0 {
            return Err(FileTransferError::InvalidRateLimit);
        }
        Ok(Self {
            bytes_per_second,
            burst_bytes,
            available_bytes: burst_bytes as f64,
            updated_at: now,
        })
    }

    pub fn delay_for(&mut self, bytes: usize, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.updated_at).as_secs_f64();
        self.available_bytes = (self.available_bytes + elapsed * self.bytes_per_second as f64)
            .min(self.burst_bytes as f64);
        self.updated_at = now;
        if bytes as f64 <= self.available_bytes {
            self.available_bytes -= bytes as f64;
            return Duration::ZERO;
        }
        let deficit = bytes as f64 - self.available_bytes;
        Duration::from_secs_f64(deficit / self.bytes_per_second as f64)
    }
}

fn validate_metadata(
    metadata: &FileTransferMetadata,
    max_file_bytes: u64,
) -> Result<(), FileTransferError> {
    validate_transfer_id(&metadata.transfer_id)?;
    validate_file_name(&metadata.file_name)?;
    if metadata.file_size > max_file_bytes {
        return Err(FileTransferError::FileTooLarge(metadata.file_size));
    }
    if metadata.resume_offset > metadata.file_size {
        return Err(FileTransferError::InvalidResumeOffset {
            offset: metadata.resume_offset,
            size: metadata.file_size,
        });
    }
    if metadata.sha256.iter().all(|byte| *byte == 0) {
        return Err(FileTransferError::MissingHash);
    }
    Ok(())
}

pub fn validate_file_name(file_name: &str) -> Result<(), FileTransferError> {
    if file_name.is_empty()
        || file_name.len() > MAX_FILE_NAME_BYTES
        || file_name == "."
        || file_name == ".."
        || file_name.contains(['/', '\\', ':', '\0'])
        || file_name.chars().any(char::is_control)
    {
        return Err(FileTransferError::InvalidFileName);
    }
    Ok(())
}

fn validate_transfer_id(transfer_id: &[u8; 16]) -> Result<(), FileTransferError> {
    if transfer_id.iter().all(|byte| *byte == 0) {
        return Err(FileTransferError::ZeroTransferId);
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

    fn metadata(data: &[u8]) -> FileTransferMetadata {
        let digest = Sha256::digest(data);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);
        FileTransferMetadata {
            transfer_id: [1; 16],
            file_name: "report.txt".to_owned(),
            file_size: data.len() as u64,
            resume_offset: 0,
            sha256,
        }
    }

    #[test]
    fn metadata_and_chunks_round_trip() {
        let metadata = metadata(b"hello");
        let encoded = encode_file_metadata(&metadata, 1024).unwrap();
        assert_eq!(decode_file_metadata(&encoded, 1024).unwrap(), metadata);
        let chunk = FileChunk {
            transfer_id: [1; 16],
            offset: 2,
            data: b"llo".to_vec(),
        };
        assert_eq!(
            decode_file_chunk(&encode_file_chunk(&chunk).unwrap()).unwrap(),
            chunk
        );
    }

    #[test]
    fn unsafe_file_names_are_rejected() {
        for name in [
            "../secret",
            "folder/file",
            "folder\\file",
            "C:secret",
            ".",
            "",
        ] {
            assert_eq!(
                validate_file_name(name),
                Err(FileTransferError::InvalidFileName)
            );
        }
        assert!(validate_file_name("safe name.txt").is_ok());
    }

    #[test]
    fn ordered_chunks_are_hash_verified() {
        let data = b"hello";
        let metadata = metadata(data);
        let mut receiver = FileTransferReceiver::start(metadata.clone(), 1024, true, None).unwrap();
        receiver
            .accept_chunk(&FileChunk {
                transfer_id: [1; 16],
                offset: 0,
                data: b"he".to_vec(),
            })
            .unwrap();
        assert_eq!(
            receiver
                .accept_chunk(&FileChunk {
                    transfer_id: [1; 16],
                    offset: 2,
                    data: b"llo".to_vec(),
                })
                .unwrap()
                .completed_bytes,
            5
        );
        assert_eq!(receiver.finish().unwrap(), metadata);
    }

    #[test]
    fn resume_requires_matching_hash_state() {
        let data = b"hello";
        let mut metadata = metadata(data);
        metadata.resume_offset = 2;
        assert!(matches!(
            FileTransferReceiver::start(metadata.clone(), 1024, true, None),
            Err(FileTransferError::InvalidResumeState)
        ));
        let mut hasher = Sha256::new();
        hasher.update(b"he");
        let mut receiver = FileTransferReceiver::start(
            metadata,
            1024,
            true,
            Some(FileResumeState { offset: 2, hasher }),
        )
        .unwrap();
        receiver
            .accept_chunk(&FileChunk {
                transfer_id: [1; 16],
                offset: 2,
                data: b"llo".to_vec(),
            })
            .unwrap();
        assert!(receiver.finish().is_ok());
    }

    #[test]
    fn permission_order_and_hash_failures_are_enforced() {
        let metadata = metadata(b"hello");
        assert!(matches!(
            FileTransferReceiver::start(metadata.clone(), 1024, false, None),
            Err(FileTransferError::PermissionDenied)
        ));
        let mut receiver = FileTransferReceiver::start(metadata, 1024, true, None).unwrap();
        assert_eq!(
            receiver.accept_chunk(&FileChunk {
                transfer_id: [1; 16],
                offset: 1,
                data: b"bad".to_vec(),
            }),
            Err(FileTransferError::UnexpectedOffset {
                expected: 0,
                received: 1,
            })
        );
    }

    #[test]
    fn rate_limiter_preserves_an_interactive_bandwidth_budget() {
        let now = Instant::now();
        let mut limiter = FileTransferRateLimiter::new(1000, 100, now).unwrap();
        assert_eq!(limiter.delay_for(100, now), Duration::ZERO);
        assert_eq!(limiter.delay_for(100, now), Duration::from_millis(100));
        assert_eq!(
            limiter.delay_for(100, now + Duration::from_millis(100)),
            Duration::ZERO
        );
    }
}
