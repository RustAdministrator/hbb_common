#[cfg(windows)]
use std::os::windows::prelude::*;
use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    io::Cursor,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI32, Ordering},
        Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufStream as TokioBufStream},
};

use crate::{anyhow::anyhow, bail, get_version_number, message_proto::*, ResultType, Stream};
// https://doc.rust-lang.org/std/os/windows/fs/trait.MetadataExt.html
use crate::{
    compress::{compress, decompress_limited},
    config::Config,
};

static NEXT_JOB_ID: AtomicI32 = AtomicI32::new(1);
const FILE_BLOCK_DECOMPRESS_MAX_LEN: usize = 128 * 1024;
/// The most a job that receives into memory (a print job) accepts. Such a job is started by
/// the peer and nothing else bounds it.
const MEMORY_JOB_MAX_BYTES: u64 = 1024 * 1024 * 1024;

pub fn get_next_job_id() -> i32 {
    NEXT_JOB_ID.fetch_add(1, Ordering::SeqCst)
}

pub fn update_next_job_id(id: i32) {
    NEXT_JOB_ID.store(id, Ordering::SeqCst);
}

/// Makes sure no later [`get_next_job_id`] returns `id` or anything below it. A job restored
/// from an earlier run keeps its id, while the counter starts again at 1 in every run; without
/// this a new job gets the id of a restored one, and blocks go to whichever is found first.
pub fn reserve_job_id(id: i32) {
    NEXT_JOB_ID.fetch_max(id.saturating_add(1), Ordering::SeqCst);
}

/// A directory tree holds more entries than the caller allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyEntries {
    pub limit: usize,
}

impl std::fmt::Display for TooManyEntries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "more than {} entries", self.limit)
    }
}

impl std::error::Error for TooManyEntries {}

/// The limit a walk was stopped at, when that is why it failed.
pub fn too_many_entries(err: &crate::anyhow::Error) -> Option<TooManyEntries> {
    err.downcast_ref::<TooManyEntries>().copied()
}

pub fn read_dir(path: &Path, include_hidden: bool) -> ResultType<FileDirectory> {
    let mut dir = FileDirectory {
        path: get_string(path),
        ..Default::default()
    };
    #[cfg(windows)]
    if "/" == &get_string(path) {
        let drives = unsafe { winapi::um::fileapi::GetLogicalDrives() };
        for i in 0..32 {
            if drives & (1 << i) != 0 {
                let name = format!(
                    "{}:",
                    std::char::from_u32('A' as u32 + i as u32).unwrap_or('A')
                );
                dir.entries.push(FileEntry {
                    name,
                    entry_type: FileType::DirDrive.into(),
                    ..Default::default()
                });
            }
        }
        return Ok(dir);
    }
    for entry in path.read_dir()?.flatten() {
        let p = entry.path();
        let name = p
            .file_name()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        if name.is_empty() {
            continue;
        }
        let mut is_hidden = false;
        let meta;
        if let Ok(tmp) = std::fs::symlink_metadata(&p) {
            meta = tmp;
        } else {
            continue;
        }
        // docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
        #[cfg(windows)]
        if meta.file_attributes() & 0x2 != 0 {
            is_hidden = true;
        }
        #[cfg(not(windows))]
        if name.find('.').unwrap_or(usize::MAX) == 0 {
            is_hidden = true;
        }
        if is_hidden && !include_hidden {
            continue;
        }
        let (entry_type, size) = {
            if p.is_dir() {
                if meta.file_type().is_symlink() {
                    (FileType::DirLink.into(), 0)
                } else {
                    (FileType::Dir.into(), 0)
                }
            } else if meta.file_type().is_symlink() {
                (FileType::FileLink.into(), 0)
            } else {
                (FileType::File.into(), meta.len())
            }
        };
        let modified_time = meta
            .modified()
            .map(|x| {
                x.duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|x| x.as_secs())
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        dir.entries.push(FileEntry {
            name: get_file_name(&p),
            entry_type,
            is_hidden,
            size,
            modified_time,
            ..Default::default()
        });
    }
    Ok(dir)
}

#[inline]
pub fn get_file_name(p: &Path) -> String {
    p.file_name()
        .map(|p| p.to_str().unwrap_or(""))
        .unwrap_or("")
        .to_owned()
}

#[inline]
pub fn get_string(path: &Path) -> String {
    path.to_str().unwrap_or("").to_owned()
}

#[inline]
pub fn get_path(path: &str) -> PathBuf {
    Path::new(path).to_path_buf()
}

#[inline]
pub fn get_home_as_string() -> String {
    get_string(&Config::get_home())
}

/// Collects the files under `path` into `files`. Stops with [`TooManyEntries`] as soon as
/// there are more than `max_files`, instead of walking the rest of the tree first.
fn read_dir_recursive(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
    max_files: usize,
    files: &mut Vec<FileEntry>,
) -> ResultType<()> {
    if path.is_dir() {
        // to-do: symbol link handling, cp the link rather than the content
        // to-do: file mode, for unix
        let fd = read_dir(path, include_hidden)?;
        for entry in fd.entries.iter() {
            match entry.entry_type.enum_value() {
                Ok(FileType::File) => {
                    let mut entry = entry.clone();
                    entry.name = get_string(&prefix.join(entry.name));
                    files.push(entry);
                    if files.len() > max_files {
                        return Err(TooManyEntries { limit: max_files }.into());
                    }
                }
                Ok(FileType::Dir) => {
                    // A subdirectory that cannot be read is left out, as before. Running
                    // over the limit is not that kind of error.
                    if let Err(err) = read_dir_recursive(
                        &path.join(&entry.name),
                        &prefix.join(&entry.name),
                        include_hidden,
                        max_files,
                        files,
                    ) {
                        if too_many_entries(&err).is_some() {
                            return Err(err);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    } else if path.is_file() {
        let (size, modified_time) = if let Ok(meta) = std::fs::metadata(path) {
            (
                meta.len(),
                meta.modified()
                    .map(|x| {
                        x.duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .map(|x| x.as_secs())
                            .unwrap_or(0)
                    })
                    .unwrap_or(0),
            )
        } else {
            (0, 0)
        };
        files.push(FileEntry {
            entry_type: FileType::File.into(),
            size,
            modified_time,
            ..Default::default()
        });
        Ok(())
    } else {
        bail!("Not exists");
    }
}

pub fn get_recursive_files(path: &str, include_hidden: bool) -> ResultType<Vec<FileEntry>> {
    get_recursive_files_limited(path, include_hidden, usize::MAX)
}

/// [`get_recursive_files`] that gives up with [`TooManyEntries`] once the tree is known to
/// hold more than `max_files` files.
pub fn get_recursive_files_limited(
    path: &str,
    include_hidden: bool,
    max_files: usize,
) -> ResultType<Vec<FileEntry>> {
    let mut files = Vec::new();
    read_dir_recursive(
        &get_path(path),
        &get_path(""),
        include_hidden,
        max_files,
        &mut files,
    )?;
    Ok(files)
}

/// Collects the empty directories under `path`. `budget` is what is left of the number of
/// directories the walk may visit; the walk stops with [`TooManyEntries`] when it is used up.
fn read_empty_dirs_recursive(
    path: &Path,
    prefix: &Path,
    include_hidden: bool,
    limit: usize,
    budget: &mut usize,
    dirs: &mut Vec<FileDirectory>,
) -> ResultType<()> {
    if path.is_dir() {
        if *budget == 0 {
            return Err(TooManyEntries { limit }.into());
        }
        *budget -= 1;
        // to-do: symbol link handling, cp the link rather than the content
        // to-do: file mode, for unix
        let fd = read_dir(path, include_hidden)?;
        if fd.entries.is_empty() {
            dirs.push(fd);
        } else {
            for entry in fd.entries.iter() {
                if let Ok(FileType::Dir) = entry.entry_type.enum_value() {
                    if let Err(err) = read_empty_dirs_recursive(
                        &path.join(&entry.name),
                        &prefix.join(&entry.name),
                        include_hidden,
                        limit,
                        budget,
                        dirs,
                    ) {
                        if too_many_entries(&err).is_some() {
                            return Err(err);
                        }
                    }
                }
            }
        }
        Ok(())
    } else if path.is_file() {
        Ok(())
    } else {
        bail!("Not exists");
    }
}

pub fn get_empty_dirs_recursive(
    path: &str,
    include_hidden: bool,
) -> ResultType<Vec<FileDirectory>> {
    get_empty_dirs_recursive_limited(path, include_hidden, usize::MAX)
}

/// [`get_empty_dirs_recursive`] that visits at most `max_dirs` directories and gives up with
/// [`TooManyEntries`] when the tree has more.
pub fn get_empty_dirs_recursive_limited(
    path: &str,
    include_hidden: bool,
    max_dirs: usize,
) -> ResultType<Vec<FileDirectory>> {
    let mut dirs = Vec::new();
    let mut budget = max_dirs;
    read_empty_dirs_recursive(
        &get_path(path),
        &get_path(""),
        include_hidden,
        max_dirs,
        &mut budget,
        &mut dirs,
    )?;
    Ok(dirs)
}

#[inline]
pub fn is_file_exists(file_path: &str) -> bool {
    return Path::new(file_path).exists();
}

#[inline]
pub fn can_enable_overwrite_detection(version: i64) -> bool {
    version >= get_version_number("1.1.10")
}

#[repr(i32)]
#[derive(Copy, Clone, Serialize, Debug, PartialEq)]
pub enum JobType {
    Generic = 0,
    Printer = 1,
}

impl Default for JobType {
    fn default() -> Self {
        JobType::Generic
    }
}

impl From<JobType> for file_transfer_send_request::FileType {
    fn from(t: JobType) -> Self {
        match t {
            JobType::Generic => file_transfer_send_request::FileType::Generic,
            JobType::Printer => file_transfer_send_request::FileType::Printer,
        }
    }
}

impl From<i32> for JobType {
    fn from(value: i32) -> Self {
        match value {
            0 => JobType::Generic,
            1 => JobType::Printer,
            _ => JobType::Generic,
        }
    }
}

impl Into<i32> for JobType {
    fn into(self) -> i32 {
        self as i32
    }
}

impl JobType {
    pub fn from_proto(t: ::protobuf::EnumOrUnknown<file_transfer_send_request::FileType>) -> Self {
        match t.enum_value() {
            Ok(file_transfer_send_request::FileType::Generic) => JobType::Generic,
            Ok(file_transfer_send_request::FileType::Printer) => JobType::Printer,
            _ => JobType::Generic,
        }
    }
}

#[derive(Debug)]
pub enum DataSource {
    FilePath(PathBuf),
    MemoryCursor(Cursor<Vec<u8>>),
}

impl Default for DataSource {
    fn default() -> Self {
        DataSource::FilePath(PathBuf::new())
    }
}

impl serde::Serialize for DataSource {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            DataSource::FilePath(p) => serializer.serialize_str(p.to_str().unwrap_or("")),
            DataSource::MemoryCursor(_) => serializer.serialize_str(""),
        }
    }
}

impl Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::FilePath(p) => write!(f, "File: {}", p.to_string_lossy().to_string()),
            DataSource::MemoryCursor(_) => write!(f, "Bytes"),
        }
    }
}

impl DataSource {
    fn to_meta(&self) -> String {
        match self {
            DataSource::FilePath(p) => p.to_string_lossy().to_string(),
            DataSource::MemoryCursor(_) => "".to_string(),
        }
    }
}

enum DataStream {
    FileStream(File),
    BufStream(TokioBufStream<Cursor<Vec<u8>>>),
}

impl Debug for DataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataStream::FileStream(fs) => write!(f, "{:?}", fs),
            DataStream::BufStream(_) => write!(f, "BufStream"),
        }
    }
}

impl DataStream {
    async fn write_all(&mut self, buf: &[u8]) -> ResultType<()> {
        match self {
            DataStream::FileStream(fs) => fs.write_all(buf).await?,
            DataStream::BufStream(bs) => bs.write_all(buf).await?,
        }
        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DataStream::FileStream(fs) => fs.read(buf).await,
            DataStream::BufStream(bs) => bs.read(buf).await,
        }
    }

    /// Waits for writes that were handed to the file and reports their error. A tokio file
    /// completes a write in the background; without this the last error is never seen.
    async fn flush(&mut self, sync: bool) -> ResultType<()> {
        match self {
            DataStream::FileStream(fs) => {
                fs.flush().await?;
                if sync {
                    fs.sync_all().await?;
                }
            }
            DataStream::BufStream(bs) => bs.flush().await?,
        }
        Ok(())
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct FileDigest {
    pub size: u64,
    pub modified: u64,
}

#[derive(Default, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferJob {
    pub id: i32,
    pub r#type: JobType,
    pub remote: String,
    pub data_source: DataSource,
    pub show_hidden: bool,
    pub is_remote: bool,
    pub is_last_job: bool,
    pub is_resume: bool,
    pub file_num: i32,
    #[serde(skip_serializing)]
    files: Vec<FileEntry>,
    pub conn_id: i32, // server only

    #[serde(skip_serializing)]
    data_stream: Option<DataStream>,
    pub total_size: u64,
    finished_size: u64,
    transferred: u64,
    enable_overwrite_detection: bool,
    file_confirmed: bool,
    // indicating the last file is skipped
    file_skipped: bool,
    file_is_waiting: bool,
    default_overwrite_strategy: Option<bool>,
    #[serde(skip_serializing)]
    digest: FileDigest,
    /// A message that was produced for the peer while the stream had no room for it. It is
    /// sent before anything else is read. `Some(log)` marks the job's final message.
    #[serde(skip_serializing)]
    pending_send: Option<(Message, Option<String>)>,
    /// Set by the first failed write. A failed job takes no more blocks and never moves a
    /// partial file into place.
    #[serde(skip_serializing)]
    failed: bool,
    /// Bytes in the file being written, including what was there before a resume.
    #[serde(skip_serializing)]
    file_written: u64,
    /// The size the sender announced for the file being written, when one is known.
    #[serde(skip_serializing)]
    file_expected: Option<u64>,
    /// A file is open for writing, or was, and has not been moved into place yet.
    #[serde(skip_serializing)]
    file_opened: bool,
    /// `digest` was set by the sender for the file that comes next and has not been used yet.
    #[serde(skip_serializing)]
    digest_is_fresh: bool,
    /// A resume offset agreed for a file that is not open yet: `(file number, offset)`.
    #[serde(skip_serializing)]
    pending_resume: Option<(i32, u64)>,
    /// Number of the last block read from, or written to, the current file. The blocks of a
    /// file are numbered from 1 in `FileTransferBlock::blk_id`; zero means none yet.
    #[serde(skip_serializing)]
    last_block_id: u32,
    /// The file `last_block_id` counts for, on the reading side.
    #[serde(skip_serializing)]
    block_id_file_num: i32,
    /// Held while this job writes to its destination. See [`TransferJob::claim_destination`].
    #[serde(skip_serializing)]
    destination_claim: Option<DestinationClaim>,
    /// A job that reads local files for the peer.
    #[serde(skip_serializing)]
    reads_local_files: bool,
    /// The highest file number the peer has answered a digest for. Everything before it has
    /// been processed by the peer, because the stream is ordered.
    #[serde(skip_serializing)]
    peer_confirmed_file_num: i32,
}

lazy_static::lazy_static! {
    /// Destinations that a write job of this process is writing to right now.
    static ref ACTIVE_DESTINATIONS: Mutex<HashSet<String>> = Default::default();
}

/// One entry of the set of destinations in use; leaving it is dropping this.
#[derive(Debug)]
struct DestinationClaim(String);

impl DestinationClaim {
    fn key(path: &Path) -> String {
        let key = get_string(path);
        if cfg!(windows) {
            // The same file under another spelling of its name.
            key.replace('/', "\\").to_lowercase()
        } else {
            key
        }
    }
}

impl Drop for DestinationClaim {
    fn drop(&mut self) {
        ACTIVE_DESTINATIONS.lock().unwrap().remove(&self.0);
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct TransferJobMeta {
    #[serde(default)]
    pub id: i32,
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub show_hidden: bool,
    #[serde(default)]
    pub file_num: i32,
    #[serde(default)]
    pub is_remote: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RemoveJobMeta {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub is_remote: bool,
    #[serde(default)]
    pub no_confirm: bool,
}

#[inline]
fn get_ext(name: &str) -> &str {
    if let Some(i) = name.rfind('.') {
        return &name[i + 1..];
    }
    ""
}

/// Extensions of files whose content is compressed already. Trying to compress their blocks
/// again costs processor time and gains nothing.
const COMPRESSED_EXTENSIONS: &[&str] = &[
    // archives and compressed streams
    "xz", "gz", "zip", "7z", "rar", "bz2", "tgz", "tbz2", "txz", "zst", "lz4", "lzma", "br", "cab",
    "jar", "apk", "aab", "ipa", "msix", "appx", "deb", "rpm", "dmg", "squashfs",
    // images
    "png", "jpg", "jpeg", "gif", "webp", "heic", "heif", "avif", "jxl",
    // video and audio
    "mp4", "m4v", "mkv", "mov", "avi", "webm", "wmv", "flv", "mts", "m2ts", "mpg", "mpeg", "mp3",
    "aac", "m4a", "ogg", "oga", "opus", "flac", "wma",
    // documents that are zip containers
    "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub",
];

#[inline]
fn is_compressed_file(name: &str) -> bool {
    let ext = get_ext(name);
    COMPRESSED_EXTENSIONS
        .iter()
        .any(|compressed| ext.eq_ignore_ascii_case(compressed))
}

/// Whether one path component names something Windows would not treat as a
/// plain file: an NTFS stream (`name:stream`), a device (`CON`, `NUL.txt`, ...)
/// or a name that ends in a dot or a space (which the API silently trims).
/// Not gated by platform so it can be tested everywhere; the validator below
/// applies it on Windows.
pub fn windows_component_unsafe(component: &str) -> bool {
    if component.is_empty() || component == "." {
        return false;
    }
    if component.contains(':') {
        return true;
    }
    if component.ends_with('.') || component.ends_with(' ') {
        return true;
    }
    let base = component.split('.').next().unwrap_or("").trim_end();
    let upper = base.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    // COM0-COM9 and LPT0-LPT9, and the same with a superscript one, two or three.
    let Some(number) = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut number = number.chars();
    matches!(
        (number.next(), number.next()),
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
    )
}

/// Whether the last component of `path` names something Windows would not treat as a plain
/// file. Used for a single-file transfer, whose destination is the path itself.
pub fn windows_destination_unsafe(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(windows_component_unsafe)
}

/// Checks a path that the user interface built as the destination of a transfer written on
/// this system. The interface joins a folder the user chose with a name that comes from the
/// peer, so a path that climbs out with `..` is never what the user chose.
pub fn validate_local_destination(path: &str) -> ResultType<()> {
    validate_fs_path_argument(path, "destination path")?;
    for component in Path::new(path).components() {
        match component {
            std::path::Component::ParentDir => {
                bail!("destination path must not contain '..'");
            }
            std::path::Component::Normal(name) => {
                if cfg!(windows) && name.to_str().is_some_and(windows_component_unsafe) {
                    bail!("destination path component is not a plain Windows file name");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn validate_file_name_no_traversal(name: &str) -> ResultType<()> {
    if name.bytes().any(|b| b == 0) {
        bail!("file name contains null bytes");
    }
    if cfg!(windows) {
        if let Some(component) = name
            .split(|c: char| c == '/' || c == '\\')
            .find(|s| windows_component_unsafe(s))
        {
            bail!("file name component is not a plain Windows file name: {component}");
        }
    }
    let has_traversal = name
        .split(|c: char| c == '/' || (cfg!(windows) && c == '\\'))
        .filter(|s| !s.is_empty())
        .any(|s| s == "..");
    if has_traversal {
        bail!("path traversal detected in file name");
    }
    #[cfg(windows)]
    {
        if name.len() >= 2 {
            let bytes = name.as_bytes();
            if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                bail!("absolute path detected in file name");
            }
        }
        if name.starts_with('/') || name.starts_with('\\') {
            bail!("absolute path detected in file name");
        }
    }
    #[cfg(not(windows))]
    if name.starts_with('/') {
        bail!("absolute path detected in file name");
    }
    Ok(())
}

fn validate_transfer_file_names(files: &[FileEntry]) -> ResultType<()> {
    // Single-file transfer may use an empty relative name, because
    // the destination file path is carried by transfer metadata.
    if files.len() == 1 && files.first().map_or(false, |f| f.name.is_empty()) {
        return Ok(());
    }
    for file in files {
        if file.name.is_empty() {
            bail!("empty file name in multi-file transfer");
        }
        validate_file_name_no_traversal(&file.name)?;
    }
    Ok(())
}

#[inline]
fn validate_fs_path_argument(path: &str, arg_name: &str) -> ResultType<()> {
    if path.is_empty() {
        bail!("{arg_name} cannot be empty");
    }
    if path.bytes().any(|b| b == 0) {
        bail!("{arg_name} contains null bytes");
    }
    Ok(())
}

fn validate_no_symlink_components(base: &PathBuf, name: &str) -> ResultType<()> {
    if name.is_empty() {
        return Ok(());
    }
    let mut current = base.clone();
    for component in Path::new(name).components() {
        match component {
            std::path::Component::Normal(seg) => {
                current.push(seg);
                // Best-effort guard: path-based checks are inherently TOCTOU-prone
                // if local filesystem state changes between validation and write.
                match std::fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        // This is inherent to filesystem-based checks and acknowledged as a limitation.
                        // For true protection, you'd need openat(2) / O_NOFOLLOW at write time.
                        if meta.file_type().is_symlink() {
                            bail!("symlink path component is not allowed");
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // Component does not exist yet, continue best-effort validation.
                    }
                    Err(err) => {
                        bail!(
                            "failed to validate path component '{}': {}",
                            current.display(),
                            err
                        );
                    }
                }
            }
            std::path::Component::CurDir => {}
            _ => {
                bail!("invalid file name component");
            }
        }
    }
    Ok(())
}

fn join_validated_path(base: &PathBuf, name: &str) -> ResultType<PathBuf> {
    validate_file_name_no_traversal(name)?;
    validate_no_symlink_components(base, name)?;
    Ok(TransferJob::join(base, name))
}

impl TransferJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new_write(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
    ) -> Self {
        log::info!("new write {}", data_source);
        Self {
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            files: Vec::new(),
            total_size: 0,
            enable_overwrite_detection,
            ..Default::default()
        }
    }

    pub fn with_files(mut self, files: Vec<FileEntry>) -> ResultType<Self> {
        self.set_files(files)?;
        Ok(self)
    }

    pub fn new_read(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
    ) -> ResultType<Self> {
        Self::new_read_limited(
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            enable_overwrite_detection,
            usize::MAX,
        )
    }

    /// [`TransferJob::new_read`] that fails with [`TooManyEntries`] as soon as the source is
    /// known to hold more than `max_files` files, without walking the rest of it.
    #[allow(clippy::too_many_arguments)]
    pub fn new_read_limited(
        id: i32,
        r#type: JobType,
        remote: String,
        data_source: DataSource,
        file_num: i32,
        show_hidden: bool,
        is_remote: bool,
        enable_overwrite_detection: bool,
        max_files: usize,
    ) -> ResultType<Self> {
        log::info!("new read {}", data_source);
        let (files, total_size) = match &data_source {
            DataSource::FilePath(p) => {
                let p = p.to_str().ok_or(anyhow!("Invalid path"))?;
                let files = get_recursive_files_limited(p, show_hidden, max_files)?;
                let total_size = files.iter().map(|x| x.size).sum();
                (files, total_size)
            }
            DataSource::MemoryCursor(c) => (Vec::new(), c.get_ref().len() as u64),
        };
        Ok(Self {
            id,
            r#type,
            remote,
            data_source,
            file_num,
            show_hidden,
            is_remote,
            files,
            total_size,
            enable_overwrite_detection,
            reads_local_files: true,
            peer_confirmed_file_num: file_num,
            ..Default::default()
        })
    }

    pub async fn get_buf_data(self) -> ResultType<Option<Vec<u8>>> {
        match self.data_stream {
            Some(DataStream::BufStream(mut bs)) => {
                bs.flush().await?;
                Ok(Some(bs.into_inner().into_inner()))
            }
            _ => Ok(None),
        }
    }

    #[inline]
    pub fn files(&self) -> &Vec<FileEntry> {
        &self.files
    }

    #[inline]
    pub fn set_files(&mut self, files: Vec<FileEntry>) -> ResultType<()> {
        validate_transfer_file_names(&files)?;
        if let DataSource::FilePath(base) = &self.data_source {
            for file in &files {
                validate_no_symlink_components(base, &file.name)?;
            }
            // A single file is written to the path itself, so the name to check is there.
            let single_file = files.len() == 1 && files[0].name.is_empty();
            if cfg!(windows) && single_file && windows_destination_unsafe(base) {
                bail!("destination is not a plain Windows file name");
            }
        }
        self.total_size = files.iter().map(|x| x.size).sum();
        self.files = files;
        Ok(())
    }

    #[inline]
    pub fn set_digest(&mut self, size: u64, modified: u64) {
        self.digest.size = size;
        self.digest.modified = modified;
        self.digest_is_fresh = true;
    }

    #[inline]
    pub fn id(&self) -> i32 {
        self.id
    }

    #[inline]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    #[inline]
    pub fn finished_size(&self) -> u64 {
        self.finished_size
    }

    #[inline]
    pub fn transferred(&self) -> u64 {
        self.transferred
    }

    #[inline]
    pub fn file_num(&self) -> i32 {
        self.file_num
    }

    fn resolve_entry_path(&self, base: &PathBuf, name: &str) -> Option<PathBuf> {
        if self.r#type == JobType::Generic {
            match join_validated_path(base, name) {
                Ok(path) => Some(path),
                Err(err) => {
                    log::error!("Invalid file name in transfer job {}: {}", self.id, err);
                    None
                }
            }
        } else {
            Some(Self::join(base, name))
        }
    }

    /// Whether a write has failed. Such a job is dead: see [`TransferJob::write`].
    #[inline]
    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// Marks the destination of this write job as in use until the job is dropped. Fails when
    /// another job of this process is writing there: the two would share the same temporary
    /// `.download` files and each would damage the other's result.
    pub fn claim_destination(&mut self) -> ResultType<()> {
        if self.destination_claim.is_some() {
            return Ok(());
        }
        let DataSource::FilePath(path) = &self.data_source else {
            return Ok(());
        };
        let key = DestinationClaim::key(path);
        if !ACTIVE_DESTINATIONS.lock().unwrap().insert(key.clone()) {
            bail!("another transfer is already writing to this destination");
        }
        self.destination_claim = Some(DestinationClaim(key));
        Ok(())
    }

    /// Moves the current file into place without waiting for its last write and without
    /// returning the error. Kept for old callers; use [`TransferJob::finish_file`].
    pub fn modify_time(&self) {
        if let Err(err) = self.move_current_file_into_place() {
            log::error!(
                "transfer job {}: file {} was not completed: {}",
                self.id,
                self.file_num,
                err
            );
        }
    }

    /// Completes the file that is being written: waits for its last write, closes it and moves
    /// the `.download` file into place. Returns the error instead of hiding it; on an error the
    /// job is failed and the partial file stays where it is.
    pub async fn finish_file(&mut self) -> ResultType<()> {
        if self.r#type == JobType::Printer {
            return Ok(());
        }
        let result = self.close_and_place_current_file(false).await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Waits for the last write of the open file, closes it and moves it into place.
    /// `sync` also waits for the data to reach the disk, as is done between two files.
    async fn close_and_place_current_file(&mut self, sync: bool) -> ResultType<()> {
        // A write to a file is completed in the background; its error is reported here.
        let flushed = match self.data_stream.as_mut() {
            Some(stream) => stream.flush(sync).await,
            None => Ok(()),
        };
        self.data_stream = None;
        flushed?;
        self.move_current_file_into_place()?;
        self.file_opened = false;
        Ok(())
    }

    /// Moves the current file's `.download` into place and sets its modification time.
    /// Refuses when the job has failed or when fewer bytes arrived than the sender announced.
    fn move_current_file_into_place(&self) -> ResultType<()> {
        if self.r#type == JobType::Printer {
            return Ok(());
        }
        if self.failed {
            bail!("the transfer failed; the partial file was left as it is");
        }
        if let DataSource::FilePath(p) = &self.data_source {
            let file_num = self.file_num as usize;
            if file_num < self.files.len() {
                let entry = &self.files[file_num];
                let Some(path) = self.resolve_entry_path(p, &entry.name) else {
                    bail!("invalid file name in transfer job");
                };
                let download_path = format!("{}.download", get_string(&path));
                if std::fs::symlink_metadata(&download_path).is_err() {
                    if self.file_opened {
                        bail!("the partial file disappeared before it was complete");
                    }
                    // Nothing was received for this file (for example it was skipped).
                    return Ok(());
                }
                // The sender says the file is finished. Whatever happens below, the partial
                // file is no longer something a later resume may continue from.
                let digest_path = format!("{}.digest", get_string(&path));
                std::fs::remove_file(digest_path).ok();
                if let Some(expected) = self.file_expected.filter(|_| self.file_opened) {
                    if self.file_written < expected {
                        bail!(
                            "file is incomplete: {} of {} bytes arrived",
                            self.file_written,
                            expected
                        );
                    }
                }
                std::fs::rename(&download_path, &path)?;
                filetime::set_file_mtime(
                    &path,
                    filetime::FileTime::from_unix_time(entry.modified_time as _, 0),
                )
                .ok();
            }
        }
        Ok(())
    }

    pub fn remove_download_file(&self) {
        if self.r#type == JobType::Printer {
            return;
        }
        if let DataSource::FilePath(p) = &self.data_source {
            let file_num = self.file_num as usize;
            if file_num < self.files.len() {
                let entry = &self.files[file_num];
                let Some(path) = self.resolve_entry_path(p, &entry.name) else {
                    return;
                };
                let download_path = format!("{}.download", get_string(&path));
                let digest_path = format!("{}.digest", get_string(&path));
                std::fs::remove_file(download_path).ok();
                std::fs::remove_file(digest_path).ok();
            }
        }
    }

    #[inline]
    pub fn set_finished_size_on_resume(&mut self) {
        if self.is_resume && self.file_num > 0 {
            let finished_size: u64 = self
                .files
                .iter()
                .take(self.file_num as usize)
                .map(|file| file.size)
                .sum();
            self.finished_size = finished_size;
        }
    }

    /// Writes one block. The first error fails the job: the stream is closed, later blocks are
    /// refused and the partial file is never moved into place. The caller must stop the
    /// transfer and tell the peer.
    pub async fn write(&mut self, block: FileTransferBlock) -> ResultType<()> {
        if self.failed {
            bail!("the transfer has already failed");
        }
        let result = self.write_block(block).await;
        if result.is_err() {
            self.failed = true;
            self.data_stream = None;
        }
        result
    }

    async fn write_block(&mut self, block: FileTransferBlock) -> ResultType<()> {
        if block.id != self.id {
            bail!("Wrong id");
        }
        match &self.data_source {
            DataSource::FilePath(p) => {
                let file_num = block.file_num as usize;
                if file_num >= self.files.len() {
                    bail!("Wrong file number");
                }
                if file_num != self.file_num as usize || self.data_stream.is_none() {
                    let p = p.clone();
                    // Close the file that was being written before anything else changes, so
                    // that a failure below cannot send later blocks into it.
                    if self.data_stream.is_some() {
                        self.close_and_place_current_file(true).await?;
                    }
                    self.open_file_for_write(&p, file_num).await?;
                    self.file_num = block.file_num;
                }
            }
            DataSource::MemoryCursor(c) => {
                if self.data_stream.is_none() {
                    self.data_stream = Some(DataStream::BufStream(TokioBufStream::new(c.clone())));
                }
                // Everything received for such a job stays in memory until it is complete.
                if self.finished_size >= MEMORY_JOB_MAX_BYTES {
                    bail!(
                        "data received in memory is over the limit of {} bytes",
                        MEMORY_JOB_MAX_BYTES
                    );
                }
            }
        }
        // Zero is a sender that does not number its blocks; there is nothing to check then.
        if block.blk_id != 0 {
            let expected = next_block_id(self.last_block_id);
            if block.blk_id != expected {
                bail!(
                    "block {} of the file arrived where block {} was expected: file data was lost or repeated on the way",
                    block.blk_id,
                    expected
                );
            }
            self.last_block_id = block.blk_id;
        }
        let written = if block.compressed {
            let tmp = decompress_limited(&block.data, FILE_BLOCK_DECOMPRESS_MAX_LEN)?;
            self.data_stream
                .as_mut()
                .ok_or(anyhow!("data stream is None"))?
                .write_all(&tmp)
                .await?;
            tmp.len() as u64
        } else {
            self.data_stream
                .as_mut()
                .ok_or(anyhow!("file is None"))?
                .write_all(&block.data)
                .await?;
            block.data.len() as u64
        };
        self.finished_size += written;
        self.file_written += written;
        self.transferred += block.data.len() as u64;
        Ok(())
    }

    /// Opens file `file_num` of the job for writing, continuing a partial file when a resume
    /// offset was agreed for it and starting a fresh `.download` otherwise.
    async fn open_file_for_write(&mut self, base: &PathBuf, file_num: usize) -> ResultType<()> {
        if let Some((_, offset)) = self
            .pending_resume
            .take()
            .filter(|(resumed, _)| *resumed as usize == file_num)
        {
            // The sender starts at `offset`. Writing its data anywhere else would produce a
            // file of the right name and the wrong content.
            return self.open_partial_for_write(base, file_num, offset).await;
        }
        let entry = &self.files[file_num];
        let (path, digest_path) = if self.r#type == JobType::Printer {
            (base.to_string_lossy().to_string(), None)
        } else {
            let path = join_validated_path(base, &entry.name)?;
            // NOTE: We intentionally keep path-based validation + regular file open here.
            // This still has a known TOCTOU window for symlink races, but avoids a large
            // cross-platform rewrite for now.
            // Revisit with descriptor/handle-based no-follow open in future hardening.
            if let Some(pp) = path.parent() {
                std::fs::create_dir_all(pp).ok();
            }
            let file_path = get_string(&path);
            (
                format!("{}.download", &file_path),
                Some(format!("{}.digest", &file_path)),
            )
        };
        if let Some(dp) = digest_path.as_ref() {
            if Path::new(dp).exists() {
                std::fs::remove_file(dp)?;
            }
        }
        self.data_stream = Some(DataStream::FileStream(File::create(&path).await?));
        self.note_file_opened(file_num, 0);
        if let Some(dp) = digest_path.as_ref() {
            std::fs::write(dp, json!(self.digest).to_string()).ok();
        }
        Ok(())
    }

    /// Continues the `.download` file left by an interrupted transfer at the agreed offset.
    async fn open_partial_for_write(
        &mut self,
        base: &PathBuf,
        file_num: usize,
        offset: u64,
    ) -> ResultType<()> {
        let path = join_validated_path(base, &self.files[file_num].name)?;
        let download_path = format!("{}.download", get_string(&path));
        // Not `create`: the offset was agreed for a file that exists.
        let mut file = OpenOptions::new().write(true).open(&download_path).await?;
        let present = file.metadata().await?.len();
        if present < offset {
            bail!(
                "the partial file has {} bytes, fewer than the agreed offset {}",
                present,
                offset
            );
        }
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        self.data_stream = Some(DataStream::FileStream(file));
        self.transferred += offset;
        self.finished_size += offset;
        self.note_file_opened(file_num, offset);
        Ok(())
    }

    /// Records what is known about the file that was just opened for writing.
    fn note_file_opened(&mut self, file_num: usize, already_present: u64) {
        self.file_opened = true;
        // Both sides count the blocks of a file from where this connection starts it.
        self.last_block_id = 0;
        self.file_written = already_present;
        // The digest that precedes a file is the sender's own measurement of that file; the
        // listing may be older. A listing size of zero means "not known".
        self.file_expected = if std::mem::take(&mut self.digest_is_fresh) {
            Some(self.digest.size)
        } else {
            self.files
                .get(file_num)
                .map(|entry| entry.size)
                .filter(|size| *size > 0)
        };
    }

    #[inline]
    pub fn join(p: &PathBuf, name: &str) -> PathBuf {
        if name.is_empty() {
            p.clone()
        } else {
            p.join(name)
        }
    }

    /// Open the data stream for the current file.
    /// Returns Ok(true) if job is done, Ok(false) otherwise.
    async fn open_data_stream(&mut self) -> ResultType<bool> {
        let file_num = self.file_num as usize;
        match &mut self.data_source {
            DataSource::FilePath(p) => {
                if file_num >= self.files.len() {
                    // job done
                    self.data_stream.take();
                    return Ok(true);
                };
                if self.data_stream.is_none() {
                    match File::open(Self::join(p, &self.files[file_num].name)).await {
                        Ok(file) => {
                            self.data_stream = Some(DataStream::FileStream(file));
                            self.file_confirmed = false;
                            self.file_is_waiting = false;
                        }
                        // On open error, behave the same as validation failure: advance
                        // to next file and return the error.
                        Err(err) => {
                            self.file_num += 1;
                            self.file_confirmed = false;
                            self.file_is_waiting = false;
                            return Err(err.into());
                        }
                    }
                }
            }
            DataSource::MemoryCursor(c) => {
                if self.data_stream.is_none() {
                    let mut t = std::io::Cursor::new(Vec::new());
                    std::mem::swap(&mut t, c);
                    self.data_stream = Some(DataStream::BufStream(TokioBufStream::new(t)));
                }
            }
        }
        Ok(false)
    }

    /// Get current file's digest (last_modified, file_size) for overwrite detection.
    async fn get_current_digest(&self) -> ResultType<(u64, u64)> {
        let meta = match self.data_stream.as_ref().ok_or(anyhow!("file is None"))? {
            DataStream::FileStream(file) => file.metadata().await?,
            DataStream::BufStream(_) => bail!("No digest for buf stream"),
        };
        let last_modified = meta
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        Ok((last_modified, meta.len()))
    }

    async fn init_data_stream(&mut self, stream: &mut crate::Stream) -> ResultType<()> {
        if self.open_data_stream().await? {
            return Ok(());
        }
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
            && !self.file_is_waiting()
        {
            self.send_current_digest(stream).await?;
            self.set_file_is_waiting(true);
        }
        Ok(())
    }

    /// Initialize data stream for CM (Connection Manager) scenario.
    /// Returns digest info (last_modified, file_size) if overwrite detection is enabled,
    /// so caller can send it via IPC instead of network stream.
    /// Returns Ok(None) if job is done or already initialized.
    pub async fn init_data_stream_for_cm(&mut self) -> ResultType<Option<(u64, u64)>> {
        if self.open_data_stream().await? {
            return Ok(None);
        }
        // For overwrite detection, return digest info instead of sending via stream
        if self.r#type == JobType::Generic
            && self.enable_overwrite_detection
            && !self.file_confirmed()
            && !self.file_is_waiting()
        {
            let digest = self.get_current_digest().await?;
            self.set_file_is_waiting(true);
            return Ok(Some(digest));
        }
        Ok(None)
    }

    pub async fn read(&mut self) -> ResultType<Option<FileTransferBlock>> {
        if self.r#type == JobType::Generic {
            if self.enable_overwrite_detection && !self.file_confirmed() {
                return Ok(None);
            }
        }

        let file_num = self.file_num as usize;
        let name = match &self.data_source {
            DataSource::FilePath(p) => {
                if file_num >= self.files.len() {
                    self.data_stream.take();
                    return Ok(None);
                };
                if self.files.len() == 1 && self.files[file_num].name.is_empty() {
                    p.file_name()
                        .map(|p| p.to_str().unwrap_or(""))
                        .unwrap_or("")
                } else {
                    &self.files[file_num].name
                }
            }
            DataSource::MemoryCursor(..) => "",
        };
        const BUF_SIZE: usize = 128 * 1024;
        let mut buf: Vec<u8> = vec![0; BUF_SIZE];
        let mut compressed = false;
        let mut offset: usize = 0;
        loop {
            match self
                .data_stream
                .as_mut()
                .ok_or(anyhow!("data stream is None"))?
                .read(&mut buf[offset..])
                .await
            {
                Err(err) => {
                    self.file_num += 1;
                    self.data_stream = None;
                    self.file_confirmed = false;
                    self.file_is_waiting = false;
                    return Err(err.into());
                }
                Ok(n) => {
                    offset += n;
                    if n == 0 || offset == BUF_SIZE {
                        break;
                    }
                }
            }
        }
        unsafe { buf.set_len(offset) };
        if offset == 0 {
            if matches!(self.data_source, DataSource::MemoryCursor(_)) {
                self.data_stream.take();
                return Ok(None);
            }
            self.file_num += 1;
            self.data_stream = None;
            self.file_confirmed = false;
            self.file_is_waiting = false;
        } else {
            self.finished_size += offset as u64;
            if matches!(self.data_source, DataSource::FilePath(_)) && !is_compressed_file(name) {
                let tmp = compress(&buf);
                if tmp.len() < buf.len() {
                    buf = tmp;
                    compressed = true;
                }
            }
            self.transferred += buf.len() as u64;
        }
        let blk_id = self.next_read_block_id(file_num as i32);
        Ok(Some(FileTransferBlock {
            id: self.id,
            file_num: file_num as _,
            data: buf.into(),
            compressed,
            blk_id,
            ..Default::default()
        }))
    }

    /// The number of the block that was just read from file `file_num`. The empty block that
    /// ends a file is numbered too, so the receiver notices when the last data block is lost.
    fn next_read_block_id(&mut self, file_num: i32) -> u32 {
        if self.block_id_file_num != file_num {
            self.block_id_file_num = file_num;
            self.last_block_id = 0;
        }
        self.last_block_id = next_block_id(self.last_block_id);
        self.last_block_id
    }

    // Only for generic job and file stream
    async fn send_current_digest(&mut self, stream: &mut Stream) -> ResultType<()> {
        let (last_modified, file_size) = self.get_current_digest().await?;
        let mut msg = Message::new();
        let mut resp = FileResponse::new();
        resp.set_digest(FileTransferDigest {
            id: self.id,
            file_num: self.file_num,
            last_modified,
            file_size,
            is_resume: self.is_resume,
            ..Default::default()
        });
        msg.set_file_response(resp);
        stream.send(&msg).await?;
        log::info!(
            "id: {}, file_num: {}, digest message is sent. waiting for confirm. msg: {:?}",
            self.id,
            self.file_num,
            msg
        );
        Ok(())
    }

    pub fn set_overwrite_strategy(&mut self, overwrite_strategy: Option<bool>) {
        self.default_overwrite_strategy = overwrite_strategy;
    }

    pub fn default_overwrite_strategy(&self) -> Option<bool> {
        self.default_overwrite_strategy
    }

    pub fn set_file_confirmed(&mut self, file_confirmed: bool) {
        log::info!("id: {}, file_confirmed: {}", self.id, file_confirmed);
        self.file_confirmed = file_confirmed;
        self.file_skipped = false;
    }

    pub fn set_file_is_waiting(&mut self, file_is_waiting: bool) {
        self.file_is_waiting = file_is_waiting;
    }

    #[inline]
    pub fn file_is_waiting(&self) -> bool {
        self.file_is_waiting
    }

    #[inline]
    pub fn file_confirmed(&self) -> bool {
        self.file_confirmed
    }

    /// Indicating whether the last file is skipped
    #[inline]
    pub fn file_skipped(&self) -> bool {
        self.file_skipped
    }

    /// Indicating whether the whole task is skipped
    #[inline]
    pub fn job_skipped(&self) -> bool {
        self.file_skipped() && self.files.len() == 1
    }

    /// Check whether the job is completed after `read` returns `None`
    /// This is a helper function which gives additional lifecycle when the job reads `None`.
    /// If returns `true`, it means we can delete the job automatically. `False` otherwise.
    ///
    /// [`Note`]
    /// Conditions:
    /// 1. Files are not waiting for confirmation by peers.
    #[inline]
    pub fn job_completed(&self) -> bool {
        // has no error, Condition 2
        !self.enable_overwrite_detection || (!self.file_confirmed && !self.file_is_waiting)
    }

    /// Get job error message, useful for getting status when job had finished
    pub fn job_error(&self) -> Option<String> {
        if self.job_skipped() {
            return Some("skipped".to_string());
        }
        None
    }

    pub fn set_file_skipped(&mut self) -> bool {
        log::debug!("skip file {} in job {}", self.file_num, self.id);
        self.data_stream.take();
        self.file_opened = false;
        self.set_file_confirmed(false);
        self.set_file_is_waiting(false);
        self.file_num += 1;
        self.file_skipped = true;
        true
    }

    async fn set_stream_offset(&mut self, file_num: usize, offset: u64) {
        if let DataSource::FilePath(p) = &self.data_source {
            let entry = &self.files[file_num];
            let Some(path) = self.resolve_entry_path(p, &entry.name) else {
                return;
            };
            let file_path = get_string(&path);
            let download_path = format!("{}.download", &file_path);
            let digest_path = format!("{}.digest", &file_path);

            let mut f = if Path::new(&download_path).exists() && Path::new(&digest_path).exists() {
                // If both download and digest files exist, seek (writer) to the offset
                // NOTE: same as write path: best-effort symlink validation happened earlier,
                // but this reopen remains TOCTOU-prone by design for now.
                match OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&download_path)
                    .await
                {
                    Ok(f) => f,
                    Err(e) => {
                        log::warn!("Failed to open file {}: {}", download_path, e);
                        return;
                    }
                }
            } else if Path::new(&file_path).exists() {
                // If `file_path` exists, seek (reader) to the offset
                match File::open(&file_path).await {
                    Ok(f) => f,
                    Err(e) => {
                        log::warn!("Failed to open file {}: {}", file_path, e);
                        return;
                    }
                }
            } else {
                log::warn!(
                    "File {} not found, cannot seek to offset {}",
                    file_path,
                    offset
                );
                return;
            };
            if f.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {
                self.data_stream = Some(DataStream::FileStream(f));
                self.transferred += offset;
                self.finished_size += offset;
                self.note_file_opened(file_num, offset);
            }
        }
    }

    pub async fn confirm(&mut self, r: &FileTransferSendConfirmRequest) -> bool {
        if self.file_num() != r.file_num {
            // This branch will always be hit if:
            // 1. `confirm()` is called in `ui_cm_interface.rs`
            // 2. Not resuming
            //
            // It is ok. Because `confirm()` in `ui_cm_interface.rs` is only used for resuming.
            //
            // A resume offset for a file that is not open yet must not be lost, though: the
            // sender will start there, and this side would otherwise start a fresh file.
            if let Some(file_transfer_send_confirm_request::Union::OffsetBlk(offset)) = r.union {
                if offset > 0 && !self.reads_local_files {
                    self.pending_resume = Some((r.file_num, offset as u64));
                }
            }
            log::info!("file num truncated, ignoring");
        } else {
            // The peer answers a file's digest only after it has processed everything sent
            // before that digest, so every earlier file has arrived.
            self.peer_confirmed_file_num = self.peer_confirmed_file_num.max(r.file_num);
            match r.union {
                Some(file_transfer_send_confirm_request::Union::Skip(s)) => {
                    if s {
                        self.set_file_skipped();
                    } else {
                        self.set_file_confirmed(true);
                    }
                }
                Some(file_transfer_send_confirm_request::Union::OffsetBlk(offset)) => {
                    self.set_file_confirmed(true);
                    // If offset is greater than 0, we need to seek to the offset
                    if offset > 0 {
                        self.set_stream_offset(r.file_num as usize, offset as u64)
                            .await;
                        if self.data_stream.is_none() && !self.reads_local_files {
                            // Retried, and checked, when the first block of the file arrives.
                            self.pending_resume = Some((r.file_num, offset as u64));
                        }
                    }
                }
                _ => {}
            }
        }
        true
    }

    /// The file a later resume should start from.
    ///
    /// A reader moves to the next file as soon as it has read the last byte of the current
    /// one, long before the peer has received it. With overwrite detection the peer answers a
    /// digest for every file, and that answer is the only proof that the files before it
    /// arrived; so a reader does not move the resume point past the last answered file.
    fn resume_file_num(&self) -> i32 {
        if self.reads_local_files && self.enable_overwrite_detection {
            self.file_num.min(self.peer_confirmed_file_num)
        } else {
            self.file_num
        }
    }

    #[inline]
    pub fn gen_meta(&self) -> TransferJobMeta {
        TransferJobMeta {
            id: self.id,
            remote: self.remote.to_string(),
            to: self.data_source.to_meta(),
            file_num: self.resume_file_num(),
            show_hidden: self.show_hidden,
            is_remote: self.is_remote,
        }
    }
}

/// The block number that follows `last` within a file. Zero is never used: it means "not
/// numbered".
#[inline]
fn next_block_id(last: u32) -> u32 {
    last.checked_add(1).unwrap_or(1)
}

#[inline]
pub fn new_error<T: std::string::ToString>(id: i32, err: T, file_num: i32) -> Message {
    let mut resp = FileResponse::new();
    resp.set_error(FileTransferError {
        id,
        error: err.to_string(),
        file_num,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_dir(id: i32, path: String, files: Vec<FileEntry>) -> Message {
    let mut resp = FileResponse::new();
    resp.set_dir(FileDirectory {
        id,
        path,
        entries: files,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_block(block: FileTransferBlock) -> Message {
    let mut resp = FileResponse::new();
    resp.set_block(block);
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn new_send_confirm(r: FileTransferSendConfirmRequest) -> Message {
    let mut msg_out = Message::new();
    let mut action = FileAction::new();
    action.set_send_confirm(r);
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_receive(
    id: i32,
    path: String,
    file_num: i32,
    files: Vec<FileEntry>,
    total_size: u64,
) -> Message {
    let mut action = FileAction::new();
    action.set_receive(FileTransferReceiveRequest {
        id,
        path,
        files,
        file_num,
        total_size,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_send(
    id: i32,
    r#type: JobType,
    path: String,
    file_num: i32,
    include_hidden: bool,
) -> Message {
    log::info!("new send: {}, id: {}", path, id);
    let mut action = FileAction::new();
    let t: file_transfer_send_request::FileType = r#type.into();
    action.set_send(FileTransferSendRequest {
        id,
        path,
        include_hidden,
        file_num,
        file_type: t.into(),
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_action(action);
    msg_out
}

#[inline]
pub fn new_done(id: i32, file_num: i32) -> Message {
    let mut resp = FileResponse::new();
    resp.set_done(FileTransferDone {
        id,
        file_num,
        ..Default::default()
    });
    let mut msg_out = Message::new();
    msg_out.set_file_response(resp);
    msg_out
}

#[inline]
pub fn remove_job(id: i32, jobs: &mut Vec<TransferJob>) -> Option<TransferJob> {
    jobs.iter()
        .position(|x| x.id() == id)
        .map(|index| jobs.remove(index))
}

#[inline]
pub fn get_job(id: i32, jobs: &mut [TransferJob]) -> Option<&mut TransferJob> {
    jobs.iter_mut().find(|x| x.id() == id)
}

#[inline]
pub fn get_job_immutable(id: i32, jobs: &[TransferJob]) -> Option<&TransferJob> {
    jobs.iter().find(|x| x.id() == id)
}

/// True for the error a queueing stream returns when its outbound queue is full.
#[inline]
pub fn is_would_block(err: &crate::anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|err| err.kind() == std::io::ErrorKind::WouldBlock)
}

/// Sends `message`, or keeps it in `slot` when the stream has no room right now.
/// Returns whether it was sent. Any other error is returned to the caller.
async fn send_or_keep(
    stream: &mut crate::Stream,
    message: Message,
    final_log: Option<String>,
    slot: &mut Option<(Message, Option<String>)>,
) -> ResultType<bool> {
    match stream.send(&message).await {
        Ok(()) => Ok(true),
        Err(err) if is_would_block(&err) => {
            *slot = Some((message, final_log));
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

async fn init_jobs(jobs: &mut Vec<TransferJob>, stream: &mut crate::Stream) -> ResultType<()> {
    for job in jobs.iter_mut() {
        if job.is_last_job || job.pending_send.is_some() {
            // A kept message goes out first, in order.
            continue;
        }
        if let Err(err) = job.init_data_stream(stream).await {
            if is_would_block(&err) {
                // The digest could not be queued; it is sent on a later tick.
                continue;
            }
            let message = new_error(job.id(), err, job.file_num());
            send_or_keep(stream, message, None, &mut job.pending_send).await?;
        }
    }
    Ok(())
}

/// How many blocks one call of [`handle_read_jobs`] may read. The callers run it on a 1 ms
/// timer; one block per call holds a transfer to 128 MiB/s whatever the disk and the link
/// can do. The call stays short enough for the loop that makes it to serve everything else.
const READ_STEPS_PER_CALL: usize = 4;

/// What one step of the read jobs did.
#[derive(Default)]
struct ReadStep {
    /// The log line of a job that finished in this step; empty otherwise.
    job_log: String,
    /// A block was read and queued, and the same job may have more.
    more: bool,
}

/// The sending side of every read job. Called on a timer.
///
/// The stream does not wait in `send`, so this function reads from disk only when the stream
/// reports room for file data, and never drops what it has read: a message that could not be
/// queued stays with its job and is sent first on a later call.
pub async fn handle_read_jobs(
    jobs: &mut Vec<TransferJob>,
    stream: &mut crate::Stream,
) -> ResultType<String> {
    if !stream.file_send_ready() {
        return Ok(Default::default());
    }
    for _ in 0..READ_STEPS_PER_CALL {
        // Before every step: the step before may have ended a file, and the next one has
        // to be opened (and its digest sent) before it can be read.
        init_jobs(jobs, stream).await?;
        let step = read_jobs_step(jobs, stream).await?;
        // One finished job per call: the caller gets one log line back.
        if !step.job_log.is_empty() || !step.more || !stream.file_send_ready() {
            return Ok(step.job_log);
        }
    }
    Ok(Default::default())
}

/// One step: the first active job sends what it kept, or reads and sends one block.
async fn read_jobs_step(
    jobs: &mut Vec<TransferJob>,
    stream: &mut crate::Stream,
) -> ResultType<ReadStep> {
    let mut step = ReadStep::default();
    let mut finished = Vec::new();
    for job in jobs.iter_mut() {
        if job.is_last_job {
            continue;
        }
        if let Some((message, final_log)) = job.pending_send.take() {
            let last = final_log.clone();
            if send_or_keep(stream, message, final_log, &mut job.pending_send).await? {
                if let Some(log) = last {
                    step.job_log = log;
                    finished.push(job.id());
                }
            }
            break;
        }
        match job.read().await {
            Err(err) => {
                let message = new_error(job.id(), err, job.file_num());
                send_or_keep(stream, message, None, &mut job.pending_send).await?;
            }
            Ok(Some(block)) => {
                step.more =
                    send_or_keep(stream, new_block(block), None, &mut job.pending_send).await?;
            }
            Ok(None) => {
                if job.job_completed() {
                    let (log, message) = match job.job_error() {
                        Some(err) => (
                            serialize_transfer_job(job, false, false, &err),
                            new_error(job.id(), err, job.file_num()),
                        ),
                        None => (
                            serialize_transfer_job(job, true, false, ""),
                            new_done(job.id(), job.file_num()),
                        ),
                    };
                    if send_or_keep(stream, message, Some(log.clone()), &mut job.pending_send)
                        .await?
                    {
                        step.job_log = log;
                        finished.push(job.id());
                    }
                } else {
                    // waiting confirmation.
                }
            }
        }
        // Break to handle jobs one by one.
        break;
    }
    for id in finished {
        let _ = remove_job(id, jobs);
    }
    Ok(step)
}

/// Removes `path` and the directories below it when they hold no files. Links are removed,
/// not followed.
///
/// A directory that still holds files stays, and that is not an error: the caller removed
/// the files it wanted to remove before calling this. Any other failure to remove `path`
/// itself is returned.
pub fn remove_all_empty_dir(path: &Path) -> ResultType<()> {
    let fd = read_dir(path, true)?;
    for entry in fd.entries.iter() {
        match entry.entry_type.enum_value() {
            Ok(FileType::Dir) => {
                remove_all_empty_dir(&path.join(&entry.name)).ok();
            }
            Ok(FileType::DirLink) | Ok(FileType::FileLink) => {
                remove_link(&path.join(&entry.name)).ok();
            }
            _ => {}
        }
    }
    match std::fs::remove_dir(path) {
        Err(err) if !is_dir_not_empty(&err) => Err(err.into()),
        _ => Ok(()),
    }
}

/// Removes a link without touching what it points to. On Windows a link to a directory is
/// itself a directory and `remove_file` refuses it.
fn remove_link(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path))
}

fn is_dir_not_empty(err: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        // ERROR_DIR_NOT_EMPTY
        err.raw_os_error() == Some(145)
    }
    #[cfg(not(windows))]
    {
        matches!(
            err.raw_os_error(),
            Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
        )
    }
}

#[inline]
pub fn remove_file(file: &str) -> ResultType<()> {
    validate_fs_path_argument(file, "file path")?;
    std::fs::remove_file(get_path(file))?;
    Ok(())
}

#[inline]
pub fn create_dir(dir: &str) -> ResultType<()> {
    validate_fs_path_argument(dir, "directory path")?;
    std::fs::create_dir_all(get_path(dir))?;
    Ok(())
}

#[inline]
pub fn rename_file(path: &str, new_name: &str) -> ResultType<()> {
    validate_fs_path_argument(path, "path")?;
    if new_name.is_empty() {
        bail!("new file name cannot be empty");
    }
    validate_file_name_no_traversal(new_name)?;
    let path = std::path::Path::new(&path);
    if path.exists() {
        let dir = path
            .parent()
            .ok_or(anyhow!("Parent directoy of {path:?} not exists"))?;
        let new_path = dir.join(&new_name);
        std::fs::rename(&path, &new_path)?;
        Ok(())
    } else {
        bail!("{path:?} not exists");
    }
}

#[inline]
pub fn transform_windows_path(entries: &mut Vec<FileEntry>) {
    for entry in entries {
        entry.name = entry.name.replace('\\', "/");
    }
}

pub enum DigestCheckResult {
    IsSame,
    NeedConfirm(FileTransferDigest),
    NoSuchFile,
}

#[inline]
pub fn is_write_need_confirmation(
    is_resume: bool,
    file_path: &str,
    digest: &FileTransferDigest,
) -> ResultType<DigestCheckResult> {
    let path = Path::new(file_path);
    let digest_file = format!("{}.digest", file_path);
    let download_file = format!("{}.download", file_path);
    if is_resume && Path::new(&digest_file).exists() && Path::new(&download_file).exists() {
        // If the digest file exists, it means the file was transferred before.
        // We can use the digest file to check whether the file is the same.
        if let Ok(content) = std::fs::read_to_string(digest_file) {
            if let Ok(local_digest) = serde_json::from_str::<FileDigest>(&content) {
                let is_identical = local_digest.modified == digest.last_modified
                    && local_digest.size == digest.file_size;
                if is_identical {
                    if let Ok(download_metadata) = std::fs::metadata(download_file) {
                        // Get the file size of the local file
                        // Only send confirmation if the file is not empty.
                        let transferred_size = download_metadata.len();
                        if transferred_size > 0 {
                            return Ok(DigestCheckResult::NeedConfirm(FileTransferDigest {
                                id: digest.id,
                                file_num: digest.file_num,
                                last_modified: digest.last_modified,
                                file_size: digest.file_size,
                                is_identical,
                                transferred_size,
                                ..Default::default()
                            }));
                        }
                    }
                }
            }
        }
    }

    if path.exists() && path.is_file() {
        let metadata = std::fs::metadata(path)?;
        let modified_time = metadata.modified()?;
        let remote_mt = Duration::from_secs(digest.last_modified);
        let local_mt = modified_time.duration_since(UNIX_EPOCH)?;
        // [Note]
        // We decide to give the decision whether to override the existing file to users,
        // which obey the behavior of the file manager in our system.
        let mut is_identical = false;
        if remote_mt == local_mt && digest.file_size == metadata.len() {
            is_identical = true;
        }
        Ok(DigestCheckResult::NeedConfirm(FileTransferDigest {
            id: digest.id,
            file_num: digest.file_num,
            last_modified: local_mt.as_secs(),
            file_size: metadata.len(),
            is_identical,
            ..Default::default()
        }))
    } else {
        // If the file does not exist, or the digest file and download file do not exist, we return NoSuchFile.
        Ok(DigestCheckResult::NoSuchFile)
    }
}

pub fn serialize_transfer_jobs(jobs: &[TransferJob]) -> String {
    let mut v = vec![];
    for job in jobs {
        let value = serde_json::to_value(job).unwrap_or_default();
        v.push(value);
    }
    serde_json::to_string(&v).unwrap_or_default()
}

pub fn serialize_transfer_job(job: &TransferJob, done: bool, cancel: bool, error: &str) -> String {
    let mut value = serde_json::to_value(job).unwrap_or_default();
    value["done"] = json!(done);
    value["cancel"] = json!(cancel);
    value["error"] = json!(error);
    serde_json::to_string(&value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf::Message as _;

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            Self {
                path: unique_temp_dir(prefix),
            }
        }

        fn join(&self, path: &str) -> PathBuf {
            self.path.join(path)
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), timestamp))
    }

    fn new_file_entry(name: &str) -> FileEntry {
        let mut entry = FileEntry::new();
        entry.name = name.to_string();
        entry
    }

    fn new_validation_job(id: i32) -> TransferJob {
        TransferJob::new_write(
            id,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(std::env::temp_dir().join(format!("rustdesk_validation_{id}"))),
            0,
            false,
            true,
            false,
        )
    }

    fn new_write_job(id: i32, download_dir: PathBuf, name: &str) -> ResultType<TransferJob> {
        let job = TransferJob::new_write(
            id,
            JobType::Generic,
            "/fake/remote".to_string(),
            DataSource::FilePath(download_dir),
            0,
            false,
            true,
            false,
        )
        .with_files(vec![new_file_entry(name)])?;
        Ok(job)
    }

    fn assert_err_contains(err: anyhow::Error, expected: &str) {
        assert!(
            err.to_string().contains(expected),
            "expected error containing '{}', got: {}",
            expected,
            err
        );
    }

    #[test]
    fn windows_component_rules() {
        for unsafe_name in [
            "a.txt:stream",
            "x:y",
            "CON",
            "con",
            "NUL.txt",
            "Aux.tar.gz",
            "COM1",
            "COM0",
            "lpt9.log",
            "PRN ",
            "name.",
            "name ",
            "CONIN$",
        ] {
            assert!(windows_component_unsafe(unsafe_name), "{unsafe_name}");
        }
        for fine in [
            "a.txt",
            "readme",
            ".hidden",
            "console.txt",
            "COM10",
            "LPT",
            "com.example.app",
            "my file.txt",
            "",
            ".",
        ] {
            assert!(!windows_component_unsafe(fine), "{fine}");
        }
    }

    #[test]
    fn validator_applies_the_windows_rules_only_on_windows() {
        let res = validate_file_name_no_traversal("dir/CON.txt");
        assert_eq!(res.is_err(), cfg!(windows));
        let res = validate_file_name_no_traversal("dir/a.txt:s");
        assert_eq!(res.is_err(), cfg!(windows));
        assert!(validate_file_name_no_traversal("dir/ok.txt").is_ok());
        assert!(validate_file_name_no_traversal("../x").is_err());
    }

    #[test]
    fn path_traversal_e2e_write_rejects_relative_escape() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_relative");
        let downloads = tmp_root.join("downloads");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");

        let err = new_write_job(1, downloads, "../traversal_proof.txt")
            .expect_err("relative path traversal must be rejected");
        assert_err_contains(err, "path traversal");
        assert!(!tmp_root.join("traversal_proof.txt").exists());
    }

    #[test]
    fn path_traversal_e2e_write_rejects_absolute_path() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_absolute");
        let downloads = tmp_root.join("downloads");
        let absolute_target = tmp_root.join("fake_ssh").join("authorized_keys");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");

        let err = new_write_job(2, downloads, &absolute_target.to_string_lossy())
            .expect_err("absolute path must be rejected");
        assert_err_contains(err, "absolute path");
        assert!(!absolute_target.exists());
    }

    #[test]
    #[cfg_attr(windows, ignore = "requires symlink privilege to create test symlink")]
    fn path_traversal_e2e_write_rejects_symlink_escape() {
        let tmp_root = TestTempDir::new("rustdesk_e2e_symlink");
        let downloads = tmp_root.join("downloads");
        let outside = tmp_root.join("outside");
        let escaped_target = outside.join("escape.txt");
        std::fs::create_dir_all(&downloads).expect("create downloads dir");
        std::fs::create_dir_all(&outside).expect("create outside dir");

        let symlink_path = downloads.join("link");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside, &symlink_path).expect("create symlink for test");
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_dir;
            symlink_dir(&outside, &symlink_path).expect("create directory symlink for test");
        }

        let err = new_write_job(3, downloads, "link/escape.txt")
            .expect_err("symlink traversal must be rejected");
        assert_err_contains(err, "symlink");
        assert!(!escaped_target.exists());
    }

    #[test]
    fn set_files_allows_single_empty_name_for_single_file_transfer() {
        let mut job = new_validation_job(101);
        assert!(job.set_files(vec![new_file_entry("")]).is_ok());
    }

    #[test]
    fn set_files_rejects_empty_name_in_multi_file_transfer() {
        let mut job = new_validation_job(102);
        let err = job
            .set_files(vec![new_file_entry(""), new_file_entry("ok.txt")])
            .expect_err("empty name in multi-file transfer must be rejected");
        assert_err_contains(err, "empty file name");
    }

    #[test]
    fn set_files_rejects_null_byte_name() {
        let mut job = new_validation_job(103);
        let err = job
            .set_files(vec![new_file_entry("bad\0name.txt")])
            .expect_err("null byte in file name must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn set_files_rejects_mixed_entries_when_one_is_traversal() {
        let mut job = new_validation_job(104);
        let err = job
            .set_files(vec![
                new_file_entry("safe/file.txt"),
                new_file_entry("../../escape.txt"),
            ])
            .expect_err("any traversal entry must reject the full file list");
        assert_err_contains(err, "path traversal");
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_unc_absolute_path() {
        let mut job = new_validation_job(105);
        let err = job
            .set_files(vec![new_file_entry("\\\\server\\share\\payload.txt")])
            .expect_err("UNC absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }

    #[cfg(not(windows))]
    #[test]
    fn set_files_allows_backslash_prefixed_name_on_unix() {
        let mut job = new_validation_job(105);
        assert!(job
            .set_files(vec![new_file_entry("\\\\server\\share\\payload.txt")])
            .is_ok());
    }

    #[test]
    fn remove_file_rejects_empty_path() {
        let err = remove_file("").expect_err("empty file path must be rejected");
        assert_err_contains(err, "cannot be empty");
    }

    #[test]
    fn remove_file_rejects_null_byte_path() {
        let err = remove_file("bad\0path").expect_err("null byte path must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn create_dir_rejects_empty_path() {
        let err = create_dir("").expect_err("empty directory path must be rejected");
        assert_err_contains(err, "cannot be empty");
    }

    #[test]
    fn create_dir_rejects_null_byte_path() {
        let err = create_dir("bad\0path").expect_err("null byte path must be rejected");
        assert_err_contains(err, "null bytes");
    }

    #[test]
    fn rename_file_rejects_invalid_new_name() {
        let tmp_root = TestTempDir::new("rustdesk_rename_invalid");
        let src = tmp_root.join("source.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create temp dir");
        std::fs::write(&src, b"content").expect("create source file");

        let src_str = src.to_string_lossy().to_string();

        let err_empty =
            rename_file(&src_str, "").expect_err("empty new file name must be rejected");
        assert_err_contains(err_empty, "cannot be empty");

        let err_traversal = rename_file(&src_str, "../escape.txt")
            .expect_err("traversal new file name must be rejected");
        assert_err_contains(err_traversal, "path traversal");

        let err_null = rename_file(&src_str, "bad\0name.txt")
            .expect_err("null byte in new file name must be rejected");
        assert_err_contains(err_null, "null bytes");

        #[cfg(windows)]
        {
            let err_abs = rename_file(&src_str, "C:\\Windows\\Temp\\payload.txt")
                .expect_err("absolute new file name must be rejected");
            assert_err_contains(err_abs, "absolute path");
        }
        #[cfg(not(windows))]
        {
            let err_abs = rename_file(&src_str, "/tmp/payload.txt")
                .expect_err("absolute new file name must be rejected");
            assert_err_contains(err_abs, "absolute path");
        }
    }

    #[test]
    fn rename_file_accepts_valid_new_name() {
        let tmp_root = TestTempDir::new("rustdesk_rename_ok");
        let src = tmp_root.join("rename_src.txt");
        let dst = tmp_root.join("renamed.txt");
        std::fs::create_dir_all(&tmp_root.path).expect("create temp dir");
        std::fs::write(&src, b"content").expect("create source file");

        let src_str = src.to_string_lossy().to_string();
        rename_file(&src_str, "renamed.txt").expect("rename should succeed");

        assert!(!src.exists());
        assert!(dst.exists());
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_windows_drive_absolute_path() {
        let mut job = new_validation_job(106);
        let err = job
            .set_files(vec![new_file_entry("C:\\Windows\\Temp\\payload.txt")])
            .expect_err("drive-letter absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }

    #[cfg(windows)]
    #[test]
    fn set_files_rejects_windows_verbatim_drive_absolute_path() {
        let mut job = new_validation_job(1061);
        let err = job
            .set_files(vec![new_file_entry(r"\\?\C:\Windows\Temp\x.txt")])
            .expect_err("verbatim drive absolute path must be rejected");
        assert_err_contains(err, "absolute path");
    }
    /// Deterministic data that does not compress, so every block stays 128 KiB.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut data = Vec::with_capacity(len + 8);
        while data.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.extend_from_slice(&state.to_le_bytes());
        }
        data.truncate(len);
        data
    }

    #[test]
    fn would_block_is_recognised_through_anyhow() {
        let full: crate::anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "outbox is full").into();
        assert!(is_would_block(&full));
        let closed: crate::anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed").into();
        assert!(!is_would_block(&closed));
        assert!(!is_would_block(&anyhow!("something else")));
    }

    /// The sender reads on a 1 ms timer; the receiver takes a few milliseconds per block. Before
    /// the readiness check the outbox filled up and `handle_read_jobs` failed with `WouldBlock`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_receiver_gets_every_block_of_a_file_larger_than_the_outbox() {
        const BLOCK: usize = 128 * 1024;
        let tmp = TestTempDir::new("rustdesk_fs_backpressure");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let src = tmp.join("source.bin");
        let dst = tmp.join("result.bin");
        // 64 blocks through an outbox of 8 entries.
        let data = incompressible(64 * BLOCK + 1234);
        std::fs::write(&src, &data).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let size = data.len() as u64;
        let receiver = {
            let dst = dst.clone();
            tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let local = tcp.local_addr().unwrap();
                let mut stream = Stream::from(tcp, local);
                let mut job = TransferJob::new_write(
                    7,
                    JobType::Generic,
                    "peer".to_owned(),
                    DataSource::FilePath(dst),
                    0,
                    true,
                    false,
                    false,
                )
                .with_files(vec![FileEntry {
                    size,
                    ..Default::default()
                }])
                .unwrap();
                let mut blocks = 0;
                loop {
                    let bytes = stream.next().await.expect("open").expect("readable");
                    let message = Message::parse_from_bytes(&bytes).unwrap();
                    let Some(message::Union::FileResponse(response)) = message.union else {
                        continue;
                    };
                    match response.union {
                        Some(file_response::Union::Block(block)) => {
                            job.write(block).await.unwrap();
                            blocks += 1;
                            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
                        }
                        Some(file_response::Union::Done(_)) => {
                            job.modify_time();
                            return blocks;
                        }
                        other => panic!("unexpected file response: {:?}", other),
                    }
                }
            })
        };

        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let local = tcp.local_addr().unwrap();
        let mut stream = Stream::from(tcp, local).into_duplex(8);
        let mut jobs = vec![TransferJob::new_read(
            7,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(src),
            0,
            true,
            false,
            false,
        )
        .unwrap()];
        let mut skipped = 0;
        while !jobs.is_empty() {
            if !stream.file_send_ready() {
                skipped += 1;
            }
            handle_read_jobs(&mut jobs, &mut stream)
                .await
                .expect("a full outbox must not end the transfer");
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let blocks = tokio::time::timeout(std::time::Duration::from_secs(60), receiver)
            .await
            .expect("receiver finished")
            .unwrap();
        assert!(blocks >= 65, "blocks received: {}", blocks);
        assert!(skipped > 0, "the test must exercise a full outbox");
        assert!(std::fs::read(&dst).unwrap() == data, "content differs");
    }

    /// A message that could not be queued stays with the job and goes out first, once.
    #[tokio::test]
    async fn kept_message_is_sent_before_anything_else_is_read() {
        let tmp = TestTempDir::new("rustdesk_fs_pending");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let src = tmp.join("source.bin");
        std::fs::write(&src, b"abc").unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let local = tcp.local_addr().unwrap();
        let mut stream = Stream::from(tcp, local);
        let mut jobs = vec![TransferJob::new_read(
            9,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(src),
            0,
            true,
            false,
            false,
        )
        .unwrap()];
        // As if a final message had been refused by a full queue on an earlier tick.
        jobs[0].pending_send = Some((new_done(9, 0), Some("kept".to_owned())));

        let log = handle_read_jobs(&mut jobs, &mut stream).await.unwrap();
        assert_eq!(log, "kept");
        assert!(jobs.is_empty(), "the kept final message ends the job");

        let peer_local = peer.local_addr().unwrap();
        let mut peer = Stream::from(peer, peer_local);
        let bytes = peer.next().await.unwrap().unwrap();
        let message = Message::parse_from_bytes(&bytes).unwrap();
        let Some(message::Union::FileResponse(response)) = message.union else {
            panic!("expected a file response");
        };
        assert!(
            matches!(response.union, Some(file_response::Union::Done(_))),
            "the kept message is sent as it was, before any block"
        );
    }

    async fn finish(job: &mut TransferJob) -> ResultType<()> {
        job.finish_file().await
    }

    // ---- write, finish and resume must fail safely (FT-06, FT-07 size, FT-04, N-05) ----

    fn data_block(id: i32, file_num: i32, data: &[u8]) -> FileTransferBlock {
        FileTransferBlock {
            id,
            file_num,
            data: data.to_vec().into(),
            ..Default::default()
        }
    }

    fn write_job_for(id: i32, dir: &Path, files: &[(&str, u64)]) -> TransferJob {
        TransferJob::new_write(
            id,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(dir.to_path_buf()),
            0,
            false,
            false,
            false,
        )
        .with_files(
            files
                .iter()
                .map(|(name, size)| FileEntry {
                    name: (*name).to_owned(),
                    size: *size,
                    ..Default::default()
                })
                .collect(),
        )
        .expect("valid file list")
    }

    #[tokio::test]
    async fn block_after_a_failed_open_does_not_touch_the_previous_file() {
        let tmp = TestTempDir::new("rustdesk_fs_failed_open");
        std::fs::create_dir_all(&tmp.path).unwrap();
        // With the `.download` suffix this name is longer than a file name may be.
        let too_long = "b".repeat(250);
        let mut job = write_job_for(21, &tmp.path, &[("a", 0), (too_long.as_str(), 0)]);

        job.write(data_block(21, 0, b"AAA")).await.unwrap();
        assert!(job.write(data_block(21, 1, b"BBB")).await.is_err());
        // The sender does not know yet and keeps sending.
        let _ = job.write(data_block(21, 1, b"CCC")).await;
        let _ = finish(&mut job).await;
        drop(job);

        assert_eq!(std::fs::read(tmp.join("a")).unwrap(), b"AAA");
    }

    #[tokio::test]
    async fn corrupt_compressed_block_leaves_no_final_file() {
        let tmp = TestTempDir::new("rustdesk_fs_corrupt_block");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let mut job = write_job_for(22, &tmp.path, &[("x", 0)]);

        let mut block = data_block(22, 0, b"this is not compressed data");
        block.compressed = true;
        assert!(job.write(block).await.is_err());
        let _ = finish(&mut job).await;

        assert!(
            !tmp.join("x").exists(),
            "a failed file was moved into place"
        );
    }

    #[tokio::test]
    async fn short_file_is_not_moved_into_place() {
        let tmp = TestTempDir::new("rustdesk_fs_short_file");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let mut job = write_job_for(23, &tmp.path, &[("x", 10)]);

        job.write(data_block(23, 0, b"only")).await.unwrap();
        assert!(finish(&mut job).await.is_err());

        assert!(
            !tmp.join("x").exists(),
            "4 of 10 bytes were accepted as the file"
        );
        assert!(tmp.join("x.download").exists(), "the partial file is kept");
        assert!(
            !tmp.join("x.digest").exists(),
            "a file with a hole must not be continued by a later resume"
        );
    }

    #[tokio::test]
    async fn error_moving_the_file_into_place_is_returned() {
        let tmp = TestTempDir::new("rustdesk_fs_rename_error");
        // The destination name is taken by a directory that is not empty.
        std::fs::create_dir_all(tmp.join("x")).unwrap();
        std::fs::write(tmp.join("x").join("keep"), b"keep").unwrap();
        let mut job = write_job_for(24, &tmp.path, &[("x", 3)]);

        job.write(data_block(24, 0, b"abc")).await.unwrap();
        assert!(finish(&mut job).await.is_err());
        assert_eq!(std::fs::read(tmp.join("x").join("keep")).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn resume_offset_for_a_later_file_is_applied_when_that_file_opens() {
        let tmp = TestTempDir::new("rustdesk_fs_resume_later_file");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let first = incompressible(1000);
        let second = incompressible(300_000);
        let half = 150_000usize;
        // Left by an interrupted transfer of the second file.
        std::fs::write(tmp.join("b.download"), &second[..half]).unwrap();
        std::fs::write(tmp.join("b.digest"), b"{}").unwrap();

        let mut job = write_job_for(
            25,
            &tmp.path,
            &[("a", first.len() as u64), ("b", second.len() as u64)],
        );
        job.is_resume = true;
        job.write(data_block(25, 0, &first)).await.unwrap();
        // Both sides agree to continue the second file while the first is still current here.
        job.confirm(&FileTransferSendConfirmRequest {
            id: 25,
            file_num: 1,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(
                half as u32,
            )),
            ..Default::default()
        })
        .await;
        job.write(data_block(25, 1, &second[half..])).await.unwrap();
        finish(&mut job).await.unwrap();
        drop(job);

        assert!(std::fs::read(tmp.join("a")).unwrap() == first, "first file");
        assert!(
            std::fs::read(tmp.join("b")).unwrap() == second,
            "the resumed file differs from the source"
        );
    }

    /// A `.download` file left by an earlier, interrupted transfer says nothing about the
    /// file that is already in place.
    #[tokio::test]
    async fn leftover_partial_file_does_not_replace_the_file_in_place() {
        let tmp = TestTempDir::new("rustdesk_fs_leftover_partial");
        std::fs::create_dir_all(&tmp.path).unwrap();
        std::fs::write(tmp.join("x"), b"complete").unwrap();
        std::fs::write(tmp.join("x.download"), b"half").unwrap();
        let mut job = write_job_for(34, &tmp.path, &[("x", 0)]);

        job.write(data_block(34, 0, b"new")).await.unwrap();
        // The new transfer breaks before it is complete.
        let mut block = data_block(34, 0, b"this is not compressed data");
        block.compressed = true;
        assert!(job.write(block).await.is_err());
        let _ = finish(&mut job).await;
        drop(job);

        assert_eq!(std::fs::read(tmp.join("x")).unwrap(), b"complete");
    }

    /// Writes `blocks` blocks into a file on a device that is always full, then finishes.
    #[cfg(target_os = "linux")]
    async fn write_to_a_full_disk(blocks: usize) {
        if !Path::new("/dev/full").exists() {
            return;
        }
        let tmp = TestTempDir::new("rustdesk_fs_full_disk");
        std::fs::create_dir_all(&tmp.path).unwrap();
        // Every write to this device reports "no space left on device".
        std::os::unix::fs::symlink("/dev/full", tmp.join("x.download")).unwrap();
        let mut job = write_job_for(26, &tmp.path, &[("unused", 0), ("x", 0)]);

        let mut errors = Vec::new();
        for _ in 0..blocks {
            if let Err(err) = job.write(data_block(26, 1, &[7u8; 4096])).await {
                errors.push(format!("write: {}", err));
            }
        }
        if let Err(err) = finish(&mut job).await {
            errors.push(format!("finish: {}", err));
        }
        drop(job);

        // 28 is "no space left on device".
        assert!(
            errors.iter().any(|err| err.contains("os error 28")),
            "the write error was not reported: {:?}",
            errors
        );
        assert!(
            std::fs::symlink_metadata(tmp.join("x")).is_err(),
            "a file that could not be written was moved into place"
        );
    }

    /// The error of the last write is known only when the file is closed.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn full_disk_on_the_last_block_fails_the_job() {
        write_to_a_full_disk(1).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn full_disk_in_the_middle_fails_the_job_and_nothing_is_moved_into_place() {
        write_to_a_full_disk(2).await;
    }

    /// Runs the digest and confirmation step for the reader's current file, as the peer would.
    async fn peer_confirms_current_file(job: &mut TransferJob) {
        job.init_data_stream_for_cm().await.unwrap();
        let file_num = job.file_num();
        job.confirm(&FileTransferSendConfirmRequest {
            id: job.id(),
            file_num,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
            ..Default::default()
        })
        .await;
    }

    /// Reads the reader's current file to its end and returns the blocks, the empty one included.
    async fn read_current_file(job: &mut TransferJob) -> Vec<FileTransferBlock> {
        let mut blocks = Vec::new();
        loop {
            let block = job.read().await.unwrap().expect("a block");
            let last = block.data.is_empty();
            blocks.push(block);
            if last {
                return blocks;
            }
        }
    }

    #[tokio::test]
    async fn resume_point_does_not_pass_a_file_the_peer_has_not_answered_for() {
        let tmp = TestTempDir::new("rustdesk_fs_resume_point");
        let source = tmp.join("source");
        let target = tmp.join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(source.join("one"), incompressible(200_000)).unwrap();
        std::fs::write(source.join("two"), incompressible(1000)).unwrap();
        let new_reader = |file_num: i32| {
            TransferJob::new_read(
                27,
                JobType::Generic,
                "peer".to_owned(),
                DataSource::FilePath(source.clone()),
                file_num,
                true,
                false,
                true,
            )
            .unwrap()
        };

        // The first connection: the whole first file is read and queued, and then the
        // connection is lost before the peer has received it.
        let mut reader = new_reader(0);
        assert_eq!(reader.files().len(), 2);
        peer_confirms_current_file(&mut reader).await;
        let lost = read_current_file(&mut reader).await;
        assert!(lost.len() >= 2);
        assert_eq!(reader.file_num(), 1, "the reader itself has moved on");
        let saved = reader.gen_meta();
        drop(reader);

        // The second connection continues from what was saved.
        let files = new_reader(0).files().clone();
        let mut writer = TransferJob::new_write(
            27,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(target.clone()),
            saved.file_num,
            true,
            false,
            true,
        )
        .with_files(files.clone())
        .unwrap();
        let mut reader = new_reader(saved.file_num);
        while (reader.file_num() as usize) < files.len() {
            peer_confirms_current_file(&mut reader).await;
            for block in read_current_file(&mut reader).await {
                writer.write(block).await.unwrap();
            }
        }
        finish(&mut writer).await.unwrap();
        drop(writer);

        for file in &files {
            assert!(
                std::fs::read(target.join(&file.name)).ok()
                    == Some(std::fs::read(source.join(&file.name)).unwrap()),
                "{} did not arrive after the resume",
                file.name
            );
        }
    }

    #[tokio::test]
    async fn failed_job_takes_no_more_blocks() {
        let tmp = TestTempDir::new("rustdesk_fs_failed_job");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let mut job = write_job_for(28, &tmp.path, &[("x", 0)]);
        assert!(!job.has_failed());

        let mut block = data_block(28, 0, b"garbage");
        block.compressed = true;
        assert!(job.write(block).await.is_err());
        assert!(job.has_failed());
        let err = job.write(data_block(28, 0, b"fine")).await.unwrap_err();
        assert_err_contains(err, "already failed");
        assert!(job.finish_file().await.is_err());
        assert!(!tmp.join("x").exists());
    }

    #[tokio::test]
    async fn sender_digest_decides_the_expected_size_for_its_own_file_only() {
        let tmp = TestTempDir::new("rustdesk_fs_digest_size");
        std::fs::create_dir_all(&tmp.path).unwrap();
        // The listing is older than the files: it says 10 bytes for both.
        let mut job = write_job_for(29, &tmp.path, &[("a", 10), ("b", 10)]);

        // The sender measured 4 bytes when it opened the first file.
        job.set_digest(4, 0);
        job.write(data_block(29, 0, b"1234")).await.unwrap();
        // No digest precedes the second file, so the first one's must not be applied to it.
        job.write(data_block(29, 1, b"12345")).await.unwrap();
        assert_eq!(std::fs::read(tmp.join("a")).unwrap(), b"1234");
        let err = job.finish_file().await.unwrap_err();
        assert_err_contains(err, "5 of 10 bytes");
        assert!(!tmp.join("b").exists());
    }

    #[tokio::test]
    async fn empty_file_and_exact_size_are_complete() {
        let tmp = TestTempDir::new("rustdesk_fs_exact_size");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let mut job = write_job_for(30, &tmp.path, &[("empty", 0), ("exact", 3)]);

        job.write(data_block(30, 0, b"")).await.unwrap();
        job.write(data_block(30, 1, b"abc")).await.unwrap();
        job.write(data_block(30, 1, b"")).await.unwrap();
        job.finish_file().await.unwrap();
        // Asking again changes nothing.
        job.finish_file().await.unwrap();

        assert_eq!(std::fs::read(tmp.join("empty")).unwrap(), b"");
        assert_eq!(std::fs::read(tmp.join("exact")).unwrap(), b"abc");
        assert!(!tmp.join("exact.download").exists());
        assert!(!tmp.join("exact.digest").exists());
    }

    #[tokio::test]
    async fn resume_offset_beyond_the_partial_file_fails_the_job() {
        let tmp = TestTempDir::new("rustdesk_fs_resume_too_far");
        std::fs::create_dir_all(&tmp.path).unwrap();
        std::fs::write(tmp.join("a.download"), b"x").unwrap();
        std::fs::write(tmp.join("b.download"), b"12345").unwrap();
        std::fs::write(tmp.join("b.digest"), b"{}").unwrap();
        let mut job = write_job_for(31, &tmp.path, &[("a", 1), ("b", 20)]);
        job.write(data_block(31, 0, b"x")).await.unwrap();
        job.confirm(&FileTransferSendConfirmRequest {
            id: 31,
            file_num: 1,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(10)),
            ..Default::default()
        })
        .await;

        let err = job
            .write(data_block(31, 1, b"0123456789"))
            .await
            .unwrap_err();
        assert_err_contains(err, "fewer than the agreed offset");
        assert!(job.has_failed());
        assert_eq!(std::fs::read(tmp.join("b.download")).unwrap(), b"12345");
    }

    #[tokio::test]
    async fn reader_resume_point_follows_the_peer_answers() {
        let tmp = TestTempDir::new("rustdesk_fs_resume_answers");
        std::fs::create_dir_all(&tmp.path).unwrap();
        std::fs::write(tmp.join("one"), b"1").unwrap();
        std::fs::write(tmp.join("two"), b"2").unwrap();
        let mut reader = TransferJob::new_read(
            32,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(tmp.path.clone()),
            0,
            true,
            false,
            true,
        )
        .unwrap();

        peer_confirms_current_file(&mut reader).await;
        read_current_file(&mut reader).await;
        assert_eq!((reader.file_num(), reader.gen_meta().file_num), (1, 0));
        // The peer skips the second file: that answer proves the first one arrived.
        reader.init_data_stream_for_cm().await.unwrap();
        reader
            .confirm(&FileTransferSendConfirmRequest {
                id: 32,
                file_num: 1,
                union: Some(file_transfer_send_confirm_request::Union::Skip(true)),
                ..Default::default()
            })
            .await;
        assert_eq!((reader.file_num(), reader.gen_meta().file_num), (2, 1));

        // Without overwrite detection the peer answers nothing, and the old rule stays.
        let mut reader = TransferJob::new_read(
            33,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(tmp.path.clone()),
            0,
            true,
            false,
            false,
        )
        .unwrap();
        reader.init_data_stream_for_cm().await.unwrap();
        read_current_file(&mut reader).await;
        assert_eq!((reader.file_num(), reader.gen_meta().file_num), (1, 1));
    }

    // ---- the blocks of a file are numbered, and a gap fails the job (FT-07) ----

    fn numbered_block(id: i32, file_num: i32, blk_id: u32, data: &[u8]) -> FileTransferBlock {
        let mut block = data_block(id, file_num, data);
        block.blk_id = blk_id;
        block
    }

    #[tokio::test]
    async fn reader_numbers_the_blocks_of_every_file_from_one() {
        let tmp = TestTempDir::new("rustdesk_fs_block_numbers");
        std::fs::create_dir_all(&tmp.path).unwrap();
        // Three data blocks and the empty one that ends the file; then one and the end.
        std::fs::write(tmp.join("one"), incompressible(300_000)).unwrap();
        std::fs::write(tmp.join("two"), b"2").unwrap();
        let mut reader = TransferJob::new_read(
            41,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(tmp.path.clone()),
            0,
            true,
            false,
            true,
        )
        .unwrap();

        let mut numbers = Vec::new();
        while (reader.file_num() as usize) < reader.files().len() {
            peer_confirms_current_file(&mut reader).await;
            let blocks = read_current_file(&mut reader).await;
            numbers.push(blocks.iter().map(|block| block.blk_id).collect::<Vec<_>>());
        }
        numbers.sort();
        assert_eq!(numbers, vec![vec![1, 2], vec![1, 2, 3, 4]]);
    }

    #[tokio::test]
    async fn lost_block_fails_the_job() {
        let tmp = TestTempDir::new("rustdesk_fs_lost_block");
        std::fs::create_dir_all(&tmp.path).unwrap();
        // This receiver does not know the size, so only the numbers can show the loss.
        let mut job = write_job_for(42, &tmp.path, &[("x", 0)]);

        job.write(numbered_block(42, 0, 1, b"first "))
            .await
            .unwrap();
        // Block 2 never arrives.
        let third = job.write(numbered_block(42, 0, 3, b"third")).await;
        let _ = job.write(numbered_block(42, 0, 4, b"")).await;
        let finished = finish(&mut job).await;
        drop(job);

        assert!(
            !tmp.join("x").exists(),
            "a file with a hole was moved into place"
        );
        assert!(third.is_err() && finished.is_err());
    }

    #[tokio::test]
    async fn repeated_block_fails_the_job() {
        let tmp = TestTempDir::new("rustdesk_fs_repeated_block");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let mut job = write_job_for(43, &tmp.path, &[("x", 0)]);

        job.write(numbered_block(43, 0, 1, b"once")).await.unwrap();
        let err = job
            .write(numbered_block(43, 0, 1, b"once"))
            .await
            .unwrap_err();
        assert_err_contains(
            err,
            "block 1 of the file arrived where block 2 was expected",
        );
        assert!(job.has_failed());
        assert!(job.finish_file().await.is_err());
        assert!(!tmp.join("x").exists());
    }

    #[tokio::test]
    async fn blocks_without_numbers_are_accepted() {
        let tmp = TestTempDir::new("rustdesk_fs_unnumbered_blocks");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let mut job = write_job_for(44, &tmp.path, &[("x", 6)]);

        // A sender that does not number its blocks leaves the field at zero.
        job.write(data_block(44, 0, b"abc")).await.unwrap();
        job.write(data_block(44, 0, b"def")).await.unwrap();
        job.write(data_block(44, 0, b"")).await.unwrap();
        job.finish_file().await.unwrap();
        assert_eq!(std::fs::read(tmp.join("x")).unwrap(), b"abcdef");
    }

    #[tokio::test]
    async fn numbering_starts_again_for_each_file_and_for_a_resumed_file() {
        let tmp = TestTempDir::new("rustdesk_fs_block_numbers_restart");
        std::fs::create_dir_all(&tmp.path).unwrap();
        std::fs::write(tmp.join("b.download"), b"12345").unwrap();
        std::fs::write(tmp.join("b.digest"), b"{}").unwrap();
        let mut job = write_job_for(45, &tmp.path, &[("a", 2), ("b", 10)]);

        job.write(numbered_block(45, 0, 1, b"aa")).await.unwrap();
        job.write(numbered_block(45, 0, 2, b"")).await.unwrap();
        // The sender continues the second file at byte 5 and counts from one again.
        job.confirm(&FileTransferSendConfirmRequest {
            id: 45,
            file_num: 1,
            union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(5)),
            ..Default::default()
        })
        .await;
        job.write(numbered_block(45, 1, 1, b"67890")).await.unwrap();
        job.write(numbered_block(45, 1, 2, b"")).await.unwrap();
        job.finish_file().await.unwrap();

        assert_eq!(std::fs::read(tmp.join("a")).unwrap(), b"aa");
        assert_eq!(std::fs::read(tmp.join("b")).unwrap(), b"1234567890");
    }

    #[test]
    fn block_numbers_never_use_zero() {
        assert_eq!(next_block_id(0), 1);
        assert_eq!(next_block_id(41), 42);
        assert_eq!(next_block_id(u32::MAX), 1);
    }

    // ---- paths, job ids and limits (N-03, N-04, FT-11, FT-12, FT-15) ----

    #[test]
    fn restored_job_id_is_never_handed_out_again() {
        // The counter is shared by every test of this process, so only relations are checked.
        let restored = get_next_job_id() + 1000;
        reserve_job_id(restored);
        assert!(get_next_job_id() > restored);
        // Reserving an id that is already behind the counter changes nothing.
        let before = get_next_job_id();
        reserve_job_id(1);
        assert_eq!(get_next_job_id(), before + 1);
        reserve_job_id(i32::MAX);
    }

    fn tree_with_files(prefix: &str, dirs: usize, files_per_dir: usize) -> TestTempDir {
        let tmp = TestTempDir::new(prefix);
        for dir in 0..dirs {
            let path = tmp.join(&format!("d{}", dir));
            std::fs::create_dir_all(&path).unwrap();
            for file in 0..files_per_dir {
                std::fs::write(path.join(format!("f{}", file)), b"x").unwrap();
            }
        }
        tmp
    }

    #[test]
    fn file_walk_stops_at_the_limit() {
        let tmp = tree_with_files("rustdesk_fs_walk_limit", 4, 5);
        let root = get_string(&tmp.path);

        assert_eq!(get_recursive_files(&root, true).unwrap().len(), 20);
        assert_eq!(
            get_recursive_files_limited(&root, true, 20).unwrap().len(),
            20
        );
        let err = get_recursive_files_limited(&root, true, 19).unwrap_err();
        assert_eq!(too_many_entries(&err), Some(TooManyEntries { limit: 19 }));
        let err = get_recursive_files_limited(&root, true, 0).unwrap_err();
        assert_eq!(too_many_entries(&err), Some(TooManyEntries { limit: 0 }));
        // Another failure is not mistaken for the limit.
        let err =
            get_recursive_files_limited(&get_string(&tmp.join("missing")), true, 5).unwrap_err();
        assert_eq!(too_many_entries(&err), None);

        let job = |limit| {
            TransferJob::new_read_limited(
                51,
                JobType::Generic,
                "peer".to_owned(),
                DataSource::FilePath(tmp.path.clone()),
                0,
                true,
                false,
                true,
                limit,
            )
        };
        assert_eq!(job(20).unwrap().files().len(), 20);
        assert!(too_many_entries(&job(19).unwrap_err()).is_some());
    }

    #[test]
    fn empty_directory_walk_stops_at_the_limit() {
        let tmp = tree_with_files("rustdesk_fs_empty_dirs_limit", 3, 1);
        for dir in 0..4 {
            std::fs::create_dir_all(tmp.join(&format!("empty{}", dir))).unwrap();
        }
        let root = get_string(&tmp.path);

        // The root, three directories with a file and four empty ones are visited.
        assert_eq!(get_empty_dirs_recursive(&root, true).unwrap().len(), 4);
        assert_eq!(
            get_empty_dirs_recursive_limited(&root, true, 8)
                .unwrap()
                .len(),
            4
        );
        let err = get_empty_dirs_recursive_limited(&root, true, 7).unwrap_err();
        assert_eq!(too_many_entries(&err), Some(TooManyEntries { limit: 7 }));
    }

    #[tokio::test]
    async fn job_that_receives_into_memory_is_bounded() {
        let mut job = TransferJob::new_write(
            52,
            JobType::Printer,
            "peer".to_owned(),
            DataSource::MemoryCursor(std::io::Cursor::new(Vec::new())),
            0,
            false,
            true,
            false,
        );
        job.write(data_block(52, 0, b"page")).await.unwrap();
        assert!(!job.has_failed());
        // As if the peer had already sent everything that is accepted.
        job.finished_size = MEMORY_JOB_MAX_BYTES;
        let err = job.write(data_block(52, 0, b"more")).await.unwrap_err();
        assert_err_contains(err, "over the limit");
        assert!(job.has_failed());
    }

    #[test]
    fn windows_device_names_include_port_zero_and_superscript_digits() {
        for name in [
            "COM0",
            "com0.txt",
            "LPT0",
            "COM9",
            "LPT1",
            "COM\u{b9}",
            "lpt\u{b2}.log",
            "COM\u{b3}",
            "NUL",
            "con.txt",
            "a:b",
            "name.",
            "name ",
        ] {
            assert!(windows_component_unsafe(name), "{} must be refused", name);
        }
        for name in [
            "COM",
            "COM10",
            "COMA",
            "LPT",
            "LPT00",
            "COMPUTER.txt",
            "com1x",
            "console",
            "nul1",
            "a.b",
        ] {
            assert!(!windows_component_unsafe(name), "{} is a plain name", name);
        }
        assert!(windows_destination_unsafe(Path::new("/downloads/NUL")));
        assert!(windows_destination_unsafe(Path::new("/downloads/x:stream")));
        assert!(!windows_destination_unsafe(Path::new(
            "/downloads/report.txt"
        )));
        assert!(!windows_destination_unsafe(Path::new("/")));
    }

    #[test]
    fn local_destination_must_not_climb_out_of_its_folder() {
        assert!(validate_local_destination("/home/user/Downloads/report.txt").is_ok());
        assert!(validate_local_destination("relative/report.txt").is_ok());
        assert!(validate_local_destination("/home/user/Downloads/../.ssh/keys").is_err());
        assert!(validate_local_destination("../x").is_err());
        assert!(validate_local_destination("").is_err());
        assert!(validate_local_destination("a\0b").is_err());
        // A name that only looks like a parent step is a name.
        assert!(validate_local_destination("/home/user/Downloads/..x/a..b").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn local_destination_is_checked_with_windows_rules() {
        assert!(validate_local_destination(r"C:\Users\user\Downloads\report.txt").is_ok());
        assert!(validate_local_destination(r"C:\Users\user\Downloads\..\..\x.bat").is_err());
        assert!(validate_local_destination(r"C:\Users\user\Downloads\NUL").is_err());
        assert!(validate_local_destination(r"C:\Users\user\Downloads\x.txt:stream").is_err());
        let mut job = new_validation_job(53);
        job.data_source = DataSource::FilePath(PathBuf::from(r"C:\Users\user\Downloads\COM0"));
        let err = job
            .set_files(vec![new_file_entry("")])
            .expect_err("a device name as the destination of a single file");
        assert_err_contains(err, "not a plain Windows file name");
    }

    #[tokio::test]
    async fn second_job_to_the_same_destination_is_refused() {
        let tmp = TestTempDir::new("rustdesk_fs_destination_claim");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let mut first = write_job_for(54, &tmp.path, &[("x", 0)]);
        let mut second = write_job_for(55, &tmp.path, &[("x", 0)]);
        let other_dir = tmp.join("other");
        let mut elsewhere = write_job_for(56, &other_dir, &[("x", 0)]);

        first.claim_destination().unwrap();
        // Asking again for the same job is not a second claim.
        first.claim_destination().unwrap();
        let err = second.claim_destination().unwrap_err();
        assert_err_contains(err, "already writing to this destination");
        elsewhere.claim_destination().unwrap();

        // The destination is free again when the job that held it is gone.
        drop(first);
        second.claim_destination().unwrap();
    }

    #[test]
    fn directory_with_only_links_and_empty_directories_is_removed() {
        let tmp = TestTempDir::new("rustdesk_fs_remove_links");
        let target = tmp.join("target");
        let doomed = tmp.join("doomed");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep"), b"keep").unwrap();
        std::fs::create_dir_all(doomed.join("empty").join("deeper")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, doomed.join("dir-link")).unwrap();
            std::os::unix::fs::symlink(target.join("keep"), doomed.join("file-link")).unwrap();
        }
        #[cfg(windows)]
        {
            // Needs the privilege to create links; the test is still valid without them.
            let _ = std::os::windows::fs::symlink_dir(&target, doomed.join("dir-link"));
            let _ =
                std::os::windows::fs::symlink_file(target.join("keep"), doomed.join("file-link"));
        }

        remove_all_empty_dir(&doomed).unwrap();

        assert!(!doomed.exists(), "the directory is still there");
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"keep");
    }

    #[test]
    fn directory_that_still_holds_a_file_stays_without_an_error() {
        let tmp = TestTempDir::new("rustdesk_fs_remove_not_empty");
        let dir = tmp.join("dir");
        std::fs::create_dir_all(dir.join("empty")).unwrap();
        std::fs::write(dir.join("kept.txt"), b"kept").unwrap();

        remove_all_empty_dir(&dir).unwrap();

        assert!(dir.join("kept.txt").exists());
        assert!(!dir.join("empty").exists());
        assert!(remove_all_empty_dir(&tmp.join("missing")).is_err());
    }

    // ---- small speed-ups ----

    #[test]
    fn already_compressed_files_are_recognised_whatever_the_case() {
        for name in [
            "a.zip",
            "A.ZIP",
            "photo.JPG",
            "photo.jpeg",
            "clip.Mp4",
            "song.flac",
            "disk.7z",
            "report.docx",
            "dir.with.dots/archive.tar.gz",
            "x.zst",
        ] {
            assert!(is_compressed_file(name), "{}", name);
        }
        for name in ["a.txt", "zip", "a.zip.txt", "noext", "data.bin", "a.c", ""] {
            assert!(!is_compressed_file(name), "{}", name);
        }
    }

    /// One call reads several blocks when the stream has room, and still one job at a time.
    #[tokio::test]
    async fn one_call_reads_several_blocks() {
        const BLOCK: usize = 128 * 1024;
        let tmp = TestTempDir::new("rustdesk_fs_steps_per_call");
        std::fs::create_dir_all(&tmp.path).unwrap();
        let src = tmp.join("source.bin");
        std::fs::write(&src, incompressible(10 * BLOCK)).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let local = tcp.local_addr().unwrap();
        // A plain TCP stream always has room.
        let mut stream = Stream::from(tcp, local);
        let mut jobs = vec![TransferJob::new_read(
            61,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(src),
            0,
            true,
            false,
            false,
        )
        .unwrap()];

        let peer_local = peer.local_addr().unwrap();
        let mut peer = Stream::from(peer, peer_local);
        let received = tokio::spawn(async move {
            let mut numbers = Vec::new();
            loop {
                let bytes = peer.next().await.unwrap().unwrap();
                let message = Message::parse_from_bytes(&bytes).unwrap();
                let Some(message::Union::FileResponse(response)) = message.union else {
                    continue;
                };
                match response.union {
                    Some(file_response::Union::Block(block)) => numbers.push(block.blk_id),
                    Some(file_response::Union::Done(_)) => return numbers,
                    other => panic!("unexpected file response: {:?}", other),
                }
            }
        });

        // Ten data blocks, the empty one, and the final message: far fewer calls than blocks.
        let mut calls = 0;
        while !jobs.is_empty() {
            handle_read_jobs(&mut jobs, &mut stream).await.unwrap();
            calls += 1;
            assert!(calls <= 12, "the transfer does not end");
        }
        assert!(calls <= 5, "{} calls for 11 blocks", calls);
        let numbers = tokio::time::timeout(std::time::Duration::from_secs(30), received)
            .await
            .expect("receiver finished")
            .unwrap();
        assert_eq!(numbers, (1..=11).collect::<Vec<u32>>());
    }

    /// Several steps in one call cross from one file to the next.
    #[tokio::test]
    async fn one_call_goes_on_to_the_next_file() {
        let tmp = TestTempDir::new("rustdesk_fs_steps_across_files");
        let source = tmp.join("source");
        std::fs::create_dir_all(&source).unwrap();
        for index in 0..6 {
            // Data that does not compress, so that a block is as long as what was read.
            std::fs::write(
                source.join(format!("f{}", index)),
                incompressible(index * 100),
            )
            .unwrap();
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let local = tcp.local_addr().unwrap();
        let mut stream = Stream::from(tcp, local);
        let mut jobs = vec![TransferJob::new_read(
            62,
            JobType::Generic,
            "peer".to_owned(),
            DataSource::FilePath(source),
            0,
            true,
            false,
            false,
        )
        .unwrap()];
        let files = jobs[0].files().len();
        assert_eq!(files, 6);

        let peer_local = peer.local_addr().unwrap();
        let mut peer = Stream::from(peer, peer_local);
        let received = tokio::spawn(async move {
            let mut bytes_per_file = vec![0usize; 6];
            loop {
                let bytes = peer.next().await.unwrap().unwrap();
                let message = Message::parse_from_bytes(&bytes).unwrap();
                let Some(message::Union::FileResponse(response)) = message.union else {
                    continue;
                };
                match response.union {
                    Some(file_response::Union::Block(block)) => {
                        bytes_per_file[block.file_num as usize] += block.data.len();
                    }
                    Some(file_response::Union::Done(_)) => return bytes_per_file,
                    other => panic!("unexpected file response: {:?}", other),
                }
            }
        });

        let mut calls = 0;
        while !jobs.is_empty() {
            handle_read_jobs(&mut jobs, &mut stream).await.unwrap();
            calls += 1;
            assert!(calls <= 40, "the transfer does not end");
        }
        let mut bytes_per_file = tokio::time::timeout(std::time::Duration::from_secs(30), received)
            .await
            .expect("receiver finished")
            .unwrap();
        // The order of the files in the job is the order of the directory listing.
        bytes_per_file.sort_unstable();
        assert_eq!(bytes_per_file, vec![0, 100, 200, 300, 400, 500]);
    }
}
