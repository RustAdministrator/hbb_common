#[cfg(feature = "webrtc")]
use crate::webrtc;
use crate::{config, tcp, websocket, ResultType};
use bytes::{Bytes, BytesMut};
use sodiumoxide::crypto::secretbox::Key;
use std::{
    collections::{HashMap, VecDeque},
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, Notify},
    task::JoinHandle,
};

const SLOW_ASYNC_WRITE_THRESHOLD: Duration = Duration::from_millis(250);
const ASYNC_WRITE_ONE_SECOND_CHECKPOINT: Duration = Duration::from_secs(1);
const ASYNC_WRITE_FOUR_SECOND_CHECKPOINT: Duration = Duration::from_secs(4);
const SLOW_ASYNC_WRITE_LOG_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncStreamProgressSnapshot {
    pub context: String,
    pub queued_messages: usize,
    pub active_write_kind: Option<&'static str>,
    pub active_write_bytes: usize,
    pub active_write_elapsed_ms: Option<u128>,
    pub last_read_elapsed_ms: u128,
    pub last_write_elapsed_ms: u128,
    pub completed_messages: u64,
    pub completed_bytes: u64,
    pub latest_replacements: u64,
    pub rejected_messages: u64,
}

struct IoProgressState {
    last_read_at: Instant,
    last_write_at: Instant,
    active_write: Option<(&'static str, usize, Instant)>,
    completed_messages: u64,
    completed_bytes: u64,
}

impl IoProgressState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            last_read_at: now,
            last_write_at: now,
            active_write: None,
            completed_messages: 0,
            completed_bytes: 0,
        }
    }
}

struct OutboundMessage {
    bytes: Bytes,
    kind: &'static str,
    encrypt: bool,
    completion: Option<oneshot::Sender<Result<(), String>>>,
}

enum OutboundEntry {
    Reliable(OutboundMessage),
    Latest((u64, u64)),
}

struct OutboundState {
    entries: VecDeque<OutboundEntry>,
    latest: HashMap<(u64, u64), OutboundMessage>,
    latest_generation: u64,
    capacity: usize,
    closed: bool,
    latest_replacements: u64,
    rejected_messages: u64,
}

#[derive(Clone)]
struct OutboundQueue {
    state: Arc<Mutex<OutboundState>>,
    notify: Arc<Notify>,
}

impl OutboundQueue {
    fn new(capacity: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(OutboundState {
                entries: VecDeque::new(),
                latest: HashMap::new(),
                latest_generation: 0,
                capacity: capacity.max(1),
                closed: false,
                latest_replacements: 0,
                rejected_messages: 0,
            })),
            notify: Arc::new(Notify::new()),
        }
    }

    fn enqueue(&self, message: OutboundMessage) -> ResultType<()> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            state.rejected_messages = state.rejected_messages.saturating_add(1);
            return Err(Error::new(ErrorKind::BrokenPipe, "async stream writer is closed").into());
        }
        if state.entries.len() >= state.capacity {
            state.rejected_messages = state.rejected_messages.saturating_add(1);
            return Err(Error::new(ErrorKind::WouldBlock, "async stream outbox is full").into());
        }
        state.entries.push_back(OutboundEntry::Reliable(message));
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    fn enqueue_barrier(&self, message: OutboundMessage) -> ResultType<()> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            state.rejected_messages = state.rejected_messages.saturating_add(1);
            return Err(Error::new(ErrorKind::BrokenPipe, "async stream writer is closed").into());
        }
        if state.entries.len() >= state.capacity {
            state.rejected_messages = state.rejected_messages.saturating_add(1);
            return Err(Error::new(ErrorKind::WouldBlock, "async stream outbox is full").into());
        }
        state.latest_generation = state.latest_generation.wrapping_add(1);
        state.entries.push_back(OutboundEntry::Reliable(message));
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    fn enqueue_latest(&self, key: u64, message: OutboundMessage) -> ResultType<()> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            state.rejected_messages = state.rejected_messages.saturating_add(1);
            return Err(Error::new(ErrorKind::BrokenPipe, "async stream writer is closed").into());
        }
        let generation_key = (key, state.latest_generation);
        if let Some(previous) = state.latest.get_mut(&generation_key) {
            *previous = message;
            state.latest_replacements = state.latest_replacements.saturating_add(1);
            return Ok(());
        }
        if state.entries.len() >= state.capacity {
            state.rejected_messages = state.rejected_messages.saturating_add(1);
            return Err(Error::new(ErrorKind::WouldBlock, "async stream outbox is full").into());
        }
        state.latest.insert(generation_key, message);
        state
            .entries
            .push_back(OutboundEntry::Latest(generation_key));
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    async fn dequeue(&self) -> Option<OutboundMessage> {
        loop {
            let notified = self.notify.notified();
            {
                let mut state = self.state.lock().unwrap();
                while let Some(entry) = state.entries.pop_front() {
                    match entry {
                        OutboundEntry::Reliable(message) => return Some(message),
                        OutboundEntry::Latest(key) => {
                            if let Some(message) = state.latest.remove(&key) {
                                return Some(message);
                            }
                        }
                    }
                }
                if state.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        drop(state);
        self.notify.notify_waiters();
    }

    fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }

    fn counters(&self) -> (u64, u64) {
        let state = self.state.lock().unwrap();
        (state.latest_replacements, state.rejected_messages)
    }

    fn fail_pending(&self, error: &str) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        let mut pending: Vec<_> = state
            .entries
            .drain(..)
            .filter_map(|entry| match entry {
                OutboundEntry::Reliable(message) => Some(message),
                OutboundEntry::Latest(_) => None,
            })
            .collect();
        pending.extend(state.latest.drain().map(|(_, message)| message));
        for message in pending {
            if let Some(completion) = message.completion {
                let _ = completion.send(Err(error.to_owned()));
            }
        }
        drop(state);
        self.notify.notify_waiters();
    }
}

enum StreamReader {
    #[cfg(feature = "webrtc")]
    WebRTC(webrtc::WebRTCStream),
    WebSocket(websocket::WsReadHalf),
    Tcp(tcp::FramedReadHalf),
}

impl StreamReader {
    async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(stream) => stream.next().await,
            Self::WebSocket(stream) => stream.next().await,
            Self::Tcp(stream) => stream.next().await,
        }
    }
}

enum StreamWriter {
    #[cfg(feature = "webrtc")]
    WebRTC(webrtc::WebRTCStream),
    WebSocket(websocket::WsWriteHalf),
    Tcp(tcp::FramedWriteHalf),
}

impl StreamWriter {
    async fn send(&mut self, bytes: Bytes, encrypt: bool) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(stream) => {
                if encrypt {
                    stream.send_raw(bytes.to_vec()).await
                } else {
                    stream.send_bytes(bytes).await
                }
            }
            Self::WebSocket(stream) => {
                if encrypt {
                    stream.send_raw(bytes.to_vec()).await
                } else {
                    stream.send_bytes(bytes).await
                }
            }
            Self::Tcp(stream) => {
                if encrypt {
                    stream.send_raw(bytes.to_vec()).await
                } else {
                    stream.send_bytes(bytes).await
                }
            }
        }
    }

    fn tcp_diagnostics(&self) -> Option<tcp::TcpSocketDiagnostics> {
        match self {
            Self::Tcp(stream) => stream.tcp_diagnostics(),
            _ => None,
        }
    }
}

pub struct DuplexStream {
    reader: StreamReader,
    outbox: OutboundQueue,
    writer_task: JoinHandle<()>,
    writer_errors: mpsc::UnboundedReceiver<String>,
    writer_error_channel_closed: bool,
    terminal_writer_error: Option<String>,
    local_addr: SocketAddr,
    secure_transport: bool,
    secured: bool,
    context: String,
    progress: Arc<Mutex<IoProgressState>>,
    send_timeout_ms: Arc<AtomicU64>,
}

impl DuplexStream {
    async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Some(error) = self.terminal_writer_error.as_ref() {
            return Some(Err(Error::new(ErrorKind::BrokenPipe, error.clone())));
        }
        let result = if self.writer_error_channel_closed {
            self.reader.next().await
        } else {
            tokio::select! {
                result = self.reader.next() => result,
                error = self.writer_errors.recv() => {
                    match error {
                        Some(error) => {
                            self.terminal_writer_error = Some(error.clone());
                            Some(Err(Error::new(ErrorKind::BrokenPipe, error)))
                        }
                        None => {
                            self.writer_error_channel_closed = true;
                            self.reader.next().await
                        }
                    }
                }
            }
        };
        if matches!(result, Some(Ok(_))) {
            self.progress.lock().unwrap().last_read_at = Instant::now();
        }
        result
    }

    fn enqueue(&self, bytes: Bytes, kind: &'static str, encrypt: bool) -> ResultType<()> {
        self.outbox.enqueue(OutboundMessage {
            bytes,
            kind,
            encrypt,
            completion: None,
        })
    }

    fn enqueue_barrier(&self, bytes: Bytes, kind: &'static str) -> ResultType<()> {
        self.outbox.enqueue_barrier(OutboundMessage {
            bytes,
            kind,
            encrypt: true,
            completion: None,
        })
    }

    fn enqueue_latest(&self, key: u64, bytes: Bytes, kind: &'static str) -> ResultType<()> {
        self.outbox.enqueue_latest(
            key,
            OutboundMessage {
                bytes,
                kind,
                encrypt: true,
                completion: None,
            },
        )
    }

    async fn enqueue_and_wait(&self, bytes: Bytes, kind: &'static str) -> ResultType<()> {
        let (completion, completed) = oneshot::channel();
        self.outbox.enqueue(OutboundMessage {
            bytes,
            kind,
            encrypt: true,
            completion: Some(completion),
        })?;
        match completed.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(Error::new(ErrorKind::BrokenPipe, error).into()),
            Err(_) => Err(Error::new(
                ErrorKind::BrokenPipe,
                "async stream writer stopped before completing the send",
            )
            .into()),
        }
    }

    fn progress_snapshot(&self) -> AsyncStreamProgressSnapshot {
        let now = Instant::now();
        let progress = self.progress.lock().unwrap();
        let (active_write_kind, active_write_bytes, active_write_elapsed_ms) = progress
            .active_write
            .map(|(kind, bytes, started)| {
                (
                    Some(kind),
                    bytes,
                    Some(now.saturating_duration_since(started).as_millis()),
                )
            })
            .unwrap_or((None, 0, None));
        let (latest_replacements, rejected_messages) = self.outbox.counters();
        AsyncStreamProgressSnapshot {
            context: self.context.clone(),
            queued_messages: self.outbox.len(),
            active_write_kind,
            active_write_bytes,
            active_write_elapsed_ms,
            last_read_elapsed_ms: now
                .saturating_duration_since(progress.last_read_at)
                .as_millis(),
            last_write_elapsed_ms: now
                .saturating_duration_since(progress.last_write_at)
                .as_millis(),
            completed_messages: progress.completed_messages,
            completed_bytes: progress.completed_bytes,
            latest_replacements,
            rejected_messages,
        }
    }
}

impl Drop for DuplexStream {
    fn drop(&mut self) {
        self.outbox.close();
        self.writer_task.abort();
    }
}

async fn run_stream_writer(
    mut writer: StreamWriter,
    outbox: OutboundQueue,
    errors: mpsc::UnboundedSender<String>,
    context: String,
    progress: Arc<Mutex<IoProgressState>>,
    send_timeout_ms: Arc<AtomicU64>,
) {
    while let Some(message) = outbox.dequeue().await {
        let OutboundMessage {
            bytes: payload,
            kind,
            encrypt,
            completion,
        } = message;
        let started = Instant::now();
        let bytes = payload.len();
        progress.lock().unwrap().active_write = Some((kind, bytes, started));
        let timeout_ms = send_timeout_ms.load(Ordering::Relaxed);
        let tcp_diagnostics = writer.tcp_diagnostics();
        let send = async {
            if timeout_ms == 0 {
                writer.send(payload, encrypt).await
            } else {
                match tokio::time::timeout(
                    Duration::from_millis(timeout_ms),
                    writer.send(payload, encrypt),
                )
                .await
                {
                    Ok(result) => result,
                    // A timed-out write may have emitted only part of a frame.
                    // Treat it as terminal and drop the writer below; never
                    // attempt another write on the same byte stream.
                    Err(_) => Err(Error::new(
                        ErrorKind::TimedOut,
                        format!("async stream send exceeded {timeout_ms}ms"),
                    )
                    .into()),
                }
            }
        };
        tokio::pin!(send);
        let checkpoints = [
            SLOW_ASYNC_WRITE_THRESHOLD,
            ASYNC_WRITE_ONE_SECOND_CHECKPOINT,
            ASYNC_WRITE_FOUR_SECOND_CHECKPOINT,
        ];
        let mut checkpoint = 0usize;
        let mut next_log_at = checkpoints[checkpoint];
        loop {
            let sleep_for = next_log_at.saturating_sub(started.elapsed());
            tokio::select! {
                result = &mut send => {
                    match result {
                        Ok(()) => {
                            let mut state = progress.lock().unwrap();
                            state.active_write = None;
                            state.last_write_at = Instant::now();
                            state.completed_messages = state.completed_messages.saturating_add(1);
                            state.completed_bytes = state.completed_bytes.saturating_add(bytes as u64);
                            drop(state);
                            if started.elapsed() >= SLOW_ASYNC_WRITE_THRESHOLD {
                                log::warn!(
                                    "async stream send recovered: context={}, kind={}, bytes={}, elapsed_ms={}, queued={}",
                                    context,
                                    kind,
                                    bytes,
                                    started.elapsed().as_millis(),
                                    outbox.len()
                                );
                            }
                            if let Some(completion) = completion {
                                let _ = completion.send(Ok(()));
                            }
                        }
                        Err(error) => {
                            progress.lock().unwrap().active_write = None;
                            let detail = format!(
                                "async stream send failed: context={context}, kind={}, bytes={}, elapsed_ms={}, timeout_ms={}, error={error}",
                                kind,
                                bytes,
                                started.elapsed().as_millis(),
                                timeout_ms
                            );
                            log::warn!("{detail}");
                            if let Some(completion) = completion {
                                let _ = completion.send(Err(detail.clone()));
                            }
                            let _ = errors.send(detail);
                            outbox.fail_pending("async stream writer stopped after a send failure");
                            return;
                        }
                    }
                    break;
                }
                _ = tokio::time::sleep(sleep_for) => {
                    let snapshot = {
                        let state = progress.lock().unwrap();
                        (
                            Instant::now().saturating_duration_since(state.last_read_at).as_millis(),
                            Instant::now().saturating_duration_since(state.last_write_at).as_millis(),
                            state.completed_messages,
                            state.completed_bytes,
                        )
                    };
                    let tcp_info = tcp_diagnostics
                        .as_ref()
                        .and_then(|diagnostics| diagnostics.snapshot().ok())
                        .map(|info| info.to_string())
                        .unwrap_or_else(|| "unavailable".to_owned());
                    let (latest_replacements, rejected_messages) = outbox.counters();
                    log::warn!(
                        "async stream send stalled: context={}, kind={}, bytes={}, elapsed_ms={}, timeout_ms={}, queued={}, last_read_ms={}, last_write_ms={}, completed_messages={}, completed_bytes={}, latest_replacements={}, rejected_messages={}, tcp_info=[{}]",
                        context,
                        kind,
                        bytes,
                        started.elapsed().as_millis(),
                        timeout_ms,
                        outbox.len(),
                        snapshot.0,
                        snapshot.1,
                        snapshot.2,
                        snapshot.3,
                        latest_replacements,
                        rejected_messages,
                        tcp_info
                    );
                    if checkpoint + 1 < checkpoints.len() {
                        checkpoint += 1;
                        next_log_at = checkpoints[checkpoint];
                    } else {
                        next_log_at = next_log_at.saturating_add(SLOW_ASYNC_WRITE_LOG_INTERVAL);
                    }
                }
            }
        }
    }
}

// support Websocket and tcp.
pub enum Stream {
    #[cfg(feature = "webrtc")]
    WebRTC(webrtc::WebRTCStream),
    WebSocket(websocket::WsFramedStream),
    Tcp(tcp::FramedStream),
    Duplex(DuplexStream),
}

impl Stream {
    #[inline]
    pub fn has_secure_transport(&self) -> bool {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(_) => true,
            Stream::WebSocket(s) => s.has_tls_transport(),
            Stream::Tcp(_) => false,
            Stream::Duplex(s) => s.secure_transport,
        }
    }

    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_send_timeout(ms),
            Stream::WebSocket(s) => s.set_send_timeout(ms),
            Stream::Tcp(s) => s.set_send_timeout(ms),
            Stream::Duplex(s) => s.send_timeout_ms.store(ms, Ordering::Relaxed),
        }
    }

    #[inline]
    pub fn set_raw(&mut self) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_raw(),
            Stream::WebSocket(s) => s.set_raw(),
            Stream::Tcp(s) => s.set_raw(),
            Stream::Duplex(_) => log::warn!("set_raw ignored after stream split"),
        }
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: bytes::Bytes) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_bytes(bytes).await,
            Stream::WebSocket(s) => s.send_bytes(bytes).await,
            Stream::Tcp(s) => s.send_bytes(bytes).await,
            Stream::Duplex(s) => s.enqueue(bytes, "Bytes", false),
        }
    }

    #[inline]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.send_raw(bytes).await,
            Stream::WebSocket(s) => s.send_raw(bytes).await,
            Stream::Tcp(s) => s.send_raw(bytes).await,
            Stream::Duplex(s) => s.enqueue(Bytes::from(bytes), "Raw", true),
        }
    }

    #[inline]
    pub fn set_key(&mut self, key: Key) {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.set_key(key),
            Stream::WebSocket(s) => s.set_key(key),
            Stream::Tcp(s) => s.set_key(key),
            Stream::Duplex(_) => log::warn!("set_key ignored after stream split"),
        }
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.is_secured(),
            Stream::WebSocket(s) => s.is_secured(),
            Stream::Tcp(s) => s.is_secured(),
            Stream::Duplex(s) => s.secured,
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        timeout: u64,
    ) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Stream::WebRTC(s) => s.next_timeout(timeout).await,
            Stream::WebSocket(s) => s.next_timeout(timeout).await,
            Stream::Tcp(s) => s.next_timeout(timeout).await,
            Stream::Duplex(s) => {
                match tokio::time::timeout(Duration::from_millis(timeout), s.next()).await {
                    Ok(result) => result,
                    Err(_) => None,
                }
            }
        }
    }

    /// establish connect from websocket
    #[inline]
    pub async fn connect_websocket(
        url: impl AsRef<str>,
        local_addr: Option<SocketAddr>,
        proxy_conf: Option<&config::Socks5Server>,
        timeout_ms: u64,
    ) -> ResultType<Self> {
        let ws_stream =
            websocket::WsFramedStream::new(url, local_addr, proxy_conf, timeout_ms).await?;
        log::debug!("WebSocket connection established");
        Ok(Self::WebSocket(ws_stream))
    }

    /// send message
    #[inline]
    pub async fn send(&mut self, msg: &impl protobuf::Message) -> ResultType<()> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.send(msg).await,
            Self::WebSocket(ws) => ws.send(msg).await,
            Self::Tcp(tcp) => tcp.send(msg).await,
            Self::Duplex(stream) => {
                stream.enqueue(Bytes::from(msg.write_to_bytes()?), "Message", true)
            }
        }
    }

    pub async fn send_tagged(
        &mut self,
        kind: &'static str,
        msg: &impl protobuf::Message,
    ) -> ResultType<()> {
        match self {
            Self::Duplex(stream) => stream.enqueue(Bytes::from(msg.write_to_bytes()?), kind, true),
            _ => self.send(msg).await,
        }
    }

    pub async fn send_ordering_tagged(
        &mut self,
        kind: &'static str,
        msg: &impl protobuf::Message,
    ) -> ResultType<()> {
        match self {
            Self::Duplex(stream) => {
                stream.enqueue_barrier(Bytes::from(msg.write_to_bytes()?), kind)
            }
            _ => self.send(msg).await,
        }
    }

    pub async fn send_tagged_and_wait(
        &mut self,
        kind: &'static str,
        msg: &impl protobuf::Message,
    ) -> ResultType<()> {
        match self {
            Self::Duplex(stream) => {
                stream
                    .enqueue_and_wait(Bytes::from(msg.write_to_bytes()?), kind)
                    .await
            }
            _ => self.send(msg).await,
        }
    }

    pub async fn send_latest(
        &mut self,
        key: u64,
        kind: &'static str,
        msg: &impl protobuf::Message,
    ) -> ResultType<()> {
        match self {
            Self::Duplex(stream) => {
                stream.enqueue_latest(key, Bytes::from(msg.write_to_bytes()?), kind)
            }
            _ => self.send(msg).await,
        }
    }

    /// receive message
    #[inline]
    pub async fn next(&mut self) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.next().await,
            Self::WebSocket(ws) => ws.next().await,
            Self::Tcp(tcp) => tcp.next().await,
            Self::Duplex(stream) => stream.next().await,
        }
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(s) => s.local_addr(),
            Self::WebSocket(ws) => ws.local_addr(),
            Self::Tcp(tcp) => tcp.local_addr(),
            Self::Duplex(stream) => stream.local_addr,
        }
    }

    pub fn into_duplex(self, outbox_capacity: usize) -> Self {
        self.into_duplex_with_context(outbox_capacity, "stream")
    }

    pub fn into_duplex_with_context(
        self,
        outbox_capacity: usize,
        context: impl Into<String>,
    ) -> Self {
        let local_addr = self.local_addr();
        let secure_transport = self.has_secure_transport();
        let secured = self.is_secured();
        let (reader, writer) = match self {
            #[cfg(feature = "webrtc")]
            Self::WebRTC(stream) => (
                StreamReader::WebRTC(stream.clone()),
                StreamWriter::WebRTC(stream),
            ),
            Self::WebSocket(stream) => {
                let (reader, writer) = stream.into_split();
                (
                    StreamReader::WebSocket(reader),
                    StreamWriter::WebSocket(writer),
                )
            }
            Self::Tcp(stream) => {
                let (reader, writer) = stream.into_split();
                (StreamReader::Tcp(reader), StreamWriter::Tcp(writer))
            }
            Self::Duplex(stream) => return Self::Duplex(stream),
        };
        let outbox = OutboundQueue::new(outbox_capacity);
        let writer_outbox = outbox.clone();
        let (error_tx, error_rx) = mpsc::unbounded_channel();
        let context = context.into();
        let progress = Arc::new(Mutex::new(IoProgressState::new()));
        let send_timeout_ms = Arc::new(AtomicU64::new(0));
        let writer_task = tokio::spawn(run_stream_writer(
            writer,
            writer_outbox,
            error_tx,
            context.clone(),
            progress.clone(),
            send_timeout_ms.clone(),
        ));
        Self::Duplex(DuplexStream {
            reader,
            outbox,
            writer_task,
            writer_errors: error_rx,
            writer_error_channel_closed: false,
            terminal_writer_error: None,
            local_addr,
            secure_transport,
            secured,
            context,
            progress,
            send_timeout_ms,
        })
    }

    pub fn async_writer_progress(&self) -> Option<AsyncStreamProgressSnapshot> {
        match self {
            Self::Duplex(stream) => Some(stream.progress_snapshot()),
            _ => None,
        }
    }

    #[inline]
    pub fn from(stream: TcpStream, stream_addr: SocketAddr) -> Self {
        Self::Tcp(tcp::FramedStream::from_tcp(stream, stream_addr))
    }

    #[inline]
    #[cfg(feature = "webrtc")]
    pub fn get_webrtc_stream(&self) -> Option<webrtc::WebRTCStream> {
        match self {
            Self::WebRTC(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    fn message(value: &'static [u8], kind: &'static str) -> OutboundMessage {
        OutboundMessage {
            bytes: Bytes::from_static(value),
            kind,
            encrypt: true,
            completion: None,
        }
    }

    #[tokio::test]
    async fn latest_messages_replace_in_place_without_reordering_reliable_messages() {
        let queue = OutboundQueue::new(4);
        queue.enqueue(message(b"control-1", "control")).unwrap();
        queue
            .enqueue_latest(7, message(b"feedback-old", "feedback"))
            .unwrap();
        queue
            .enqueue_latest(7, message(b"feedback-new", "feedback"))
            .unwrap();
        queue.enqueue(message(b"control-2", "control")).unwrap();

        assert_eq!(queue.dequeue().await.unwrap().bytes, &b"control-1"[..]);
        assert_eq!(queue.dequeue().await.unwrap().bytes, &b"feedback-new"[..]);
        assert_eq!(queue.dequeue().await.unwrap().bytes, &b"control-2"[..]);
    }

    #[tokio::test]
    async fn latest_messages_with_new_stream_key_do_not_cross_ordering_barrier() {
        let queue = OutboundQueue::new(4);
        queue
            .enqueue_latest(7, message(b"old-stream-frame", "video"))
            .unwrap();
        queue
            .enqueue_barrier(message(b"switch-display", "ordering"))
            .unwrap();
        queue
            .enqueue_latest(8, message(b"new-stream-frame", "video"))
            .unwrap();

        assert_eq!(
            queue.dequeue().await.unwrap().bytes,
            &b"old-stream-frame"[..]
        );
        assert_eq!(queue.dequeue().await.unwrap().bytes, &b"switch-display"[..]);
        assert_eq!(
            queue.dequeue().await.unwrap().bytes,
            &b"new-stream-frame"[..]
        );
    }

    #[test]
    fn outbox_capacity_is_bounded() {
        let queue = OutboundQueue::new(2);
        queue.enqueue(message(b"one", "control")).unwrap();
        queue.enqueue(message(b"two", "control")).unwrap();
        assert!(queue.enqueue(message(b"three", "control")).is_err());
        assert!(queue
            .enqueue_latest(1, message(b"feedback", "feedback"))
            .is_err());
    }

    #[tokio::test]
    async fn writer_failure_notifies_pending_confirmed_send() {
        let queue = OutboundQueue::new(2);
        let (completion, completed) = oneshot::channel();
        queue
            .enqueue(OutboundMessage {
                bytes: Bytes::from_static(b"close"),
                kind: "close",
                encrypt: true,
                completion: Some(completion),
            })
            .unwrap();

        queue.fail_pending("write failed");

        assert_eq!(completed.await.unwrap(), Err("write failed".to_owned()));
        assert!(queue.dequeue().await.is_none());
    }

    #[tokio::test]
    async fn duplex_preserves_plain_send_bytes_and_encrypted_send_raw_semantics() {
        let (left, right) = tokio::io::duplex(4096);
        let addr = "127.0.0.1:0".parse().unwrap();
        let key = Key([11; sodiumoxide::crypto::secretbox::KEYBYTES]);
        let mut local = tcp::FramedStream::from(left, addr);
        local.set_key(key.clone());
        let mut stream = Stream::Tcp(local).into_duplex(4);
        let mut remote = tcp::FramedStream::from(right, addr);

        stream
            .send_bytes(Bytes::from_static(b"plain"))
            .await
            .unwrap();
        assert_eq!(&remote.next().await.unwrap().unwrap()[..], b"plain");

        remote.set_key(key);
        stream.send_raw(b"encrypted".to_vec()).await.unwrap();
        assert_eq!(&remote.next().await.unwrap().unwrap()[..], b"encrypted");
    }

    struct ReadableBlockedWrite {
        inbound: Bytes,
    }

    impl AsyncRead for ReadableBlockedWrite {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.inbound.is_empty() {
                return Poll::Pending;
            }
            let count = self.inbound.len().min(buf.remaining());
            buf.put_slice(&self.inbound[..count]);
            self.inbound.advance(count);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ReadableBlockedWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn blocked_writer_stream(inbound: Option<&'static [u8]>) -> Stream {
        let mut encoded = BytesMut::new();
        if let Some(payload) = inbound {
            crate::bytes_codec::BytesCodec::encode_frame(
                false,
                Bytes::from_static(payload),
                &mut encoded,
            )
            .unwrap();
        }
        Stream::Tcp(tcp::FramedStream::from(
            ReadableBlockedWrite {
                inbound: encoded.freeze(),
            },
            "127.0.0.1:0".parse().unwrap(),
        ))
        .into_duplex_with_context(4, "duplex-test")
    }

    #[tokio::test]
    async fn duplex_reader_progresses_while_writer_is_blocked() {
        let mut stream = blocked_writer_stream(Some(b"inbound-control"));
        stream
            .send_bytes(Bytes::from_static(b"blocked-video"))
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_millis(100), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(&received[..], b"inbound-control");
        let progress = stream.async_writer_progress().unwrap();
        assert_eq!(progress.context, "duplex-test");
        assert!(
            progress.active_write_kind == Some("Bytes") || progress.queued_messages == 1,
            "the blocked write must remain active or queued"
        );
    }

    #[tokio::test]
    async fn duplex_dynamic_send_timeout_reports_writer_failure_to_reader() {
        let mut stream = blocked_writer_stream(None);
        stream.set_send_timeout(25);
        stream
            .send_bytes(Bytes::from_static(b"blocked-video"))
            .await
            .unwrap();

        let error = tokio::time::timeout(Duration::from_millis(250), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("exceeded 25ms"));
        let repeated = stream.next().await.unwrap().unwrap_err();
        assert_eq!(repeated.kind(), ErrorKind::BrokenPipe);
        assert_eq!(repeated.to_string(), error.to_string());
    }
}
