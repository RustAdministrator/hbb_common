#[cfg(feature = "webrtc")]
use crate::webrtc;
use crate::{config, tcp, websocket, ResultType};
use bytes::{Bytes, BytesMut};
use sodiumoxide::crypto::secretbox::Key;
use std::{
    collections::{HashMap, VecDeque},
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, Notify},
    task::JoinHandle,
};

const SLOW_ASYNC_WRITE_THRESHOLD: Duration = Duration::from_millis(250);
const SLOW_ASYNC_WRITE_LOG_INTERVAL: Duration = Duration::from_secs(5);

struct OutboundMessage {
    bytes: Bytes,
    kind: &'static str,
    encrypt: bool,
    completion: Option<oneshot::Sender<Result<(), String>>>,
}

enum OutboundEntry {
    Reliable(OutboundMessage),
    Latest(u64),
}

struct OutboundState {
    entries: VecDeque<OutboundEntry>,
    latest: HashMap<u64, OutboundMessage>,
    capacity: usize,
    closed: bool,
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
                capacity: capacity.max(1),
                closed: false,
            })),
            notify: Arc::new(Notify::new()),
        }
    }

    fn enqueue(&self, message: OutboundMessage) -> ResultType<()> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Error::new(ErrorKind::BrokenPipe, "async stream writer is closed").into());
        }
        if state.entries.len() >= state.capacity {
            return Err(Error::new(ErrorKind::WouldBlock, "async stream outbox is full").into());
        }
        state.entries.push_back(OutboundEntry::Reliable(message));
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    fn enqueue_latest(&self, key: u64, message: OutboundMessage) -> ResultType<()> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Error::new(ErrorKind::BrokenPipe, "async stream writer is closed").into());
        }
        if let Some(previous) = state.latest.get_mut(&key) {
            *previous = message;
            return Ok(());
        }
        if state.entries.len() >= state.capacity {
            return Err(Error::new(ErrorKind::WouldBlock, "async stream outbox is full").into());
        }
        state.latest.insert(key, message);
        state.entries.push_back(OutboundEntry::Latest(key));
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
}

pub struct DuplexStream {
    reader: StreamReader,
    outbox: OutboundQueue,
    writer_task: JoinHandle<()>,
    writer_errors: mpsc::UnboundedReceiver<String>,
    writer_error_channel_closed: bool,
    local_addr: SocketAddr,
    secure_transport: bool,
    secured: bool,
}

impl DuplexStream {
    async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        if self.writer_error_channel_closed {
            return self.reader.next().await;
        }
        tokio::select! {
            result = self.reader.next() => result,
            error = self.writer_errors.recv() => {
                match error {
                    Some(error) => Some(Err(Error::new(ErrorKind::BrokenPipe, error))),
                    None => {
                        self.writer_error_channel_closed = true;
                        self.reader.next().await
                    }
                }
            }
        }
    }

    fn enqueue(&self, bytes: Bytes, kind: &'static str, encrypt: bool) -> ResultType<()> {
        self.outbox.enqueue(OutboundMessage {
            bytes,
            kind,
            encrypt,
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
) {
    while let Some(message) = outbox.dequeue().await {
        let started = Instant::now();
        let send = writer.send(message.bytes, message.encrypt);
        tokio::pin!(send);
        let mut next_log = SLOW_ASYNC_WRITE_THRESHOLD;
        loop {
            tokio::select! {
                result = &mut send => {
                    match result {
                        Ok(()) => {
                            if started.elapsed() >= SLOW_ASYNC_WRITE_THRESHOLD {
                                log::warn!(
                                    "async stream send recovered: kind={}, elapsed_ms={}, queued={}",
                                    message.kind,
                                    started.elapsed().as_millis(),
                                    outbox.len()
                                );
                            }
                            if let Some(completion) = message.completion {
                                let _ = completion.send(Ok(()));
                            }
                        }
                        Err(error) => {
                            let detail = format!(
                                "async stream send failed: kind={}, elapsed_ms={}, error={error}",
                                message.kind,
                                started.elapsed().as_millis()
                            );
                            log::warn!("{detail}");
                            if let Some(completion) = message.completion {
                                let _ = completion.send(Err(detail.clone()));
                            }
                            let _ = errors.send(detail);
                            outbox.fail_pending("async stream writer stopped after a send failure");
                            return;
                        }
                    }
                    break;
                }
                _ = tokio::time::sleep(next_log) => {
                    log::warn!(
                        "async stream send stalled: kind={}, elapsed_ms={}, queued={}",
                        message.kind,
                        started.elapsed().as_millis(),
                        outbox.len()
                    );
                    next_log = SLOW_ASYNC_WRITE_LOG_INTERVAL;
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
            Stream::Duplex(_) => log::warn!("set_send_timeout ignored after stream split"),
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
        let writer_task = tokio::spawn(run_stream_writer(writer, writer_outbox, error_tx));
        Self::Duplex(DuplexStream {
            reader,
            outbox,
            writer_task,
            writer_errors: error_rx,
            writer_error_channel_closed: false,
            local_addr,
            secure_transport,
            secured,
        })
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
}
