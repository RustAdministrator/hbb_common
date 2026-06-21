use crate::{bail, bytes_codec::BytesCodec, config::Socks5Server, proxy::Proxy, ResultType};
use anyhow::Context as AnyhowCtx;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use sodiumoxide::crypto::{
    box_,
    secretbox::{self, Key, Nonce},
};
use std::{
    io::{self, Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{lookup_host, TcpListener, TcpSocket, TcpStream, ToSocketAddrs},
};
use tokio_socks::IntoTargetAddr;
use tokio_util::codec::Framed;

pub trait TcpStreamTrait: AsyncRead + AsyncWrite + Unpin {}
pub struct DynTcpStream(pub Box<dyn TcpStreamTrait + Send + Sync>);

const TCP_PATH_MTU_WRITE_CHUNK_LIMIT: usize = 1200;
const TCP_PATH_MTU_MSS_CAP: u32 = TCP_PATH_MTU_WRITE_CHUNK_LIMIT as u32;
const TCP_PATH_MTU_PACED_WRITE_THRESHOLD: usize = TCP_PATH_MTU_WRITE_CHUNK_LIMIT * 2;
const TCP_PATH_MTU_PACED_WRITE_DELAY: Duration = Duration::from_millis(1);
static TCP_PATH_MTU_PACED_WRITE_LOGS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct Encrypt(pub Key, pub u64, pub u64);

pub struct FramedStream(
    pub Framed<DynTcpStream, BytesCodec>,
    pub SocketAddr,
    pub Option<Encrypt>,
    pub u64,
);

impl Deref for FramedStream {
    type Target = Framed<DynTcpStream, BytesCodec>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FramedStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for DynTcpStream {
    type Target = Box<dyn TcpStreamTrait + Send + Sync>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DynTcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(crate) fn new_socket(
    addr: std::net::SocketAddr,
    reuse: bool,
) -> Result<TcpSocket, std::io::Error> {
    let socket = match addr {
        std::net::SocketAddr::V4(..) => TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuseport(true).ok();
        socket.set_reuseaddr(true).ok();
    }
    socket.bind(addr)?;
    Ok(socket)
}

impl FramedStream {
    pub async fn new<T: ToSocketAddrs + std::fmt::Display>(
        remote_addr: T,
        local_addr: Option<SocketAddr>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        for remote_addr in lookup_host(&remote_addr).await? {
            let local = if let Some(addr) = local_addr {
                addr
            } else {
                crate::config::Config::get_any_listen_addr(remote_addr.is_ipv4())
            };
            if let Ok(socket) = new_socket(local, true) {
                if let Ok(Ok(stream)) =
                    super::timeout(ms_timeout, socket.connect(remote_addr)).await
                {
                    configure_connected_tcp_stream(&stream, "connect");
                    let addr = stream.local_addr()?;
                    return Ok(Self(
                        Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
                        addr,
                        None,
                        0,
                    ));
                }
            }
        }
        bail!(format!("Failed to connect to {remote_addr}"));
    }

    pub async fn connect<'t, T>(
        target: T,
        local_addr: Option<SocketAddr>,
        proxy_conf: &Socks5Server,
        ms_timeout: u64,
    ) -> ResultType<Self>
    where
        T: IntoTargetAddr<'t>,
    {
        let proxy = Proxy::from_conf(proxy_conf, Some(ms_timeout))?;
        proxy.connect::<T>(target, local_addr).await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.1
    }

    pub fn set_send_timeout(&mut self, ms: u64) {
        self.3 = ms;
    }

    pub fn from(stream: TcpStream, addr: SocketAddr) -> Self {
        configure_connected_tcp_stream(&stream, "accepted");
        Self(
            Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
            addr,
            None,
            0,
        )
    }

    pub fn set_raw(&mut self) {
        self.0.codec_mut().set_raw();
        self.2 = None;
    }

    pub fn is_secured(&self) -> bool {
        self.2.is_some()
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        let mut msg = msg;
        if let Some(key) = self.2.as_mut() {
            msg = key.enc(&msg);
        }
        self.send_bytes(bytes::Bytes::from(msg)).await?;
        Ok(())
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        if self.should_send_paced(bytes.len()) {
            if self.3 > 0 {
                super::timeout(self.3, self.send_bytes_paced(bytes)).await??;
            } else {
                self.send_bytes_paced(bytes).await?;
            }
            return Ok(());
        }
        if self.3 > 0 {
            super::timeout(self.3, self.0.send(bytes)).await??;
        } else {
            self.0.send(bytes).await?;
        }
        Ok(())
    }

    fn should_send_paced(&self, len: usize) -> bool {
        len > TCP_PATH_MTU_PACED_WRITE_THRESHOLD && !self.0.codec().is_raw()
    }

    async fn send_bytes_paced(&mut self, bytes: Bytes) -> io::Result<()> {
        self.0.flush().await?;

        let mut framed = BytesMut::with_capacity(bytes.len() + 4);
        BytesCodec::encode_frame(self.0.codec().is_raw(), bytes, &mut framed)?;

        let total_len = framed.len();
        let chunk_count = total_len.div_ceil(TCP_PATH_MTU_WRITE_CHUNK_LIMIT);
        let log_count = TCP_PATH_MTU_PACED_WRITE_LOGS.fetch_add(1, Ordering::Relaxed);
        if log_count < 32 {
            log::info!(
                "tcp path mtu guard paced framed write: total_bytes={}, chunk_limit={}, chunks={}, local={}",
                total_len,
                TCP_PATH_MTU_WRITE_CHUNK_LIMIT,
                chunk_count,
                self.1
            );
        }

        let stream = self.0.get_mut();
        let mut offset = 0;
        while offset < total_len {
            let end = (offset + TCP_PATH_MTU_WRITE_CHUNK_LIMIT).min(total_len);
            stream.write_all(&framed[offset..end]).await?;
            stream.flush().await?;
            offset = end;
            if offset < total_len {
                tokio::time::sleep(TCP_PATH_MTU_PACED_WRITE_DELAY).await;
            }
        }
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        let mut res = self.0.next().await;
        if let Some(Ok(bytes)) = res.as_mut() {
            if let Some(key) = self.2.as_mut() {
                if let Err(err) = key.dec(bytes) {
                    return Some(Err(err));
                }
            }
        }
        res
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        if let Ok(res) = super::timeout(ms, self.next()).await {
            res
        } else {
            None
        }
    }

    pub fn set_key(&mut self, key: Key) {
        self.2 = Some(Encrypt::new(key));
    }

    fn get_nonce(seqnum: u64) -> Nonce {
        let mut nonce = Nonce([0u8; secretbox::NONCEBYTES]);
        nonce.0[..std::mem::size_of_val(&seqnum)].copy_from_slice(&seqnum.to_le_bytes());
        nonce
    }
}

const DEFAULT_BACKLOG: u32 = 128;

pub async fn new_listener<T: ToSocketAddrs>(addr: T, reuse: bool) -> ResultType<TcpListener> {
    if !reuse {
        Ok(TcpListener::bind(addr).await?)
    } else {
        let addr = lookup_host(&addr)
            .await?
            .next()
            .context("could not resolve to any address")?;
        new_socket(addr, true)?
            .listen(DEFAULT_BACKLOG)
            .map_err(anyhow::Error::msg)
    }
}

pub async fn listen_any(port: u16) -> ResultType<TcpListener> {
    if let Ok(mut socket) = TcpSocket::new_v6() {
        #[cfg(unix)]
        {
            // illumos has no support for SO_REUSEPORT
            #[cfg(not(target_os = "illumos"))]
            socket.set_reuseport(true).ok();
            socket.set_reuseaddr(true).ok();
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            let raw_fd = socket.into_raw_fd();
            let sock2 = unsafe { socket2::Socket::from_raw_fd(raw_fd) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_fd(sock2.into_raw_fd()) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::prelude::{FromRawSocket, IntoRawSocket};
            let raw_socket = socket.into_raw_socket();
            let sock2 = unsafe { socket2::Socket::from_raw_socket(raw_socket) };
            sock2.set_only_v6(false).ok();
            socket = unsafe { TcpSocket::from_raw_socket(sock2.into_raw_socket()) };
        }
        if socket
            .bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
            .is_ok()
        {
            if let Ok(l) = socket.listen(DEFAULT_BACKLOG) {
                return Ok(l);
            }
        }
    }
    Ok(new_socket(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        true,
    )?
    .listen(DEFAULT_BACKLOG)?)
}

impl Unpin for DynTcpStream {}

impl AsyncRead for DynTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl AsyncWrite for DynTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len().min(TCP_PATH_MTU_WRITE_CHUNK_LIMIT);
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, &buf[..len])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

impl<R: AsyncRead + AsyncWrite + Unpin> TcpStreamTrait for R {}

fn configure_connected_tcp_stream(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        log::warn!(
            "tcp path mtu guard: failed to enable TCP_NODELAY: context={context}, err={err}"
        );
    }

    let local = stream.local_addr().ok();
    let peer = stream.peer_addr().ok();
    if peer.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return;
    }

    match set_tcp_maxseg(stream, TCP_PATH_MTU_MSS_CAP) {
        Ok(()) => log::info!(
            "tcp path mtu guard enabled: context={context}, write_chunk_cap={}, tcp_mss_cap={}, local={local:?}, peer={peer:?}",
            TCP_PATH_MTU_WRITE_CHUNK_LIMIT,
            TCP_PATH_MTU_MSS_CAP
        ),
        Err(err) => log::warn!(
            "tcp path mtu guard write cap active but TCP_MAXSEG unavailable: context={context}, write_chunk_cap={}, tcp_mss_cap={}, local={local:?}, peer={peer:?}, err={err}",
            TCP_PATH_MTU_WRITE_CHUNK_LIMIT,
            TCP_PATH_MTU_MSS_CAP
        ),
    }
}

#[cfg(unix)]
fn set_tcp_maxseg(stream: &TcpStream, mss: u32) -> io::Result<()> {
    use std::{mem, os::unix::io::AsRawFd};

    let value = mss as libc::c_int;
    // SAFETY: `stream.as_raw_fd()` is a valid TCP socket fd owned by `stream`;
    // `value` is passed with its exact size and lives for this call.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &value as *const _ as *const libc::c_void,
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn set_tcp_maxseg(stream: &TcpStream, mss: u32) -> io::Result<()> {
    use std::{mem, os::windows::io::AsRawSocket};
    use winapi::{
        shared::ws2def::IPPROTO_TCP,
        um::winsock2::{setsockopt, SOCKET_ERROR},
    };

    const TCP_MAXSEG: i32 = 4;

    let value = mss as i32;
    // SAFETY: `stream.as_raw_socket()` is a valid TCP socket owned by `stream`;
    // `value` is passed with its exact size and lives for this call.
    let rc = unsafe {
        setsockopt(
            stream.as_raw_socket() as _,
            IPPROTO_TCP as i32,
            TCP_MAXSEG,
            &value as *const _ as *const i8,
            mem::size_of_val(&value) as i32,
        )
    };
    if rc == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn set_tcp_maxseg(_stream: &TcpStream, _mss: u32) -> io::Result<()> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "TCP_MAXSEG is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker_ref;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct RecordingStream {
        write_len: Arc<AtomicUsize>,
    }

    impl AsyncRead for RecordingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_len.store(buf.len(), Ordering::Relaxed);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn dyn_tcp_stream_caps_write_chunks() {
        let write_len = Arc::new(AtomicUsize::new(0));
        let mut stream = DynTcpStream(Box::new(RecordingStream {
            write_len: write_len.clone(),
        }));
        let data = vec![0; TCP_PATH_MTU_WRITE_CHUNK_LIMIT + 321];
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        match AsyncWrite::poll_write(Pin::new(&mut stream), &mut cx, &data) {
            Poll::Ready(Ok(n)) => assert_eq!(n, TCP_PATH_MTU_WRITE_CHUNK_LIMIT),
            Poll::Ready(Err(err)) => panic!("write failed: {}", err),
            Poll::Pending => panic!("write unexpectedly pending"),
        }
        assert_eq!(
            write_len.load(Ordering::Relaxed),
            TCP_PATH_MTU_WRITE_CHUNK_LIMIT
        );
    }

    struct RecordingWrites {
        writes: Arc<Mutex<Vec<usize>>>,
    }

    impl AsyncRead for RecordingWrites {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RecordingWrites {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buf.len());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn framed_stream_paces_large_writes() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingWrites {
            writes: writes.clone(),
        };
        let mut framed = FramedStream(
            Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
            "127.0.0.1:0".parse().unwrap(),
            None,
            0,
        );
        let data = Bytes::from(vec![7; TCP_PATH_MTU_PACED_WRITE_THRESHOLD + 321]);

        framed.send_bytes(data).await.unwrap();

        let writes = writes.lock().unwrap();
        assert!(writes.len() > 1);
        assert!(writes
            .iter()
            .all(|len| *len <= TCP_PATH_MTU_WRITE_CHUNK_LIMIT));
    }

    #[test]
    fn framed_stream_pacing_decision_respects_raw_streams() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingWrites { writes };
        let mut framed = FramedStream(
            Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
            "127.0.0.1:0".parse().unwrap(),
            None,
            0,
        );

        assert!(!framed.should_send_paced(TCP_PATH_MTU_PACED_WRITE_THRESHOLD));
        assert!(framed.should_send_paced(TCP_PATH_MTU_PACED_WRITE_THRESHOLD + 1));

        framed.set_raw();
        assert!(!framed.should_send_paced(TCP_PATH_MTU_PACED_WRITE_THRESHOLD + 1));
    }
}

impl Encrypt {
    pub fn new(key: Key) -> Self {
        Self(key, 0, 0)
    }

    pub fn dec(&mut self, bytes: &mut BytesMut) -> Result<(), Error> {
        if bytes.len() <= 1 {
            return Ok(());
        }
        self.2 += 1;
        let nonce = FramedStream::get_nonce(self.2);
        match secretbox::open(bytes, &nonce, &self.0) {
            Ok(res) => {
                bytes.clear();
                bytes.put_slice(&res);
                Ok(())
            }
            Err(()) => Err(Error::new(ErrorKind::Other, "decryption error")),
        }
    }

    pub fn enc(&mut self, data: &[u8]) -> Vec<u8> {
        self.1 += 1;
        let nonce = FramedStream::get_nonce(self.1);
        secretbox::seal(&data, &nonce, &self.0)
    }

    pub fn decode(
        symmetric_data: &[u8],
        their_pk_b: &[u8],
        our_sk_b: &box_::SecretKey,
    ) -> ResultType<Key> {
        if their_pk_b.len() != box_::PUBLICKEYBYTES {
            anyhow::bail!("Handshake failed: pk length {}", their_pk_b.len());
        }
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let mut pk_ = [0u8; box_::PUBLICKEYBYTES];
        pk_[..].copy_from_slice(their_pk_b);
        let their_pk_b = box_::PublicKey(pk_);
        let symmetric_key = box_::open(symmetric_data, &nonce, &their_pk_b, &our_sk_b)
            .map_err(|_| anyhow::anyhow!("Handshake failed: box decryption failure"))?;
        if symmetric_key.len() != secretbox::KEYBYTES {
            anyhow::bail!("Handshake failed: invalid secret key length from peer");
        }
        let mut key = [0u8; secretbox::KEYBYTES];
        key[..].copy_from_slice(&symmetric_key);
        Ok(Key(key))
    }
}
