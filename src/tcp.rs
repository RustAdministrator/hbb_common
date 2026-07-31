use crate::{
    bail,
    bytes_codec::BytesCodec,
    config::{keys, Config, Socks5Server},
    proxy::Proxy,
    ResultType,
};
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
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    net::{lookup_host, TcpListener, TcpSocket, TcpStream, ToSocketAddrs},
};
use tokio_socks::IntoTargetAddr;
use tokio_util::codec::{Framed, FramedRead};

pub trait TcpStreamTrait: AsyncRead + AsyncWrite + Unpin {}
pub struct DynTcpStream(pub Box<dyn TcpStreamTrait + Send + Sync>);

// Keep a single framed write below common VPN and tunnel MTUs. TCP still owns
// ordering and retransmission; this only avoids large writes entering fragile
// virtual-adapter/offload paths as one application buffer.
const TCP_FRAMED_WRITE_CHUNK_LIMIT: usize = 1200;
const TCP_FRAMED_WRITE_MSS_CAP: u32 = TCP_FRAMED_WRITE_CHUNK_LIMIT as u32;
const TCP_FRAMED_WRITE_PACING_INTERVAL: usize = 4;
const TCP_FRAMED_WRITE_PACING_DELAY: std::time::Duration = std::time::Duration::from_millis(1);
const TCP_FRAMED_WRITE_LOG_LIMIT: usize = 32;
static TCP_FRAMED_WRITE_LOGS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpInfoSnapshot {
    pub state: i32,
    pub mss: u32,
    pub rtt_us: u32,
    pub rtt_var_us: u32,
    pub bytes_in_flight: u32,
    pub congestion_window_bytes: u32,
    pub send_window_bytes: u32,
    pub receive_window_bytes: u32,
    pub unacked_packets: u32,
    pub lost_packets: u32,
    pub retransmit_packets: u32,
    pub retransmitted_bytes: u64,
    pub timeout_episodes: u32,
    pub path_mtu: u32,
}

impl std::fmt::Display for TcpInfoSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "state={}, mss={}, rtt_us={}, rtt_var_us={}, bytes_in_flight={}, cwnd_bytes={}, send_window_bytes={}, receive_window_bytes={}, unacked_packets={}, lost_packets={}, retransmit_packets={}, retransmitted_bytes={}, timeout_episodes={}, path_mtu={}",
            self.state,
            self.mss,
            self.rtt_us,
            self.rtt_var_us,
            self.bytes_in_flight,
            self.congestion_window_bytes,
            self.send_window_bytes,
            self.receive_window_bytes,
            self.unacked_packets,
            self.lost_packets,
            self.retransmit_packets,
            self.retransmitted_bytes,
            self.timeout_episodes,
            self.path_mtu
        )
    }
}

// Android's libc crate does not expose `tcp_info`. This is the stable Linux
// UAPI prefix through `tcpi_total_retrans`; newer kernels may return more data,
// which `getsockopt` safely truncates to this caller-provided buffer.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[repr(C)]
#[derive(Default)]
struct LinuxTcpInfo {
    state: u8,
    _ca_state: u8,
    retransmits: u8,
    _probes: u8,
    _backoff: u8,
    _options: u8,
    _window_scales: u8,
    _delivery_rate_flags: u8,
    _rto: u32,
    _ato: u32,
    snd_mss: u32,
    _rcv_mss: u32,
    unacked: u32,
    _sacked: u32,
    lost: u32,
    _retrans: u32,
    _fackets: u32,
    _last_data_sent: u32,
    _last_ack_sent: u32,
    _last_data_recv: u32,
    _last_ack_recv: u32,
    pmtu: u32,
    _rcv_ssthresh: u32,
    rtt: u32,
    rtt_var: u32,
    _snd_ssthresh: u32,
    snd_cwnd: u32,
    _advmss: u32,
    _reordering: u32,
    _rcv_rtt: u32,
    rcv_space: u32,
    total_retrans: u32,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone)]
pub(crate) struct TcpSocketDiagnostics {
    fd: std::os::unix::io::RawFd,
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct TcpSocketDiagnostics {
    socket: std::os::windows::io::RawSocket,
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
#[derive(Clone)]
pub(crate) struct TcpSocketDiagnostics;

impl TcpSocketDiagnostics {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn from_stream(stream: &TcpStream) -> Option<Self> {
        use std::os::unix::io::AsRawFd;
        Some(Self {
            fd: stream.as_raw_fd(),
        })
    }

    #[cfg(windows)]
    fn from_stream(stream: &TcpStream) -> Option<Self> {
        use std::os::windows::io::AsRawSocket;
        Some(Self {
            socket: stream.as_raw_socket(),
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    fn from_stream(_stream: &TcpStream) -> Option<Self> {
        None
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn snapshot(&self) -> io::Result<TcpInfoSnapshot> {
        use std::mem;

        let mut info = LinuxTcpInfo::default();
        let mut len = mem::size_of::<LinuxTcpInfo>() as libc::socklen_t;
        // SAFETY: `info` points to a buffer sized for `tcp_info`, and `fd`
        // remains owned by the live framed stream while snapshots are taken.
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_TCP,
                libc::TCP_INFO,
                &mut info as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if (len as usize) < mem::size_of::<LinuxTcpInfo>() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("TCP_INFO returned only {len} bytes"),
            ));
        }
        let bytes_in_flight = info.unacked.saturating_mul(info.snd_mss);
        Ok(TcpInfoSnapshot {
            state: i32::from(info.state),
            mss: info.snd_mss,
            rtt_us: info.rtt,
            rtt_var_us: info.rtt_var,
            bytes_in_flight,
            congestion_window_bytes: info.snd_cwnd.saturating_mul(info.snd_mss),
            send_window_bytes: 0,
            receive_window_bytes: info.rcv_space,
            unacked_packets: info.unacked,
            lost_packets: info.lost,
            retransmit_packets: info.total_retrans,
            retransmitted_bytes: 0,
            timeout_episodes: u32::from(info.retransmits),
            path_mtu: info.pmtu,
        })
    }

    #[cfg(windows)]
    pub(crate) fn snapshot(&self) -> io::Result<TcpInfoSnapshot> {
        use std::{mem, ptr};
        use winapi::{
            shared::mstcpip::SIO_TCP_INFO,
            um::winsock2::{WSAIoctl, SOCKET_ERROR},
        };

        #[repr(C)]
        #[derive(Default)]
        struct WindowsTcpInfoV1 {
            state: i32,
            mss: u32,
            connection_time_ms: u64,
            timestamps_enabled: u8,
            rtt_us: u32,
            min_rtt_us: u32,
            bytes_in_flight: u32,
            cwnd: u32,
            send_window: u32,
            receive_window: u32,
            receive_buffer: u32,
            bytes_out: u64,
            bytes_in: u64,
            bytes_reordered: u32,
            bytes_retransmitted: u32,
            fast_retransmit: u32,
            duplicate_acks_in: u32,
            timeout_episodes: u32,
            syn_retransmit: u8,
            send_limit_transitions_receive_window: u32,
            send_limit_time_receive_window: u32,
            send_limit_bytes_receive_window: u64,
            send_limit_transitions_cwnd: u32,
            send_limit_time_cwnd: u32,
            send_limit_bytes_cwnd: u64,
            send_limit_transitions_sender: u32,
            send_limit_time_sender: u32,
            send_limit_bytes_sender: u64,
        }

        let mut version = 1u32;
        let mut info = WindowsTcpInfoV1::default();
        let mut returned = 0u32;
        // SAFETY: all pointers refer to live, correctly sized buffers and no
        // overlapped operation is requested.
        let rc = unsafe {
            WSAIoctl(
                self.socket as _,
                SIO_TCP_INFO,
                &mut version as *mut _ as _,
                mem::size_of_val(&version) as u32,
                &mut info as *mut _ as _,
                mem::size_of::<WindowsTcpInfoV1>() as u32,
                &mut returned,
                ptr::null_mut(),
                None,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        Ok(TcpInfoSnapshot {
            state: info.state,
            mss: info.mss,
            rtt_us: info.rtt_us,
            bytes_in_flight: info.bytes_in_flight,
            congestion_window_bytes: info.cwnd,
            send_window_bytes: info.send_window,
            receive_window_bytes: info.receive_window,
            retransmit_packets: info.fast_retransmit,
            retransmitted_bytes: u64::from(info.bytes_retransmitted),
            timeout_episodes: info.timeout_episodes,
            ..Default::default()
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    pub(crate) fn snapshot(&self) -> io::Result<TcpInfoSnapshot> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "TCP_INFO is not supported on this platform",
        ))
    }
}

#[derive(Clone)]
pub struct Encrypt(pub Key, pub u64, pub u64);

pub struct FramedStream(
    pub Framed<DynTcpStream, BytesCodec>,
    pub SocketAddr,
    pub Option<Encrypt>,
    pub u64,
    pub(crate) Option<TcpSocketDiagnostics>,
    pub(crate) bool,
);

pub struct FramedReadHalf {
    stream: FramedRead<ReadHalf<DynTcpStream>, BytesCodec>,
    decrypt: Option<Encrypt>,
}

pub struct FramedWriteHalf {
    stream: WriteHalf<DynTcpStream>,
    encrypt: Option<Encrypt>,
    raw: bool,
    send_timeout: u64,
    pending: BytesMut,
    diagnostics: Option<TcpSocketDiagnostics>,
    write_pacing_enabled: bool,
}

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
    pub fn from_dyn(stream: DynTcpStream, addr: SocketAddr) -> Self {
        Self(
            Framed::new(stream, BytesCodec::new()),
            addr,
            None,
            0,
            None,
            tcp_write_pacing_enabled(),
        )
    }

    pub fn into_split(self) -> (FramedReadHalf, FramedWriteHalf) {
        let Self(stream, _addr, encrypt, send_timeout, diagnostics, write_pacing_enabled) = self;
        let parts = stream.into_parts();
        let raw = parts.codec.is_raw();
        let (read_io, write_io) = tokio::io::split(parts.io);
        let mut read = FramedRead::new(read_io, parts.codec);
        read.read_buffer_mut().extend_from_slice(&parts.read_buf);
        (
            FramedReadHalf {
                stream: read,
                decrypt: encrypt.clone(),
            },
            FramedWriteHalf {
                stream: write_io,
                encrypt,
                raw,
                send_timeout,
                pending: parts.write_buf,
                diagnostics,
                write_pacing_enabled,
            },
        )
    }

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
                    let diagnostics = TcpSocketDiagnostics::from_stream(&stream);
                    return Ok(Self(
                        Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
                        addr,
                        None,
                        0,
                        diagnostics,
                        tcp_write_pacing_enabled(),
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

    pub fn from(stream: impl TcpStreamTrait + Send + Sync + 'static, addr: SocketAddr) -> Self {
        Self(
            Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
            addr,
            None,
            0,
            None,
            tcp_write_pacing_enabled(),
        )
    }

    pub fn from_tcp(stream: TcpStream, addr: SocketAddr) -> Self {
        configure_connected_tcp_stream(&stream, "accepted");
        let diagnostics = TcpSocketDiagnostics::from_stream(&stream);
        Self(
            Framed::new(DynTcpStream(Box::new(stream)), BytesCodec::new()),
            addr,
            None,
            0,
            diagnostics,
            tcp_write_pacing_enabled(),
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
        if self.should_send_bounded(bytes.len()) {
            if self.3 > 0 {
                super::timeout(self.3, self.send_bytes_bounded(bytes)).await??;
            } else {
                self.send_bytes_bounded(bytes).await?;
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

    fn should_send_bounded(&self, len: usize) -> bool {
        len > TCP_FRAMED_WRITE_CHUNK_LIMIT && !self.0.codec().is_raw()
    }

    async fn send_bytes_bounded(&mut self, bytes: Bytes) -> io::Result<()> {
        self.0.flush().await?;

        let mut framed = BytesMut::with_capacity(bytes.len() + 4);
        BytesCodec::encode_frame(self.0.codec().is_raw(), bytes, &mut framed)?;

        let total_len = framed.len();
        let chunk_count = total_len.div_ceil(TCP_FRAMED_WRITE_CHUNK_LIMIT);
        let log_count = TCP_FRAMED_WRITE_LOGS.fetch_add(1, Ordering::Relaxed);
        if log_count < TCP_FRAMED_WRITE_LOG_LIMIT {
            log::info!(
                "tcp large framed write split: total_bytes={}, chunk_limit={}, chunks={}, local={}",
                total_len,
                TCP_FRAMED_WRITE_CHUNK_LIMIT,
                chunk_count,
                self.1
            );
        }

        let pacing_enabled = self.5;
        let started = Instant::now();
        let paced_delays =
            write_wire_bytes(self.0.get_mut(), &framed, true, pacing_enabled).await?;
        if pacing_enabled
            && (log_count < TCP_FRAMED_WRITE_LOG_LIMIT || started.elapsed().as_millis() >= 250)
        {
            log::info!(
                "tcp paced framed write: total_bytes={}, chunks={}, paced_delays={}, pacing_delay_ms={}, elapsed_ms={}, local={}",
                total_len,
                chunk_count,
                paced_delays,
                TCP_FRAMED_WRITE_PACING_DELAY.as_millis(),
                started.elapsed().as_millis(),
                self.1
            );
        }
        self.0.get_mut().flush().await
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
        super::timeout(ms, self.next()).await.unwrap_or_default()
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

impl FramedReadHalf {
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        let mut result = self.stream.next().await;
        if let Some(Ok(bytes)) = result.as_mut() {
            if let Some(key) = self.decrypt.as_mut() {
                if let Err(err) = key.dec(bytes) {
                    return Some(Err(err));
                }
            }
        }
        result
    }
}

impl FramedWriteHalf {
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    pub async fn send_raw(&mut self, mut msg: Vec<u8>) -> ResultType<()> {
        if let Some(key) = self.encrypt.as_mut() {
            msg = key.enc(&msg);
        }
        self.send_bytes(Bytes::from(msg)).await
    }

    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        let timeout = self.send_timeout;
        if timeout > 0 {
            super::timeout(timeout, self.send_bytes_inner(bytes)).await??;
        } else {
            self.send_bytes_inner(bytes).await?;
        }
        Ok(())
    }

    async fn send_bytes_inner(&mut self, bytes: Bytes) -> io::Result<()> {
        if !self.pending.is_empty() {
            let pending = self.pending.split().freeze();
            let bounded = !self.raw;
            self.write_wire_bytes(&pending, bounded, bounded && self.write_pacing_enabled)
                .await?;
        }

        let bounded = bytes.len() > TCP_FRAMED_WRITE_CHUNK_LIMIT && !self.raw;
        let mut framed = BytesMut::with_capacity(bytes.len() + 4);
        BytesCodec::encode_frame(self.raw, bytes, &mut framed)?;
        let pacing_enabled = bounded && self.write_pacing_enabled;
        let started = Instant::now();
        let paced_delays = self
            .write_wire_bytes(&framed, bounded, pacing_enabled)
            .await?;
        if pacing_enabled && started.elapsed().as_millis() >= 250 {
            log::info!(
                "tcp split writer pacing summary: total_bytes={}, paced_delays={}, pacing_delay_ms={}, elapsed_ms={}",
                framed.len(),
                paced_delays,
                TCP_FRAMED_WRITE_PACING_DELAY.as_millis(),
                started.elapsed().as_millis()
            );
        }
        self.stream.flush().await
    }

    async fn write_wire_bytes(
        &mut self,
        bytes: &[u8],
        bounded: bool,
        pacing_enabled: bool,
    ) -> io::Result<usize> {
        write_wire_bytes(&mut self.stream, bytes, bounded, pacing_enabled).await
    }

    pub(crate) fn tcp_diagnostics(&self) -> Option<TcpSocketDiagnostics> {
        // The raw identifier remains valid because the returned clone is used
        // only inside the writer task while this write half owns the socket.
        self.diagnostics.clone()
    }
}

pub(crate) fn tcp_write_pacing_enabled() -> bool {
    Config::get_option(keys::OPTION_TCP_WRITE_PACING) == "Y"
}

async fn write_wire_bytes<W: AsyncWrite + Unpin>(
    stream: &mut W,
    bytes: &[u8],
    bounded: bool,
    pacing_enabled: bool,
) -> io::Result<usize> {
    if !bounded {
        stream.write_all(bytes).await?;
        return Ok(0);
    }

    let chunks = bytes.chunks(TCP_FRAMED_WRITE_CHUNK_LIMIT);
    let chunk_count = chunks.len();
    let mut paced_delays = 0;
    for (index, chunk) in chunks.enumerate() {
        stream.write_all(chunk).await?;
        if pacing_enabled
            && index + 1 < chunk_count
            && (index + 1) % TCP_FRAMED_WRITE_PACING_INTERVAL == 0
        {
            tokio::time::sleep(TCP_FRAMED_WRITE_PACING_DELAY).await;
            paced_delays += 1;
        }
    }
    Ok(paced_delays)
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
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

impl<R: AsyncRead + AsyncWrite + Unpin> TcpStreamTrait for R {}

pub(crate) fn configure_connected_tcp_stream(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        log::warn!(
            "tcp stream configure: failed to enable TCP_NODELAY: context={context}, err={err}"
        );
    }

    let local = stream.local_addr().ok();
    let peer = stream.peer_addr().ok();
    if peer.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return;
    }

    match set_tcp_maxseg(stream, TCP_FRAMED_WRITE_MSS_CAP) {
        Ok(()) => log::info!(
            "tcp path write guard enabled: context={context}, write_chunk_cap={}, tcp_mss_cap={}, local={local:?}, peer={peer:?}",
            TCP_FRAMED_WRITE_CHUNK_LIMIT,
            TCP_FRAMED_WRITE_MSS_CAP
        ),
        Err(err) => log::warn!(
            "tcp path write guard active but TCP_MAXSEG unavailable: context={context}, write_chunk_cap={}, tcp_mss_cap={}, local={local:?}, peer={peer:?}, err={err}",
            TCP_FRAMED_WRITE_CHUNK_LIMIT,
            TCP_FRAMED_WRITE_MSS_CAP
        ),
    }
}

#[cfg(unix)]
fn set_tcp_maxseg(stream: &TcpStream, mss: u32) -> io::Result<()> {
    use std::{mem, os::unix::io::AsRawFd};

    let value = mss as libc::c_int;
    // SAFETY: the fd belongs to `stream`, and `value` has the exact size
    // supplied to setsockopt for the duration of this call.
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
    // SAFETY: the socket belongs to `stream`, and `value` has the exact size
    // supplied to setsockopt for the duration of this call.
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
    use bytes::Buf;
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

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
    async fn framed_stream_splits_large_writes_into_path_safe_chunks() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingWrites {
            writes: writes.clone(),
        };
        let mut framed = FramedStream::from(stream, "127.0.0.1:0".parse().unwrap());
        let data = Bytes::from(vec![7; 64 * 1024 + 321]);
        let expected_payload_len = data.len();

        framed.send_bytes(data).await.unwrap();

        let writes = writes.lock().unwrap();
        assert!(writes.len() > 1);
        assert!(writes
            .iter()
            .all(|len| *len <= TCP_FRAMED_WRITE_CHUNK_LIMIT));
        assert!(writes.iter().sum::<usize>() >= expected_payload_len);
    }

    #[tokio::test]
    async fn split_writer_keeps_path_safe_chunks() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingWrites {
            writes: writes.clone(),
        };
        let framed = FramedStream::from(stream, "127.0.0.1:0".parse().unwrap());
        let (_reader, mut writer) = framed.into_split();

        writer
            .send_bytes(Bytes::from(vec![9; 64 * 1024 + 17]))
            .await
            .unwrap();

        let writes = writes.lock().unwrap();
        assert!(writes.len() > 1);
        assert!(writes
            .iter()
            .all(|len| *len <= TCP_FRAMED_WRITE_CHUNK_LIMIT));
    }

    #[tokio::test]
    async fn paced_writer_delays_after_each_four_chunks_except_the_last() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mut stream = RecordingWrites {
            writes: writes.clone(),
        };
        let data = vec![3; TCP_FRAMED_WRITE_CHUNK_LIMIT * 10];

        let paced_delays = write_wire_bytes(&mut stream, &data, true, true)
            .await
            .unwrap();

        assert_eq!(paced_delays, 2);
        assert_eq!(writes.lock().unwrap().len(), 10);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn native_tcp_info_snapshot_reports_live_socket_state() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
            Err(error) => panic!("loopback bind failed: {}", error),
        };
        let address = listener.local_addr().unwrap();
        let connect = TcpStream::connect(address);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        let client = match client {
            Ok(client) => client,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
            Err(error) => panic!("loopback connect failed: {}", error),
        };
        let (_server, _) = match accepted {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
            Err(error) => panic!("loopback accept failed: {}", error),
        };
        let diagnostics = TcpSocketDiagnostics::from_stream(&client).unwrap();

        let snapshot = match diagnostics.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
            Err(error) => panic!("TCP_INFO snapshot failed: {}", error),
        };

        assert!(snapshot.state > 0);
        assert!(snapshot.mss > 0);
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

    #[tokio::test]
    async fn split_reader_progresses_while_writer_is_blocked() {
        let payload = Bytes::from_static(b"inbound-video-frame");
        let mut encoded = BytesMut::new();
        BytesCodec::encode_frame(false, payload.clone(), &mut encoded).unwrap();
        let framed = FramedStream::from(
            ReadableBlockedWrite {
                inbound: encoded.freeze(),
            },
            "127.0.0.1:0".parse().unwrap(),
        );
        let (mut reader, mut writer) = framed.into_split();
        let write_task = tokio::spawn(async move {
            writer
                .send_bytes(Bytes::from_static(b"blocked-feedback"))
                .await
        });
        tokio::task::yield_now().await;

        let received = tokio::time::timeout(Duration::from_millis(100), reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(&received[..], &payload[..]);
        assert!(!write_task.is_finished());
        write_task.abort();
    }

    #[tokio::test]
    async fn split_preserves_independent_encryption_counters() {
        let (left, right) = tokio::io::duplex(4096);
        let addr = "127.0.0.1:0".parse().unwrap();
        let key = Key([7; secretbox::KEYBYTES]);
        let mut local = FramedStream::from(left, addr);
        let mut remote = FramedStream::from(right, addr);
        local.set_key(key.clone());
        remote.set_key(key);

        local.send_raw(b"before-split-left".to_vec()).await.unwrap();
        assert_eq!(
            &remote.next().await.unwrap().unwrap()[..],
            b"before-split-left"
        );
        remote
            .send_raw(b"before-split-right".to_vec())
            .await
            .unwrap();
        assert_eq!(
            &local.next().await.unwrap().unwrap()[..],
            b"before-split-right"
        );

        let (mut reader, mut writer) = local.into_split();
        writer.send_raw(b"after-split-left".to_vec()).await.unwrap();
        assert_eq!(
            &remote.next().await.unwrap().unwrap()[..],
            b"after-split-left"
        );
        remote
            .send_raw(b"after-split-right".to_vec())
            .await
            .unwrap();
        assert_eq!(
            &reader.next().await.unwrap().unwrap()[..],
            b"after-split-right"
        );
    }

    #[test]
    fn bounded_write_decision_excludes_small_and_raw_messages() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingWrites { writes };
        let mut framed = FramedStream::from(stream, "127.0.0.1:0".parse().unwrap());

        assert!(!framed.should_send_bounded(TCP_FRAMED_WRITE_CHUNK_LIMIT));
        assert!(framed.should_send_bounded(TCP_FRAMED_WRITE_CHUNK_LIMIT + 1));
        framed.set_raw();
        assert!(!framed.should_send_bounded(TCP_FRAMED_WRITE_CHUNK_LIMIT + 1));
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
