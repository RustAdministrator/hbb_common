use crate::ResultType;
use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use fast_socks5::{client::Socks5Datagram, util::target_addr::TargetAddr as FastTargetAddr};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{lookup_host, TcpStream, ToSocketAddrs, UdpSocket};
use tokio_socks::{IntoTargetAddr, TargetAddr};
use tokio_util::{codec::BytesCodec, udp::UdpFramed};

pub enum FramedSocket {
    Direct(UdpFramed<BytesCodec>),
    ProxySocks(Socks5UdpSocket),
}

pub struct Socks5UdpSocket {
    framed: Socks5Datagram<TcpStream>,
    recv_buf: Vec<u8>,
}

fn new_socket(addr: SocketAddr, reuse: bool, buf_size: usize) -> Result<Socket, std::io::Error> {
    let socket = match addr {
        SocketAddr::V4(..) => Socket::new(Domain::ipv4(), Type::dgram(), None),
        SocketAddr::V6(..) => Socket::new(Domain::ipv6(), Type::dgram(), None),
    }?;
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuse_port(true).ok();
        socket.set_reuse_address(true).ok();
    }
    // only nonblocking work with tokio, https://stackoverflow.com/questions/64649405/receiver-on-tokiompscchannel-only-receives-messages-when-buffer-is-full
    socket.set_nonblocking(true)?;
    if buf_size > 0 {
        socket.set_recv_buffer_size(buf_size).ok();
    }
    log::debug!(
        "Receive buf size of udp {}: {:?}",
        addr,
        socket.recv_buffer_size()
    );
    if addr.is_ipv6() && addr.ip().is_unspecified() && addr.port() > 0 {
        socket.set_only_v6(false).ok();
    }
    socket.bind(&addr.into())?;
    Ok(socket)
}

impl FramedSocket {
    pub async fn new<T: ToSocketAddrs>(addr: T) -> ResultType<Self> {
        Self::new_reuse(addr, false, 0).await
    }

    pub async fn new_reuse<T: ToSocketAddrs>(
        addr: T,
        reuse: bool,
        buf_size: usize,
    ) -> ResultType<Self> {
        let addr = lookup_host(&addr)
            .await?
            .next()
            .context("could not resolve to any address")?;
        Ok(Self::Direct(UdpFramed::new(
            UdpSocket::from_std(new_socket(addr, reuse, buf_size)?.into_udp_socket())?,
            BytesCodec::new(),
        )))
    }

    pub async fn new_proxy<'a, T: ToSocketAddrs>(
        proxy: &str,
        local: T,
        username: &'a str,
        password: &'a str,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let framed = if username.trim().is_empty() {
            super::timeout(ms_timeout, Socks5UdpSocket::connect(proxy, local)).await??
        } else {
            super::timeout(
                ms_timeout,
                Socks5UdpSocket::connect_with_password(proxy, local, username, password),
            )
            .await??
        };
        log::trace!(
            "Socks5 udp connected, local addr: {:?}, target addr: {}",
            framed.local_addr(),
            framed.socks_addr()
        );
        Ok(Self::ProxySocks(framed))
    }

    #[inline]
    pub async fn send(
        &mut self,
        msg: &impl Message,
        addr: impl IntoTargetAddr<'_>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();
        let send_data = Bytes::from(msg.write_to_bytes()?);
        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = addr {
                    f.send((send_data, addr)).await?
                }
            }
            Self::ProxySocks(f) => f.send(send_data, addr).await?,
        };
        Ok(())
    }

    // https://stackoverflow.com/a/68733302/1926020
    #[inline]
    pub async fn send_raw(
        &mut self,
        msg: &'static [u8],
        addr: impl IntoTargetAddr<'static>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();

        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = addr {
                    f.send((Bytes::from(msg), addr)).await?
                }
            }
            Self::ProxySocks(f) => f.send(Bytes::from(msg), addr).await?,
        };
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        match self {
            Self::Direct(f) => match f.next().await {
                Some(Ok((data, addr))) => {
                    Some(Ok((data, addr.into_target_addr().ok()?.to_owned())))
                }
                Some(Err(e)) => Some(Err(anyhow!(e))),
                None => None,
            },
            Self::ProxySocks(f) => Some(f.next().await),
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        ms: u64,
    ) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        if let Ok(res) =
            tokio::time::timeout(std::time::Duration::from_millis(ms), self.next()).await
        {
            res
        } else {
            None
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            FramedSocket::Direct(x) => x.get_ref().local_addr().ok(),
            FramedSocket::ProxySocks(x) => x.local_addr().ok(),
        }
    }
}

impl Socks5UdpSocket {
    async fn connect<T: ToSocketAddrs>(proxy: &str, local: T) -> ResultType<Self> {
        let stream = TcpStream::connect(proxy).await?;
        let socket = UdpSocket::bind(local).await?;
        Ok(Self {
            framed: Socks5Datagram::use_socket(stream, socket).await?,
            recv_buf: vec![0; 64 * 1024],
        })
    }

    async fn connect_with_password<T: ToSocketAddrs>(
        proxy: &str,
        local: T,
        username: &str,
        password: &str,
    ) -> ResultType<Self> {
        let stream = TcpStream::connect(proxy).await?;
        let socket = UdpSocket::bind(local).await?;
        Ok(Self {
            framed: Socks5Datagram::use_socket_with_password(stream, socket, username, password)
                .await?,
            recv_buf: vec![0; 64 * 1024],
        })
    }

    async fn send(&self, data: Bytes, addr: TargetAddr<'static>) -> ResultType<()> {
        self.framed
            .send_to(&data, to_fast_target_addr(addr)?)
            .await?;
        Ok(())
    }

    async fn next(&mut self) -> ResultType<(BytesMut, TargetAddr<'static>)> {
        let (len, addr) = self.framed.recv_from(&mut self.recv_buf).await?;
        Ok((
            BytesMut::from(&self.recv_buf[..len]),
            from_fast_target_addr(addr),
        ))
    }

    fn socks_addr(&self) -> String {
        self.framed
            .proxy_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default()
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.framed.get_ref().local_addr()
    }
}

fn to_fast_target_addr(addr: TargetAddr<'static>) -> ResultType<FastTargetAddr> {
    match addr {
        TargetAddr::Ip(addr) => Ok(FastTargetAddr::Ip(addr)),
        TargetAddr::Domain(domain, port) => Ok(FastTargetAddr::Domain(domain.into_owned(), port)),
    }
}

fn from_fast_target_addr(addr: FastTargetAddr) -> TargetAddr<'static> {
    match addr {
        FastTargetAddr::Ip(addr) => TargetAddr::Ip(addr),
        FastTargetAddr::Domain(domain, port) => TargetAddr::Domain(domain.into(), port),
    }
}
