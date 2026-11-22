use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crabdns_core::{DnsPipeline, QueryContext, QueryProtocol, build_raw_formerr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use crate::{GRACEFUL_DRAIN_TIMEOUT, drain_join_set};

const MAX_TCP_PIPELINE_INFLIGHT: usize = 32;
const MAX_TCP_CONN_LIFETIME: Duration = Duration::from_secs(300);
const ACCEPT_ERR_BACKOFF: Duration = Duration::from_millis(50);

pub(crate) struct ActiveConnGuard {
    pipeline: Arc<DnsPipeline>,
    is_dot: bool,
}

impl ActiveConnGuard {
    pub(crate) fn new_tcp(pipeline: Arc<DnsPipeline>) -> Self {
        pipeline.inc_tcp_active();
        Self {
            pipeline,
            is_dot: false,
        }
    }

    pub(crate) fn new_dot(pipeline: Arc<DnsPipeline>) -> Self {
        pipeline.inc_dot_active();
        Self {
            pipeline,
            is_dot: true,
        }
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        if self.is_dot {
            self.pipeline.dec_dot_active();
        } else {
            self.pipeline.dec_tcp_active();
        }
    }
}

pub(crate) struct IpConnLimiter {
    global: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

pub(crate) struct IpConnGuard {
    _global: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for IpConnGuard {
    fn drop(&mut self) {
        let mut guard = self
            .per_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = guard.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                guard.remove(&self.ip);
            }
        }
    }
}

impl IpConnLimiter {
    pub(crate) fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_global.max(1))),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip: max_per_ip.max(1),
        }
    }

    pub(crate) fn try_acquire(&self, ip: IpAddr) -> Option<IpConnGuard> {
        let global = Arc::clone(&self.global).try_acquire_owned().ok()?;
        let mut guard = self
            .per_ip
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = guard.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            if *entry == 0 {
                guard.remove(&ip);
            }
            return None;
        }
        *entry += 1;
        Some(IpConnGuard {
            _global: global,
            per_ip: Arc::clone(&self.per_ip),
            ip,
        })
    }
}

pub(crate) fn bind_udp_sockets(
    addr: SocketAddr,
    count: usize,
) -> anyhow::Result<Vec<Arc<UdpSocket>>> {
    #[cfg(unix)]
    {
        let mut sockets = Vec::with_capacity(count);
        for _ in 0..count {
            let domain = socket2::Domain::for_address(addr);
            let sock =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            sock.set_reuse_address(true)?;
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            let std_sock: std::net::UdpSocket = sock.into();
            sockets.push(Arc::new(UdpSocket::from_std(std_sock)?));
        }
        Ok(sockets)
    }
    #[cfg(not(unix))]
    {
        let _ = count;
        let sock = std::net::UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        Ok(vec![Arc::new(UdpSocket::from_std(sock)?)])
    }
}

pub(crate) async fn run_udp_server(
    socket: Arc<UdpSocket>,
    pipeline: Arc<DnsPipeline>,
    limiter: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut buf = vec![0_u8; 4096];
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            recv_res = socket.recv_from(&mut buf) => {
                let (len, peer) = match recv_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "UDP DNS recv error; backing off");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&limiter).try_acquire_owned() else {
                    pipeline.record_udp_dropped();
                    tracing::warn!(peer = %peer, "UDP DNS query dropped: max inflight reached");
                    continue;
                };
                let packet = buf[..len].to_vec();
                let sock = Arc::clone(&socket);
                let pipe = Arc::clone(&pipeline);
                tasks.spawn(async move {
                    let _permit = permit;
                    match pipe.handle_packet(&packet, peer).await {
                        Ok(resp) => {
                            let _ = sock.send_to(&resp, peer).await;
                        }
                        Err(err) => {
                            tracing::debug!(peer = %peer, error = %err, "failed to handle UDP DNS query");
                        }
                    }
                });
            }
        }
    }
    drain_join_set(&mut tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

pub(crate) async fn run_tcp_server(
    listener: TcpListener,
    pipeline: Arc<DnsPipeline>,
    max_connections: usize,
    idle_timeout: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let per_ip_limit = (max_connections / 2).max(8);
    let limiter = IpConnLimiter::new(max_connections.max(1), per_ip_limit);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accept_res = listener.accept() => {
                let (stream, peer) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(error = %err, "TCP DNS accept error; backing off");
                        tokio::time::sleep(ACCEPT_ERR_BACKOFF).await;
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let Some(guard) = limiter.try_acquire(peer.ip()) else {
                    pipeline.record_tcp_rejected();
                    tracing::warn!(peer = %peer, "TCP DNS connection rejected: connection limit reached");
                    drop(stream);
                    continue;
                };
                let pipe = Arc::clone(&pipeline);
                let conn_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    let _guard = guard;
                    let _active = ActiveConnGuard::new_tcp(Arc::clone(&pipe));
                    if let Err(err) = handle_dns_stream_with_context(
                        stream,
                        peer,
                        pipe,
                        idle_timeout,
                        QueryProtocol::Tcp,
                        None,
                        conn_shutdown,
                    )
                    .await
                    {
                        tracing::debug!(peer = %peer, error = %err, "TCP DNS connection closed");
                    }
                });
            }
        }
    }
    drain_join_set(&mut tasks, GRACEFUL_DRAIN_TIMEOUT).await;
}

pub(crate) async fn handle_dns_stream_with_context<S>(
    stream: S,
    peer: SocketAddr,
    pipeline: Arc<DnsPipeline>,
    idle_timeout: Duration,
    protocol: QueryProtocol,
    client_id: Option<String>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (resp_tx, mut resp_rx) = mpsc::channel::<Vec<u8>>(MAX_TCP_PIPELINE_INFLIGHT);
    let (write_err_tx, mut write_err_rx) = watch::channel(false);

    let reader_fut = async {
        let mut len_buf = [0_u8; 2];
        let mut inflight = JoinSet::new();
        let inflight_sem = Arc::new(Semaphore::new(MAX_TCP_PIPELINE_INFLIGHT));
        let conn_deadline = tokio::time::Instant::now() + MAX_TCP_CONN_LIFETIME;

        loop {
            let read_res = tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                _ = write_err_rx.changed() => {
                    if *write_err_rx.borrow() {
                        break;
                    }
                    continue;
                }
                () = tokio::time::sleep_until(conn_deadline) => break,
                Some(_) = inflight.join_next(), if !inflight.is_empty() => continue,
                res = tokio::time::timeout(idle_timeout, reader.read_exact(&mut len_buf)) => res,
            };
            let Ok(Ok(_)) = read_res else {
                break;
            };
            let len = usize::from(u16::from_be_bytes(len_buf));
            if len == 0 || len > 65_535 {
                break;
            }
            let mut query = vec![0_u8; len];
            if !matches!(
                tokio::time::timeout(idle_timeout, reader.read_exact(&mut query)).await,
                Ok(Ok(_))
            ) {
                break;
            }

            let permit_res = tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = write_err_rx.changed() => break,
                res = tokio::time::timeout(idle_timeout, Arc::clone(&inflight_sem).acquire_owned()) => res,
            };
            let Ok(Ok(permit)) = permit_res else {
                break;
            };

            let pipe = Arc::clone(&pipeline);
            let tx = resp_tx.clone();
            let cid = client_id.clone();
            inflight.spawn(async move {
                let _permit = permit;
                let ctx = QueryContext {
                    client_addr: peer,
                    protocol,
                    client_id: cid,
                };
                let resp_opt = match pipe.handle_packet_with_context(&query, ctx).await {
                    Ok(resp) => Some(resp),
                    Err(_) => build_raw_formerr(&query),
                };
                if let Some(resp) = resp_opt {
                    let _ = tx.send(resp).await;
                }
            });
        }
        drop(resp_tx);
        drain_join_set(&mut inflight, GRACEFUL_DRAIN_TIMEOUT).await;
    };

    let writer_fut = async {
        let mut write_buf = Vec::with_capacity(514);
        while let Some(resp) = resp_rx.recv().await {
            let Ok(resp_len) = u16::try_from(resp.len()) else {
                continue;
            };
            write_buf.clear();
            write_buf.extend_from_slice(&resp_len.to_be_bytes());
            write_buf.extend_from_slice(&resp);
            let write_res = tokio::time::timeout(idle_timeout, async {
                writer.write_all(&write_buf).await?;
                writer.flush().await
            })
            .await;
            if !matches!(write_res, Ok(Ok(()))) {
                let _ = write_err_tx.send(true);
                break;
            }
        }
    };

    tokio::join!(reader_fut, writer_fut);
    Ok(())
}
