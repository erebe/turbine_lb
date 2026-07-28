use crate::r#match::MatchContext;
use crate::{create_udp_socket, Rule, LOCAL_ADDR_V4, LOCAL_ADDR_V6};
use futures::task::noop_waker_ref;
use socket2::SockAddr;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, field, info, span, warn, Instrument, Level};

const MAX_DATAGRAM_SIZE: usize = 65_536;
const SESSION_CHANNEL_CAPACITY: usize = 64;
const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub async fn run_udp_listener(
    listen_addr: SocketAddr,
    mut config_rx: watch::Receiver<Arc<Rule>>,
    tasks_counter: Arc<AtomicUsize>,
) -> anyhow::Result<()> {
    let sock = create_udp_socket(listen_addr)?;
    let listen_sock = Arc::new(UdpSocket::from_std(std::net::UdpSocket::from(sock))?);
    let mut rule = config_rx.borrow_and_update().clone();

    info!("starting");
    let _guard = scopeguard::guard((), |_| {
        info!("stopped");
    });

    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut cleanup_interval = tokio::time::interval(SESSION_CLEANUP_INTERVAL);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        select! {
            biased;

            _ = cleanup_interval.tick() => {
                sessions.retain(|_, tx| !tx.is_closed());
            }

            ret = config_rx.changed() => {
                match ret {
                    Ok(_) => {
                        rule = config_rx.borrow_and_update().clone();
                        continue;
                    }
                    Err(_) => {
                        warn!("Asked to shutdown UDP listener, draining recv queue");
                        // Best-effort: drain any pending datagram then exit
                        let mut cx = Context::from_waker(noop_waker_ref());
                        let mut poll_buf = tokio::io::ReadBuf::new(&mut buf);
                        match listen_sock.poll_recv_from(&mut cx, &mut poll_buf) {
                            Poll::Ready(Ok(client_addr)) => {
                                let n = poll_buf.filled().len();
                                dispatch_datagram(
                                    &listen_sock,
                                    listen_addr,
                                    client_addr,
                                    &buf[..n],
                                    &rule,
                                    &mut sessions,
                                    &tasks_counter,
                                );
                            }
                            Poll::Ready(Err(err)) => {
                                error!("error while draining UDP queue: {:?}", err);
                            }
                            Poll::Pending => {}
                        }
                        break;
                    }
                }
            }

            recv = listen_sock.recv_from(&mut buf) => {
                let (n, client_addr) = match recv {
                    Ok(x) => x,
                    Err(err) => {
                        error!("error receiving UDP datagram: {:?}", err);
                        continue;
                    }
                };

                dispatch_datagram(
                    &listen_sock,
                    listen_addr,
                    client_addr,
                    &buf[..n],
                    &rule,
                    &mut sessions,
                    &tasks_counter,
                );
            }
        }
    }

    Ok(())
}

fn dispatch_datagram(
    listen_sock: &Arc<UdpSocket>,
    listen_addr: SocketAddr,
    client_addr: SocketAddr,
    data: &[u8],
    rule: &Rule,
    sessions: &mut HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
    tasks_counter: &Arc<AtomicUsize>,
) {
    // Try existing session first
    if let Some(tx) = sessions.get(&client_addr) {
        match tx.try_send(data.to_vec()) {
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Backpressure — drop the datagram (UDP semantics)
                debug!(
                    "UDP session channel full for {}, dropping datagram",
                    client_addr
                );
                return;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                sessions.remove(&client_addr);
                // fall through to create a new session
            }
        }
    }

    // Create a new session
    let match_context = MatchContext::for_destination(listen_addr);
    let Some(upstream) = match_context.find_matching_upstream(&rule.upstreams) else {
        warn!(
            "Dropping UDP datagram from {}: No upstream found for {:?}",
            client_addr, match_context
        );
        return;
    };

    if upstream.cfg.proxy_protocol {
        warn!(
            "proxy_protocol is not supported for UDP upstreams (upstream={}), ignoring",
            upstream.cfg.name
        );
    }

    let backend = upstream.load_balancing.pick_backend(&upstream.backends);

    let (tx, rx) = mpsc::channel::<Vec<u8>>(SESSION_CHANNEL_CAPACITY);
    // Enqueue the initial datagram before spawning to make sure it is first in line
    if tx.try_send(data.to_vec()).is_err() {
        // channel just created and single-slot only holds one — can't happen
        return;
    }
    sessions.insert(client_addr, tx);

    let listen_sock = listen_sock.clone();
    let tasks_counter = tasks_counter.clone();
    let idle_timeout = upstream.cfg.cnx_max_duration;
    let connect_timeout = upstream.cfg.connect_timeout;
    let backend_addr = backend.addr;

    let span = span!(
        Level::INFO,
        "udp",
        peer = %client_addr,
        upstream = %upstream.cfg.name,
        upstream_addr = %backend_addr,
        timeout = field::Empty,
    );
    span.record("timeout", format!("{}s", idle_timeout.as_secs().max(1)));

    tokio::spawn(
        async move {
            tasks_counter.fetch_add(1, Ordering::Relaxed);
            let _guard = scopeguard::guard((), |_| {
                tasks_counter.fetch_sub(1, Ordering::Relaxed);
            });

            if let Err(err) = run_udp_session(
                listen_sock,
                client_addr,
                backend_addr,
                rx,
                idle_timeout,
                connect_timeout,
            )
            .await
            {
                warn!("UDP session error: {:?}", err);
            }
        }
        .instrument(span),
    );
}

async fn run_udp_session(
    listen_sock: Arc<UdpSocket>,
    client_addr: SocketAddr,
    backend_addr: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    idle_timeout: Duration,
    connect_timeout: Duration,
) -> anyhow::Result<()> {
    info!("opening UDP session");
    let _guard = scopeguard::guard((), |_| {
        info!("UDP session closed");
    });

    let bind_addr = if backend_addr.is_ipv4() {
        LOCAL_ADDR_V4
    } else {
        LOCAL_ADDR_V6
    };

    let backend_sock =
        tokio::time::timeout(connect_timeout, connect_backend(bind_addr, backend_addr))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Cannot connect UDP socket to {} after {:?}",
                    backend_addr,
                    connect_timeout
                )
            })??;

    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
    loop {
        select! {
            biased;

            _ = tokio::time::sleep(idle_timeout) => {
                warn!("idle timeout of {:?} elapsed. Closing UDP session", idle_timeout);
                break;
            }

            msg = rx.recv() => match msg {
                Some(data) => {
                    if let Err(err) = backend_sock.send(&data).await {
                        warn!("failed to send UDP datagram to backend: {:?}", err);
                        break;
                    }
                }
                None => {
                    // Sender side dropped — session evicted from map; exit cleanly.
                    break;
                }
            },

            result = backend_sock.recv(&mut buf) => match result {
                Ok(n) => {
                    if let Err(err) = listen_sock.send_to(&buf[..n], client_addr).await {
                        warn!("failed to send UDP datagram to client: {:?}", err);
                        break;
                    }
                }
                Err(err) => {
                    warn!("failed to receive UDP datagram from backend: {:?}", err);
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn connect_backend(
    bind_addr: SocketAddr,
    backend_addr: SocketAddr,
) -> anyhow::Result<UdpSocket> {
    let sock = create_udp_socket(bind_addr)?;
    sock.connect(&SockAddr::from(backend_addr))?;
    let sock = UdpSocket::from_std(std::net::UdpSocket::from(sock))?;
    Ok(sock)
}
