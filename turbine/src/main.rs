use std::cmp::max;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod config;
mod event_loop;
mod load_balancing_strategy;
mod r#match;
mod peekable_stream;
mod splice_strategy;
mod tls;

use crate::peekable_stream::PeekableStream;
use anyhow::Context;
use clap::Parser;
use ktls::KtlsStream;
use nonempty::NonEmpty;
use rustls::internal::msgs::deframer::MessageDeframer;
use rustls::internal::msgs::handshake::{ConvertServerNameList, HandshakePayload, ProtocolName};
use rustls::internal::msgs::message::{Message, MessagePayload};
use rustls::internal::record_layer::RecordLayer;
use rustls::server::DnsName;

use socket2::{Domain, SockAddr, SockRef, TcpKeepalive};
use std::io::{Error, IoSlice};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::Duration;

use crate::config::types::{Protocol, UpstreamConfig};
use crate::config::ConfigWatcher;
use crate::event_loop::LBAppContext;
use crate::load_balancing_strategy::{Backend, LoadBalancingStrategy};
use crate::r#match::MatchContext;
use crate::splice_strategy::ebpf_sockmap::SockMapSplice;

use crate::splice_strategy::SocketSplice;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, Interest, ReadBuf};
use tokio::net::TcpStream;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::{pin, select};
use tokio_rustls::TlsAcceptor;
use tokio_splice::{zero_copy_bidirectional, Stream};
use tracing::{debug, info, warn, Span};
use tracing_subscriber::EnvFilter;

const LOCAL_ADDR_V6: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
const LOCAL_ADDR_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

struct Rule {
    pub protocol: Protocol,
    pub upstreams: NonEmpty<Upstream>,
}

impl Rule {
    pub fn files_to_watch_for_reload(&self) -> impl Iterator<Item = &Path> {
        self.upstreams
            .iter()
            .filter_map(|u| {
                u.cfg
                    .tls
                    .as_ref()
                    .map(|t| [t.private_key.as_path(), t.certificate.as_path()])
            })
            .flatten()
    }
}

struct Upstream {
    pub cfg: UpstreamConfig,
    pub backends: NonEmpty<Backend>,
    pub load_balancing: LoadBalancingStrategy,
    pub tls_acceptor: Option<TlsAcceptor>,
}

/// Tcp Proxy
#[derive(clap::Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment, long_about = None)]
struct CmdLine {
    /// Path to the config file
    #[arg(short = 'c', long, default_value = "config.yaml")]
    config: PathBuf,

    /// Control the log verbosity. i.e: TRACE, DEBUG, INFO, WARN, ERROR, OFF
    /// for more details: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax
    #[arg(
        long,
        global = true,
        value_name = "LOG_LEVEL",
        verbatim_doc_comment,
        env = "RUST_LOG",
        default_value = "INFO"
    )]
    log_lvl: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmd_line: CmdLine = CmdLine::parse();

    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_env_filter(
            EnvFilter::builder()
                .parse(&cmd_line.log_lvl)
                .expect("Invalid log filter"),
        )
        .init();

    let rules = config::parse_config(&cmd_line.config)?;
    let (config_tx, config_rx) = mpsc::channel(10);
    let (shutdown_tx, mut lb_context) = LBAppContext::new();
    let task_counter = lb_context.tasks_running.clone();
    tokio::spawn(async move {
        lb_context.listen_config_change(config_rx).await;
    });
    let _ = config_tx.send(rules).await;
    let _config_watch = ConfigWatcher::new(cmd_line.config.clone(), config_tx)
        .expect("Cannot watch for config file changes");

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    select! {
        biased;
        _ = sigterm.recv() => info!("Receive SIGTERM. Waiting 15 to receive in-flight connection"),
        _ = sigint.recv() => info!("Receive SIGTINT. Waiting 15 to receive in-flight connection"),
    }

    // Kube takes a bit of time to clean up everything. So LB can still receive new cnx during 10/15secs
    select! {
        _ = tokio::time::sleep(Duration::from_secs(15)) => {}
        _ = sigint.recv() => info!("Received double SIGTINT. Sending stop immediately"),
    }
    let _ = shutdown_tx.send(());

    // Wait to drain all the connections
    let sigint = sigint.recv();
    pin!(sigint);
    loop {
        let nb_task = task_counter.load(Ordering::Relaxed);
        if nb_task == 0 {
            break;
        }

        info!("Waiting for {} cnx to shutdown", nb_task);
        select! {
            biased;

            _ = &mut sigint => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                info!("Received triple SIGINT. Exiting immediatly")
            }
        }
    }

    Ok(())
}

fn tcp_keep_alive_cfg() -> &'static TcpKeepalive {
    static KEEP_ALIVE: TcpKeepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(20))
        .with_retries(3);

    &KEEP_ALIVE
}
fn create_socket(bind: SocketAddr) -> anyhow::Result<socket2::Socket> {
    let sock = socket2::Socket::new(
        Domain::for_address(bind),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sock.set_tcp_keepalive(tcp_keep_alive_cfg())?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    //sock.set_ip_transparent(true)?;
    sock.set_keepalive(true)?;
    sock.set_nodelay(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SockAddr::from(bind))?;

    Ok(sock)
}

async fn handle_client(
    local: &Rule,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    info!("handling new connection");
    let _guard = scopeguard::guard((), |_| {
        info!("connections closed");
    });
    stream.set_nodelay(true)?;
    SockRef::from(&stream).set_tcp_keepalive(tcp_keep_alive_cfg())?;

    let match_context = match local.protocol {
        Protocol::Tls => {
            let (sni, alpns) = extract_tls_info(&stream).await?;
            debug!("SNI: {:?}", sni.as_ref().map(|x| x.as_ref()).unwrap_or(""));
            MatchContext::new(&stream, sni, alpns)
        }
        Protocol::Tcp => MatchContext::new(&stream, None, None),
    };

    // Select the correct upstream based on matches
    let Some(upstream) = match_context.find_matching_upstream(&local.upstreams) else {
        warn!(
            "Dropping connection: No upstream found for {:?}",
            match_context
        );
        return Ok(());
    };

    // Round-robin the upstreams
    let backend = upstream.load_balancing.pick_backend(&upstream.backends);

    let span = Span::current();
    span.record("upstream", upstream.cfg.name.as_str());
    span.record("upstream_addr", backend.addr.to_string());
    span.record("proxy", upstream.cfg.proxy_protocol);
    span.record(
        "timeout",
        format!("{}m", max(upstream.cfg.cnx_max_duration.as_secs(), 1) / 60),
    );

    info!("connecting to upstream");
    let sock = if backend.addr.is_ipv4() {
        create_socket(LOCAL_ADDR_V4)?
    } else {
        create_socket(LOCAL_ADDR_V6)?
    };

    let mut sock = match sock.connect(&SockAddr::from(backend.addr)) {
        Ok(_) => TcpStream::from_std(std::net::TcpStream::from(sock)),

        // wait for the socket to be connected if not already
        Err(err) if matches!(err.raw_os_error(), Some(nix::libc::EINPROGRESS)) => {
            let sock = TcpStream::from_std(std::net::TcpStream::from(sock))?;
            tokio::time::timeout(upstream.cfg.connect_timeout, sock.writable())
                .await
                .with_context(|| {
                    format!(
                        "Cannot connect to remote after {:?}",
                        upstream.cfg.connect_timeout
                    )
                })??;

            //       EINPROGRESS
            //               The socket is nonblocking and the connection cannot be
            //               completed immediately.  (UNIX domain sockets failed with
            //               EAGAIN instead.)  It is possible to select(2) or poll(2)
            //               for completion by selecting the socket for writing.  After
            //               select(2) indicates writability, use getsockopt(2) to read
            //               the SO_ERROR option at level SOL_SOCKET to determine
            //               whether connect() completed successfully (SO_ERROR is
            //               zero) or unsuccessfully (SO_ERROR is one of the usual
            //               error codes listed here, explaining the reason for the
            //               failure).
            if let Some(err) = sock.take_error()? {
                return Err(anyhow::Error::msg(format!(
                    "Error while connecting to remote: {:?}",
                    err
                )));
            }

            Ok(sock)
        }
        Err(err) => Err(err),
    }?;

    // Send proxy protocol header
    if upstream.cfg.proxy_protocol {
        let proxy_protocol_header = ppp::v2::Builder::with_addresses(
            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
            ppp::v2::Protocol::Stream,
            (peer_addr, stream.local_addr().unwrap()),
        )
        .build()?;
        sock.write_all(proxy_protocol_header.as_slice()).await?;
    }

    // TCP/TLS PASSTHROUGH
    let Some(tls_acceptor) = &upstream.tls_acceptor else {
        // If we're not doing TLS, just copy the data
        let splicer = SockMapSplice::new();
        let ret = tokio::time::timeout(
            upstream.cfg.cnx_max_duration,
            splicer.splice_bidirectional(&mut stream, &mut sock),
        )
        .await;
        match ret {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                warn!("closing cnx {:?}", err);
            }
            Err(_) => {
                warn!(
                    "timeout of {:?} elapsed. Closing cnx",
                    upstream.cfg.cnx_max_duration
                );
            }
        }
        return Ok(());
    };

    // TLS TERMINATION
    // Setup KTLS
    let tls_stream = tls_acceptor.accept(ktls::CorkStream::new(stream)).await?;
    let ktls_stream = ktls::config_ktls_server(tls_stream).await?;
    let (drain, tcp) = ktls_stream.into_raw();
    if let Some(data) = drain {
        sock.write_all(&data).await?;
    };
    let mut ktls_stream = KtlsTcpStream {
        inner: KtlsStream::new(tcp, None),
    };

    // Data transfer loop
    let timeout = tokio::time::sleep(upstream.cfg.cnx_max_duration);
    pin!(timeout);
    loop {
        select! {
            biased;

            ret = zero_copy_bidirectional(&mut ktls_stream, &mut sock) => {
                if let Err(err) = ret {
                   // if err.kind() == InvalidInput {
                   //         ktls_stream.inner.handle_msg();
                   //     warn!("error while copying data: {:?}", err);
                   //     continue;
                   // }
                   warn!("closing cnx {:?}", err);
                        break;
                }
            }

            _ = &mut timeout => {
               warn!("timeout of {:?} elapsed. Closing cnx", upstream.cfg.cnx_max_duration);
                    break;
            }
        }
    }

    Ok(())
}

async fn extract_tls_info(
    stream: &TcpStream,
) -> anyhow::Result<(Option<DnsName>, Option<Vec<ProtocolName>>)> {
    let mut tls_deframer = MessageDeframer::default();
    let mut record_layer = RecordLayer::new();
    let mut peek_stream = PeekableStream::new(stream);

    stream.readable().await?;
    tls_deframer.read(&mut peek_stream)?;
    let msg = tls_deframer
        .pop(&mut record_layer)?
        .with_context(|| "No TLS frame read")?;
    let msg = Message::try_from(msg.message)?;
    let (snv_names, alpns) = match &msg.payload {
        MessagePayload::Handshake { parsed, .. } => match &parsed.payload {
            HandshakePayload::ClientHello(msg) => {
                (msg.get_sni_extension(), msg.get_alpn_extension())
            }
            msg => {
                return Err(anyhow::Error::msg(format!(
                    "Invalid TLS msg, expecting client hello handshake: {:?}",
                    msg
                )))
            }
        },
        msg => {
            return Err(anyhow::Error::msg(format!(
                "Invalid TLS msg, expecting client hello handshake: {:?}",
                msg
            )))
        }
    };

    let sni = snv_names.and_then(|s| s.get_single_hostname());

    anyhow::Ok((sni.map(|x| x.to_owned()), alpns.map(|x| x.to_owned())))
}

pub struct KtlsTcpStream {
    pub inner: KtlsStream<TcpStream>,
}

impl AsyncRead for KtlsTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        unsafe { Pin::new_unchecked(&mut self.inner) }.poll_read(cx, buf)
    }
}

impl AsRawFd for KtlsTcpStream {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsyncWrite for KtlsTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        unsafe { Pin::new_unchecked(&mut self.inner) }.poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
        unsafe { Pin::new_unchecked(&mut self.inner) }.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
        unsafe { Pin::new_unchecked(&mut self.inner) }.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        unsafe { Pin::new_unchecked(&mut self.inner) }.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl Stream for KtlsTcpStream {
    fn poll_read_ready_n(&self, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_read_ready(cx)
    }

    fn poll_write_ready_n(&self, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_write_ready(cx)
    }

    fn try_io_n<R>(
        &self,
        interest: Interest,
        f: impl FnOnce() -> std::io::Result<R>,
    ) -> std::io::Result<R> {
        self.inner.try_io(interest, f)
    }
}
