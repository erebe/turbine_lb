#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod peekable_stream;

use crate::peekable_stream::PeekableStream;
use anyhow::Context;
use clap::Parser;
use duration_str::deserialize_duration;
use nonempty::NonEmpty;
use rustls::internal::msgs::deframer::MessageDeframer;
use rustls::internal::msgs::handshake::{ConvertServerNameList, HandshakePayload};
use rustls::internal::msgs::message::{Message, MessagePayload};
use rustls::internal::record_layer::RecordLayer;
use rustls::server::DnsName;
use serde::Deserialize;
use socket2::{Domain, SockAddr};
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::time::timeout;
use tokio_splice::zero_copy_bidirectional;
use tracing::{error, field, info, info_span, warn, Instrument, Level, Span};
use tracing_subscriber::EnvFilter;

const LOCAL_ADDR_V6: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
const LOCAL_ADDR_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum Protocol {
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    pub protocol: Protocol,
    pub listen_addr: NonEmpty<SocketAddr>,
    pub upstreams: NonEmpty<Upstream>,
    #[serde(deserialize_with = "deserialize_duration")]
    pub cnx_max_duration: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub connect_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize)]
struct Upstream {
    pub name: String,
    pub addrs: NonEmpty<SocketAddr>,
    #[serde(skip)]
    pub round_robin_counter: Arc<AtomicUsize>,
    pub proxy_protocol: bool,
    pub r#match: Match,
}

#[derive(Debug, Clone, Deserialize)]
pub enum Match {
    Any,
    Sni(String),
    DestinationPort(u16),
}

/// Tcp Proxy
#[derive(clap::Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment, long_about = None)]
struct CmdLine {
    /// Path to the config file
    #[arg(short = 'c', long, default_value = "config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmd_line: CmdLine = CmdLine::parse();

    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(Level::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let config: Config = serde_yaml::from_reader(BufReader::new(File::open(cmd_line.config)?))?;

    let rules = config.rules.into_iter().flat_map(|mut x| {
        let listen_addr = std::mem::replace(&mut x.listen_addr, NonEmpty::new(LOCAL_ADDR_V4));
        let rule = Arc::new(x);
        listen_addr
            .into_iter()
            .map(move |addr| (addr, rule.clone()))
    });

    for (listen_addr, rule) in rules {
        info!("{:?} server listening on {}", rule.protocol, listen_addr);
        let tcp_server = create_socket(listen_addr)?;
        tcp_server.listen(4096)?;
        let tcp_server = TcpListener::from_std(std::net::TcpListener::from(tcp_server))?;

        let server_loop = async move {
            loop {
                let (stream, peer_addr) = match tcp_server.accept().await {
                    Ok(cnx) => cnx,
                    Err(err) => {
                        error!("error accepting new connections: {:?}", err);
                        continue;
                    }
                };

                let span = info_span!("cnx",
                    peer = %peer_addr,
                    upstream = field::Empty,
                    upstream_addr = field::Empty,
                    proxy = field::Empty,
                    timeout = ?rule.cnx_max_duration);

                let cnx_max_duration = rule.cnx_max_duration;
                let rule = rule.clone();
                let proxied_client_loop = async move {
                    if let Err(err) = handle_client(&rule, stream, peer_addr).await {
                        warn!("{:?}", err);
                    }
                }
                .instrument(span);

                tokio::spawn(timeout(cnx_max_duration, proxied_client_loop));
            }
        };

        tokio::spawn(server_loop);
    }

    let _ = tokio::signal::ctrl_c().await;
    Ok(())
}

fn create_socket(bind: SocketAddr) -> anyhow::Result<socket2::Socket> {
    let sock = socket2::Socket::new(
        Domain::for_address(bind),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    sock.set_reuse_address(true)?;
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

    let cnx_sni = match local.protocol {
        Protocol::Tls => match extract_sni(&stream).await? {
            Some(sni) => {
                info!("SNI: {}", sni.as_ref());
                Some(sni)
            }
            None => None,
        },
        Protocol::Tcp => None,
    };

    // Select the correct upstream based on matches
    let upstream = local
        .upstreams
        .iter()
        .find(|upstream| match &upstream.r#match {
            Match::Any => true,
            Match::Sni(sni) => cnx_sni
                .as_ref()
                .map(|cnx_sni| cnx_sni.as_ref() == sni.as_str())
                .unwrap_or(false),
            Match::DestinationPort(dport) => stream.local_addr().unwrap().port() == *dport,
        })
        .unwrap_or_else(|| {
            warn!("No upstream found, defaulting to first one. Add an Match::Any rule to avoid this message");
            local.upstreams.first()
        });

    // Round-robin the upstreams
    let upstream_addr = {
        let ix = upstream.round_robin_counter.fetch_add(1, Ordering::Relaxed);
        &upstream.addrs[ix % upstream.addrs.len()]
    };

    let span = Span::current();
    span.record("upstream", upstream.name.as_str());
    span.record("upstream_addr", upstream_addr.to_string());
    span.record("proxy", upstream.proxy_protocol);

    info!("connecting to upstream");
    let sock = if upstream_addr.is_ipv4() {
        create_socket(LOCAL_ADDR_V4)?
    } else {
        create_socket(LOCAL_ADDR_V6)?
    };

    let mut sock = match sock.connect(&SockAddr::from(*upstream_addr)) {
        Ok(_) => TcpStream::from_std(std::net::TcpStream::from(sock)),

        // wait for the socket to be connected if not already
        Err(err) if matches!(err.raw_os_error(), Some(nix::libc::EINPROGRESS)) => {
            let sock = TcpStream::from_std(std::net::TcpStream::from(sock))?;
            tokio::time::timeout(local.connect_timeout, sock.writable())
                .await
                .with_context(|| {
                    format!("Cannot connect to remote after {:?}", local.connect_timeout)
                })??;

            Ok(sock)
        }
        Err(err) => Err(err),
    }?;

    // Send proxy protocol header
    if upstream.proxy_protocol {
        let proxy_protocol_header = ppp::v2::Builder::with_addresses(
            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
            ppp::v2::Protocol::Stream,
            (peer_addr, stream.local_addr().unwrap()),
        )
        .build()?;
        sock.write_all(proxy_protocol_header.as_slice()).await?;
    }

    let timeout = tokio::time::sleep(local.cnx_max_duration);

    // Data transfer loop
    select! {
        biased;

        ret = zero_copy_bidirectional(&mut stream, &mut sock) => {
            if let Err(err) = ret {
               warn!("closing cnx {:?}", err);
            }
        }

        _ = timeout => {
           warn!("timeout of {:?} elapsed. Closing cnx", local.cnx_max_duration);
        }
    }

    Ok(())
}

async fn extract_sni(stream: &TcpStream) -> anyhow::Result<Option<DnsName>> {
    let mut tls_deframer = MessageDeframer::default();
    let mut record_layer = RecordLayer::new();
    let mut peek_stream = PeekableStream::new(stream);

    stream.readable().await?;
    tls_deframer.read(&mut peek_stream)?;
    let msg = tls_deframer
        .pop(&mut record_layer)?
        .with_context(|| "No TLS frame read")?;
    let msg = Message::try_from(msg.message)?;
    let snv_names = match &msg.payload {
        MessagePayload::Handshake { parsed, .. } => match &parsed.payload {
            HandshakePayload::ClientHello(msg) => {
                let srv_names = msg.get_sni_extension();
                srv_names
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

    anyhow::Ok(sni.map(|x| x.to_owned()))
}
