mod peekable_stream;

use crate::peekable_stream::PeekableStream;
use anyhow::Context;
use clap::Parser;
use rustls::internal::msgs::deframer::MessageDeframer;
use rustls::internal::msgs::handshake::{ConvertServerNameList, HandshakePayload};
use rustls::internal::msgs::message::{Message, MessagePayload};
use rustls::internal::record_layer::RecordLayer;
use rustls::server::DnsName;
use socket2::{Domain, SockAddr};
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use duration_str::deserialize_duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::timeout;
use tokio_splice::zero_copy_bidirectional;
use tracing::{error, info, info_span, warn, Instrument, Level};
use tracing_subscriber::EnvFilter;
use url::Host;
use url::Url;

const LOCAL_ADDR_V6: SocketAddr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
const LOCAL_ADDR_V4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum Protocol {
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy)]
struct LocalToRemote {
    protocol: Protocol,
    listen_addr: SocketAddr,
    remote: SocketAddr,
    use_proxy_protocol: bool,
    cnx_max_duration: Duration,
    connect_timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct Config {
   pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    pub protocol: Protocol,
    pub listen_addr: Vec<SocketAddr>,
    pub upstreams: Vec<Upstream>,
    #[serde(deserialize_with = "deserialize_duration")]
    pub cnx_max_duration: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub connect_timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct Upstream {
    pub addrs: Vec<SocketAddr>,
    pub proxy_protocol: bool,
    pub r#match: Match,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Match {
    Any,
    Sni(String)
}

/// Tcp Proxy
#[derive(clap::Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment, long_about = None)]
struct CmdLine {
    /// Listen on local and forwards traffic to remote. Can be specified multiple times
    /// examples:
    /// 'tcp://22:[fd00:cafe::5]:22?proxy_protocol'   =>       listen locally on tcp on port 1212 and forward to google.com on port 443
    #[arg(short = 'F', long, required=true, value_name = "tcp://[BIND:]PORT:HOST:PORT?proxy_protocol", value_parser = parse_tunnel_arg, verbatim_doc_comment)]
    local_to_remote: Vec<LocalToRemote>,
}

fn parse_tunnel_arg(arg: &str) -> Result<LocalToRemote, io::Error> {
    use std::io::Error;

    match &arg[..6] {
        "tcp://" => {
            let (local_bind, remaining) = parse_local_bind(&arg[6..])?;
            let (dest_host, dest_port, options) = parse_tunnel_dest(remaining)?;
            let remote = match dest_host {
                Host::Ipv4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, dest_port)),
                Host::Ipv6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, dest_port, 0, 0)),
                Host::Domain(_) => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid local protocol for tunnel {}", arg),
                    ))
                }
            };
            Ok(LocalToRemote {
                protocol: Protocol::Tcp,
                listen_addr: local_bind,
                remote,
                use_proxy_protocol: options.get("proxy_protocol").is_some(),
                cnx_max_duration: {
                    let timeout_min: u64 = options
                        .get("timeout")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(10u64);
                    Duration::from_secs(60 * timeout_min)
                },
                connect_timeout: Duration::from_secs(10),
            })
        }
        "tls://" => {
            let (local_bind, remaining) = parse_local_bind(&arg[6..])?;
            let (dest_host, dest_port, options) = parse_tunnel_dest(remaining)?;
            let remote = match dest_host {
                Host::Ipv4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, dest_port)),
                Host::Ipv6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, dest_port, 0, 0)),
                Host::Domain(_) => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid local protocol for tunnel {}", arg),
                    ))
                }
            };
            Ok(LocalToRemote {
                protocol: Protocol::Tls,
                listen_addr: local_bind,
                remote,
                use_proxy_protocol: options.get("proxy_protocol").is_some(),
                cnx_max_duration: {
                    let timeout_min: u64 = options
                        .get("timeout")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(10u64);
                    Duration::from_secs(60 * timeout_min)
                },
                connect_timeout: Duration::from_secs(10),
            })
        }
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid local protocol for tunnel {}", arg),
        )),
    }
}

fn parse_local_bind(arg: &str) -> Result<(SocketAddr, &str), io::Error> {
    use std::io::Error;

    let (bind, remaining) = if arg.starts_with('[') {
        // ipv6 bind
        let Some((ipv6_str, remaining)) = arg.split_once(']') else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse IPv6 bind from {}", arg),
            ));
        };
        let Ok(ipv6_addr) = Ipv6Addr::from_str(&ipv6_str[1..]) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse IPv6 bind from {}", ipv6_str),
            ));
        };

        (IpAddr::V6(ipv6_addr), remaining)
    } else {
        // Maybe ipv4 addr
        let (ipv4_str, remaining) = arg.split_once(':').unwrap_or((arg, ""));

        match Ipv4Addr::from_str(ipv4_str) {
            Ok(ip4_addr) => (IpAddr::V4(ip4_addr), remaining),
            // Must be the port, so we default to ipv4 bind
            Err(_) => (IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()), arg),
        }
    };

    let remaining = remaining.trim_start_matches(':');
    let (port_str, remaining) = remaining.split_once([':', '?']).unwrap_or((remaining, ""));

    let Ok(bind_port): Result<u16, _> = port_str.parse() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse bind port from {}", port_str),
        ));
    };

    Ok((SocketAddr::new(bind, bind_port), remaining))
}

#[allow(clippy::type_complexity)]
fn parse_tunnel_dest(
    remaining: &str,
) -> Result<(Host<String>, u16, BTreeMap<String, String>), io::Error> {
    use std::io::Error;

    let Ok(remote) = Url::parse(&format!("https://{}", remaining)) else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse remote from {}", remaining),
        ));
    };

    let Some(remote_host) = remote.host() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse remote host from {}", remaining),
        ));
    };

    let Some(remote_port) = remote.port_or_known_default() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse remote port from {}", remaining),
        ));
    };

    let options: BTreeMap<String, String> = remote.query_pairs().into_owned().collect();
    Ok((remote_host.to_owned(), remote_port, options))
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
    let config: Config = serde_yaml::from_reader(BufReader::new(File::open("config.yaml")?))?;
    info!("{:?}", config);
    let  x = serde_yaml::to_string(&Match::Sni("toto".to_string()));
    info!("{:?}", x);

    for local in cmd_line.local_to_remote {
        info!("TCP server listening on {}", local.listen_addr);
        let tcp_server = create_socket(local.listen_addr)?;
        tcp_server.listen(4096)?;
        let tcp_server =
            tokio::net::TcpListener::from_std(std::net::TcpListener::from(tcp_server))?;
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
                    remote = %local.remote,
                    proxy = local.use_proxy_protocol,
                    timeout = ?local.cnx_max_duration);

                let proxied_client_loop = async move {
                    if let Err(err) = handle_client(local, stream, peer_addr).await {
                        warn!("{:?}", err);
                    }
                }
                .instrument(span);

                tokio::spawn(timeout(local.cnx_max_duration, proxied_client_loop));
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
    local: LocalToRemote,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    info!("handling new connection");
    let _guard = scopeguard::guard((), |_| {
        info!("connections closed");
    });

    if local.protocol == Protocol::Tls {
        if let Some(sni) = extract_sni(&stream).await? {
            info!("SNI: {}", sni.as_ref());
        }
    }


    let sock = if local.remote.is_ipv4() {
        create_socket(LOCAL_ADDR_V4)?
    } else {
        create_socket(LOCAL_ADDR_V6)?
    };

    let mut sock = match sock.connect(&SockAddr::from(local.remote)) {
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

    if local.use_proxy_protocol {
        let proxy_protocol_header = ppp::v2::Builder::with_addresses(
            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
            ppp::v2::Protocol::Stream,
            (peer_addr, stream.local_addr().unwrap()),
        )
        .build()?;
        sock.write_all(proxy_protocol_header.as_slice()).await?;
    }

    let timeout = tokio::time::sleep(local.cnx_max_duration);
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
