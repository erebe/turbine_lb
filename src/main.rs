use std::net::{SocketAddr, SocketAddrV6};
use socket2::{Domain, Protocol, SockAddr};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {

    let sock = socket2::Socket::new(Domain::IPV6, socket2::Type::STREAM, Some(Protocol::TCP))?;

    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_ip_transparent(true)?;
    sock.set_nonblocking(true)?;

    let sock: SocketAddr = "[::]:1080".parse()?;

    let x = tokio::net::TcpListener::bind(sock)?;

    nix::fcntl::splice()
    Ok(())
}
