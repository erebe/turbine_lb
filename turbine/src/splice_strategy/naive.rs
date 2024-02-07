use std::io;
use tokio::net::TcpStream;

async fn splice(local: &mut TcpStream, upstream: &mut TcpStream) -> Result<(), io::Error> {
    tokio::io::copy_bidirectional(local, upstream)
        .await
        .map(|_| ())
}
