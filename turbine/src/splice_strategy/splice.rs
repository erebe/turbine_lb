use std::io;
use tokio::net::TcpStream;
use tokio_splice::zero_copy_bidirectional;

async fn splice(local: &mut TcpStream, upstream: &mut TcpStream) -> Result<(), io::Error> {
    zero_copy_bidirectional(local, upstream).await.map(|_| ())
}
