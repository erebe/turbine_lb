use std::io;
use tokio::net::TcpStream;

use crate::splice_strategy::ebpf_sockmap::SockMapSplice;
use crate::splice_strategy::naive::NaiveSplice;
use crate::splice_strategy::splice::SpliceSyscall;
use crate::KtlsTcpStream;

pub mod ebpf_sockmap;
pub mod naive;
pub mod splice;

pub trait SocketSplice {
    async fn splice_bidirectional(
        &self,
        local: &mut TcpStream,
        upstream: &mut TcpStream,
    ) -> io::Result<()>;
    async fn splice_ktls_bidirectional(
        &self,
        local: &mut KtlsTcpStream,
        upstream: &mut TcpStream,
    ) -> io::Result<()>;
}

impl SocketSplice for SockMapSplice {
    async fn splice_bidirectional(
        &self,
        local: &mut TcpStream,
        upstream: &mut TcpStream,
    ) -> io::Result<()> {
        self.splice(local, upstream).await
    }

    async fn splice_ktls_bidirectional(
        &self,
        _local: &mut KtlsTcpStream,
        _upstream: &mut TcpStream,
    ) -> io::Result<()> {
        todo!()
    }
}

impl SocketSplice for NaiveSplice {
    async fn splice_bidirectional(
        &self,
        local: &mut TcpStream,
        upstream: &mut TcpStream,
    ) -> io::Result<()> {
        self.splice(local, upstream).await
    }

    async fn splice_ktls_bidirectional(
        &self,
        local: &mut KtlsTcpStream,
        upstream: &mut TcpStream,
    ) -> io::Result<()> {
        self.splice(local, upstream).await
    }
}

impl SocketSplice for SpliceSyscall {
    async fn splice_bidirectional(
        &self,
        local: &mut TcpStream,
        upstream: &mut TcpStream,
    ) -> io::Result<()> {
        self.splice(local, upstream).await
    }

    async fn splice_ktls_bidirectional(
        &self,
        local: &mut KtlsTcpStream,
        upstream: &mut TcpStream,
    ) -> io::Result<()> {
        self.splice(local, upstream).await
    }
}
