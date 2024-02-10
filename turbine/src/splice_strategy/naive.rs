use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Default)]
pub struct NaiveSplice {}

impl NaiveSplice {
    pub async fn splice<A, B>(&self, local: &mut A, upstream: &mut B) -> Result<(), io::Error>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        tokio::io::copy_bidirectional(local, upstream)
            .await
            .map(|_| ())
    }
}
