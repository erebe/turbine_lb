use std::io;
use tokio_splice::{zero_copy_bidirectional, Stream};

#[derive(Default)]
pub struct SpliceSyscall {}

impl SpliceSyscall {
    pub async fn splice<A, B>(&self, local: &mut A, upstream: &mut B) -> Result<(), io::Error>
    where
        A: Stream + Unpin,
        B: Stream + Unpin,
    {
        zero_copy_bidirectional(local, upstream).await.map(|_| ())
    }
}
