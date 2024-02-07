use socket2::SockRef;
use std::io::Read;
use std::mem::MaybeUninit;
use tokio::net::TcpStream;

pub struct PeekableStream<'a> {
    inner: SockRef<'a>,
}

impl<'a> PeekableStream<'a> {
    pub fn new(stream: &'a TcpStream) -> PeekableStream<'a> {
        Self {
            inner: socket2::SockRef::from(stream),
        }
    }
}

impl Read for PeekableStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buf = unsafe { std::mem::transmute::<&mut [u8], &mut [MaybeUninit<u8>]>(buf) };
        self.inner.peek(buf)
    }
}
