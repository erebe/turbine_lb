use socket2::SockRef;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::ops::Deref;
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

impl Write for PeekableStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.deref().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.deref().flush()
    }
}
