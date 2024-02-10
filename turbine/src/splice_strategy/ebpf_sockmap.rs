use aya::maps::{MapData, SockHash};
use aya::programs::SkSkb;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::os::fd::AsRawFd;

use nix::libc;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use tokio::io::Interest;
use tokio::net::TcpStream;
use tracing::log::warn;
use tracing::{debug, info};

static SOCKS: Lazy<Mutex<(SockHash<MapData, u32>, Bpf)>> = Lazy::new(|| {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/splice-ebpf"
    ))
    .expect("Failed to load ebpf program. Make sure to build the project first.");
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/splice-ebpf"
    ))
    .expect("Failed to load ebpf program. Make sure to build the project first.");

    #[cfg(debug_assertions)]
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let intercept_ingress: SockHash<MapData, u32> = bpf
        .take_map("INGRESS")
        .unwrap()
        .try_into()
        .expect("Failed to get ebpf map intercept ingress");
    let map_fd = intercept_ingress
        .fd()
        .try_clone()
        .expect("Failed to clone map fd");

    let prog: &mut SkSkb = bpf
        .program_mut("stream_parser")
        .unwrap()
        .try_into()
        .expect("Failed to get ebpf stream parser");
    prog.load().expect("Failed to load ebpf stream parser");
    prog.attach(&map_fd)
        .expect("Failed to attach ebpf stream parser");

    let prog: &mut SkSkb = bpf
        .program_mut("stream_verdict")
        .unwrap()
        .try_into()
        .expect("Failed to get ebpf stream verdict");
    prog.load().expect("Failed to load ebpf stream verdict");
    prog.attach(&map_fd)
        .expect("Failed to attach ebpf stream verdict");

    Mutex::new((intercept_ingress, bpf))
});

pub struct SockMapSplice {
    socks: &'static Mutex<(SockHash<MapData, u32>, Bpf)>,
}

impl Default for SockMapSplice {
    fn default() -> Self {
        Self::new()
    }
}

impl SockMapSplice {
    pub fn new() -> Self {
        Self {
            socks: SOCKS.deref(),
        }
    }

    pub async fn splice(
        &self,
        local: &mut TcpStream,
        upstream: &mut TcpStream,
    ) -> Result<(), io::Error> {
        let key = socket_hash(local.local_addr().unwrap(), local.peer_addr().unwrap());
        if let Err(err) = self.socks.lock().0.insert(key, upstream.as_raw_fd(), 0) {
            warn!("{:?}", err);
            return Ok(());
        }

        let key = socket_hash(
            upstream.local_addr().unwrap(),
            upstream.peer_addr().unwrap(),
        );
        if let Err(err) = self.socks.lock().0.insert(key, local.as_raw_fd(), 0) {
            warn!("{:?}", err);
            return Ok(());
        }

        // We need to forward the already buffered packet in user space
        let _ = tokio::io::copy_bidirectional(local, upstream).await;
        //select! {
        //    ret = await_termination(local) => {
        //        info!("local socket terminated: {:?}", ret);
        //    },
        //    ret = await_termination(upstream) => {
        //        info!("upstream socket terminated {:?}", ret);
        //    }
        //}
        info!("Connection closed");

        Ok(())
    }
}

async fn await_termination(sock: &mut TcpStream) -> anyhow::Result<()> {
    let _ = sock.ready(Interest::READABLE.add(Interest::ERROR)).await;
    let _ = sock.ready(Interest::ERROR).await;

    Ok(())
}

#[inline(always)]
fn socket_hash(local_addr: SocketAddr, peer_addr: SocketAddr) -> u32 {
    let (lip, lport) = match local_addr {
        SocketAddr::V4(s) => (u128::from(s.ip().to_ipv6_mapped()), s.port() as u32),
        SocketAddr::V6(s) => (u128::from(*s.ip()), s.port() as u32),
    };
    let (rip, rport) = match peer_addr {
        SocketAddr::V4(s) => (u128::from(s.ip().to_ipv6_mapped()), s.port() as u32),
        SocketAddr::V6(s) => (u128::from(*s.ip()), s.port() as u32),
    };

    let [a, aa, aaa, aaaa, b, bb, bbb, bbbb, c, cc, ccc, cccc, d, dd, ddd, dddd] =
        lip.to_be_bytes();
    let mut key: u32 = u32::from_be_bytes([a, aa, aaa, aaaa]).to_be();
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(u32::from_be_bytes([b, bb, bbb, bbbb]).to_be())
        .0;
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(u32::from_be_bytes([c, cc, ccc, cccc]).to_be())
        .0;
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(u32::from_be_bytes([d, dd, ddd, dddd]).to_be())
        .0;

    // local port is in host byte order
    // https://codebrowser.dev/linux/linux/include/uapi/linux/bpf.h.html#6117
    key = 31u32.overflowing_mul(key).0.overflowing_add(lport).0;

    let [a, aa, aaa, aaaa, b, bb, bbb, bbbb, c, cc, ccc, cccc, d, dd, ddd, dddd] =
        rip.to_be_bytes();
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(u32::from_be_bytes([a, aa, aaa, aaaa]).to_be())
        .0;
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(u32::from_be_bytes([b, bb, bbb, bbbb]).to_be())
        .0;
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(u32::from_be_bytes([c, cc, ccc, cccc]).to_be())
        .0;
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(u32::from_be_bytes([d, dd, ddd, dddd]).to_be())
        .0;
    key = 31u32
        .overflowing_mul(key)
        .0
        .overflowing_add(rport.to_be())
        .0;
    key
}
