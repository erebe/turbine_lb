
use aya::maps::{MapData, SockHash};
use aya::programs::SkSkb;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use nix::libc;
use once_cell::sync::Lazy;
use tracing::{debug, info};
use tracing::log::warn;

static SOCKS: Lazy<SockHash<MapData, u32>> = Lazy::new(|| {
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
    )).expect("Failed to load ebpf program. Make sure to build the project first.");
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/splice-ebpf"
    )).expect("Failed to load ebpf program. Make sure to build the project first.");

    #[cfg(debug_assertions)]
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let intercept_ingress: SockHash<MapData, u32> = bpf
        .take_map("INTERCEPT_INGRESS")
        .unwrap()
        .try_into()
        .expect("Failed to get ebpf map intercept ingress");
    let map_fd = intercept_ingress.fd().try_clone().expect("Failed to clone map fd");

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

    intercept_ingress
});

pub fn init() {
    info!("Hello");
    SOCKS.iter().for_each(|key| {
        info!("sockmap key: {:?}", key);
    });
}
