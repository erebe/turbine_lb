#![no_std]
#![no_main]

use aya_bpf::{macros::stream_parser, programs::SkBuffContext};
use aya_bpf::{macros::stream_verdict, bindings::sk_action};
use aya_bpf::bindings::BPF_ANY;
use aya_bpf::macros::map;
use aya_bpf::maps::{SockHash};
use aya_log_ebpf::info;

#[map(name = "INGRESS")]
static mut INGRESS: SockHash<u32> = SockHash::with_max_entries(2048, BPF_ANY);

#[stream_parser]
fn stream_parser(ctx: SkBuffContext) -> u32 {
    ctx.len()
}

#[stream_verdict]
fn stream_verdict(ctx: SkBuffContext) -> u32 {
    let mut key: u32 = ctx.skb.local_ipv6()[0];
    key = 31 * key + ctx.skb.local_ipv6()[1];
    key = 31 * key + ctx.skb.local_ipv6()[2];
    key = 31 * key + ctx.skb.local_ipv6()[3];
    key = 31 * key + ctx.skb.local_port();
    key = 31 * key + ctx.skb.remote_ipv6()[0];
    key = 31 * key + ctx.skb.remote_ipv6()[1];
    key = 31 * key + ctx.skb.remote_ipv6()[2];
    key = 31 * key + ctx.skb.remote_ipv6()[3];
    key = 31 * key + ctx.skb.remote_port();
    info!(&ctx, "hash {}", key);

    let _ret = unsafe { INGRESS.redirect_skb(&ctx, &mut key, 0) };
    sk_action::SK_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
