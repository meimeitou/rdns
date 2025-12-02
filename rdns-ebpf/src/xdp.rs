#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};

#[path = "common.rs"]
mod common;
use common::{parse_dns_packet, send_dns_event, should_pass};

/// IP 黑名单 (key: IP地址, value: 1)
#[map]
static IP_BLACKLIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

/// IP 白名单 (key: IP地址, value: 1)
#[map]
static IP_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

/// 过滤模式 (key: 0, value: 0=blacklist, 1=whitelist)
#[map]
static FILTER_MODE: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// DNS 事件 RingBuf
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn rdns_xdp(ctx: XdpContext) -> u32 {
    match try_rdns_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_rdns_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // 解析 DNS 包
    let (src_ip, dst_ip, src_port, dst_port, dns_ptr, dns_len) =
        match parse_dns_packet(data, data_end) {
            Some(result) => result,
            None => return Ok(xdp_action::XDP_PASS), // 非 DNS 包，放行
        };

    // 检查是否应该放行
    let pass = should_pass(src_ip, &IP_BLACKLIST, &IP_WHITELIST, &FILTER_MODE);

    if !pass {
        // 被过滤，丢弃
        return Ok(xdp_action::XDP_DROP);
    }

    // 发送事件到用户态
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    send_dns_event(
        &DNS_EVENTS,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        dns_ptr,
        dns_len,
        data_end,
        ifindex,
    );

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
