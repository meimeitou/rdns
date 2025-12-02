#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{HashMap, RingBuf},
    programs::TcContext,
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

#[classifier]
pub fn rdns_tc(ctx: TcContext) -> i32 {
    match try_rdns_tc(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_rdns_tc(ctx: &TcContext) -> Result<i32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // 解析 DNS 包
    let (src_ip, dst_ip, src_port, dst_port, dns_ptr, dns_len) =
        match parse_dns_packet(data, data_end) {
            Some(result) => result,
            None => return Ok(TC_ACT_OK), // 非 DNS 包，放行
        };

    // 检查是否应该放行
    let pass = should_pass(src_ip, &IP_BLACKLIST, &IP_WHITELIST, &FILTER_MODE);

    if !pass {
        // 被过滤，丢弃
        return Ok(TC_ACT_SHOT);
    }

    // 发送事件到用户态
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
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

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
