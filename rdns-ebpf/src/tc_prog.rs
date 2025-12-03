//! TC 程序 - 独立部署
//! 
//! 功能：纯 DNS 流量抓取（双向：入口 + 出口）
//! 
//! 特点：
//! - 不做任何过滤，只负责抓取
//! - 支持 IPv4 和 IPv6
//! - 可与 XDP 配合使用（XDP 过滤，TC 抓取）
//! - 也可单独使用（仅抓取，不过滤）

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use rdns_common::{DnsEvent, DNS_MAX_LEN};

const ETH_HDR_LEN: usize = core::mem::size_of::<EthHdr>();
const IPV4_HDR_LEN: usize = core::mem::size_of::<Ipv4Hdr>();
const IPV6_HDR_LEN: usize = core::mem::size_of::<Ipv6Hdr>();
const UDP_HDR_LEN: usize = core::mem::size_of::<UdpHdr>();
const DNS_PORT: u16 = 53;

/// DNS 事件 RingBuf
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// 检查指针边界
#[inline(always)]
fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Option<*const T> {
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

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

    // 解析以太网头
    let eth_hdr: *const EthHdr = ptr_at(data, data_end, 0).ok_or(())?;
    let ether_type = unsafe { core::ptr::addr_of!((*eth_hdr).ether_type).read_unaligned() };

    let ifindex = unsafe { (*ctx.skb.skb).ifindex };

    match ether_type {
        EtherType::Ipv4 => process_ipv4(data, data_end, ifindex),
        EtherType::Ipv6 => process_ipv6(data, data_end, ifindex),
        _ => Ok(TC_ACT_OK),
    }
}

/// 处理 IPv4 DNS 包
#[inline(always)]
fn process_ipv4(data: usize, data_end: usize, ifindex: u32) -> Result<i32, ()> {
    let ipv4_hdr: *const Ipv4Hdr = ptr_at(data, data_end, ETH_HDR_LEN).ok_or(())?;
    
    let proto = unsafe { core::ptr::addr_of!((*ipv4_hdr).proto).read_unaligned() };
    if proto != IpProto::Udp {
        return Ok(TC_ACT_OK);
    }

    let src_addr = unsafe { core::ptr::addr_of!((*ipv4_hdr).src_addr).read_unaligned() };
    let dst_addr = unsafe { core::ptr::addr_of!((*ipv4_hdr).dst_addr).read_unaligned() };

    // 解析 UDP 头
    let udp_hdr: *const UdpHdr = ptr_at(data, data_end, ETH_HDR_LEN + IPV4_HDR_LEN).ok_or(())?;
    let src_port = unsafe { u16::from_be(core::ptr::addr_of!((*udp_hdr).source).read_unaligned()) };
    let dst_port = unsafe { u16::from_be(core::ptr::addr_of!((*udp_hdr).dest).read_unaligned()) };

    if dst_port != DNS_PORT && src_port != DNS_PORT {
        return Ok(TC_ACT_OK);
    }

    // DNS payload
    let dns_offset = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;
    let dns_ptr = data + dns_offset;
    if dns_ptr >= data_end {
        return Ok(TC_ACT_OK);
    }

    let available_len = data_end - dns_ptr;
    let dns_len = if available_len > 512 { 512 } else { available_len };

    // 构建 IP 数组
    let src_bytes = src_addr.to_be_bytes();
    let dst_bytes = dst_addr.to_be_bytes();
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    src_ip[0] = src_bytes[0]; src_ip[1] = src_bytes[1];
    src_ip[2] = src_bytes[2]; src_ip[3] = src_bytes[3];
    dst_ip[0] = dst_bytes[0]; dst_ip[1] = dst_bytes[1];
    dst_ip[2] = dst_bytes[2]; dst_ip[3] = dst_bytes[3];

    // 发送事件
    send_event(4, src_ip, dst_ip, src_port, dst_port, dns_ptr, dns_len, data_end, ifindex);

    Ok(TC_ACT_OK)
}

/// 处理 IPv6 DNS 包
#[inline(always)]
fn process_ipv6(data: usize, data_end: usize, ifindex: u32) -> Result<i32, ()> {
    let ipv6_hdr: *const Ipv6Hdr = ptr_at(data, data_end, ETH_HDR_LEN).ok_or(())?;
    
    let next_hdr = unsafe { core::ptr::addr_of!((*ipv6_hdr).next_hdr).read_unaligned() };
    if next_hdr != IpProto::Udp {
        return Ok(TC_ACT_OK);
    }

    let src_addr = unsafe { core::ptr::addr_of!((*ipv6_hdr).src_addr).read_unaligned() };
    let dst_addr = unsafe { core::ptr::addr_of!((*ipv6_hdr).dst_addr).read_unaligned() };
    let src_ip: [u8; 16] = unsafe { src_addr.in6_u.u6_addr8 };
    let dst_ip: [u8; 16] = unsafe { dst_addr.in6_u.u6_addr8 };

    // 解析 UDP 头
    let udp_hdr: *const UdpHdr = ptr_at(data, data_end, ETH_HDR_LEN + IPV6_HDR_LEN).ok_or(())?;
    let src_port = unsafe { u16::from_be(core::ptr::addr_of!((*udp_hdr).source).read_unaligned()) };
    let dst_port = unsafe { u16::from_be(core::ptr::addr_of!((*udp_hdr).dest).read_unaligned()) };

    if dst_port != DNS_PORT && src_port != DNS_PORT {
        return Ok(TC_ACT_OK);
    }

    // DNS payload
    let dns_offset = ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN;
    let dns_ptr = data + dns_offset;
    if dns_ptr >= data_end {
        return Ok(TC_ACT_OK);
    }

    let available_len = data_end - dns_ptr;
    let dns_len = if available_len > 512 { 512 } else { available_len };

    // 发送事件
    send_event(6, src_ip, dst_ip, src_port, dst_port, dns_ptr, dns_len, data_end, ifindex);

    Ok(TC_ACT_OK)
}

/// 发送 DNS 事件到 RingBuf
#[inline(always)]
fn send_event(
    ip_version: u8,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    dns_ptr: usize,
    dns_len: usize,
    data_end: usize,
    ifindex: u32,
) {
    let copy_len = if dns_len > DNS_MAX_LEN { DNS_MAX_LEN } else { dns_len };

    if dns_ptr + copy_len > data_end {
        return;
    }

    if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).ip_version = ip_version;
            (*event)._reserved = [0, 0, 0];
            (*event).src_ip = src_ip;
            (*event).dst_ip = dst_ip;
            (*event).src_port = src_port;
            (*event).dst_port = dst_port;
            (*event).payload_len = copy_len as u16;
            (*event).ifindex = ifindex;

            let src = dns_ptr as *const u8;
            let dst = (*event).payload.as_mut_ptr();

            // 展开复制宏
            macro_rules! copy_byte {
                ($i:expr) => {
                    if $i < copy_len && dns_ptr + $i < data_end {
                        *dst.add($i) = *src.add($i);
                    }
                };
            }

            // 展开 64 字节
            copy_byte!(0);  copy_byte!(1);  copy_byte!(2);  copy_byte!(3);
            copy_byte!(4);  copy_byte!(5);  copy_byte!(6);  copy_byte!(7);
            copy_byte!(8);  copy_byte!(9);  copy_byte!(10); copy_byte!(11);
            copy_byte!(12); copy_byte!(13); copy_byte!(14); copy_byte!(15);
            copy_byte!(16); copy_byte!(17); copy_byte!(18); copy_byte!(19);
            copy_byte!(20); copy_byte!(21); copy_byte!(22); copy_byte!(23);
            copy_byte!(24); copy_byte!(25); copy_byte!(26); copy_byte!(27);
            copy_byte!(28); copy_byte!(29); copy_byte!(30); copy_byte!(31);
            copy_byte!(32); copy_byte!(33); copy_byte!(34); copy_byte!(35);
            copy_byte!(36); copy_byte!(37); copy_byte!(38); copy_byte!(39);
            copy_byte!(40); copy_byte!(41); copy_byte!(42); copy_byte!(43);
            copy_byte!(44); copy_byte!(45); copy_byte!(46); copy_byte!(47);
            copy_byte!(48); copy_byte!(49); copy_byte!(50); copy_byte!(51);
            copy_byte!(52); copy_byte!(53); copy_byte!(54); copy_byte!(55);
            copy_byte!(56); copy_byte!(57); copy_byte!(58); copy_byte!(59);
            copy_byte!(60); copy_byte!(61); copy_byte!(62); copy_byte!(63);
        }
        entry.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
