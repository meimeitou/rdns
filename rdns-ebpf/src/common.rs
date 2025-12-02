#![allow(unused_attributes)]

use aya_ebpf::maps::{HashMap, RingBuf};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use rdns_common::{DnsEvent, DNS_MAX_LEN};

pub const ETH_HDR_LEN: usize = core::mem::size_of::<EthHdr>();
pub const IPV4_HDR_LEN: usize = core::mem::size_of::<Ipv4Hdr>();
pub const UDP_HDR_LEN: usize = core::mem::size_of::<UdpHdr>();
pub const DNS_PORT: u16 = 53;

/// 检查指针边界
#[inline(always)]
pub fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Option<*const T> {
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

/// 解析 DNS 数据包
/// 返回: Option<(src_ip, dst_ip, src_port, dst_port, dns_payload_ptr, dns_payload_len)>
#[inline(always)]
pub fn parse_dns_packet(
    data: usize,
    data_end: usize,
) -> Option<(u32, u32, u16, u16, usize, u16)> {
    // 1. 解析以太网头
    let eth_hdr: *const EthHdr = ptr_at(data, data_end, 0)?;
    
    // 使用 read_unaligned 读取 packed struct 字段
    let ether_type = unsafe { core::ptr::addr_of!((*eth_hdr).ether_type).read_unaligned() };

    // 只处理 IPv4
    if ether_type != EtherType::Ipv4 {
        return None;
    }

    // 2. 解析 IPv4 头
    let ipv4_hdr: *const Ipv4Hdr = ptr_at(data, data_end, ETH_HDR_LEN)?;
    
    let proto = unsafe { core::ptr::addr_of!((*ipv4_hdr).proto).read_unaligned() };
    
    // 只处理 UDP
    if proto != IpProto::Udp {
        return None;
    }

    let src_ip = unsafe { u32::from_be(core::ptr::addr_of!((*ipv4_hdr).src_addr).read_unaligned()) };
    let dst_ip = unsafe { u32::from_be(core::ptr::addr_of!((*ipv4_hdr).dst_addr).read_unaligned()) };

    // 3. 解析 UDP 头
    let udp_hdr: *const UdpHdr = ptr_at(data, data_end, ETH_HDR_LEN + IPV4_HDR_LEN)?;
    
    let src_port = unsafe { u16::from_be(core::ptr::addr_of!((*udp_hdr).source).read_unaligned()) };
    let dst_port = unsafe { u16::from_be(core::ptr::addr_of!((*udp_hdr).dest).read_unaligned()) };

    // 只处理 DNS 端口 (53)
    if dst_port != DNS_PORT && src_port != DNS_PORT {
        return None;
    }

    // 4. 获取 DNS payload
    let dns_offset = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;
    
    // 直接计算可用的 DNS 数据长度（从 data_end 减去 dns 起始位置）
    // 这样验证器可以追踪边界
    let dns_start = data + dns_offset;
    if dns_start >= data_end {
        return None;
    }
    
    let available_len = data_end - dns_start;
    
    // 限制最大长度为 512 字节（DNS UDP 典型最大值）
    // 这给验证器一个明确的上界
    let dns_len = if available_len > 512 { 512 } else { available_len as u16 };
    
    // 再次验证边界（帮助验证器）
    if data + dns_offset + (dns_len as usize) > data_end {
        return None;
    }

    Some((
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        dns_start,
        dns_len,
    ))
}

/// 检查 IP 是否在黑名单中
#[inline(always)]
pub fn is_ip_blacklisted(ip: u32, blacklist: &HashMap<u32, u8>) -> bool {
    unsafe { blacklist.get(&ip).is_some() }
}

/// 检查 IP 是否在白名单中
#[inline(always)]
pub fn is_ip_whitelisted(ip: u32, whitelist: &HashMap<u32, u8>) -> bool {
    unsafe { whitelist.get(&ip).is_some() }
}

/// 检查是否应该放行
/// 过滤逻辑：白名单优先，然后检查黑名单
/// 1. 如果 IP 在白名单中 -> 放行
/// 2. 如果 IP 在黑名单中 -> 丢弃
/// 3. 否则 -> 放行
#[inline(always)]
pub fn should_pass(
    src_ip: u32,
    blacklist: &HashMap<u32, u8>,
    whitelist: &HashMap<u32, u8>,
    _filter_mode: &HashMap<u32, u8>,
) -> bool {
    // 白名单优先：在白名单中则直接放行
    if is_ip_whitelisted(src_ip, whitelist) {
        return true;
    }
    
    // 检查黑名单：在黑名单中则丢弃
    if is_ip_blacklisted(src_ip, blacklist) {
        return false;
    }
    
    // 默认放行
    true
}

/// 发送 DNS 事件到 RingBuf
/// 完全展开循环复制前 64 字节
#[inline(always)]
pub fn send_dns_event(
    events: &RingBuf,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    dns_ptr: usize,
    dns_len: u16,
    data_end: usize,
    ifindex: u32,
) {
    // 计算实际要复制的长度，最大 DNS_MAX_LEN (64)
    let copy_len = if (dns_len as usize) > DNS_MAX_LEN {
        DNS_MAX_LEN
    } else {
        dns_len as usize
    };
    
    // 边界检查
    if dns_ptr + copy_len > data_end {
        return;
    }

    if let Some(mut entry) = events.reserve::<DnsEvent>(0) {
        let event = entry.as_mut_ptr();
        unsafe {
            (*event).src_ip = src_ip;
            (*event).dst_ip = dst_ip;
            (*event).src_port = src_port;
            (*event).dst_port = dst_port;
            (*event).payload_len = copy_len as u16;
            (*event).ifindex = ifindex;
            
            let src = dns_ptr as *const u8;
            let dst = (*event).payload.as_mut_ptr();
            
            // 完全展开的复制 - 64 字节
            // 每个字节都有单独的边界检查
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
