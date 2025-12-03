//! DNS 事件处理器
//! 
//! 从 eBPF RingBuf 接收 DNS 事件并处理

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use anyhow::Result;
use log::{info, warn};
use tokio::sync::RwLock;

use crate::dns_parser;
use crate::ebpf_loader::EbpfManager;
use crate::metrics;
use rdns_common::DnsEvent;

/// 格式化 IP 地址（支持 IPv4 和 IPv6）
fn format_ip(event: &DnsEvent) -> (String, String) {
    if event.ip_version == 4 {
        let src = Ipv4Addr::new(
            event.src_ip[0], event.src_ip[1], event.src_ip[2], event.src_ip[3]
        ).to_string();
        let dst = Ipv4Addr::new(
            event.dst_ip[0], event.dst_ip[1], event.dst_ip[2], event.dst_ip[3]
        ).to_string();
        (src, dst)
    } else {
        let src = Ipv6Addr::from(event.src_ip).to_string();
        let dst = Ipv6Addr::from(event.dst_ip).to_string();
        (src, dst)
    }
}

/// 尝试从截断的 DNS payload 中提取部分域名
fn extract_partial_domain(payload: &[u8]) -> Option<String> {
    // DNS 查询格式：跳过 12 字节 header
    if payload.len() <= 12 {
        return None;
    }
    
    let qname_start = 12;
    let mut domain_parts = Vec::new();
    let mut pos = qname_start;
    
    // 解析域名标签
    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 {
            break; // 域名结束
        }
        if len > 63 || pos + 1 + len > payload.len() {
            // 标签不完整，提取已有部分
            break;
        }
        
        if let Ok(label) = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]) {
            domain_parts.push(label.to_string());
        }
        pos += 1 + len;
    }
    
    if domain_parts.is_empty() {
        None
    } else {
        let domain = domain_parts.join(".");
        // 如果域名被截断，添加省略号
        if pos < payload.len() && payload[pos] != 0 {
            Some(format!("{}...", domain))
        } else {
            Some(domain)
        }
    }
}

/// 处理单个 DNS 事件
fn process_event(event: &DnsEvent) {
    let (src_ip, dst_ip) = format_ip(event);
    let src_port = event.src_port;
    let dst_port = event.dst_port;

    // 更新 metrics
    metrics::DNS_PACKETS_TOTAL.inc();
    metrics::DNS_PACKETS_BY_SRC
        .with_label_values(&[&src_ip])
        .inc();

    let ip_ver = if event.ip_version == 4 { "IPv4" } else { "IPv6" };
    let payload_len = event.payload_len as usize;
    let actual_len = payload_len.min(event.payload.len());
    
    if actual_len > 0 {
        match dns_parser::parse_dns_packet(&event.payload[..actual_len]) {
            Ok(dns_info) => {
                let qtype = if dns_info.is_query { "Q" } else { "R" };
                let truncated = if payload_len > actual_len { " (truncated)" } else { "" };
                info!(
                    "DNS [{}] {} {}: {}{} | {}:{} -> {}:{}",
                    ip_ver, qtype, dns_info.query_type, dns_info.domain, truncated,
                    src_ip, src_port, dst_ip, dst_port
                );
            }
            Err(_) => {
                // 解析失败，尝试提取部分域名
                if let Some(partial) = extract_partial_domain(&event.payload[..actual_len]) {
                    info!(
                        "DNS [{}]: {} (partial) | {}:{} -> {}:{}",
                        ip_ver, partial, src_ip, src_port, dst_ip, dst_port
                    );
                } else {
                    info!(
                        "DNS [{}]: {}:{} -> {}:{} (payload {} bytes, captured {}, parse failed)",
                        ip_ver, src_ip, src_port, dst_ip, dst_port, payload_len, actual_len
                    );
                }
            }
        }
    } else {
        info!(
            "DNS [{}]: {}:{} -> {}:{} (no payload)",
            ip_ver, src_ip, src_port, dst_ip, dst_port
        );
    }
}

/// 运行事件处理循环
/// 
/// 从 EbpfManager 的 RingBuf 读取 DNS 事件并处理
pub async fn run_event_loop(ebpf: Arc<RwLock<EbpfManager>>) -> Result<()> {
    info!("Starting DNS event processor...");
    
    loop {
        // 短暂持有锁来处理事件
        {
            let mut ebpf = ebpf.write().await;
            
            // 处理 XDP RingBuf（如果存在）
            if let Some(mut ring_buf) = ebpf.get_xdp_ring_buf() {
                while let Some(item) = ring_buf.next() {
                    let data: &[u8] = item.as_ref();
                    if data.len() >= std::mem::size_of::<DnsEvent>() {
                        let event: &DnsEvent = unsafe { &*(data.as_ptr() as *const DnsEvent) };
                        process_event(event);
                    } else {
                        warn!("Received malformed DNS event from XDP");
                    }
                }
            }
            
            // 处理 TC RingBuf（如果存在）
            if let Some(mut ring_buf) = ebpf.get_tc_ring_buf() {
                while let Some(item) = ring_buf.next() {
                    let data: &[u8] = item.as_ref();
                    if data.len() >= std::mem::size_of::<DnsEvent>() {
                        let event: &DnsEvent = unsafe { &*(data.as_ptr() as *const DnsEvent) };
                        process_event(event);
                    } else {
                        warn!("Received malformed DNS event from TC");
                    }
                }
            }
        }
        
        // 释放锁后休眠，避免忙等待
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}
