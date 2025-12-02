//! DNS 事件处理器
//! 
//! 注意：当前版本只传递元数据，不传递 DNS payload
//! 后续版本可以使用 perf buffer 或其他方式传递完整数据

use std::net::Ipv4Addr;
use std::sync::Arc;
use aya::maps::{MapData, RingBuf};
use anyhow::Result;
use log::{info, warn};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::filter::DomainFilter;
use crate::metrics;
use rdns_common::DnsEvent;

/// 处理 RingBuf 中的 DNS 事件
pub async fn run_event_loop(
    ring_buf: &mut RingBuf<&mut MapData>,
    _config: Arc<RwLock<Config>>,
    _domain_filter: Arc<RwLock<DomainFilter>>,
) -> Result<()> {
    info!("Starting DNS event handler...");

    loop {
        // 检查是否有新事件
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = item.as_ref();
            
            if data.len() < std::mem::size_of::<DnsEvent>() {
                warn!("Received malformed DNS event");
                continue;
            }

            // 解析事件
            let event: &DnsEvent = unsafe { &*(data.as_ptr() as *const DnsEvent) };
            
            // 处理事件
            process_event(event);
        }

        // 短暂休眠避免忙等待
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

/// 处理单个 DNS 事件（只有元数据，无 payload）
fn process_event(event: &DnsEvent) {
    let src_ip = Ipv4Addr::from(event.src_ip);
    let dst_ip = Ipv4Addr::from(event.dst_ip);
    let src_port = event.src_port;
    let dst_port = event.dst_port;

    // 更新总包数 metrics
    metrics::DNS_PACKETS_TOTAL.inc();
    metrics::DNS_PACKETS_BY_SRC
        .with_label_values(&[&src_ip.to_string()])
        .inc();

    info!(
        "DNS packet: {}:{} -> {}:{}, len={}",
        src_ip, src_port,
        dst_ip, dst_port,
        event.payload_len
    );
}
