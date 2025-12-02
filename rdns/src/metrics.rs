//! Prometheus metrics 模块

use prometheus::{
    IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    Encoder, TextEncoder,
};
use std::sync::OnceLock;

/// 全局 metrics registry
static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// 获取 registry
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| Registry::new())
}

// ============== DNS 包统计 ==============

lazy_static::lazy_static! {
    /// 总 DNS 包数
    pub static ref DNS_PACKETS_TOTAL: IntCounter = IntCounter::new(
        "rdns_dns_packets_total",
        "Total DNS packets captured"
    ).unwrap();

    /// 按源 IP 统计
    pub static ref DNS_PACKETS_BY_SRC: IntCounterVec = IntCounterVec::new(
        Opts::new("rdns_dns_packets_by_src", "DNS packets by source IP"),
        &["src_ip"]
    ).unwrap();

    /// 按域名统计
    pub static ref DNS_QUERIES_BY_DOMAIN: IntCounterVec = IntCounterVec::new(
        Opts::new("rdns_dns_queries_by_domain", "DNS queries by domain"),
        &["domain"]
    ).unwrap();

    /// 被过滤的包
    pub static ref DNS_FILTERED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("rdns_dns_filtered_total", "DNS packets filtered"),
        &["reason"]
    ).unwrap();

    /// IP 黑名单大小
    pub static ref IP_BLACKLIST_SIZE: IntGauge = IntGauge::new(
        "rdns_ip_blacklist_size",
        "Current IP blacklist size"
    ).unwrap();

    /// IP 白名单大小
    pub static ref IP_WHITELIST_SIZE: IntGauge = IntGauge::new(
        "rdns_ip_whitelist_size",
        "Current IP whitelist size"
    ).unwrap();

    /// 域名黑名单大小
    pub static ref DOMAIN_BLACKLIST_SIZE: IntGauge = IntGauge::new(
        "rdns_domain_blacklist_size",
        "Current domain blacklist size"
    ).unwrap();

    /// 域名白名单大小
    pub static ref DOMAIN_WHITELIST_SIZE: IntGauge = IntGauge::new(
        "rdns_domain_whitelist_size",
        "Current domain whitelist size"
    ).unwrap();

    /// 运行时间（秒）
    pub static ref UPTIME_SECONDS: IntGauge = IntGauge::new(
        "rdns_uptime_seconds",
        "Daemon uptime in seconds"
    ).unwrap();
}

/// 注册所有 metrics
pub fn register_metrics() {
    let r = registry();
    
    r.register(Box::new(DNS_PACKETS_TOTAL.clone())).ok();
    r.register(Box::new(DNS_PACKETS_BY_SRC.clone())).ok();
    r.register(Box::new(DNS_QUERIES_BY_DOMAIN.clone())).ok();
    r.register(Box::new(DNS_FILTERED_TOTAL.clone())).ok();
    r.register(Box::new(IP_BLACKLIST_SIZE.clone())).ok();
    r.register(Box::new(IP_WHITELIST_SIZE.clone())).ok();
    r.register(Box::new(DOMAIN_BLACKLIST_SIZE.clone())).ok();
    r.register(Box::new(DOMAIN_WHITELIST_SIZE.clone())).ok();
    r.register(Box::new(UPTIME_SECONDS.clone())).ok();
}

/// 导出 metrics 为 Prometheus 格式文本
pub fn export_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// 更新 uptime
pub fn update_uptime(start_time: std::time::Instant) {
    UPTIME_SECONDS.set(start_time.elapsed().as_secs() as i64);
}
