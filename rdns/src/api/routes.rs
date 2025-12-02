//! API 路由定义

use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::ebpf_loader::EbpfManager;
use crate::filter::DomainFilter;
use super::handlers;

/// 应用状态
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub ebpf: Arc<RwLock<EbpfManager>>,
    pub domain_filter: Arc<RwLock<DomainFilter>>,
    pub start_time: std::time::Instant,
}

/// 创建 API 路由
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // 健康检查
        .route("/health", get(handlers::health))
        
        // Metrics
        .route("/metrics", get(handlers::metrics))
        
        // 配置
        .route("/config", get(handlers::get_config))
        .route("/config/reload", post(handlers::reload_config))
        
        // eBPF 状态
        .route("/ebpf/status", get(handlers::ebpf_status))
        .route("/ebpf/interfaces", get(handlers::list_interfaces))
        
        // IP 黑名单
        .route("/filter/ip/blacklist", get(handlers::get_ip_blacklist))
        .route("/filter/ip/blacklist", post(handlers::add_ip_blacklist))
        .route("/filter/ip/blacklist/:ip", delete(handlers::remove_ip_blacklist))
        
        // IP 白名单
        .route("/filter/ip/whitelist", get(handlers::get_ip_whitelist))
        .route("/filter/ip/whitelist", post(handlers::add_ip_whitelist))
        .route("/filter/ip/whitelist/:ip", delete(handlers::remove_ip_whitelist))
        
        // 域名黑名单
        .route("/filter/domain/blacklist", get(handlers::get_domain_blacklist))
        .route("/filter/domain/blacklist", post(handlers::add_domain_blacklist))
        .route("/filter/domain/blacklist/:domain", delete(handlers::remove_domain_blacklist))
        
        // 域名白名单
        .route("/filter/domain/whitelist", get(handlers::get_domain_whitelist))
        .route("/filter/domain/whitelist", post(handlers::add_domain_whitelist))
        .route("/filter/domain/whitelist/:domain", delete(handlers::remove_domain_whitelist))
        
        .with_state(state)
}
