//! API 请求处理器

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;

use super::routes::AppState;
use crate::metrics;

// ============== 响应类型 ==============

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }
}

impl ApiResponse<()> {
    pub fn ok_message(msg: &str) -> Self {
        ApiResponse {
            success: true,
            data: None,
            message: Some(msg.to_string()),
        }
    }

    pub fn error(msg: &str) -> Self {
        ApiResponse {
            success: false,
            data: None,
            message: Some(msg.to_string()),
        }
    }
}

// ============== 请求类型 ==============

#[derive(Deserialize)]
pub struct IpRequest {
    pub ip: String,
}

#[derive(Deserialize)]
pub struct DomainRequest {
    pub domain: String,
}

// ============== 健康检查 ==============

pub async fn health() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::success("ok"))
}

// ============== Metrics ==============

pub async fn metrics() -> String {
    crate::metrics::export_metrics()
}

// ============== 配置 ==============

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<crate::config::Config>> {
    let config = state.config.read().await;
    Json(ApiResponse::success(config.clone()))
}

pub async fn reload_config(
    State(_state): State<Arc<AppState>>,
) -> Json<ApiResponse<()>> {
    // TODO: 实现配置热更新
    Json(ApiResponse::ok_message("Config reload not implemented yet"))
}

// ============== eBPF 状态 ==============

#[derive(Serialize)]
pub struct EbpfStatus {
    pub hook_type: String,
    pub interfaces: Vec<String>,
    pub uptime_seconds: u64,
    pub ip_blacklist_size: usize,
    pub ip_whitelist_size: usize,
}

pub async fn ebpf_status(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<EbpfStatus>> {
    let mut ebpf = state.ebpf.write().await;
    
    let status = EbpfStatus {
        hook_type: ebpf.hook_type().to_string(),
        interfaces: ebpf.interfaces().to_vec(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        ip_blacklist_size: ebpf.blacklist_size().unwrap_or(0),
        ip_whitelist_size: ebpf.whitelist_size().unwrap_or(0),
    };
    
    Json(ApiResponse::success(status))
}

pub async fn list_interfaces(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<Vec<String>>> {
    let ebpf = state.ebpf.read().await;
    Json(ApiResponse::success(ebpf.interfaces().to_vec()))
}

// ============== IP 黑名单 ==============

pub async fn get_ip_blacklist(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<Vec<String>>> {
    let config = state.config.read().await;
    Json(ApiResponse::success(config.filter.ip.blacklist.clone()))
}

pub async fn add_ip_blacklist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IpRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    // 解析 IP
    let ip: Ipv4Addr = req.ip.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ApiResponse::error("Invalid IP address")))
    })?;
    
    let ip_u32 = u32::from(ip);
    
    // 添加到 eBPF map
    let mut ebpf = state.ebpf.write().await;
    ebpf.add_to_blacklist(ip_u32).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;
    
    // 更新配置
    let mut config = state.config.write().await;
    if !config.filter.ip.blacklist.contains(&req.ip) {
        config.filter.ip.blacklist.push(req.ip.clone());
    }
    
    // 更新 metrics
    metrics::IP_BLACKLIST_SIZE.set(config.filter.ip.blacklist.len() as i64);
    
    Ok(Json(ApiResponse::ok_message(&format!("IP {} added to blacklist", req.ip))))
}

pub async fn remove_ip_blacklist(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let ip_addr: Ipv4Addr = ip.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ApiResponse::error("Invalid IP address")))
    })?;
    
    let ip_u32 = u32::from(ip_addr);
    
    let mut ebpf = state.ebpf.write().await;
    ebpf.remove_from_blacklist(ip_u32).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;
    
    let mut config = state.config.write().await;
    config.filter.ip.blacklist.retain(|x| x != &ip);
    
    metrics::IP_BLACKLIST_SIZE.set(config.filter.ip.blacklist.len() as i64);
    
    Ok(Json(ApiResponse::ok_message(&format!("IP {} removed from blacklist", ip))))
}

// ============== IP 白名单 ==============

pub async fn get_ip_whitelist(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<Vec<String>>> {
    let config = state.config.read().await;
    Json(ApiResponse::success(config.filter.ip.whitelist.clone()))
}

pub async fn add_ip_whitelist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IpRequest>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let ip: Ipv4Addr = req.ip.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ApiResponse::error("Invalid IP address")))
    })?;
    
    let ip_u32 = u32::from(ip);
    
    let mut ebpf = state.ebpf.write().await;
    ebpf.add_to_whitelist(ip_u32).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;
    
    let mut config = state.config.write().await;
    if !config.filter.ip.whitelist.contains(&req.ip) {
        config.filter.ip.whitelist.push(req.ip.clone());
    }
    
    metrics::IP_WHITELIST_SIZE.set(config.filter.ip.whitelist.len() as i64);
    
    Ok(Json(ApiResponse::ok_message(&format!("IP {} added to whitelist", req.ip))))
}

pub async fn remove_ip_whitelist(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<Json<ApiResponse<()>>, (StatusCode, Json<ApiResponse<()>>)> {
    let ip_addr: Ipv4Addr = ip.parse().map_err(|_| {
        (StatusCode::BAD_REQUEST, Json(ApiResponse::error("Invalid IP address")))
    })?;
    
    let ip_u32 = u32::from(ip_addr);
    
    let mut ebpf = state.ebpf.write().await;
    ebpf.remove_from_whitelist(ip_u32).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::error(&e.to_string())))
    })?;
    
    let mut config = state.config.write().await;
    config.filter.ip.whitelist.retain(|x| x != &ip);
    
    metrics::IP_WHITELIST_SIZE.set(config.filter.ip.whitelist.len() as i64);
    
    Ok(Json(ApiResponse::ok_message(&format!("IP {} removed from whitelist", ip))))
}

// ============== 域名黑名单 ==============

pub async fn get_domain_blacklist(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<Vec<String>>> {
    let config = state.config.read().await;
    Json(ApiResponse::success(config.filter.domain.blacklist.clone()))
}

pub async fn add_domain_blacklist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DomainRequest>,
) -> Json<ApiResponse<()>> {
    let mut filter = state.domain_filter.write().await;
    filter.add_to_blacklist(&req.domain);
    
    let mut config = state.config.write().await;
    if !config.filter.domain.blacklist.contains(&req.domain) {
        config.filter.domain.blacklist.push(req.domain.clone());
    }
    
    metrics::DOMAIN_BLACKLIST_SIZE.set(config.filter.domain.blacklist.len() as i64);
    
    Json(ApiResponse::ok_message(&format!("Domain {} added to blacklist", req.domain)))
}

pub async fn remove_domain_blacklist(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Json<ApiResponse<()>> {
    let mut config = state.config.write().await;
    config.filter.domain.blacklist.retain(|x| x != &domain);
    
    // 重新同步过滤器
    let mut filter = state.domain_filter.write().await;
    filter.sync_from_config(&config.filter);
    
    metrics::DOMAIN_BLACKLIST_SIZE.set(config.filter.domain.blacklist.len() as i64);
    
    Json(ApiResponse::ok_message(&format!("Domain {} removed from blacklist", domain)))
}

// ============== 域名白名单 ==============

pub async fn get_domain_whitelist(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<Vec<String>>> {
    let config = state.config.read().await;
    Json(ApiResponse::success(config.filter.domain.whitelist.clone()))
}

pub async fn add_domain_whitelist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DomainRequest>,
) -> Json<ApiResponse<()>> {
    let mut filter = state.domain_filter.write().await;
    filter.add_to_whitelist(&req.domain);
    
    let mut config = state.config.write().await;
    if !config.filter.domain.whitelist.contains(&req.domain) {
        config.filter.domain.whitelist.push(req.domain.clone());
    }
    
    metrics::DOMAIN_WHITELIST_SIZE.set(config.filter.domain.whitelist.len() as i64);
    
    Json(ApiResponse::ok_message(&format!("Domain {} added to whitelist", req.domain)))
}

pub async fn remove_domain_whitelist(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Json<ApiResponse<()>> {
    let mut config = state.config.write().await;
    config.filter.domain.whitelist.retain(|x| x != &domain);
    
    let mut filter = state.domain_filter.write().await;
    filter.sync_from_config(&config.filter);
    
    metrics::DOMAIN_WHITELIST_SIZE.set(config.filter.domain.whitelist.len() as i64);
    
    Json(ApiResponse::ok_message(&format!("Domain {} removed from whitelist", domain)))
}
