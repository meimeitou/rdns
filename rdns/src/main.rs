//! rdns - eBPF-based DNS packet capture daemon

mod api;
mod config;
mod dns_parser;
mod ebpf_loader;
mod event_handler;
mod filter;
mod metrics;

use std::sync::Arc;
use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use tokio::sync::RwLock;
use tokio::net::TcpListener;

use api::create_router;
use api::routes::AppState;
use config::Config;
use ebpf_loader::EbpfManager;
use filter::DomainFilter;

/// eBPF-based DNS packet capture daemon
#[derive(Parser, Debug)]
#[command(name = "rdns", version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Network interfaces to attach (comma-separated, overrides config)
    #[arg(short, long, value_delimiter = ',')]
    interfaces: Option<Vec<String>>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // 1. 加载配置
    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config))?;

    // 2. 初始化日志
    let log_level = args
        .log_level
        .as_deref()
        .unwrap_or(&config.logging.level);
    
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level)
    ).init();

    info!("rdns starting...");
    info!("Config loaded from {}", args.config);

    // 3. 注册 metrics
    metrics::register_metrics();

    // 4. 加载 eBPF 程序
    info!("Loading eBPF program...");
    let mut ebpf = EbpfManager::load(&config)
        .context("Failed to load eBPF program")?;

    // 5. 附加到网卡
    let interfaces = args.interfaces.as_ref().unwrap_or(&config.interfaces);
    info!("Attaching to interfaces: {:?}", interfaces);
    ebpf.attach(interfaces)
        .context("Failed to attach eBPF program")?;

    // 6. 同步过滤配置
    info!("Syncing filter configuration...");
    ebpf.sync_filters(&config)
        .context("Failed to sync filters")?;

    // 7. 初始化域名过滤器
    let mut domain_filter = DomainFilter::new();
    domain_filter.sync_from_config(&config.filter);

    // 8. 更新 metrics
    metrics::IP_BLACKLIST_SIZE.set(config.filter.ip.blacklist.len() as i64);
    metrics::IP_WHITELIST_SIZE.set(config.filter.ip.whitelist.len() as i64);
    metrics::DOMAIN_BLACKLIST_SIZE.set(config.filter.domain.blacklist.len() as i64);
    metrics::DOMAIN_WHITELIST_SIZE.set(config.filter.domain.whitelist.len() as i64);

    // 9. 创建共享状态
    let start_time = std::time::Instant::now();
    let config = Arc::new(RwLock::new(config));
    let ebpf = Arc::new(RwLock::new(ebpf));
    let domain_filter = Arc::new(RwLock::new(domain_filter));

    let state = Arc::new(AppState {
        config: config.clone(),
        ebpf: ebpf.clone(),
        domain_filter: domain_filter.clone(),
        start_time,
    });

    // 10. 创建 HTTP 路由
    let app = create_router(state);

    // 11. 启动 HTTP 服务器
    let http_addr = {
        let cfg = config.read().await;
        cfg.server.http_addr.clone()
    };
    
    info!("Starting HTTP server on {}", http_addr);
    let listener = TcpListener::bind(&http_addr).await
        .with_context(|| format!("Failed to bind to {}", http_addr))?;

    // 12. 启动并发任务
    info!("rdns is running. Press Ctrl+C to stop.");
    
    tokio::select! {
        // HTTP API 服务
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                log::error!("HTTP server error: {}", e);
            }
        }
        
        // 事件处理（使用 event_handler 模块）
        result = event_handler::run_event_loop(ebpf.clone()) => {
            if let Err(e) = result {
                log::error!("Event processor error: {}", e);
            }
        }
        
        // Uptime 更新
        _ = async {
            loop {
                metrics::update_uptime(start_time);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        } => {}
        
        // 优雅关闭
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
        }
    }

    info!("rdns stopped.");
    Ok(())
}
