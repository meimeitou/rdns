## Plan: Rust + eBPF DNS 包捕获工具实现

使用 aya 库构建一个 eBPF 驱动的 DNS UDP 包捕获工具，包含用户态守护进程、黑白名单过滤和 HTTP 配置接口。项目采用 Cargo workspace 结构，分离 eBPF 内核程序和用户态管理服务。

---

## 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Space                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   HTTP API  │  │  Prometheus │  │     DNS Event Handler   │  │
│  │   (axum)    │  │   Metrics   │  │  (域名过滤/日志/转发)    │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    rdns Daemon (Rust)                       ││
│  │  - 加载/管理 eBPF 程序                                       ││
│  │  - 读取 TOML 配置文件                                        ││
│  │  - 同步 IP 黑白名单到 eBPF HashMap                           ││
│  │  - 从 RingBuf 接收 DNS 事件                                  ││
│  └──────────────────────────┬──────────────────────────────────┘│
│                             │ aya                               │
├─────────────────────────────┼───────────────────────────────────┤
│                             │ BPF syscall                       │
│                         Kernel Space                            │
│  ┌──────────────────────────┴──────────────────────────────────┐│
│  │              rdns-ebpf (XDP / TC 可选)                      ││
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ ││
│  │  │ IP 黑名单  │  │ IP 白名单  │  │      RingBuf           │ ││
│  │  │ HashMap    │  │ HashMap    │  │  (DNS Event → User)    │ ││
│  │  └────────────┘  └────────────┘  └────────────────────────┘ ││
│  │                                                             ││
│  │  eBPF 程序流程 (XDP/TC 共用逻辑):                            ││
│  │  1. 解析 Eth → IPv4 → UDP 头                                 ││
│  │  2. 检查 dst_port == 53 (DNS)                               ││
│  │  3. 查询 IP 黑白名单 HashMap                                 ││
│  │  4. 通过则发送事件到 RingBuf                                 ││
│  └─────────────────────────────────────────────────────────────┘│
│                             │                                   │
│                             ▼                                   │
│           Network Interfaces (eth0, eth1, ...)                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 项目结构

```
rdns/
├── Cargo.toml                         # Workspace 定义
├── config.toml                        # 默认配置文件
├── plan.md                            # 本文档
│
├── rdns/                              # 用户态守护进程
│   ├── Cargo.toml
│   ├── build.rs                       # 调用 aya-build 编译 eBPF
│   └── src/
│       ├── main.rs                    # 入口：CLI 解析、daemon 启动
│       ├── config.rs                  # TOML 配置加载与热更新
│       ├── ebpf_loader.rs             # eBPF 程序加载与 map 管理
│       ├── event_handler.rs           # RingBuf 事件消费与处理
│       ├── dns_parser.rs              # DNS 包解析（用户态）
│       ├── filter.rs                  # 高级过滤逻辑（域名匹配等）
│       ├── metrics.rs                 # Prometheus metrics 定义与导出
│       └── api/
│           ├── mod.rs
│           ├── routes.rs              # 路由定义
│           └── handlers.rs            # 请求处理器
│
├── rdns-ebpf/                         # eBPF 内核程序
│   ├── Cargo.toml
│   ├── build.rs
│   └── src/
│       ├── main.rs                    # XDP 程序入口
│       ├── tc.rs                      # TC 程序入口
│       └── common.rs                  # 共享包解析 + IP 过滤逻辑
│
└── rdns-common/                       # 共享类型
    ├── Cargo.toml
    └── src/
        └── lib.rs                     # DnsEvent、FilterAction 等
```

---

## Steps

### Step 1: 重构为 aya workspace 结构

将现有单文件项目重构为三个 crate：

| Crate | 用途 |
|-------|------|
| `rdns/` | 用户态守护进程（daemon） |
| `rdns-ebpf/` | eBPF 内核程序（XDP） |
| `rdns-common/` | 共享类型定义 |

**根 `Cargo.toml`**:
```toml
[workspace]
members = ["rdns", "rdns-common", "rdns-ebpf"]
resolver = "2"

[workspace.package]
edition = "2021"
version = "0.1.0"
```

---

### Step 2: 实现 eBPF 程序（XDP 或 TC 二选一）

**职责**：仅实现 IP 黑白名单过滤，其它高级过滤交给用户态。

#### 挂载点选择（二选一）

| 挂载点 | 位置 | 优势 | 劣势 | 适用场景 |
|--------|------|------|------|----------|
| **XDP** | 网卡驱动层 | 最高性能，可硬件卸载 | 仅支持 ingress | 高吞吐入站过滤（推荐） |
| **TC** | Traffic Control 层 | 支持 ingress + egress | 性能略低于 XDP | 需要出站过滤场景 |

> ⚠️ **注意**：XDP 和 TC 为互斥配置，同一实例只能选择一种挂载点类型。

#### 共享逻辑 `rdns-ebpf/src/common.rs`
```rust
#![no_std]

use aya_ebpf::maps::{HashMap, RingBuf};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
use rdns_common::DnsEvent;

pub const DNS_PORT: u16 = 53;

/// 通用包处理逻辑，XDP 和 TC 共用
/// 返回: (should_pass, Option<DnsEvent>)
pub fn process_packet(
    data: *const u8,
    data_end: *const u8,
    blacklist: &HashMap<u32, u8>,
    whitelist: &HashMap<u32, u8>,
) -> Result<(bool, Option<DnsEvent>), ()> {
    // 1. 解析以太网头
    // 2. 检查 IPv4 + UDP + 端口 53
    // 3. 查询黑白名单
    // 4. 构造 DnsEvent
    Ok((true, None))
}
```

#### XDP 程序 `rdns-ebpf/src/main.rs`
```rust
#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::{HashMap, RingBuf}, programs::XdpContext};

mod common;

#[map]
static IP_BLACKLIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[map]
static IP_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn rdns_xdp(ctx: XdpContext) -> u32 {
    match try_rdns_xdp(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_rdns_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let (pass, event) = common::process_packet(
        ctx.data() as *const u8,
        ctx.data_end() as *const u8,
        unsafe { &IP_BLACKLIST },
        unsafe { &IP_WHITELIST },
    )?;
    
    if let Some(evt) = event {
        // 发送到 RingBuf
    }
    
    Ok(if pass { xdp_action::XDP_PASS } else { xdp_action::XDP_DROP })
}
```

#### TC 程序 `rdns-ebpf/src/tc.rs`
```rust
#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_OK, bindings::TC_ACT_SHOT, macros::{classifier, map}, maps::{HashMap, RingBuf}, programs::TcContext};

mod common;

// 复用相同的 maps（通过 pinning 共享）
#[map]
static IP_BLACKLIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[map]
static IP_WHITELIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[classifier]
pub fn rdns_tc(ctx: TcContext) -> i32 {
    match try_rdns_tc(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK,
    }
}

fn try_rdns_tc(ctx: &TcContext) -> Result<i32, ()> {
    let (pass, event) = common::process_packet(
        ctx.data() as *const u8,
        ctx.data_end() as *const u8,
        unsafe { &IP_BLACKLIST },
        unsafe { &IP_WHITELIST },
    )?;
    
    if let Some(evt) = event {
        // 发送到 RingBuf
    }
    
    Ok(if pass { TC_ACT_OK } else { TC_ACT_SHOT })
}
```

**eBPF Maps**:
| Map | 类型 | 用途 |
|-----|------|------|
| `IP_BLACKLIST` | `HashMap<u32, u8>` | IPv4 黑名单（key=IP，value=1） |
| `IP_WHITELIST` | `HashMap<u32, u8>` | IPv4 白名单 |
| `DNS_EVENTS` | `RingBuf` | DNS 事件传输到用户态 |

---

### Step 3: 定义共享数据结构

**`rdns-common/src/lib.rs`**:
```rust
#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: u16,
    pub payload: [u8; 512],  // DNS payload（最大 512 字节 UDP）
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsEvent {}
```

---

### Step 4: 实现用户态 eBPF 加载器（多网卡 + XDP/TC 二选一）

**`rdns/src/ebpf_loader.rs`**:

```rust
use aya::{Ebpf, programs::{Xdp, XdpFlags as AyaXdpFlags, tc, SchedClassifier, TcAttachType}};
use crate::config::{EbpfHook, XdpConfig, XdpFlags, TcConfig, TcDirection};
use anyhow::Result;

pub struct EbpfLoader {
    ebpf: Ebpf,
    hook: EbpfHook,
    attached_interfaces: Vec<String>,
}

impl EbpfLoader {
    /// 根据配置加载对应的 eBPF 程序（XDP 或 TC 二选一）
    pub fn load(hook: &EbpfHook) -> Result<Self> {
        let ebpf = match hook {
            EbpfHook::Xdp(_) => Ebpf::load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/release/rdns-xdp"
            ))?,
            EbpfHook::Tc(_) => Ebpf::load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/release/rdns-tc"
            ))?,
        };
        Ok(Self { 
            ebpf, 
            hook: hook.clone(), 
            attached_interfaces: Vec::new() 
        })
    }
    
    /// 附加到多个网卡
    pub fn attach_interfaces(&mut self, interfaces: &[String]) -> Result<()> {
        for iface in interfaces {
            self.attach_single(iface)?;
            self.attached_interfaces.push(iface.clone());
        }
        Ok(())
    }
    
    /// 附加到单个网卡
    fn attach_single(&mut self, iface: &str) -> Result<()> {
        match &self.hook {
            EbpfHook::Xdp(xdp_cfg) => {
                let program: &mut Xdp = self.ebpf.program_mut("rdns_xdp")?.try_into()?;
                program.load()?;
                
                let flags = match xdp_cfg.flags {
                    XdpFlags::Default => AyaXdpFlags::default(),
                    XdpFlags::Skb => AyaXdpFlags::SKB_MODE,
                    XdpFlags::Driver => AyaXdpFlags::DRV_MODE,
                    XdpFlags::Hw => AyaXdpFlags::HW_MODE,
                };
                program.attach(iface, flags)?;
                log::info!("XDP ({:?}) attached to {}", xdp_cfg.flags, iface);
            }
            EbpfHook::Tc(tc_cfg) => {
                // 添加 clsact qdisc
                let _ = tc::qdisc_add_clsact(iface);
                
                let program: &mut SchedClassifier = self.ebpf.program_mut("rdns_tc")?.try_into()?;
                program.load()?;
                
                match tc_cfg.direction {
                    TcDirection::Ingress => {
                        program.attach(iface, TcAttachType::Ingress)?;
                        log::info!("TC ingress attached to {}", iface);
                    }
                    TcDirection::Egress => {
                        program.attach(iface, TcAttachType::Egress)?;
                        log::info!("TC egress attached to {}", iface);
                    }
                    TcDirection::Both => {
                        program.attach(iface, TcAttachType::Ingress)?;
                        program.attach(iface, TcAttachType::Egress)?;
                        log::info!("TC ingress+egress attached to {}", iface);
                    }
                }
            }
        }
        Ok(())
    }
    
    /// 获取当前挂载点类型
    pub fn hook_type(&self) -> &str {
        match &self.hook {
            EbpfHook::Xdp(_) => "xdp",
            EbpfHook::Tc(_) => "tc",
        }
    }
    
    /// 获取当前附加的网卡列表
    pub fn list_interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }
}
```

**主要功能**:
- XDP 或 TC 二选一，根据配置自动加载对应 eBPF 程序
- 支持同时附加到多个网卡
- XDP 模式支持 flags 配置（default/skb/driver/hw）
- TC 模式支持 ingress/egress/both 方向选择
- 获取 `HashMap` 引用，提供更新黑白名单的方法
- 启动 `RingBuf` 异步读取循环

---

### Step 5: 实现 TOML 配置管理

**`config.toml` 示例**:
```toml
[server]
http_addr = "0.0.0.0:8080"
metrics_addr = "0.0.0.0:9090"

# eBPF 挂载点配置（XDP 或 TC 二选一）
# 支持多个网卡
interfaces = ["eth0", "eth1"]

# 方式一：使用 XDP（推荐，高性能入站过滤）
[ebpf.xdp]
# XDP flags: "default", "skb", "driver", "hw"
flags = "default"

# 方式二：使用 TC（支持出站过滤）
# [ebpf.tc]
# direction = "ingress"  # "ingress", "egress", 或 "both"

[filter]
# 过滤模式: "blacklist" 或 "whitelist"
mode = "blacklist"

[filter.ip]
blacklist = ["192.168.1.100", "10.0.0.0/8"]
whitelist = []

[filter.domain]
# 域名过滤在用户态实现
blacklist = ["*.malware.com", "ads.example.com"]
whitelist = []

[logging]
level = "info"
```

**`rdns/src/config.rs`**:
```rust
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    /// 网卡列表（支持多个）
    pub interfaces: Vec<String>,
    pub ebpf: EbpfHook,
    pub filter: FilterConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub http_addr: String,
    pub metrics_addr: String,
}

/// eBPF 挂载点配置（XDP 或 TC 二选一）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EbpfHook {
    /// XDP 模式（高性能入站过滤）
    Xdp(XdpConfig),
    /// TC 模式（支持出站过滤）
    Tc(TcConfig),
}

#[derive(Debug, Deserialize)]
pub struct XdpConfig {
    /// XDP flags: "default", "skb", "driver", "hw"
    #[serde(default = "default_xdp_flags")]
    pub flags: XdpFlags,
}

fn default_xdp_flags() -> XdpFlags {
    XdpFlags::Default
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpFlags {
    Default,
    Skb,      // Generic XDP (fallback)
    Driver,   // Native XDP
    Hw,       // Hardware offload
}

#[derive(Debug, Deserialize)]
pub struct TcConfig {
    /// ingress, egress, 或 both
    pub direction: TcDirection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TcDirection {
    Ingress,
    Egress,
    Both,
}

#[derive(Debug, Deserialize)]
pub struct FilterConfig {
    pub mode: FilterMode,
    pub ip: IpFilterConfig,
    pub domain: DomainFilterConfig,
}

#[derive(Debug, Deserialize)]
pub struct IpFilterConfig {
    pub blacklist: Vec<String>,
    pub whitelist: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DomainFilterConfig {
    pub blacklist: Vec<String>,
    pub whitelist: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    Blacklist,
    Whitelist,
}
```

---

### Step 6: 实现 Prometheus Metrics

**`rdns/src/metrics.rs`**:
```rust
use prometheus::{IntCounter, IntCounterVec, IntGauge, Registry, Opts};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    
    // DNS 包统计
    pub static ref DNS_PACKETS_TOTAL: IntCounter = IntCounter::new(
        "rdns_dns_packets_total", 
        "Total DNS packets captured"
    ).unwrap();
    
    // 按源 IP 统计
    pub static ref DNS_PACKETS_BY_SRC: IntCounterVec = IntCounterVec::new(
        Opts::new("rdns_dns_packets_by_src", "DNS packets by source IP"),
        &["src_ip"]
    ).unwrap();
    
    // 按域名统计
    pub static ref DNS_QUERIES_BY_DOMAIN: IntCounterVec = IntCounterVec::new(
        Opts::new("rdns_dns_queries_by_domain", "DNS queries by domain"),
        &["domain"]
    ).unwrap();
    
    // 被过滤的包
    pub static ref DNS_FILTERED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("rdns_dns_filtered_total", "DNS packets filtered"),
        &["reason"]  // "ip_blacklist", "ip_whitelist", "domain_blacklist"
    ).unwrap();
    
    // 当前黑白名单大小
    pub static ref IP_BLACKLIST_SIZE: IntGauge = IntGauge::new(
        "rdns_ip_blacklist_size",
        "Current IP blacklist size"
    ).unwrap();
    
    pub static ref IP_WHITELIST_SIZE: IntGauge = IntGauge::new(
        "rdns_ip_whitelist_size", 
        "Current IP whitelist size"
    ).unwrap();
}

pub fn register_metrics() {
    REGISTRY.register(Box::new(DNS_PACKETS_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(DNS_PACKETS_BY_SRC.clone())).unwrap();
    REGISTRY.register(Box::new(DNS_QUERIES_BY_DOMAIN.clone())).unwrap();
    REGISTRY.register(Box::new(DNS_FILTERED_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(IP_BLACKLIST_SIZE.clone())).unwrap();
    REGISTRY.register(Box::new(IP_WHITELIST_SIZE.clone())).unwrap();
}
```

**Metrics 端点** (`GET /metrics`):
```
# HELP rdns_dns_packets_total Total DNS packets captured
# TYPE rdns_dns_packets_total counter
rdns_dns_packets_total 12345

# HELP rdns_dns_filtered_total DNS packets filtered
# TYPE rdns_dns_filtered_total counter
rdns_dns_filtered_total{reason="ip_blacklist"} 100
rdns_dns_filtered_total{reason="domain_blacklist"} 50
```

---

### Step 7: 构建 HTTP API

**`rdns/src/api/routes.rs`**:

| Method | Path | 功能 |
|--------|------|------|
| `GET` | `/health` | 健康检查 |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/config` | 获取当前配置 |
| `POST` | `/config/reload` | 重新加载 TOML 配置 |
| `GET` | `/ebpf/status` | 获取 eBPF 程序状态（挂载点、网卡列表） |
| `GET` | `/ebpf/interfaces` | 获取当前附加的网卡列表 |
| `POST` | `/ebpf/interfaces` | 动态添加网卡 |
| `DELETE` | `/ebpf/interfaces/{iface}` | 动态移除网卡 |
| `GET` | `/filter/ip/blacklist` | 获取 IP 黑名单 |
| `POST` | `/filter/ip/blacklist` | 添加 IP 到黑名单 |
| `DELETE` | `/filter/ip/blacklist/{ip}` | 从黑名单移除 IP |
| `GET` | `/filter/ip/whitelist` | 获取 IP 白名单 |
| `POST` | `/filter/ip/whitelist` | 添加 IP 到白名单 |
| `DELETE` | `/filter/ip/whitelist/{ip}` | 从白名单移除 IP |
| `GET` | `/filter/domain/blacklist` | 获取域名黑名单 |
| `POST` | `/filter/domain/blacklist` | 添加域名到黑名单 |
| `DELETE` | `/filter/domain/blacklist/{domain}` | 从域名黑名单移除 |

**请求/响应示例**:
```bash
# 添加 IP 到黑名单
curl -X POST http://localhost:8080/filter/ip/blacklist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'

# 响应
{"success": true, "message": "IP added to blacklist"}
```

---

### Step 8: 实现守护进程主循环

**`rdns/src/main.rs`**:
```rust
use clap::Parser;
use tokio::signal;

#[derive(Parser)]
#[command(name = "rdns", about = "eBPF-based DNS packet capture daemon")]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
    
    /// Network interfaces to attach (comma-separated, overrides config)
    #[arg(short, long, value_delimiter = ',')]
    interfaces: Option<Vec<String>>,
    
    /// Hook type: xdp or tc (overrides config)
    #[arg(long)]
    hook: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    // 1. 加载配置
    let config = config::load(&args.config)?;
    
    // 2. 初始化日志
    env_logger::init();
    
    // 3. 注册 metrics
    metrics::register_metrics();
    
    // 4. 加载 eBPF 程序
    let mut ebpf = ebpf_loader::load_and_attach(&config)?;
    
    // 5. 同步配置到 eBPF maps
    ebpf_loader::sync_ip_filters(&mut ebpf, &config.filter.ip)?;
    
    // 6. 启动并发任务
    tokio::select! {
        // RingBuf 事件处理
        _ = event_handler::run(&mut ebpf, &config) => {},
        // HTTP API 服务
        _ = api::serve(&config) => {},
        // 优雅关闭
        _ = signal::ctrl_c() => {
            log::info!("Shutting down...");
        }
    }
    
    Ok(())
}
```

---

## 依赖清单

### `rdns/Cargo.toml`
```toml
[package]
name = "rdns"
version.workspace = true
edition.workspace = true

[dependencies]
aya = "0.13"
aya-log = "0.2"
rdns-common = { path = "../rdns-common", features = ["user"] }

# Async runtime
tokio = { version = "1", features = ["full"] }

# HTTP framework
axum = "0.7"
tower-http = { version = "0.5", features = ["cors"] }

# Configuration
toml = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# CLI
clap = { version = "4", features = ["derive"] }

# Logging
log = "0.4"
env_logger = "0.11"

# Metrics
prometheus = "0.13"
lazy_static = "1.4"

# Error handling
anyhow = "1"
thiserror = "1"

# DNS parsing
dns-parser = "0.8"

[build-dependencies]
aya-build = "0.1"
```

### `rdns-ebpf/Cargo.toml`
```toml
[package]
name = "rdns-ebpf"
version.workspace = true
edition.workspace = true

[dependencies]
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"
rdns-common = { path = "../rdns-common" }
network-types = "0.0.2"

[build-dependencies]
which = { version = "7", default-features = false }
```

### `rdns-common/Cargo.toml`
```toml
[package]
name = "rdns-common"
version.workspace = true
edition.workspace = true

[features]
default = []
user = ["aya"]

[dependencies]
aya = { version = "0.13", optional = true }
```

---

## 过滤逻辑分层

| 层级 | 位置 | 过滤类型 | 说明 |
|------|------|----------|------|
| **L1** | eBPF (内核态) | IP 黑白名单 | 高性能，ns 级延迟 |
| **L2** | Rust (用户态) | 域名黑白名单 | 需解析 DNS payload |
| **L3** | Rust (用户态) | 正则/通配符匹配 | `*.ads.com` 等高级规则 |

**流程**:
```
DNS 包 → [eBPF IP 过滤] → RingBuf → [Rust 域名过滤] → 日志/Metrics/转发
              ↓ DROP                       ↓ 丢弃
```

---

## 运行要求

- **内核版本**: ≥ 5.8（RingBuf 支持）
- **权限**: root 或 `CAP_BPF` + `CAP_NET_ADMIN`
- **工具链**: 
  - `rustup target add bpfel-unknown-none`
  - `cargo install bpf-linker`

---

## 使用示例

```bash
# 使用配置文件启动（推荐）
sudo ./rdns -c config.toml

# 命令行指定多网卡 + XDP 模式
sudo ./rdns --interfaces eth0,eth1,docker0 --hook xdp

# 命令行指定 TC 模式（抓取出站流量）
sudo ./rdns --interfaces eth0 --hook tc

# 动态添加网卡（通过 API）
curl -X POST http://localhost:8080/ebpf/interfaces \
  -H "Content-Type: application/json" \
  -d '{"interface": "eth2"}'

# 查看当前状态
curl http://localhost:8080/ebpf/status
# 响应示例:
# {
#   "hook_type": "xdp",
#   "interfaces": ["eth0", "eth1"],
#   "uptime_seconds": 3600
# }
```
