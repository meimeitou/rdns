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

**eBPF Maps**:
| Map | 类型 | 用途 |
|-----|------|------|
| `IP_BLACKLIST` | `HashMap<u32, u8>` | IPv4 黑名单（key=IP，value=1） |
| `IP_WHITELIST` | `HashMap<u32, u8>` | IPv4 白名单 |
| `DNS_EVENTS` | `RingBuf` | DNS 事件传输到用户态 |

---

### Step 3: 定义共享数据结构


---

### Step 4: 实现用户态 eBPF 加载器（多网卡 + XDP/TC 二选一）

**主要功能**:
- XDP 或 TC 二选一，根据配置自动加载对应 eBPF 程序
- 支持同时附加到多个网卡
- XDP 模式支持 flags 配置（default/skb/driver/hw）
- TC 模式支持 ingress/egress/both 方向选择
- 获取 `HashMap` 引用，提供更新黑白名单的方法
- 启动 `RingBuf` 异步读取循环

---

### Step 5: 实现 TOML 配置管理


---

### Step 6: 实现 Prometheus Metrics


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

---

## 依赖清单

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
