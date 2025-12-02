# rdns - eBPF DNS 包捕获工具

基于 Rust + eBPF 的 DNS 数据包捕获和过滤工具，使用 [aya](https://github.com/aya-rs/aya) 库实现。

## 功能特性

- **eBPF 内核层过滤**: 支持 XDP 或 TC hook（二选一）
- **IP 黑白名单**: 在内核层高效过滤指定 IP
- **域名过滤**: 用户态域名黑白名单，支持精确匹配和通配符
- **多网卡支持**: 可同时监听多个网络接口
- **Prometheus 指标**: 内置 metrics 导出
- **HTTP API**: 运行时动态更新过滤配置
- **TOML 配置**: 简洁的配置文件格式

## 项目结构

```
rdns/
├── rdns-common/     # 共享数据结构
├── rdns-ebpf/       # eBPF 内核程序 (XDP/TC)
├── rdns/            # 用户态守护进程
└── config.toml      # 配置文件
```

## 编译

### 依赖

- Rust nightly (eBPF 编译需要)
- bpf-linker
- Linux 内核 >= 5.8 (RingBuf 支持)

### 安装工具链

```bash
# 安装 nightly
rustup install nightly
rustup component add rust-src --toolchain nightly

# 安装 bpf-linker
cargo install bpf-linker
```

### 编译 eBPF 程序

```bash
cargo +nightly build --package=rdns-ebpf \
    -Z build-std=core \
    --target=bpfel-unknown-none \
    --release
```

### 编译用户态程序

```bash
cargo build --package=rdns --release
```

## 运行

```bash
# 需要 root 权限加载 eBPF
sudo ./target/release/rdns -c config.toml

# 指定网卡（覆盖配置文件）
sudo ./target/release/rdns -c config.toml -i eth0,eth1

# 调试日志
sudo ./target/release/rdns -c config.toml --log-level debug
```

## HTTP API

| 端点 | 方法 | 描述 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/metrics` | GET | Prometheus 指标 |
| `/config` | GET | 当前配置 |
| `/filter/ip/blacklist` | POST | 添加 IP 到黑名单 |
| `/filter/ip/blacklist/{ip}` | DELETE | 从黑名单移除 IP |
| `/filter/ip/whitelist` | POST | 添加 IP 到白名单 |
| `/filter/ip/whitelist/{ip}` | DELETE | 从白名单移除 IP |
| `/filter/domain/blacklist` | POST | 添加域名到黑名单 |
| `/filter/domain/blacklist/{domain}` | DELETE | 从黑名单移除域名 |
| `/filter/domain/whitelist` | POST | 添加域名到白名单 |
| `/filter/domain/whitelist/{domain}` | DELETE | 从白名单移除域名 |

### 示例

```bash
# 健康检查
curl http://localhost:8080/health

# 获取 metrics
curl http://localhost:8080/metrics

# 添加 IP 到黑名单
curl -X POST http://localhost:8080/filter/ip/blacklist \
    -H "Content-Type: application/json" \
    -d '{"ip": "10.0.0.1"}'

# 移除黑名单 IP
curl -X DELETE http://localhost:8080/filter/ip/blacklist/10.0.0.1

# 添加域名到黑名单
curl -X POST http://localhost:8080/filter/domain/blacklist \
    -H "Content-Type: application/json" \
    -d '{"domain": "*.malware.com"}'
```

## Prometheus 指标

- `rdns_dns_packets_total` - DNS 包总数
- `rdns_dns_packets_by_src` - 按源 IP 统计
- `rdns_dns_queries_by_domain` - 按域名统计查询
- `rdns_dns_filtered_total` - 被过滤的包数量
- `rdns_ip_blacklist_size` - IP 黑名单大小
- `rdns_ip_whitelist_size` - IP 白名单大小
- `rdns_domain_blacklist_size` - 域名黑名单大小
- `rdns_domain_whitelist_size` - 域名白名单大小
- `rdns_uptime_seconds` - 运行时间

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                      用户态 (rdns)                       │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌───────────┐ │
│  │ HTTP API│  │DNS Parser│  │ Filter  │  │ Metrics   │ │
│  └────┬────┘  └────┬─────┘  └────┬────┘  └─────┬─────┘ │
│       │            │             │             │        │
│       └────────────┴──────┬──────┴─────────────┘        │
│                           │                             │
│                    ┌──────▼──────┐                      │
│                    │  RingBuf    │                      │
│                    └──────▲──────┘                      │
└───────────────────────────┼─────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────┐
│                      内核态 (eBPF)                       │
│                    ┌──────┴──────┐                      │
│                    │ XDP / TC    │                      │
│                    │ DNS 包解析  │                      │
│                    │ IP 过滤     │                      │
│                    └─────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

## License

MIT
