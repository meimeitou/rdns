//! 配置管理模块

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use anyhow::{Context, Result};

/// 主配置结构
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    /// 网卡列表（支持多个）
    pub interfaces: Vec<String>,
    pub ebpf: EbpfConfig,
    pub filter: FilterConfig,
    pub logging: LoggingConfig,
}

/// 服务器配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub http_addr: String,
    pub metrics_addr: String,
}

/// eBPF 配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EbpfConfig {
    /// 模式: "xdp" 或 "tc"
    #[serde(default)]
    pub mode: EbpfMode,
    /// XDP flags: "default", "skb", "driver", "hw"
    #[serde(default)]
    pub xdp_flags: XdpFlags,
    /// TC 方向: "ingress", "egress", "both"
    #[serde(default)]
    pub tc_direction: TcDirection,
    /// XDP eBPF 程序路径（可选，默认自动搜索）
    #[serde(default)]
    pub xdp_program_path: Option<String>,
    /// TC eBPF 程序路径（可选，默认自动搜索）
    #[serde(default)]
    pub tc_program_path: Option<String>,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            mode: EbpfMode::Xdp,
            xdp_flags: XdpFlags::Default,
            tc_direction: TcDirection::Ingress,
            xdp_program_path: None,
            tc_program_path: None,
        }
    }
}

/// eBPF 模式
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EbpfMode {
    #[default]
    Xdp,
    Tc,
}

/// XDP 挂载模式
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum XdpFlags {
    #[default]
    Default,
    Skb,      // Generic XDP (fallback)
    Driver,   // Native XDP
    Hw,       // Hardware offload
}

/// TC 方向
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TcDirection {
    #[default]
    Ingress,
    Egress,
    Both,
}

/// 过滤配置
/// 过滤逻辑：白名单优先，然后检查黑名单
///   1. 如果 IP/域名 在白名单中 -> 放行
///   2. 如果 IP/域名 在黑名单中 -> 过滤
///   3. 否则 -> 放行
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterConfig {
    pub ip: IpFilterConfig,
    pub domain: DomainFilterConfig,
}

/// IP 过滤配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpFilterConfig {
    #[serde(default)]
    pub blacklist: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

/// 域名过滤配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainFilterConfig {
    #[serde(default)]
    pub blacklist: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

/// 日志配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;
        
        config.validate()?;
        Ok(config)
    }

    /// 验证配置
    fn validate(&self) -> Result<()> {
        if self.interfaces.is_empty() {
            anyhow::bail!("At least one interface must be specified");
        }

        // 验证 IP 地址格式
        for ip in &self.filter.ip.blacklist {
            Self::parse_ip_or_cidr(ip)?;
        }
        for ip in &self.filter.ip.whitelist {
            Self::parse_ip_or_cidr(ip)?;
        }

        Ok(())
    }

    /// 解析 IP 地址或 CIDR
    fn parse_ip_or_cidr(s: &str) -> Result<Vec<u32>> {
        if s.contains('/') {
            // CIDR 格式
            let net: ipnet::Ipv4Net = s.parse()
                .with_context(|| format!("Invalid CIDR: {}", s))?;
            Ok(net.hosts().map(|ip| u32::from(ip)).collect())
        } else {
            // 单个 IP
            let ip: Ipv4Addr = s.parse()
                .with_context(|| format!("Invalid IP address: {}", s))?;
            Ok(vec![u32::from(ip)])
        }
    }

    /// 获取黑名单中的所有 IP（展开 CIDR）
    pub fn get_blacklist_ips(&self) -> Result<Vec<u32>> {
        let mut ips = Vec::new();
        for s in &self.filter.ip.blacklist {
            ips.extend(Self::parse_ip_or_cidr(s)?);
        }
        Ok(ips)
    }

    /// 获取白名单中的所有 IP（展开 CIDR）
    pub fn get_whitelist_ips(&self) -> Result<Vec<u32>> {
        let mut ips = Vec::new();
        for s in &self.filter.ip.whitelist {
            ips.extend(Self::parse_ip_or_cidr(s)?);
        }
        Ok(ips)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                http_addr: "0.0.0.0:8080".to_string(),
                metrics_addr: "0.0.0.0:9090".to_string(),
            },
            interfaces: vec!["eth0".to_string()],
            ebpf: EbpfConfig::default(),
            filter: FilterConfig {
                ip: IpFilterConfig {
                    blacklist: vec![],
                    whitelist: vec![],
                },
                domain: DomainFilterConfig {
                    blacklist: vec![],
                    whitelist: vec![],
                },
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
        }
    }
}
