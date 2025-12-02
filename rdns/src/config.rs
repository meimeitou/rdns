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
    pub ebpf: EbpfHook,
    pub filter: FilterConfig,
    pub logging: LoggingConfig,
}

/// 服务器配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub http_addr: String,
    pub metrics_addr: String,
}

/// eBPF 挂载点配置（XDP 或 TC 二选一）
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EbpfHook {
    /// XDP 模式（高性能入站过滤）
    Xdp(XdpConfig),
    /// TC 模式（支持出站过滤）
    Tc(TcConfig),
}

/// XDP 配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XdpConfig {
    /// XDP flags: "default", "skb", "driver", "hw"
    #[serde(default)]
    pub flags: XdpFlags,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            flags: XdpFlags::Default,
        }
    }
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

/// TC 配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TcConfig {
    /// ingress, egress, 或 both
    pub direction: TcDirection,
}

/// TC 方向
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TcDirection {
    Ingress,
    Egress,
    Both,
}

/// 过滤配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterConfig {
    pub mode: FilterMode,
    pub ip: IpFilterConfig,
    pub domain: DomainFilterConfig,
}

/// 过滤模式
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FilterMode {
    Blacklist,
    Whitelist,
}

impl FilterMode {
    pub fn as_u8(&self) -> u8 {
        match self {
            FilterMode::Blacklist => 0,
            FilterMode::Whitelist => 1,
        }
    }
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
            ebpf: EbpfHook::Xdp(XdpConfig::default()),
            filter: FilterConfig {
                mode: FilterMode::Blacklist,
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
