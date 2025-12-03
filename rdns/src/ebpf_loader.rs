//! eBPF 程序加载器
//!
//! 支持三种部署模式：
//! 1. XDP only: 过滤 + 抓取入口流量
//! 2. TC only: 抓取双向流量（无过滤）
//! 3. XDP + TC: XDP 过滤，TC 抓取双向流量

use aya::{
    maps::{Array, HashMap, MapData, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags as AyaXdpFlags},
    Ebpf,
};
use anyhow::{Context, Result};
use log::info;
use std::path::Path;

use crate::config::{Config, EbpfConfig, EbpfMode, TcDirection, XdpFlags};

/// eBPF 程序管理器
pub struct EbpfManager {
    /// XDP eBPF 程序（可选）
    xdp_ebpf: Option<Ebpf>,
    /// TC eBPF 程序（可选）
    tc_ebpf: Option<Ebpf>,
    config: EbpfConfig,
    attached_interfaces: Vec<String>,
}

impl EbpfManager {
    /// 根据配置加载对应的 eBPF 程序
    pub fn load(config: &Config) -> Result<Self> {
        let (xdp_ebpf, tc_ebpf) = match config.ebpf.mode {
            EbpfMode::Xdp => {
                // 仅 XDP
                let bytes = load_ebpf_program(
                    config.ebpf.xdp_program_path.as_deref(),
                    "XDP",
                    "rdns-xdp",
                )?;
                let ebpf = Ebpf::load(&bytes).context("Failed to load XDP eBPF program")?;
                (Some(ebpf), None)
            }
            EbpfMode::Tc => {
                // 仅 TC
                let bytes = load_ebpf_program(
                    config.ebpf.tc_program_path.as_deref(),
                    "TC",
                    "rdns-tc",
                )?;
                let ebpf = Ebpf::load(&bytes).context("Failed to load TC eBPF program")?;
                (None, Some(ebpf))
            }
            EbpfMode::XdpTc => {
                // XDP + TC
                let xdp_bytes = load_ebpf_program(
                    config.ebpf.xdp_program_path.as_deref(),
                    "XDP",
                    "rdns-xdp",
                )?;
                let tc_bytes = load_ebpf_program(
                    config.ebpf.tc_program_path.as_deref(),
                    "TC",
                    "rdns-tc",
                )?;
                let xdp_ebpf = Ebpf::load(&xdp_bytes).context("Failed to load XDP eBPF program")?;
                let tc_ebpf = Ebpf::load(&tc_bytes).context("Failed to load TC eBPF program")?;
                (Some(xdp_ebpf), Some(tc_ebpf))
            }
        };

        Ok(Self {
            xdp_ebpf,
            tc_ebpf,
            config: config.ebpf.clone(),
            attached_interfaces: Vec::new(),
        })
    }

    /// 附加到配置的网卡
    pub fn attach(&mut self, interfaces: &[String]) -> Result<()> {
        // 先加载程序
        self.load_programs()?;

        // 设置 XDP 抓取开关
        self.configure_xdp_capture()?;

        // 附加到各个网卡
        for iface in interfaces {
            self.attach_single(iface)?;
            self.attached_interfaces.push(iface.clone());
        }
        Ok(())
    }

    /// 加载 eBPF 程序
    fn load_programs(&mut self) -> Result<()> {
        // 加载 XDP 程序
        if let Some(ref mut ebpf) = self.xdp_ebpf {
            let program: &mut Xdp = ebpf
                .program_mut("rdns_xdp")
                .context("XDP program not found")?
                .try_into()?;
            program.load().context("Failed to load XDP program")?;
        }

        // 加载 TC 程序
        if let Some(ref mut ebpf) = self.tc_ebpf {
            let program: &mut SchedClassifier = ebpf
                .program_mut("rdns_tc")
                .context("TC program not found")?
                .try_into()?;
            program.load().context("Failed to load TC program")?;
        }

        Ok(())
    }

    /// 配置 XDP 抓取开关
    fn configure_xdp_capture(&mut self) -> Result<()> {
        if let Some(ref mut ebpf) = self.xdp_ebpf {
            // 获取配置 map
            if let Some(map) = ebpf.map_mut("XDP_CONFIG") {
                let mut config_map: Array<_, u32> = Array::try_from(map)?;
                
                // 确定是否启用抓取
                let capture_enabled = match self.config.mode {
                    EbpfMode::Xdp => self.config.xdp_capture_enabled,
                    EbpfMode::XdpTc => false, // XDP+TC 模式下，XDP 关闭抓取
                    EbpfMode::Tc => false,    // 不会走到这里
                };

                // 设置抓取开关 (index 0)
                let value: u32 = if capture_enabled { 1 } else { 0 };
                config_map.set(0, value, 0)?;

                info!(
                    "XDP capture: {}",
                    if capture_enabled { "enabled" } else { "disabled (TC will capture)" }
                );
            }
        }
        Ok(())
    }

    /// 附加到单个网卡
    fn attach_single(&mut self, iface: &str) -> Result<()> {
        // 附加 XDP
        if let Some(ref mut ebpf) = self.xdp_ebpf {
            let program: &mut Xdp = ebpf
                .program_mut("rdns_xdp")
                .context("XDP program not found")?
                .try_into()?;

            let flags = match self.config.xdp_flags {
                XdpFlags::Default => AyaXdpFlags::default(),
                XdpFlags::Skb => AyaXdpFlags::SKB_MODE,
                XdpFlags::Driver => AyaXdpFlags::DRV_MODE,
                XdpFlags::Hw => AyaXdpFlags::HW_MODE,
            };

            program
                .attach(iface, flags)
                .with_context(|| format!("Failed to attach XDP to {}", iface))?;

            info!("XDP ({:?}) attached to {}", self.config.xdp_flags, iface);
        }

        // 附加 TC
        if let Some(ref mut ebpf) = self.tc_ebpf {
            // 添加 clsact qdisc
            let _ = tc::qdisc_add_clsact(iface);

            let program: &mut SchedClassifier = ebpf
                .program_mut("rdns_tc")
                .context("TC program not found")?
                .try_into()?;

            match self.config.tc_direction {
                TcDirection::Ingress => {
                    program
                        .attach(iface, TcAttachType::Ingress)
                        .with_context(|| format!("Failed to attach TC ingress to {}", iface))?;
                    info!("TC ingress attached to {}", iface);
                }
                TcDirection::Egress => {
                    program
                        .attach(iface, TcAttachType::Egress)
                        .with_context(|| format!("Failed to attach TC egress to {}", iface))?;
                    info!("TC egress attached to {}", iface);
                }
                TcDirection::Both => {
                    program
                        .attach(iface, TcAttachType::Ingress)
                        .with_context(|| format!("Failed to attach TC ingress to {}", iface))?;
                    program
                        .attach(iface, TcAttachType::Egress)
                        .with_context(|| format!("Failed to attach TC egress to {}", iface))?;
                    info!("TC ingress+egress attached to {}", iface);
                }
            }
        }

        Ok(())
    }

    /// 同步过滤配置到 eBPF maps（仅 XDP 有过滤 maps）
    pub fn sync_filters(&mut self, config: &Config) -> Result<()> {
        let ebpf = match self.xdp_ebpf.as_mut() {
            Some(e) => e,
            None => {
                info!("Skipping filter sync (TC mode has no filtering)");
                return Ok(());
            }
        };

        // 同步黑名单
        let mut blacklist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?)?;

        // 清空现有条目
        let keys: Vec<u32> = blacklist.keys().filter_map(|k| k.ok()).collect();
        for key in keys {
            let _ = blacklist.remove(&key);
        }

        // 添加新条目
        let blacklist_ips = config.get_blacklist_ips()?;
        for ip in &blacklist_ips {
            blacklist.insert(*ip, 1, 0)?;
        }
        info!("Synced {} IPs to blacklist", blacklist_ips.len());

        // 同步白名单
        let mut whitelist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?)?;

        // 清空现有条目
        let keys: Vec<u32> = whitelist.keys().filter_map(|k| k.ok()).collect();
        for key in keys {
            let _ = whitelist.remove(&key);
        }

        // 添加新条目
        let whitelist_ips = config.get_whitelist_ips()?;
        for ip in &whitelist_ips {
            whitelist.insert(*ip, 1, 0)?;
        }
        info!("Synced {} IPs to whitelist", whitelist_ips.len());

        Ok(())
    }

    /// 添加 IP 到黑名单
    pub fn add_to_blacklist(&mut self, ip: u32) -> Result<()> {
        let ebpf = self.xdp_ebpf.as_mut().context("XDP not loaded, cannot modify blacklist")?;
        let mut blacklist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?)?;
        blacklist.insert(ip, 1, 0)?;
        Ok(())
    }

    /// 从黑名单移除 IP
    pub fn remove_from_blacklist(&mut self, ip: u32) -> Result<()> {
        let ebpf = self.xdp_ebpf.as_mut().context("XDP not loaded, cannot modify blacklist")?;
        let mut blacklist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?)?;
        blacklist.remove(&ip)?;
        Ok(())
    }

    /// 添加 IP 到白名单
    pub fn add_to_whitelist(&mut self, ip: u32) -> Result<()> {
        let ebpf = self.xdp_ebpf.as_mut().context("XDP not loaded, cannot modify whitelist")?;
        let mut whitelist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?)?;
        whitelist.insert(ip, 1, 0)?;
        Ok(())
    }

    /// 从白名单移除 IP
    pub fn remove_from_whitelist(&mut self, ip: u32) -> Result<()> {
        let ebpf = self.xdp_ebpf.as_mut().context("XDP not loaded, cannot modify whitelist")?;
        let mut whitelist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?)?;
        whitelist.remove(&ip)?;
        Ok(())
    }

    /// 获取 XDP 的 RingBuf（如果存在）
    pub fn get_xdp_ring_buf(&mut self) -> Option<RingBuf<&mut MapData>> {
        self.xdp_ebpf.as_mut().and_then(|ebpf| {
            ebpf.map_mut("DNS_EVENTS")
                .and_then(|map| RingBuf::try_from(map).ok())
        })
    }

    /// 获取 TC 的 RingBuf（如果存在）
    pub fn get_tc_ring_buf(&mut self) -> Option<RingBuf<&mut MapData>> {
        self.tc_ebpf.as_mut().and_then(|ebpf| {
            ebpf.map_mut("DNS_EVENTS")
                .and_then(|map| RingBuf::try_from(map).ok())
        })
    }

    /// 获取挂载点类型（兼容旧 API）
    pub fn hook_type(&self) -> &str {
        match self.config.mode {
            EbpfMode::Xdp => "xdp",
            EbpfMode::Tc => "tc",
            EbpfMode::XdpTc => "xdp+tc",
        }
    }

    /// 获取已附加的网卡列表
    pub fn interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }

    /// 获取黑名单大小
    pub fn blacklist_size(&mut self) -> Result<usize> {
        let ebpf = self.xdp_ebpf.as_mut().context("XDP not loaded")?;
        let blacklist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?)?;
        Ok(blacklist.keys().count())
    }

    /// 获取白名单大小
    pub fn whitelist_size(&mut self) -> Result<usize> {
        let ebpf = self.xdp_ebpf.as_mut().context("XDP not loaded")?;
        let whitelist: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?)?;
        Ok(whitelist.keys().count())
    }
}

/// 自动卸载 eBPF 程序
impl Drop for EbpfManager {
    fn drop(&mut self) {
        if !self.attached_interfaces.is_empty() {
            info!(
                "Cleaning up eBPF programs from: {:?}",
                self.attached_interfaces
            );
            // aya 会自动卸载，无需手动操作
        }
    }
}

/// 加载 eBPF 程序
fn load_ebpf_program(configured_path: Option<&str>, name: &str, filename: &str) -> Result<Vec<u8>> {
    // 如果配置了路径，直接使用
    if let Some(path_str) = configured_path {
        let path = Path::new(path_str);
        if path.exists() {
            info!(
                "Loading {} eBPF program from configured path: {}",
                name, path_str
            );
            return std::fs::read(path)
                .with_context(|| format!("Failed to read {} eBPF program from {}", name, path_str));
        } else {
            anyhow::bail!(
                "{} eBPF program not found at configured path: {}",
                name,
                path_str
            );
        }
    }

    // 否则自动搜索
    let search_paths = get_default_ebpf_paths(filename);
    for path_str in &search_paths {
        let path = Path::new(path_str);
        if path.exists() {
            info!("Found {} eBPF program at: {}", name, path_str);
            return std::fs::read(path)
                .with_context(|| format!("Failed to read {} eBPF program from {}", name, path_str));
        }
    }

    anyhow::bail!(
        "{} eBPF program not found. Searched paths:\n  {}",
        name,
        search_paths.join("\n  ")
    )
}

/// 获取默认的 eBPF 程序搜索路径
fn get_default_ebpf_paths(filename: &str) -> Vec<String> {
    let target_dir = "target/bpfel-unknown-none/release";

    // 尝试多种可能的基路径
    let base_paths = vec![
        ".",
        "..",
        "/usr/share/rdns",
        "/opt/rdns",
    ];

    let mut paths = Vec::new();

    for base in base_paths {
        paths.push(format!("{}/{}/{}", base, target_dir, filename));
    }

    // 也尝试直接在当前目录
    paths.push(filename.to_string());

    paths
}
