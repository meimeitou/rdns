//! eBPF 程序加载器

use aya::{
    maps::{HashMap, MapData, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags as AyaXdpFlags},
    Ebpf,
};
use anyhow::{Context, Result};
use log::info;
use std::path::Path;

use crate::config::{Config, EbpfConfig, EbpfMode, TcDirection, XdpFlags};

/// eBPF 程序管理器
pub struct EbpfManager {
    ebpf: Ebpf,
    config: EbpfConfig,
    attached_interfaces: Vec<String>,
}

impl EbpfManager {
    /// 根据配置加载对应的 eBPF 程序
    pub fn load(config: &Config) -> Result<Self> {
        let ebpf = match config.ebpf.mode {
            EbpfMode::Xdp => {
                let bytes = load_ebpf_program(
                    config.ebpf.xdp_program_path.as_deref(),
                    "XDP",
                    "rdns-xdp",
                )?;
                Ebpf::load(&bytes).context("Failed to load XDP eBPF program")?
            }
            EbpfMode::Tc => {
                let bytes = load_ebpf_program(
                    config.ebpf.tc_program_path.as_deref(),
                    "TC",
                    "rdns-tc",
                )?;
                Ebpf::load(&bytes).context("Failed to load TC eBPF program")?
            }
        };

        Ok(Self {
            ebpf,
            config: config.ebpf.clone(),
            attached_interfaces: Vec::new(),
        })
    }

    /// 附加到配置的网卡
    pub fn attach(&mut self, interfaces: &[String]) -> Result<()> {
        // 先加载程序（只需要加载一次）
        self.load_program()?;
        
        // 再附加到各个网卡
        for iface in interfaces {
            self.attach_single(iface)?;
            self.attached_interfaces.push(iface.clone());
        }
        Ok(())
    }

    /// 加载 eBPF 程序（只调用一次）
    fn load_program(&mut self) -> Result<()> {
        match self.config.mode {
            EbpfMode::Xdp => {
                let program: &mut Xdp = self.ebpf
                    .program_mut("rdns_xdp")
                    .context("XDP program not found")?
                    .try_into()?;
                program.load().context("Failed to load XDP program")?;
            }
            EbpfMode::Tc => {
                let program: &mut SchedClassifier = self.ebpf
                    .program_mut("rdns_tc")
                    .context("TC program not found")?
                    .try_into()?;
                program.load().context("Failed to load TC program")?;
            }
        }
        Ok(())
    }

    /// 附加到单个网卡
    fn attach_single(&mut self, iface: &str) -> Result<()> {
        match self.config.mode {
            EbpfMode::Xdp => {
                let program: &mut Xdp = self.ebpf
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
            EbpfMode::Tc => {
                // 添加 clsact qdisc
                let _ = tc::qdisc_add_clsact(iface);

                let program: &mut SchedClassifier = self.ebpf
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
        }
        Ok(())
    }

    /// 同步过滤配置到 eBPF maps
    /// 过滤逻辑：白名单优先，然后检查黑名单
    pub fn sync_filters(&mut self, config: &Config) -> Result<()> {
        // 同步黑名单
        let mut blacklist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?
        )?;
        
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
        let mut whitelist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?
        )?;
        
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
        let mut blacklist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?
        )?;
        blacklist.insert(ip, 1, 0)?;
        Ok(())
    }

    /// 从黑名单移除 IP
    pub fn remove_from_blacklist(&mut self, ip: u32) -> Result<()> {
        let mut blacklist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?
        )?;
        blacklist.remove(&ip)?;
        Ok(())
    }

    /// 添加 IP 到白名单
    pub fn add_to_whitelist(&mut self, ip: u32) -> Result<()> {
        let mut whitelist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?
        )?;
        whitelist.insert(ip, 1, 0)?;
        Ok(())
    }

    /// 从白名单移除 IP
    pub fn remove_from_whitelist(&mut self, ip: u32) -> Result<()> {
        let mut whitelist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?
        )?;
        whitelist.remove(&ip)?;
        Ok(())
    }

    /// 获取 RingBuf 用于事件处理
    pub fn get_ring_buf(&mut self) -> Result<RingBuf<&mut MapData>> {
        RingBuf::try_from(
            self.ebpf.map_mut("DNS_EVENTS").context("DNS_EVENTS map not found")?
        ).context("Failed to create RingBuf")
    }

    /// 获取挂载点类型
    pub fn hook_type(&self) -> &str {
        match self.config.mode {
            EbpfMode::Xdp => "xdp",
            EbpfMode::Tc => "tc",
        }
    }

    /// 获取已附加的网卡列表
    pub fn interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }

    /// 获取黑名单大小
    pub fn blacklist_size(&mut self) -> Result<usize> {
        let blacklist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_BLACKLIST").context("IP_BLACKLIST map not found")?
        )?;
        Ok(blacklist.keys().count())
    }

    /// 获取白名单大小
    pub fn whitelist_size(&mut self) -> Result<usize> {
        let whitelist: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("IP_WHITELIST").context("IP_WHITELIST map not found")?
        )?;
        Ok(whitelist.keys().count())
    }

    /// 获取已附加的网卡列表（用于日志）
    pub fn attached_interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }
}

/// 自动卸载 eBPF 程序
/// 注意：aya 使用 BPF link 方式附加程序，当 Ebpf 对象被 drop 时会自动卸载
/// 这里只需要记录日志
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
/// 如果配置了路径则使用配置的路径，否则自动搜索
fn load_ebpf_program(configured_path: Option<&str>, name: &str, filename: &str) -> Result<Vec<u8>> {
    // 如果配置了路径，直接使用
    if let Some(path_str) = configured_path {
        let path = Path::new(path_str);
        if path.exists() {
            info!("Loading {} eBPF program from configured path: {}", name, path_str);
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
        // 相对于当前工作目录
        ".",
        // 相对于可执行文件目录
        "..",
        // 常见安装位置
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
