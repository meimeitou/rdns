//! eBPF 程序加载器

use aya::{
    maps::{HashMap, MapData, RingBuf},
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags as AyaXdpFlags},
    Ebpf,
};
use anyhow::{Context, Result};
use log::info;

use crate::config::{Config, EbpfHook, TcDirection, XdpFlags};

/// eBPF 程序管理器
pub struct EbpfManager {
    ebpf: Ebpf,
    hook: EbpfHook,
    attached_interfaces: Vec<String>,
}

impl EbpfManager {
    /// 根据配置加载对应的 eBPF 程序
    pub fn load(config: &Config) -> Result<Self> {
        let ebpf = match &config.ebpf {
            EbpfHook::Xdp(_) => {
                let bytes = include_bytes!("../../target/bpfel-unknown-none/release/rdns-xdp");
                Ebpf::load(bytes).context("Failed to load XDP eBPF program")?
            }
            EbpfHook::Tc(_) => {
                let bytes = include_bytes!("../../target/bpfel-unknown-none/release/rdns-tc");
                Ebpf::load(bytes).context("Failed to load TC eBPF program")?
            }
        };

        Ok(Self {
            ebpf,
            hook: config.ebpf.clone(),
            attached_interfaces: Vec::new(),
        })
    }

    /// 附加到配置的网卡
    pub fn attach(&mut self, interfaces: &[String]) -> Result<()> {
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
                let program: &mut Xdp = self.ebpf
                    .program_mut("rdns_xdp")
                    .context("XDP program not found")?
                    .try_into()?;
                
                program.load().context("Failed to load XDP program")?;

                let flags = match xdp_cfg.flags {
                    XdpFlags::Default => AyaXdpFlags::default(),
                    XdpFlags::Skb => AyaXdpFlags::SKB_MODE,
                    XdpFlags::Driver => AyaXdpFlags::DRV_MODE,
                    XdpFlags::Hw => AyaXdpFlags::HW_MODE,
                };

                program
                    .attach(iface, flags)
                    .with_context(|| format!("Failed to attach XDP to {}", iface))?;

                info!("XDP ({:?}) attached to {}", xdp_cfg.flags, iface);
            }
            EbpfHook::Tc(tc_cfg) => {
                // 添加 clsact qdisc
                let _ = tc::qdisc_add_clsact(iface);

                let program: &mut SchedClassifier = self.ebpf
                    .program_mut("rdns_tc")
                    .context("TC program not found")?
                    .try_into()?;

                program.load().context("Failed to load TC program")?;

                match tc_cfg.direction {
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
    pub fn sync_filters(&mut self, config: &Config) -> Result<()> {
        // 设置过滤模式
        let mut filter_mode: HashMap<_, u32, u8> = HashMap::try_from(
            self.ebpf.map_mut("FILTER_MODE").context("FILTER_MODE map not found")?
        )?;
        filter_mode.insert(0, config.filter.mode.as_u8(), 0)?;
        info!("Filter mode set to {:?}", config.filter.mode);

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
        match &self.hook {
            EbpfHook::Xdp(_) => "xdp",
            EbpfHook::Tc(_) => "tc",
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
}
