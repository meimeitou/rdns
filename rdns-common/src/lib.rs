#![no_std]

/// DNS payload 最大长度 - 分离优化后可支持 64 字节
/// DNS header 占用 12 字节，剩余 52 字节用于域名
/// 这足够解析大多数域名（约 50 个字符）
pub const DNS_MAX_LEN: usize = 64;

/// IP 版本
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersion {
    #[default]
    V4 = 4,
    V6 = 6,
}

/// DNS 事件结构，用于从 eBPF 传递到用户态
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    /// IP 版本 (4 或 6)
    pub ip_version: u8,
    /// 保留字段，用于对齐
    pub _reserved: [u8; 3],
    /// 源 IP 地址 (IPv4 使用前 4 字节，IPv6 使用全部 16 字节)
    pub src_ip: [u8; 16],
    /// 目标 IP 地址 (IPv4 使用前 4 字节，IPv6 使用全部 16 字节)
    pub dst_ip: [u8; 16],
    /// 源端口 (主机字节序)
    pub src_port: u16,
    /// 目标端口 (主机字节序)
    pub dst_port: u16,
    /// DNS payload 实际长度
    pub payload_len: u16,
    /// 网卡索引
    pub ifindex: u32,
    /// DNS payload 数据（前 64 字节）
    pub payload: [u8; DNS_MAX_LEN],
}

impl Default for DnsEvent {
    fn default() -> Self {
        Self {
            ip_version: 4,
            _reserved: [0; 3],
            src_ip: [0u8; 16],
            dst_ip: [0u8; 16],
            src_port: 0,
            dst_port: 0,
            payload_len: 0,
            ifindex: 0,
            payload: [0u8; DNS_MAX_LEN],
        }
    }
}

impl DnsEvent {
    /// 获取 IPv4 源地址（仅当 ip_version == 4 时有效）
    #[inline]
    pub fn src_ipv4(&self) -> u32 {
        u32::from_be_bytes([self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3]])
    }
    
    /// 获取 IPv4 目标地址（仅当 ip_version == 4 时有效）
    #[inline]
    pub fn dst_ipv4(&self) -> u32 {
        u32::from_be_bytes([self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3]])
    }
}

/// 过滤动作
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// 允许通过
    Pass = 0,
    /// 丢弃
    Drop = 1,
}

/// 过滤模式
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// 黑名单模式：默认通过，匹配则丢弃
    Blacklist = 0,
    /// 白名单模式：默认丢弃，匹配则通过
    Whitelist = 1,
}

// 用户态实现 Pod trait
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsEvent {}
