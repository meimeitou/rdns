#![no_std]

/// DNS payload 最大长度 - 限制为 64 字节以通过 eBPF 验证器
/// 这足够解析 DNS header 和大多数查询域名
pub const DNS_MAX_LEN: usize = 64;

/// DNS 事件结构，用于从 eBPF 传递到用户态
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    /// 源 IP 地址 (主机字节序)
    pub src_ip: u32,
    /// 目标 IP 地址 (主机字节序)
    pub dst_ip: u32,
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
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            payload_len: 0,
            ifindex: 0,
            payload: [0u8; DNS_MAX_LEN],
        }
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
