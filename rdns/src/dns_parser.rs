//! DNS 包解析器（用户态）

use anyhow::Result;

/// DNS 解析结果
#[derive(Debug, Clone)]
pub struct DnsInfo {
    /// 是否为查询（false = 响应）
    pub is_query: bool,
    /// 查询类型 (A, AAAA, CNAME, MX, etc.)
    pub query_type: String,
    /// 域名
    pub domain: String,
    /// 事务 ID
    pub transaction_id: u16,
}

/// 解析 DNS 包
pub fn parse_dns_packet(data: &[u8]) -> Result<DnsInfo> {
    if data.len() < 12 {
        anyhow::bail!("DNS packet too short");
    }

    // DNS 头部
    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_query = (flags & 0x8000) == 0;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);

    if qdcount == 0 {
        anyhow::bail!("No questions in DNS packet");
    }

    // 解析第一个问题
    let mut offset = 12;
    let domain = parse_domain_name(data, &mut offset)?;
    
    if offset + 4 > data.len() {
        anyhow::bail!("DNS packet truncated");
    }

    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let query_type = match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        _ => format!("TYPE{}", qtype),
    };

    Ok(DnsInfo {
        is_query,
        query_type,
        domain,
        transaction_id,
    })
}

/// 解析 DNS 域名
fn parse_domain_name(data: &[u8], offset: &mut usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0;
    let original_offset = *offset;

    loop {
        if *offset >= data.len() {
            anyhow::bail!("Domain name extends beyond packet");
        }

        let len = data[*offset] as usize;

        if len == 0 {
            *offset += 1;
            break;
        }

        // 压缩指针
        if (len & 0xC0) == 0xC0 {
            if *offset + 1 >= data.len() {
                anyhow::bail!("Compressed pointer extends beyond packet");
            }
            
            let pointer = ((len & 0x3F) << 8) | (data[*offset + 1] as usize);
            
            if !jumped {
                jump_offset = *offset + 2;
            }
            jumped = true;
            *offset = pointer;
            continue;
        }

        *offset += 1;

        if *offset + len > data.len() {
            anyhow::bail!("Label extends beyond packet");
        }

        let label = String::from_utf8_lossy(&data[*offset..*offset + len]).to_string();
        labels.push(label);
        *offset += len;
    }

    if jumped {
        *offset = jump_offset;
    }

    if labels.is_empty() {
        Ok(".".to_string())
    } else {
        Ok(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        // 简单的 DNS 查询包: example.com A 记录
        let packet = [
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // Null terminator
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let info = parse_dns_packet(&packet).unwrap();
        assert!(info.is_query);
        assert_eq!(info.domain, "example.com");
        assert_eq!(info.query_type, "A");
        assert_eq!(info.transaction_id, 0x1234);
    }
}
