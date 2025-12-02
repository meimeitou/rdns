//! 域名过滤器（用户态）

use crate::config::{FilterConfig, FilterMode};

/// 域名过滤器
pub struct DomainFilter {
    /// 编译后的黑名单模式
    blacklist_patterns: Vec<Pattern>,
    /// 编译后的白名单模式
    whitelist_patterns: Vec<Pattern>,
}

/// 匹配模式
enum Pattern {
    /// 精确匹配
    Exact(String),
    /// 后缀匹配 (*.example.com)
    Suffix(String),
    /// 前缀匹配 (example.*)
    Prefix(String),
    /// 包含匹配 (*example*)
    Contains(String),
}

impl DomainFilter {
    /// 创建新的域名过滤器
    pub fn new() -> Self {
        Self {
            blacklist_patterns: Vec::new(),
            whitelist_patterns: Vec::new(),
        }
    }

    /// 从配置同步
    pub fn sync_from_config(&mut self, config: &FilterConfig) {
        self.blacklist_patterns = config
            .domain
            .blacklist
            .iter()
            .map(|s| Self::compile_pattern(s))
            .collect();

        self.whitelist_patterns = config
            .domain
            .whitelist
            .iter()
            .map(|s| Self::compile_pattern(s))
            .collect();
    }

    /// 编译匹配模式
    fn compile_pattern(pattern: &str) -> Pattern {
        if pattern.starts_with("*.") {
            // *.example.com -> 匹配 .example.com 结尾
            Pattern::Suffix(pattern[1..].to_lowercase())
        } else if pattern.ends_with(".*") {
            // example.* -> 匹配 example. 开头
            Pattern::Prefix(pattern[..pattern.len() - 1].to_lowercase())
        } else if pattern.starts_with('*') && pattern.ends_with('*') {
            // *example* -> 包含匹配
            Pattern::Contains(pattern[1..pattern.len() - 1].to_lowercase())
        } else {
            // 精确匹配
            Pattern::Exact(pattern.to_lowercase())
        }
    }

    /// 检查域名是否匹配模式
    fn matches(domain: &str, pattern: &Pattern) -> bool {
        let domain_lower = domain.to_lowercase();
        match pattern {
            Pattern::Exact(p) => domain_lower == *p,
            Pattern::Suffix(p) => domain_lower.ends_with(p),
            Pattern::Prefix(p) => domain_lower.starts_with(p),
            Pattern::Contains(p) => domain_lower.contains(p),
        }
    }

    /// 检查域名是否应该被过滤
    pub fn should_filter(&self, domain: &str, config: &FilterConfig) -> bool {
        match config.mode {
            FilterMode::Blacklist => {
                // 黑名单模式：匹配则过滤
                self.blacklist_patterns
                    .iter()
                    .any(|p| Self::matches(domain, p))
            }
            FilterMode::Whitelist => {
                // 白名单模式：不匹配则过滤
                !self.whitelist_patterns
                    .iter()
                    .any(|p| Self::matches(domain, p))
            }
        }
    }

    /// 添加域名到黑名单
    pub fn add_to_blacklist(&mut self, domain: &str) {
        self.blacklist_patterns.push(Self::compile_pattern(domain));
    }

    /// 添加域名到白名单
    pub fn add_to_whitelist(&mut self, domain: &str) {
        self.whitelist_patterns.push(Self::compile_pattern(domain));
    }

    /// 获取黑名单大小
    pub fn blacklist_size(&self) -> usize {
        self.blacklist_patterns.len()
    }

    /// 获取白名单大小
    pub fn whitelist_size(&self) -> usize {
        self.whitelist_patterns.len()
    }
}

impl Default for DomainFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = DomainFilter::compile_pattern("example.com");
        assert!(DomainFilter::matches("example.com", &pattern));
        assert!(DomainFilter::matches("EXAMPLE.COM", &pattern));
        assert!(!DomainFilter::matches("sub.example.com", &pattern));
    }

    #[test]
    fn test_suffix_match() {
        let pattern = DomainFilter::compile_pattern("*.example.com");
        assert!(DomainFilter::matches("sub.example.com", &pattern));
        assert!(DomainFilter::matches("a.b.example.com", &pattern));
        assert!(!DomainFilter::matches("example.com", &pattern));
    }

    #[test]
    fn test_prefix_match() {
        let pattern = DomainFilter::compile_pattern("ads.*");
        assert!(DomainFilter::matches("ads.google.com", &pattern));
        assert!(DomainFilter::matches("ads.facebook.com", &pattern));
        assert!(!DomainFilter::matches("myads.com", &pattern));
    }

    #[test]
    fn test_contains_match() {
        let pattern = DomainFilter::compile_pattern("*tracking*");
        assert!(DomainFilter::matches("tracking.example.com", &pattern));
        assert!(DomainFilter::matches("ads.tracking.net", &pattern));
        assert!(DomainFilter::matches("mytrackingservice.com", &pattern));
    }
}
