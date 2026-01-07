//! Access control lists with CIDR-based allow/deny rules.
//!
//! Provides IP-based access control with support for IPv4 and IPv6 CIDR notation.
//! Rules are evaluated in order: first matching rule wins.

use std::collections::HashMap;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Access decision result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// Request is allowed
    Allow,
    /// Request is denied
    Deny,
    /// No matching rule, use default
    NoMatch,
}

/// Access control rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AccessAction {
    Allow,
    #[default]
    Deny,
}

/// A CIDR network range for IP matching.
#[derive(Debug, Clone)]
pub struct CidrRange {
    /// Network address
    network: IpAddr,
    /// Prefix length (0-32 for IPv4, 0-128 for IPv6)
    prefix_len: u8,
}

impl CidrRange {
    /// Parses a CIDR string (e.g., "192.168.1.0/24" or "10.0.0.1").
    pub fn parse(cidr: &str) -> Result<Self, AccessError> {
        let (addr_str, prefix_str) = if let Some(idx) = cidr.find('/') {
            (&cidr[..idx], Some(&cidr[idx + 1..]))
        } else {
            (cidr, None)
        };

        let network: IpAddr = addr_str
            .parse()
            .map_err(|_| AccessError::InvalidCidr {
                cidr: cidr.to_string(),
                reason: "invalid IP address".to_string(),
            })?;

        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        let prefix_len: u8 = match prefix_str {
            Some(s) => s.parse().map_err(|_| AccessError::InvalidCidr {
                cidr: cidr.to_string(),
                reason: "invalid prefix length".to_string(),
            })?,
            None => max_prefix,
        };

        if prefix_len > max_prefix {
            return Err(AccessError::InvalidCidr {
                cidr: cidr.to_string(),
                reason: format!("prefix length {} exceeds maximum {}", prefix_len, max_prefix),
            });
        }

        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Checks if an IP address is within this CIDR range.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net_bits = u32::from_be_bytes(net.octets());
                let addr_bits = u32::from_be_bytes(addr.octets());
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - self.prefix_len)
                };
                (addr_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net_bits = u128::from_be_bytes(net.octets());
                let addr_bits = u128::from_be_bytes(addr.octets());
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - self.prefix_len)
                };
                (addr_bits & mask) == (net_bits & mask)
            }
            // IPv4 and IPv6 don't match
            _ => false,
        }
    }
}

/// A single access control rule.
#[derive(Debug, Clone)]
pub struct AccessRule {
    /// CIDR range to match
    pub cidr: CidrRange,
    /// Action to take on match
    pub action: AccessAction,
    /// Optional comment/description
    pub comment: Option<String>,
}

impl AccessRule {
    /// Creates a new allow rule for the given CIDR.
    pub fn allow(cidr: &str) -> Result<Self, AccessError> {
        Ok(Self {
            cidr: CidrRange::parse(cidr)?,
            action: AccessAction::Allow,
            comment: None,
        })
    }

    /// Creates a new deny rule for the given CIDR.
    pub fn deny(cidr: &str) -> Result<Self, AccessError> {
        Ok(Self {
            cidr: CidrRange::parse(cidr)?,
            action: AccessAction::Deny,
            comment: None,
        })
    }

    /// Adds a comment to the rule.
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    /// Checks if this rule matches the given IP.
    pub fn matches(&self, ip: &IpAddr) -> bool {
        self.cidr.contains(ip)
    }
}

/// Access control list for a site.
#[derive(Debug, Default)]
pub struct AccessList {
    /// Rules evaluated in order
    rules: Vec<AccessRule>,
    /// Default action when no rule matches
    default_action: AccessAction,
}

impl AccessList {
    /// Creates a new access list with deny as default.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: AccessAction::Deny,
        }
    }

    /// Creates an access list that allows all by default.
    pub fn allow_all() -> Self {
        Self {
            rules: Vec::new(),
            default_action: AccessAction::Allow,
        }
    }

    /// Creates an access list that denies all by default.
    pub fn deny_all() -> Self {
        Self {
            rules: Vec::new(),
            default_action: AccessAction::Deny,
        }
    }

    /// Adds a rule to the access list.
    pub fn add_rule(&mut self, rule: AccessRule) {
        self.rules.push(rule);
    }

    /// Adds an allow rule for the given CIDR.
    pub fn allow(&mut self, cidr: &str) -> Result<(), AccessError> {
        self.rules.push(AccessRule::allow(cidr)?);
        Ok(())
    }

    /// Adds a deny rule for the given CIDR.
    pub fn deny(&mut self, cidr: &str) -> Result<(), AccessError> {
        self.rules.push(AccessRule::deny(cidr)?);
        Ok(())
    }

    /// Sets the default action.
    pub fn set_default(&mut self, action: AccessAction) {
        self.default_action = action;
    }

    /// Checks if an IP address is allowed.
    pub fn check(&self, ip: &IpAddr) -> AccessDecision {
        for rule in &self.rules {
            if rule.matches(ip) {
                debug!(
                    "IP {} matched rule {:?} -> {:?}",
                    ip, rule.cidr.network, rule.action
                );
                return match rule.action {
                    AccessAction::Allow => AccessDecision::Allow,
                    AccessAction::Deny => AccessDecision::Deny,
                };
            }
        }

        debug!("IP {} no match, using default {:?}", ip, self.default_action);
        match self.default_action {
            AccessAction::Allow => AccessDecision::Allow,
            AccessAction::Deny => AccessDecision::Deny,
        }
    }

    /// Returns true if the IP is allowed.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        matches!(self.check(ip), AccessDecision::Allow)
    }

    /// Returns the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Per-site access list manager.
#[derive(Debug, Default)]
pub struct AccessListManager {
    /// Site hostname -> access list mapping
    lists: HashMap<String, AccessList>,
    /// Global access list (checked first)
    global: AccessList,
}

impl AccessListManager {
    /// Creates a new manager with allow-all defaults.
    pub fn new() -> Self {
        Self {
            lists: HashMap::new(),
            global: AccessList::allow_all(),
        }
    }

    /// Sets the global access list.
    pub fn set_global(&mut self, list: AccessList) {
        self.global = list;
    }

    /// Adds a site-specific access list.
    pub fn add_site(&mut self, hostname: &str, list: AccessList) {
        self.lists.insert(hostname.to_lowercase(), list);
    }

    /// Removes a site-specific access list.
    pub fn remove_site(&mut self, hostname: &str) {
        self.lists.remove(&hostname.to_lowercase());
    }

    /// Checks if an IP is allowed for a site.
    ///
    /// Evaluation order:
    /// 1. Global deny rules
    /// 2. Site-specific rules
    /// 3. Global allow rules
    /// 4. Default action
    pub fn check(&self, hostname: &str, ip: &IpAddr) -> AccessDecision {
        // Check global rules first
        let global_decision = self.global.check(ip);
        if matches!(global_decision, AccessDecision::Deny) {
            return AccessDecision::Deny;
        }

        // Check site-specific rules
        let normalized = hostname.to_lowercase();
        if let Some(site_list) = self.lists.get(&normalized) {
            let site_decision = site_list.check(ip);
            if !matches!(site_decision, AccessDecision::NoMatch) {
                return site_decision;
            }
        }

        // Fall back to global decision
        global_decision
    }

    /// Returns true if the IP is allowed for the site.
    pub fn is_allowed(&self, hostname: &str, ip: &IpAddr) -> bool {
        matches!(self.check(hostname, ip), AccessDecision::Allow)
    }

    /// Returns the number of configured sites.
    pub fn site_count(&self) -> usize {
        self.lists.len()
    }
}

/// Errors that can occur during access control operations.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("invalid CIDR '{cidr}': {reason}")]
    InvalidCidr { cidr: String, reason: String },
}

/// Parses an IP address from a string, handling common formats.
pub fn parse_ip(s: &str) -> Result<IpAddr, AccessError> {
    // Handle IPv6 with brackets
    let s = s.trim_start_matches('[').trim_end_matches(']');

    s.parse().map_err(|_| AccessError::InvalidCidr {
        cidr: s.to_string(),
        reason: "invalid IP address format".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parse_ipv4() {
        let cidr = CidrRange::parse("192.168.1.0/24").unwrap();
        assert!(cidr.contains(&"192.168.1.1".parse().unwrap()));
        assert!(cidr.contains(&"192.168.1.254".parse().unwrap()));
        assert!(!cidr.contains(&"192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_parse_ipv4_single() {
        let cidr = CidrRange::parse("10.0.0.1").unwrap();
        assert!(cidr.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!cidr.contains(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_cidr_parse_ipv6() {
        let cidr = CidrRange::parse("2001:db8::/32").unwrap();
        assert!(cidr.contains(&"2001:db8::1".parse().unwrap()));
        assert!(cidr.contains(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!cidr.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_invalid() {
        assert!(CidrRange::parse("not-an-ip").is_err());
        assert!(CidrRange::parse("192.168.1.0/33").is_err());
        assert!(CidrRange::parse("192.168.1.0/abc").is_err());
    }

    #[test]
    fn test_access_rule_allow() {
        let rule = AccessRule::allow("10.0.0.0/8").unwrap();
        assert!(rule.matches(&"10.1.2.3".parse().unwrap()));
        assert!(!rule.matches(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_access_rule_deny() {
        let rule = AccessRule::deny("192.168.0.0/16").unwrap();
        assert_eq!(rule.action, AccessAction::Deny);
        assert!(rule.matches(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_access_list_allow_all() {
        let list = AccessList::allow_all();
        assert!(list.is_allowed(&"1.2.3.4".parse().unwrap()));
        assert!(list.is_allowed(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_access_list_deny_all() {
        let list = AccessList::deny_all();
        assert!(!list.is_allowed(&"1.2.3.4".parse().unwrap()));
        assert!(!list.is_allowed(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_access_list_rules() {
        let mut list = AccessList::deny_all();
        // Order matters: first match wins
        // To deny a specific IP within an allow range, add the deny first
        list.deny("10.0.0.1").unwrap();        // Specific deny - must come first
        list.allow("10.0.0.0/8").unwrap();     // Then allow the broader range
        list.allow("192.168.1.0/24").unwrap();

        assert!(!list.is_allowed(&"10.0.0.1".parse().unwrap())); // Denied by specific rule
        assert!(list.is_allowed(&"10.0.0.2".parse().unwrap()));  // Allowed by /8 rule
        assert!(list.is_allowed(&"192.168.1.100".parse().unwrap()));
        assert!(!list.is_allowed(&"8.8.8.8".parse().unwrap()));  // Default deny
    }

    #[test]
    fn test_access_list_manager() {
        let mut manager = AccessListManager::new();

        // Global: deny known bad actors
        let mut global = AccessList::allow_all();
        global.deny("1.2.3.4").unwrap();
        manager.set_global(global);

        // Site-specific: only allow internal
        let mut site_list = AccessList::deny_all();
        site_list.allow("10.0.0.0/8").unwrap();
        manager.add_site("internal.example.com", site_list);

        // Global deny takes precedence
        assert!(!manager.is_allowed("any.com", &"1.2.3.4".parse().unwrap()));

        // Site-specific rules
        assert!(manager.is_allowed("internal.example.com", &"10.0.0.1".parse().unwrap()));
        assert!(!manager.is_allowed("internal.example.com", &"8.8.8.8".parse().unwrap()));

        // Other sites use global
        assert!(manager.is_allowed("public.example.com", &"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_manager_case_insensitive() {
        let mut manager = AccessListManager::new();
        manager.add_site("Example.COM", AccessList::deny_all());

        assert!(!manager.is_allowed("example.com", &"1.2.3.4".parse().unwrap()));
        assert!(!manager.is_allowed("EXAMPLE.COM", &"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_rule_with_comment() {
        let rule = AccessRule::deny("0.0.0.0/0")
            .unwrap()
            .with_comment("Block all by default");

        assert_eq!(rule.comment, Some("Block all by default".to_string()));
    }

    #[test]
    fn test_parse_ip_formats() {
        assert!(parse_ip("192.168.1.1").is_ok());
        assert!(parse_ip("::1").is_ok());
        assert!(parse_ip("[::1]").is_ok()); // Bracketed IPv6
        assert!(parse_ip("invalid").is_err());
    }

    #[test]
    fn test_cidr_zero_prefix() {
        let cidr = CidrRange::parse("0.0.0.0/0").unwrap();
        assert!(cidr.contains(&"1.2.3.4".parse().unwrap()));
        assert!(cidr.contains(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_rule_count() {
        let mut list = AccessList::new();
        assert_eq!(list.rule_count(), 0);

        list.allow("10.0.0.0/8").unwrap();
        list.deny("192.168.0.0/16").unwrap();

        assert_eq!(list.rule_count(), 2);
    }
}
