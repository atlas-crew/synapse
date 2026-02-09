//! Access control lists with CIDR-based allow/deny rules.
//!
//! Provides IP-based access control with support for IPv4 and IPv6 CIDR notation.
//! Rules are evaluated in order: first matching rule wins.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
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
        use std::str::FromStr;
        Self::from_str(cidr)
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

impl std::str::FromStr for CidrRange {
    type Err = AccessError;

    fn from_str(cidr: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = if let Some(idx) = cidr.find('/') {
            (&cidr[..idx], Some(&cidr[idx + 1..]))
        } else {
            (cidr, None)
        };

        let network: IpAddr = addr_str.parse().map_err(|_| AccessError::InvalidCidr {
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
                reason: format!(
                    "prefix length {} exceeds maximum {}",
                    prefix_len, max_prefix
                ),
            });
        }

        Ok(Self {
            network,
            prefix_len,
        })
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

        debug!(
            "IP {} no match, using default {:?}",
            ip, self.default_action
        );
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

    /// Dynamically adds a deny rule for an IP address to the global list.
    ///
    /// Used by CampaignManager for automated mitigation of high-confidence campaigns.
    ///
    /// # Arguments
    /// * `ip` - The IP address to deny
    /// * `comment` - Reason for the denial (e.g., campaign ID)
    ///
    /// # Returns
    /// Ok(()) on success, or an error if the IP is invalid.
    pub fn add_deny_ip(&mut self, ip: &IpAddr, comment: Option<&str>) -> Result<(), AccessError> {
        let cidr = match ip {
            IpAddr::V4(_) => format!("{}/32", ip),
            IpAddr::V6(_) => format!("{}/128", ip),
        };

        let mut rule = AccessRule::deny(&cidr)?;
        if let Some(c) = comment {
            rule = rule.with_comment(c);
        }

        self.global.add_rule(rule);
        tracing::info!(ip = %ip, comment = ?comment, "Added dynamic deny rule");
        Ok(())
    }

    /// Removes all deny rules for a specific IP from the global list.
    ///
    /// Used for mitigation rollback when campaign confidence drops.
    ///
    /// # Arguments
    /// * `ip` - The IP address to unblock
    ///
    /// # Returns
    /// The number of rules removed.
    pub fn remove_deny_ip(&mut self, ip: &IpAddr) -> usize {
        let ip_str = ip.to_string();

        let before_count = self.global.rules.len();
        self.global.rules.retain(|rule| {
            // Match rules by network IP and deny action
            let network_str = match rule.cidr.network {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => v6.to_string(),
            };
            !(network_str == ip_str && matches!(rule.action, AccessAction::Deny))
        });
        let removed = before_count - self.global.rules.len();

        if removed > 0 {
            tracing::info!(ip = %ip, removed = removed, "Removed dynamic deny rules");
        }

        removed
    }

    /// Returns a list of all configured site hostnames.
    pub fn list_sites(&self) -> Vec<String> {
        self.lists.keys().cloned().collect()
    }

    /// Returns the global access list for inspection/modification.
    pub fn global_list(&self) -> &AccessList {
        &self.global
    }

    /// Returns a mutable reference to the global access list.
    pub fn global_list_mut(&mut self) -> &mut AccessList {
        &mut self.global
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

// ========== SSRF Protection Functions ==========

/// Extract IPv4 address from IPv6-mapped IPv4 address (::ffff:x.x.x.x).
///
/// IPv6-mapped IPv4 addresses are commonly used to bypass SSRF protections
/// that only check IPv4 addresses. This function extracts the underlying
/// IPv4 address for proper validation.
///
/// Returns `Some(Ipv4Addr)` if the address is an IPv6-mapped IPv4, `None` otherwise.
pub fn extract_mapped_ipv4(ip: &IpAddr) -> Option<std::net::Ipv4Addr> {
    match ip {
        IpAddr::V6(v6) => {
            // Check for ::ffff:x.x.x.x format
            let segments = v6.segments();
            // IPv6-mapped IPv4: first 80 bits are 0, next 16 bits are 1s
            // Format: ::ffff:192.168.1.1 = 0:0:0:0:0:ffff:c0a8:0101
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0xffff
            {
                let octets = v6.octets();
                Some(std::net::Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if an IPv4 address is private/internal.
///
/// Private ranges (RFC 1918):
/// - 10.0.0.0/8
/// - 172.16.0.0/12
/// - 192.168.0.0/16
fn is_private_ipv4(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    false
}

/// Check if an IP address is a loopback address.
///
/// Loopback addresses:
/// - IPv4: 127.0.0.0/8
/// - IPv6: ::1
fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 127,
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Check if an IP address is a link-local address.
///
/// Link-local addresses:
/// - IPv4: 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
/// - IPv6: fe80::/10
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(v6) => {
            // fe80::/10
            let segments = v6.segments();
            (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Check if an IP is a cloud metadata endpoint.
///
/// Common cloud metadata IPs:
/// - AWS/Azure/GCP: 169.254.169.254
/// - AWS (newer): 169.254.170.2
/// - Google: metadata.google.internal typically resolves to 169.254.169.254
fn is_cloud_metadata(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 169.254.169.254 (AWS, Azure, GCP)
            if octets == [169, 254, 169, 254] {
                return true;
            }
            // 169.254.170.2 (AWS ECS task metadata)
            if octets == [169, 254, 170, 2] {
                return true;
            }
            false
        }
        IpAddr::V6(_) => false,
    }
}

/// Comprehensive SSRF check for an IP address.
///
/// Returns `true` if the IP address is potentially dangerous for SSRF attacks:
/// - Loopback addresses (127.0.0.0/8, ::1)
/// - Private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Link-local addresses (169.254.0.0/16, fe80::/10)
/// - Cloud metadata endpoints (169.254.169.254, 169.254.170.2)
/// - IPv6-mapped IPv4 addresses that resolve to any of the above
///
/// # Security
/// This function is critical for SSRF prevention. Always call this before
/// making outbound HTTP requests to user-controlled URLs.
///
/// # Example
/// ```
/// use synapse_pingora::access::is_ssrf_target;
/// use std::net::IpAddr;
///
/// // Direct localhost
/// assert!(is_ssrf_target(&"127.0.0.1".parse().unwrap()));
///
/// // IPv6-mapped localhost (SSRF bypass attempt)
/// assert!(is_ssrf_target(&"::ffff:127.0.0.1".parse().unwrap()));
///
/// // Cloud metadata endpoint
/// assert!(is_ssrf_target(&"169.254.169.254".parse().unwrap()));
///
/// // Public IP is safe
/// assert!(!is_ssrf_target(&"8.8.8.8".parse().unwrap()));
/// ```
pub fn is_ssrf_target(ip: &IpAddr) -> bool {
    // First, check if this is an IPv6-mapped IPv4 address
    // This catches SSRF bypass attempts using ::ffff:127.0.0.1
    if let Some(mapped_v4) = extract_mapped_ipv4(ip) {
        // Check the underlying IPv4 address
        if mapped_v4.octets()[0] == 127 {
            tracing::warn!(
                ip = %ip,
                mapped = %mapped_v4,
                "SSRF attempt blocked: IPv6-mapped loopback"
            );
            return true;
        }
        if is_private_ipv4(&mapped_v4) {
            tracing::warn!(
                ip = %ip,
                mapped = %mapped_v4,
                "SSRF attempt blocked: IPv6-mapped private IP"
            );
            return true;
        }
        if is_cloud_metadata(&IpAddr::V4(mapped_v4)) {
            tracing::warn!(
                ip = %ip,
                mapped = %mapped_v4,
                "SSRF attempt blocked: IPv6-mapped cloud metadata"
            );
            return true;
        }
        if is_link_local(&IpAddr::V4(mapped_v4)) {
            tracing::warn!(
                ip = %ip,
                mapped = %mapped_v4,
                "SSRF attempt blocked: IPv6-mapped link-local"
            );
            return true;
        }
        // The mapped IPv4 is public, allow it
        return false;
    }

    // Check direct addresses
    if is_loopback(ip) {
        tracing::debug!(ip = %ip, "SSRF blocked: loopback address");
        return true;
    }

    if is_cloud_metadata(ip) {
        tracing::warn!(ip = %ip, "SSRF blocked: cloud metadata endpoint");
        return true;
    }

    if is_link_local(ip) {
        tracing::debug!(ip = %ip, "SSRF blocked: link-local address");
        return true;
    }

    // Check private IPv4 ranges
    if let IpAddr::V4(v4) = ip {
        if is_private_ipv4(v4) {
            tracing::debug!(ip = %ip, "SSRF blocked: private IPv4");
            return true;
        }
    }

    // Check IPv6 unique local (fc00::/7) and site-local (deprecated but still used)
    if let IpAddr::V6(v6) = ip {
        let segments = v6.segments();
        // fc00::/7 (Unique Local Address)
        if (segments[0] & 0xfe00) == 0xfc00 {
            tracing::debug!(ip = %ip, "SSRF blocked: IPv6 unique local");
            return true;
        }
    }

    false
}

/// Result of SSRF validation with detailed reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfCheckResult {
    /// IP is safe for outbound connections
    Safe,
    /// IP is loopback (127.0.0.0/8 or ::1)
    Loopback,
    /// IP is private RFC1918
    Private,
    /// IP is link-local
    LinkLocal,
    /// IP is cloud metadata endpoint
    CloudMetadata,
    /// IP is IPv6-mapped IPv4 that resolved to a blocked address
    MappedBlocked {
        mapped_v4: std::net::Ipv4Addr,
        reason: &'static str,
    },
    /// IP is IPv6 unique local address
    Ipv6UniqueLocal,
}

impl SsrfCheckResult {
    /// Returns true if the result indicates a blocked address.
    pub fn is_blocked(&self) -> bool {
        !matches!(self, Self::Safe)
    }
}

/// Comprehensive SSRF check with detailed result.
///
/// Similar to `is_ssrf_target` but returns detailed information about why
/// an IP was blocked, useful for logging and debugging.
pub fn check_ssrf(ip: &IpAddr) -> SsrfCheckResult {
    // Check IPv6-mapped IPv4 first
    if let Some(mapped_v4) = extract_mapped_ipv4(ip) {
        if mapped_v4.octets()[0] == 127 {
            return SsrfCheckResult::MappedBlocked {
                mapped_v4,
                reason: "loopback",
            };
        }
        if is_private_ipv4(&mapped_v4) {
            return SsrfCheckResult::MappedBlocked {
                mapped_v4,
                reason: "private",
            };
        }
        if is_cloud_metadata(&IpAddr::V4(mapped_v4)) {
            return SsrfCheckResult::MappedBlocked {
                mapped_v4,
                reason: "cloud_metadata",
            };
        }
        if is_link_local(&IpAddr::V4(mapped_v4)) {
            return SsrfCheckResult::MappedBlocked {
                mapped_v4,
                reason: "link_local",
            };
        }
        return SsrfCheckResult::Safe;
    }

    if is_loopback(ip) {
        return SsrfCheckResult::Loopback;
    }
    if is_cloud_metadata(ip) {
        return SsrfCheckResult::CloudMetadata;
    }
    if is_link_local(ip) {
        return SsrfCheckResult::LinkLocal;
    }
    if let IpAddr::V4(v4) = ip {
        if is_private_ipv4(v4) {
            return SsrfCheckResult::Private;
        }
    }
    if let IpAddr::V6(v6) = ip {
        let segments = v6.segments();
        if (segments[0] & 0xfe00) == 0xfc00 {
            return SsrfCheckResult::Ipv6UniqueLocal;
        }
    }

    SsrfCheckResult::Safe
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
        list.deny("10.0.0.1").unwrap(); // Specific deny - must come first
        list.allow("10.0.0.0/8").unwrap(); // Then allow the broader range
        list.allow("192.168.1.0/24").unwrap();

        assert!(!list.is_allowed(&"10.0.0.1".parse().unwrap())); // Denied by specific rule
        assert!(list.is_allowed(&"10.0.0.2".parse().unwrap())); // Allowed by /8 rule
        assert!(list.is_allowed(&"192.168.1.100".parse().unwrap()));
        assert!(!list.is_allowed(&"8.8.8.8".parse().unwrap())); // Default deny
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

    // ==================== SSRF Protection Tests ====================

    #[test]
    fn test_extract_mapped_ipv4() {
        // IPv6-mapped IPv4 localhost
        let mapped_localhost: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let extracted = extract_mapped_ipv4(&mapped_localhost);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().to_string(), "127.0.0.1");

        // IPv6-mapped private IP
        let mapped_private: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        let extracted = extract_mapped_ipv4(&mapped_private);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().to_string(), "192.168.1.1");

        // Regular IPv6 (not mapped)
        let regular_v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(extract_mapped_ipv4(&regular_v6).is_none());

        // IPv4 (not applicable)
        let v4: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(extract_mapped_ipv4(&v4).is_none());

        // IPv6-mapped cloud metadata
        let mapped_metadata: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        let extracted = extract_mapped_ipv4(&mapped_metadata);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().to_string(), "169.254.169.254");
    }

    #[test]
    fn test_ssrf_loopback() {
        // IPv4 localhost
        assert!(is_ssrf_target(&"127.0.0.1".parse().unwrap()));
        assert!(is_ssrf_target(&"127.0.0.2".parse().unwrap()));
        assert!(is_ssrf_target(&"127.255.255.255".parse().unwrap()));

        // IPv6 localhost
        assert!(is_ssrf_target(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_ssrf_private_ipv4() {
        // 10.0.0.0/8
        assert!(is_ssrf_target(&"10.0.0.1".parse().unwrap()));
        assert!(is_ssrf_target(&"10.255.255.255".parse().unwrap()));

        // 172.16.0.0/12
        assert!(is_ssrf_target(&"172.16.0.1".parse().unwrap()));
        assert!(is_ssrf_target(&"172.31.255.255".parse().unwrap()));
        assert!(!is_ssrf_target(&"172.15.0.1".parse().unwrap())); // Not in range
        assert!(!is_ssrf_target(&"172.32.0.1".parse().unwrap())); // Not in range

        // 192.168.0.0/16
        assert!(is_ssrf_target(&"192.168.0.1".parse().unwrap()));
        assert!(is_ssrf_target(&"192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn test_ssrf_cloud_metadata() {
        // AWS/Azure/GCP metadata
        assert!(is_ssrf_target(&"169.254.169.254".parse().unwrap()));
        // AWS ECS task metadata
        assert!(is_ssrf_target(&"169.254.170.2".parse().unwrap()));
    }

    #[test]
    fn test_ssrf_link_local() {
        // IPv4 link-local
        assert!(is_ssrf_target(&"169.254.0.1".parse().unwrap()));
        assert!(is_ssrf_target(&"169.254.255.255".parse().unwrap()));

        // IPv6 link-local (fe80::/10)
        assert!(is_ssrf_target(&"fe80::1".parse().unwrap()));
        assert!(is_ssrf_target(&"fe80::abcd:1234".parse().unwrap()));
    }

    #[test]
    fn test_ssrf_ipv6_mapped_bypass_attempts() {
        // CRITICAL: These are common SSRF bypass attempts using IPv6-mapped IPv4

        // Mapped localhost
        assert!(is_ssrf_target(&"::ffff:127.0.0.1".parse().unwrap()));

        // Mapped private IPs
        assert!(is_ssrf_target(&"::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_ssrf_target(&"::ffff:172.16.0.1".parse().unwrap()));
        assert!(is_ssrf_target(&"::ffff:192.168.1.1".parse().unwrap()));

        // Mapped cloud metadata (HIGH SEVERITY)
        assert!(is_ssrf_target(&"::ffff:169.254.169.254".parse().unwrap()));

        // Mapped link-local
        assert!(is_ssrf_target(&"::ffff:169.254.1.1".parse().unwrap()));

        // Mapped public IP should be allowed
        assert!(!is_ssrf_target(&"::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ssrf_ipv6_unique_local() {
        // fc00::/7 - Unique Local Address
        assert!(is_ssrf_target(&"fc00::1".parse().unwrap()));
        assert!(is_ssrf_target(&"fd00::1".parse().unwrap()));
        assert!(is_ssrf_target(&"fdab:cdef::1234".parse().unwrap()));
    }

    #[test]
    fn test_ssrf_public_ips_allowed() {
        // Public IPv4
        assert!(!is_ssrf_target(&"8.8.8.8".parse().unwrap()));
        assert!(!is_ssrf_target(&"1.1.1.1".parse().unwrap()));
        assert!(!is_ssrf_target(&"203.0.113.1".parse().unwrap()));

        // Public IPv6
        assert!(!is_ssrf_target(&"2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_ssrf_target(&"2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn test_check_ssrf_detailed() {
        // Loopback
        assert_eq!(
            check_ssrf(&"127.0.0.1".parse().unwrap()),
            SsrfCheckResult::Loopback
        );

        // Private
        assert_eq!(
            check_ssrf(&"10.0.0.1".parse().unwrap()),
            SsrfCheckResult::Private
        );

        // Cloud metadata
        assert_eq!(
            check_ssrf(&"169.254.169.254".parse().unwrap()),
            SsrfCheckResult::CloudMetadata
        );

        // Link-local
        assert_eq!(
            check_ssrf(&"169.254.1.1".parse().unwrap()),
            SsrfCheckResult::LinkLocal
        );

        // IPv6 unique local
        assert_eq!(
            check_ssrf(&"fc00::1".parse().unwrap()),
            SsrfCheckResult::Ipv6UniqueLocal
        );

        // Safe public IP
        assert_eq!(
            check_ssrf(&"8.8.8.8".parse().unwrap()),
            SsrfCheckResult::Safe
        );

        // IPv6-mapped blocked
        let result = check_ssrf(&"::ffff:127.0.0.1".parse().unwrap());
        assert!(result.is_blocked());
        if let SsrfCheckResult::MappedBlocked { mapped_v4, reason } = result {
            assert_eq!(mapped_v4.to_string(), "127.0.0.1");
            assert_eq!(reason, "loopback");
        } else {
            panic!("Expected MappedBlocked");
        }
    }

    #[test]
    fn test_ssrf_check_result_is_blocked() {
        assert!(!SsrfCheckResult::Safe.is_blocked());
        assert!(SsrfCheckResult::Loopback.is_blocked());
        assert!(SsrfCheckResult::Private.is_blocked());
        assert!(SsrfCheckResult::LinkLocal.is_blocked());
        assert!(SsrfCheckResult::CloudMetadata.is_blocked());
        assert!(SsrfCheckResult::Ipv6UniqueLocal.is_blocked());
        assert!(SsrfCheckResult::MappedBlocked {
            mapped_v4: "127.0.0.1".parse().unwrap(),
            reason: "loopback"
        }
        .is_blocked());
    }
}
