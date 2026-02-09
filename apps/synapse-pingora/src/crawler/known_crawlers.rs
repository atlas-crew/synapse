//! Known legitimate crawler definitions.

/// Definition of a legitimate crawler/bot.
#[derive(Debug, Clone)]
pub struct CrawlerDefinition {
    /// Crawler name
    pub name: &'static str,
    /// User agent regex pattern
    pub user_agent_pattern: &'static str,
    /// Reverse DNS regex pattern for verification
    pub reverse_dns_pattern: &'static str,
    /// Optional IP ranges (CIDR notation)
    pub ip_ranges: Option<&'static [&'static str]>,
    /// Whether DNS verification is required
    pub verification_required: bool,
}

/// Known legitimate crawlers.
pub static KNOWN_CRAWLERS: &[CrawlerDefinition] = &[
    // Major search engines (verification required)
    CrawlerDefinition {
        name: "Googlebot",
        user_agent_pattern: r"(?i)googlebot|google-inspectiontool|storebot-google",
        reverse_dns_pattern: r"(?i)\.(googlebot|google)\.com$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "Bingbot",
        user_agent_pattern: r"(?i)bingbot|msnbot|bingpreview",
        reverse_dns_pattern: r"(?i)\.search\.msn\.com$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "Baiduspider",
        user_agent_pattern: r"(?i)baiduspider",
        reverse_dns_pattern: r"(?i)\.crawl\.baidu\.(com|jp)$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "YandexBot",
        user_agent_pattern: r"(?i)yandexbot",
        reverse_dns_pattern: r"(?i)\.yandex\.(com|ru|net)$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "DuckDuckBot",
        user_agent_pattern: r"(?i)duckduckbot",
        reverse_dns_pattern: r"(?i)\.duckduckgo\.com$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "Slurp",
        user_agent_pattern: r"(?i)slurp",
        reverse_dns_pattern: r"(?i)\.crawl\.yahoo\.net$",
        ip_ranges: None,
        verification_required: true,
    },
    // Social media crawlers (verification required)
    CrawlerDefinition {
        name: "Facebookbot",
        user_agent_pattern: r"(?i)facebookexternalhit",
        reverse_dns_pattern: r"(?i)\.(facebook|fbsv)\.com$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "Twitterbot",
        user_agent_pattern: r"(?i)twitterbot",
        reverse_dns_pattern: r"(?i)\.twitter\.com$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "LinkedInBot",
        user_agent_pattern: r"(?i)linkedinbot",
        reverse_dns_pattern: r"(?i)\.linkedin\.com$",
        ip_ranges: None,
        verification_required: true,
    },
    CrawlerDefinition {
        name: "Applebot",
        user_agent_pattern: r"(?i)applebot",
        reverse_dns_pattern: r"(?i)\.applebot\.apple\.com$",
        ip_ranges: None,
        verification_required: true,
    },
    // SEO tools (verification not required - trust UA)
    CrawlerDefinition {
        name: "AhrefsBot",
        user_agent_pattern: r"(?i)ahrefsbot",
        reverse_dns_pattern: r"(?i)\.ahrefs\.com$",
        ip_ranges: None,
        verification_required: false,
    },
    CrawlerDefinition {
        name: "SemrushBot",
        user_agent_pattern: r"(?i)semrushbot",
        reverse_dns_pattern: r"(?i)\.semrush\.com$",
        ip_ranges: None,
        verification_required: false,
    },
    CrawlerDefinition {
        name: "MJ12bot",
        user_agent_pattern: r"(?i)mj12bot",
        reverse_dns_pattern: r"(?i)\.majestic12\.co\.uk$",
        ip_ranges: None,
        verification_required: false,
    },
    CrawlerDefinition {
        name: "DotBot",
        user_agent_pattern: r"(?i)dotbot",
        reverse_dns_pattern: r"(?i)\.opensiteexplorer\.com$",
        ip_ranges: None,
        verification_required: false,
    },
    CrawlerDefinition {
        name: "ScreamingFrog",
        user_agent_pattern: r"(?i)screaming frog seo spider",
        reverse_dns_pattern: r".*", // No DNS verification
        ip_ranges: None,
        verification_required: false,
    },
    // Communication platform bots
    CrawlerDefinition {
        name: "Pinterestbot",
        user_agent_pattern: r"(?i)pinterest",
        reverse_dns_pattern: r"(?i)\.pinterest\.com$",
        ip_ranges: None,
        verification_required: false,
    },
    CrawlerDefinition {
        name: "Slackbot",
        user_agent_pattern: r"(?i)slackbot|slackbot-linkexpanding",
        reverse_dns_pattern: r"(?i)\.slack\.com$",
        ip_ranges: None,
        verification_required: false,
    },
    CrawlerDefinition {
        name: "Discordbot",
        user_agent_pattern: r"(?i)discordbot",
        reverse_dns_pattern: r"(?i)\.discord\.com$",
        ip_ranges: None,
        verification_required: false,
    },
];
