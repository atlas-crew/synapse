//! Rule indexing for fast candidate selection.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::waf::rule::{boolean_operands, MatchCondition, MatchValue, WafRule};

/// Method bit masks.
pub const METHOD_GET: u8 = 1 << 0;
pub const METHOD_POST: u8 = 1 << 1;
pub const METHOD_HEAD: u8 = 1 << 2;
pub const METHOD_PUT: u8 = 1 << 3;
pub const METHOD_PATCH: u8 = 1 << 4;

/// Feature requirement flags.
pub const REQ_ARGS: u16 = 1 << 0;
pub const REQ_ARG_ENTRIES: u16 = 1 << 1;
pub const REQ_BODY: u16 = 1 << 2;
pub const REQ_JSON: u16 = 1 << 3;
pub const REQ_RESPONSE: u16 = 1 << 4;
pub const REQ_RESPONSE_BODY: u16 = 1 << 5;
pub const REQ_MULTIPART: u16 = 1 << 6;

/// Rule index for fast candidate selection.
#[derive(Default)]
pub struct RuleIndex {
    pub header_bits: Vec<String>,
    pub rules: Vec<IndexedRule>,
}

/// Indexed rule metadata.
#[derive(Clone, Debug, Default)]
pub struct IndexedRule {
    pub method_mask: Option<u8>,
    pub uri_anchors: Vec<UriAnchor>,
    pub requirements: RuleRequirements,
}

/// URI anchor for prefix/contains matching.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UriAnchor {
    pub kind: UriAnchorKind,
    pub transform: UriTransform,
    pub pattern: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UriAnchorKind {
    Contains,
    Prefix,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UriTransform {
    Raw,
    Lower,
    PercentDecoded,
    PercentDecodedLower,
}

impl UriTransform {
    pub fn apply_lower(self) -> Self {
        match self {
            UriTransform::Raw => UriTransform::Lower,
            UriTransform::Lower => UriTransform::Lower,
            UriTransform::PercentDecoded => UriTransform::PercentDecodedLower,
            UriTransform::PercentDecodedLower => UriTransform::PercentDecodedLower,
        }
    }

    pub fn apply_percent_decode(self) -> Self {
        match self {
            UriTransform::Raw => UriTransform::PercentDecoded,
            UriTransform::Lower => UriTransform::PercentDecodedLower,
            UriTransform::PercentDecoded => UriTransform::PercentDecoded,
            UriTransform::PercentDecodedLower => UriTransform::PercentDecodedLower,
        }
    }
}

/// Rule requirements for feature filtering.
#[derive(Clone, Debug, Default)]
pub struct RuleRequirements {
    pub features: u16,
    pub static_required: Option<bool>,
    pub required_headers_mask: u64,
}

/// Candidate cache for repeated URIs.
#[derive(Default)]
pub struct CandidateCache {
    max_entries: usize,
    tick: u64,
    len: usize,
    by_key: HashMap<CandidateCacheKey, HashMap<String, CandidateCacheEntry>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CandidateCacheKey {
    pub method_bit: u8,
    pub available_features: u16,
    pub is_static: bool,
    pub header_mask: u64,
}

#[derive(Clone, Debug)]
struct CandidateCacheEntry {
    candidates: Arc<[usize]>,
    last_used: u64,
}

impl CandidateCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.min(65_536),
            ..Default::default()
        }
    }

    pub fn clear(&mut self) {
        self.by_key.clear();
        self.len = 0;
        self.tick = 0;
    }

    pub fn get(&mut self, key: &CandidateCacheKey, uri: &str) -> Option<Arc<[usize]>> {
        if self.max_entries == 0 {
            return None;
        }
        self.tick = self.tick.wrapping_add(1);
        let inner = self.by_key.get_mut(key)?;
        let entry = inner.get_mut(uri)?;
        entry.last_used = self.tick;
        Some(entry.candidates.clone())
    }

    pub fn insert(&mut self, key: CandidateCacheKey, uri: String, candidates: Arc<[usize]>) {
        if self.max_entries == 0 {
            return;
        }
        self.tick = self.tick.wrapping_add(1);
        let inner = self.by_key.entry(key).or_default();
        if let Some(existing) = inner.get_mut(uri.as_str()) {
            existing.candidates = candidates;
            existing.last_used = self.tick;
            return;
        }
        inner.insert(
            uri,
            CandidateCacheEntry {
                candidates,
                last_used: self.tick,
            },
        );
        self.len += 1;
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        while self.len > self.max_entries {
            let mut oldest_key: Option<CandidateCacheKey> = None;
            let mut oldest_uri: Option<String> = None;
            let mut oldest_tick = u64::MAX;

            for (key, inner) in &self.by_key {
                for (uri, entry) in inner {
                    if entry.last_used < oldest_tick {
                        oldest_tick = entry.last_used;
                        oldest_key = Some(*key);
                        oldest_uri = Some(uri.clone());
                    }
                }
            }

            let (Some(key), Some(uri)) = (oldest_key, oldest_uri) else {
                break;
            };

            if let Some(inner) = self.by_key.get_mut(&key) {
                if inner.remove(uri.as_str()).is_some() {
                    self.len = self.len.saturating_sub(1);
                }
                if inner.is_empty() {
                    self.by_key.remove(&key);
                }
            }
        }
    }
}

/// Convert method string to bit mask.
pub fn method_to_mask(method: &str) -> Option<u8> {
    if method.eq_ignore_ascii_case("GET") {
        return Some(METHOD_GET);
    }
    if method.eq_ignore_ascii_case("POST") {
        return Some(METHOD_POST);
    }
    if method.eq_ignore_ascii_case("HEAD") {
        return Some(METHOD_HEAD);
    }
    if method.eq_ignore_ascii_case("PUT") {
        return Some(METHOD_PUT);
    }
    if method.eq_ignore_ascii_case("PATCH") {
        return Some(METHOD_PATCH);
    }
    None
}

/// Build rule index from rules.
pub fn build_rule_index(rules: &[WafRule]) -> RuleIndex {
    let mut index = RuleIndex::default();

    // Collect all header fields
    let mut header_names = HashSet::<String>::new();
    for rule in rules {
        for cond in &rule.matches {
            collect_header_fields(cond, &mut header_names);
        }
    }

    let mut header_bits: Vec<String> = header_names.into_iter().collect();
    header_bits.sort();
    if header_bits.len() > 64 {
        header_bits.truncate(64);
    }

    let header_to_bit: HashMap<String, u8> = header_bits
        .iter()
        .enumerate()
        .map(|(idx, header)| (header.clone(), idx as u8))
        .collect();

    index.header_bits = header_bits;
    index.rules.reserve(rules.len());

    for rule in rules {
        let method_mask = extract_rule_method_mask(rule);
        let mut uri_anchors = extract_rule_uri_anchors(rule);
        if !uri_anchors.is_empty() {
            let mut seen = HashSet::new();
            uri_anchors.retain(|a| seen.insert(a.clone()));
        }
        let requirements = extract_rule_requirements(rule, &header_to_bit);
        index.rules.push(IndexedRule {
            method_mask,
            uri_anchors,
            requirements,
        });
    }

    index
}

/// Get candidate rule indices for a request.
pub fn get_candidate_rule_indices(
    index: &RuleIndex,
    method_bit: u8,
    uri: &str,
    available_features: u16,
    is_static: bool,
    header_mask: u64,
    rule_count: usize,
    percent_decode: impl Fn(&str) -> String,
) -> Vec<usize> {
    let mut out = Vec::new();
    let req_method_mask = if method_bit == 0 {
        None
    } else {
        Some(method_bit)
    };

    let mut uri_lower: Option<String> = None;
    let mut uri_percent_decoded: Option<String> = None;
    let mut uri_percent_decoded_lower: Option<String> = None;

    let count = rule_count.min(index.rules.len());
    for (idx, rule) in index.rules.iter().enumerate().take(count) {
        // Check method
        if let Some(rule_method_mask) = rule.method_mask {
            let Some(req_method_mask) = req_method_mask else {
                continue;
            };
            if (rule_method_mask & req_method_mask) == 0 {
                continue;
            }
        }

        // Check requirements
        let requirements = &rule.requirements;
        if (requirements.features & !available_features) != 0 {
            continue;
        }
        if requirements.static_required == Some(true) && !is_static {
            continue;
        }
        if requirements.static_required == Some(false) && is_static {
            continue;
        }
        if (requirements.required_headers_mask & !header_mask) != 0 {
            continue;
        }

        // Check URI anchors
        if !rule.uri_anchors.is_empty() {
            let mut matched = false;
            for anchor in &rule.uri_anchors {
                let haystack: &str = match anchor.transform {
                    UriTransform::Raw => uri,
                    UriTransform::Lower => {
                        if uri_lower.is_none() {
                            uri_lower = Some(uri.to_lowercase());
                        }
                        uri_lower.as_deref().unwrap_or(uri)
                    }
                    UriTransform::PercentDecoded => {
                        if uri_percent_decoded.is_none() {
                            uri_percent_decoded = Some(percent_decode(uri));
                        }
                        uri_percent_decoded.as_deref().unwrap_or(uri)
                    }
                    UriTransform::PercentDecodedLower => {
                        if uri_percent_decoded_lower.is_none() {
                            if uri_percent_decoded.is_none() {
                                uri_percent_decoded = Some(percent_decode(uri));
                            }
                            uri_percent_decoded_lower =
                                Some(uri_percent_decoded.as_deref().unwrap_or(uri).to_lowercase());
                        }
                        uri_percent_decoded_lower.as_deref().unwrap_or(uri)
                    }
                };

                matched = match anchor.kind {
                    UriAnchorKind::Contains => haystack.contains(anchor.pattern.as_str()),
                    UriAnchorKind::Prefix => haystack.starts_with(anchor.pattern.as_str()),
                };
                if matched {
                    break;
                }
            }

            if !matched {
                continue;
            }
        }

        out.push(idx);
    }

    out
}

// Helper functions for index building

fn method_mask_from_match_value(match_value: &MatchValue) -> Option<u8> {
    match match_value {
        MatchValue::Str(s) => method_to_mask(s),
        MatchValue::Arr(items) => {
            let mut mask = 0u8;
            for item in items {
                let Some(s) = item.as_str() else { continue };
                let Some(bit) = method_to_mask(s) else {
                    return None;
                };
                mask |= bit;
            }
            if mask == 0 {
                None
            } else {
                Some(mask)
            }
        }
        _ => None,
    }
}

fn possible_method_mask(condition: &MatchCondition) -> Option<u8> {
    match condition.kind.as_str() {
        "method" => condition
            .match_value
            .as_ref()
            .and_then(method_mask_from_match_value),
        "boolean" => {
            let op = condition.op.as_deref().unwrap_or("and");
            let operands = boolean_operands(condition);
            if operands.is_empty() {
                return None;
            }

            match op {
                "and" => {
                    let mut out: Option<u8> = None;
                    for operand in operands {
                        let Some(mask) = possible_method_mask(operand) else {
                            continue;
                        };
                        out = Some(match out {
                            None => mask,
                            Some(existing) => existing & mask,
                        });
                    }
                    out.filter(|m| *m != 0)
                }
                "or" => {
                    let mut mask = 0u8;
                    for operand in operands {
                        let Some(child_mask) = possible_method_mask(operand) else {
                            return None;
                        };
                        mask |= child_mask;
                    }
                    if mask == 0 {
                        None
                    } else {
                        Some(mask)
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn extract_rule_method_mask(rule: &WafRule) -> Option<u8> {
    let mut out: Option<u8> = None;
    for condition in &rule.matches {
        let Some(mask) = possible_method_mask(condition) else {
            continue;
        };
        out = Some(match out {
            None => mask,
            Some(existing) => existing & mask,
        });
    }
    out.filter(|m| *m != 0)
}

fn extract_rule_uri_anchors(rule: &WafRule) -> Vec<UriAnchor> {
    let mut out = Vec::new();
    for condition in &rule.matches {
        if let Some(mut anchors) = implied_uri_anchors(condition) {
            out.append(&mut anchors);
        }
    }
    out.retain(|a| !a.pattern.is_empty());
    out
}

fn implied_uri_anchors(condition: &MatchCondition) -> Option<Vec<UriAnchor>> {
    match condition.kind.as_str() {
        "uri" => {
            uri_anchors_from_uri_match_value(condition.match_value.as_ref(), UriTransform::Raw)
        }
        "boolean" => {
            let op = condition.op.as_deref().unwrap_or("and");
            let operands = boolean_operands(condition);
            if operands.is_empty() {
                return None;
            }
            match op {
                "and" => {
                    let mut out = Vec::new();
                    for operand in operands {
                        if let Some(mut anchors) = implied_uri_anchors(operand) {
                            out.append(&mut anchors);
                        }
                    }
                    if out.is_empty() {
                        None
                    } else {
                        Some(out)
                    }
                }
                "or" => {
                    let mut out = Vec::new();
                    for operand in operands {
                        let Some(mut anchors) = implied_uri_anchors(operand) else {
                            return None;
                        };
                        out.append(&mut anchors);
                    }
                    if out.is_empty() {
                        None
                    } else {
                        Some(out)
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn uri_anchors_from_uri_match_value(
    match_value: Option<&MatchValue>,
    transform: UriTransform,
) -> Option<Vec<UriAnchor>> {
    match match_value {
        Some(MatchValue::Str(s)) => Some(vec![UriAnchor {
            kind: UriAnchorKind::Contains,
            transform,
            pattern: s.clone(),
        }]),
        Some(MatchValue::Cond(child)) => uri_anchors_from_uri_match(child, transform),
        _ => None,
    }
}

fn uri_anchors_from_uri_match(
    condition: &MatchCondition,
    transform: UriTransform,
) -> Option<Vec<UriAnchor>> {
    match condition.kind.as_str() {
        "contains" => condition
            .match_value
            .as_ref()
            .and_then(|m| m.as_str())
            .map(|pattern| {
                vec![UriAnchor {
                    kind: UriAnchorKind::Contains,
                    transform,
                    pattern: pattern.to_string(),
                }]
            }),
        "starts_with" => condition
            .match_value
            .as_ref()
            .and_then(|m| m.as_str())
            .map(|prefix| {
                vec![UriAnchor {
                    kind: UriAnchorKind::Prefix,
                    transform,
                    pattern: prefix.to_string(),
                }]
            }),
        "equals" => condition
            .match_value
            .as_ref()
            .and_then(|m| m.as_str())
            .map(|pattern| {
                vec![UriAnchor {
                    kind: UriAnchorKind::Contains,
                    transform,
                    pattern: pattern.to_string(),
                }]
            }),
        "to_lowercase" => {
            let child = condition.match_value.as_ref()?.as_cond()?;
            uri_anchors_from_uri_match(child, transform.apply_lower())
        }
        "percent_decode" => {
            let child = condition.match_value.as_ref()?.as_cond()?;
            uri_anchors_from_uri_match(child, transform.apply_percent_decode())
        }
        "boolean" => {
            let op = condition.op.as_deref().unwrap_or("and");
            let operands = boolean_operands(condition);
            if operands.is_empty() {
                return None;
            }
            match op {
                "and" => {
                    let mut out = Vec::new();
                    for operand in operands {
                        if let Some(mut anchors) = uri_anchors_from_uri_match(operand, transform) {
                            out.append(&mut anchors);
                        }
                    }
                    if out.is_empty() {
                        None
                    } else {
                        Some(out)
                    }
                }
                "or" => {
                    let mut out = Vec::new();
                    for operand in operands {
                        let Some(mut anchors) = uri_anchors_from_uri_match(operand, transform)
                        else {
                            return None;
                        };
                        out.append(&mut anchors);
                    }
                    if out.is_empty() {
                        None
                    } else {
                        Some(out)
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

#[derive(Clone, Debug, Default)]
struct RequirementsSet {
    features: u16,
    static_required: Option<bool>,
    required_headers: HashSet<String>,
}

fn merge_and_static(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(left), Some(right)) if left == right => Some(left),
        (None, Some(value)) => Some(value),
        (Some(value), None) => Some(value),
        _ => None,
    }
}

fn req_and(mut left: RequirementsSet, right: RequirementsSet) -> RequirementsSet {
    left.features |= right.features;
    left.required_headers.extend(right.required_headers);
    left.static_required = merge_and_static(left.static_required, right.static_required);
    left
}

fn req_or(left: RequirementsSet, right: RequirementsSet) -> RequirementsSet {
    let mut out = RequirementsSet::default();
    out.features = left.features & right.features;
    out.static_required = match (left.static_required, right.static_required) {
        (Some(l), Some(r)) if l == r => Some(l),
        _ => None,
    };
    out.required_headers = left
        .required_headers
        .intersection(&right.required_headers)
        .cloned()
        .collect();
    out
}

fn extract_rule_requirements(
    rule: &WafRule,
    header_to_bit: &HashMap<String, u8>,
) -> RuleRequirements {
    let mut req = RequirementsSet::default();
    for condition in &rule.matches {
        req = req_and(req, requirements_for_condition(condition));
    }
    let mut required_headers_mask: u64 = 0;
    for header in req.required_headers {
        if let Some(bit) = header_to_bit.get(header.as_str()).copied() {
            if bit < 64 {
                required_headers_mask |= 1u64 << bit;
            }
        }
    }
    RuleRequirements {
        features: req.features,
        static_required: req.static_required,
        required_headers_mask,
    }
}

fn requirements_for_condition(condition: &MatchCondition) -> RequirementsSet {
    match condition.kind.as_str() {
        "boolean" => {
            let op = condition.op.as_deref().unwrap_or("and");
            let operands = boolean_operands(condition);
            if operands.is_empty() {
                return RequirementsSet::default();
            }
            match op {
                "and" => {
                    let mut out = RequirementsSet::default();
                    for operand in operands {
                        out = req_and(out, requirements_for_condition(operand));
                    }
                    out
                }
                "or" => {
                    let mut iter = operands.into_iter();
                    let mut out = requirements_for_condition(iter.next().unwrap());
                    for operand in iter {
                        out = req_or(out, requirements_for_condition(operand));
                    }
                    out
                }
                _ => RequirementsSet::default(),
            }
        }
        "args" => {
            let mut out = RequirementsSet {
                features: REQ_ARGS,
                ..Default::default()
            };
            if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                out = req_and(out, requirements_for_condition(child));
            }
            out
        }
        "named_argument" | "extract_argument" => {
            let mut out = RequirementsSet {
                features: REQ_ARG_ENTRIES,
                ..Default::default()
            };
            if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                out = req_and(out, requirements_for_condition(child));
            }
            out
        }
        "header" => {
            let mut out = RequirementsSet::default();
            if let Some(field) = condition.field.as_deref() {
                out.required_headers.insert(field.to_ascii_lowercase());
            }
            if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                out = req_and(out, requirements_for_condition(child));
            }
            out
        }
        "request_json" => {
            let mut out = RequirementsSet {
                features: REQ_JSON,
                ..Default::default()
            };
            if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                out = req_and(out, requirements_for_condition(child));
            }
            out
        }
        "response_code" => RequirementsSet {
            features: REQ_RESPONSE,
            ..Default::default()
        },
        "response" => {
            let mut out = RequirementsSet {
                features: REQ_RESPONSE_BODY,
                ..Default::default()
            };
            if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                out = req_and(out, requirements_for_condition(child));
            }
            out
        }
        "parse_multipart" => {
            let mut out = RequirementsSet {
                features: REQ_BODY | REQ_MULTIPART,
                ..Default::default()
            };
            if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                out = req_and(out, requirements_for_condition(child));
            }
            out
        }
        "static_content" => {
            let mut out = RequirementsSet::default();
            if let Some(target) = condition.match_value.as_ref().and_then(|m| m.as_bool()) {
                out.static_required = Some(target);
            }
            out
        }
        _ => {
            let mut out = RequirementsSet::default();
            if let Some(child) = condition.match_value.as_ref().and_then(|m| m.as_cond()) {
                out = req_and(out, requirements_for_condition(child));
            }
            out
        }
    }
}

fn collect_header_fields(condition: &MatchCondition, out: &mut HashSet<String>) {
    if condition.kind == "header" {
        if let Some(field) = condition.field.as_deref() {
            out.insert(field.to_ascii_lowercase());
        }
    }

    if let Some(mv) = condition.match_value.as_ref() {
        if let Some(child) = mv.as_cond() {
            collect_header_fields(child, out);
        } else if let Some(arr) = mv.as_arr() {
            for item in arr {
                if let Some(child) = item.as_cond() {
                    collect_header_fields(child, out);
                }
            }
        }
    }

    if let Some(selector) = condition.selector.as_ref() {
        collect_header_fields(selector, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::rule::{MatchCondition, MatchValue, WafRule};

    /// Helper: build a minimal WafRule with a method match condition.
    fn rule_with_method(id: u32, methods: &[&str]) -> WafRule {
        let match_value = if methods.len() == 1 {
            MatchValue::Str(methods[0].to_string())
        } else {
            MatchValue::Arr(
                methods
                    .iter()
                    .map(|m| MatchValue::Str(m.to_string()))
                    .collect(),
            )
        };

        WafRule {
            id,
            description: format!("rule-{}", id),
            contributing_score: None,
            risk: Some(5.0),
            blocking: None,
            matches: vec![MatchCondition {
                kind: "method".to_string(),
                match_value: Some(match_value),
                op: None,
                field: None,
                severity: None,
                pattern_name: None,
                violation_kind: None,
                direction: None,
                field_type: None,
                name: None,
                selector: None,
                cleanup_after: None,
                count: None,
                timeframe: None,
            }],
        }
    }

    /// Helper: build a WafRule with a URI contains anchor.
    fn rule_with_uri_contains(id: u32, pattern: &str) -> WafRule {
        WafRule {
            id,
            description: format!("rule-{}", id),
            contributing_score: None,
            risk: Some(5.0),
            blocking: None,
            matches: vec![MatchCondition {
                kind: "uri".to_string(),
                match_value: Some(MatchValue::Cond(Box::new(MatchCondition {
                    kind: "contains".to_string(),
                    match_value: Some(MatchValue::Str(pattern.to_string())),
                    op: None,
                    field: None,
                    severity: None,
                    pattern_name: None,
                    violation_kind: None,
                    direction: None,
                    field_type: None,
                    name: None,
                    selector: None,
                    cleanup_after: None,
                    count: None,
                    timeframe: None,
                }))),
                op: None,
                field: None,
                severity: None,
                pattern_name: None,
                violation_kind: None,
                direction: None,
                field_type: None,
                name: None,
                selector: None,
                cleanup_after: None,
                count: None,
                timeframe: None,
            }],
        }
    }

    fn noop_percent_decode(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn test_method_to_mask_known_methods() {
        assert_eq!(method_to_mask("GET"), Some(METHOD_GET));
        assert_eq!(method_to_mask("POST"), Some(METHOD_POST));
        assert_eq!(method_to_mask("HEAD"), Some(METHOD_HEAD));
        assert_eq!(method_to_mask("PUT"), Some(METHOD_PUT));
        assert_eq!(method_to_mask("PATCH"), Some(METHOD_PATCH));
    }

    #[test]
    fn test_method_to_mask_case_insensitive() {
        assert_eq!(method_to_mask("get"), Some(METHOD_GET));
        assert_eq!(method_to_mask("Post"), Some(METHOD_POST));
    }

    #[test]
    fn test_method_to_mask_unknown_returns_none() {
        assert_eq!(method_to_mask("DELETE"), None);
        assert_eq!(method_to_mask("OPTIONS"), None);
        assert_eq!(method_to_mask("CONNECT"), None);
    }

    #[test]
    fn test_build_rule_index_method_filtering() {
        let rules = vec![
            rule_with_method(1, &["GET"]),
            rule_with_method(2, &["POST"]),
            rule_with_method(3, &["GET", "POST"]),
        ];

        let index = build_rule_index(&rules);
        assert_eq!(index.rules.len(), 3);

        // Rule 0 (GET only)
        assert_eq!(index.rules[0].method_mask, Some(METHOD_GET));
        // Rule 1 (POST only)
        assert_eq!(index.rules[1].method_mask, Some(METHOD_POST));
        // Rule 2 (GET | POST)
        assert_eq!(index.rules[2].method_mask, Some(METHOD_GET | METHOD_POST));
    }

    #[test]
    fn test_get_candidates_get_method_returns_only_get_rules() {
        let rules = vec![
            rule_with_method(1, &["GET"]),
            rule_with_method(2, &["POST"]),
            rule_with_method(3, &["GET", "POST"]),
        ];

        let index = build_rule_index(&rules);

        let candidates = get_candidate_rule_indices(
            &index,
            METHOD_GET,
            "/any-path",
            0,     // no feature requirements
            false, // not static
            0,     // no header mask
            rules.len(),
            noop_percent_decode,
        );

        // Should include rule 0 (GET) and rule 2 (GET|POST), but NOT rule 1 (POST)
        assert!(candidates.contains(&0), "GET rule should be a candidate");
        assert!(
            !candidates.contains(&1),
            "POST-only rule should NOT be a candidate for GET"
        );
        assert!(
            candidates.contains(&2),
            "GET|POST rule should be a candidate for GET"
        );
    }

    #[test]
    fn test_get_candidates_post_method_returns_only_post_rules() {
        let rules = vec![
            rule_with_method(1, &["GET"]),
            rule_with_method(2, &["POST"]),
            rule_with_method(3, &["GET", "POST"]),
        ];

        let index = build_rule_index(&rules);

        let candidates = get_candidate_rule_indices(
            &index,
            METHOD_POST,
            "/any-path",
            0,
            false,
            0,
            rules.len(),
            noop_percent_decode,
        );

        assert!(
            !candidates.contains(&0),
            "GET-only rule should NOT be a candidate for POST"
        );
        assert!(candidates.contains(&1), "POST rule should be a candidate");
        assert!(
            candidates.contains(&2),
            "GET|POST rule should be a candidate for POST"
        );
    }

    #[test]
    fn test_get_candidates_uri_anchor_filtering() {
        let rules = vec![
            rule_with_uri_contains(1, "/admin"),
            rule_with_uri_contains(2, "/api"),
        ];

        let index = build_rule_index(&rules);

        // Request to /admin/dashboard
        let candidates = get_candidate_rule_indices(
            &index,
            0, // no method filter (unknown method)
            "/admin/dashboard",
            0,
            false,
            0,
            rules.len(),
            noop_percent_decode,
        );
        assert!(
            candidates.contains(&0),
            "/admin rule should match /admin/dashboard"
        );
        assert!(
            !candidates.contains(&1),
            "/api rule should NOT match /admin/dashboard"
        );

        // Request to /api/v1/users
        let candidates = get_candidate_rule_indices(
            &index,
            0,
            "/api/v1/users",
            0,
            false,
            0,
            rules.len(),
            noop_percent_decode,
        );
        assert!(
            !candidates.contains(&0),
            "/admin rule should NOT match /api/v1/users"
        );
        assert!(
            candidates.contains(&1),
            "/api rule should match /api/v1/users"
        );
    }

    #[test]
    fn test_get_candidates_no_method_constraint_matches_all() {
        // A rule without method constraint should match any request method
        let rules = vec![rule_with_uri_contains(1, "/health")];

        let index = build_rule_index(&rules);
        // Method mask is None for the rule (no method condition)
        assert!(index.rules[0].method_mask.is_none());

        let candidates = get_candidate_rule_indices(
            &index,
            METHOD_GET,
            "/health",
            0,
            false,
            0,
            rules.len(),
            noop_percent_decode,
        );
        assert!(
            candidates.contains(&0),
            "rule without method constraint should match GET"
        );

        let candidates = get_candidate_rule_indices(
            &index,
            METHOD_POST,
            "/health",
            0,
            false,
            0,
            rules.len(),
            noop_percent_decode,
        );
        assert!(
            candidates.contains(&0),
            "rule without method constraint should match POST"
        );
    }

    #[test]
    fn test_candidate_cache_insert_and_get() {
        let mut cache = CandidateCache::new(10);
        let key = CandidateCacheKey {
            method_bit: METHOD_GET,
            available_features: 0,
            is_static: false,
            header_mask: 0,
        };
        let candidates: Arc<[usize]> = Arc::from(vec![0, 2, 5].as_slice());
        cache.insert(key, "/test".to_string(), candidates.clone());

        let result = cache.get(&key, "/test");
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_ref(), &[0, 2, 5]);
    }

    #[test]
    fn test_candidate_cache_eviction() {
        let mut cache = CandidateCache::new(2);
        let key = CandidateCacheKey {
            method_bit: METHOD_GET,
            available_features: 0,
            is_static: false,
            header_mask: 0,
        };

        cache.insert(key, "/a".to_string(), Arc::from(vec![0].as_slice()));
        cache.insert(key, "/b".to_string(), Arc::from(vec![1].as_slice()));
        cache.insert(key, "/c".to_string(), Arc::from(vec![2].as_slice()));

        // Cache has capacity 2, so /a should have been evicted
        assert!(cache.get(&key, "/a").is_none());
        // /b and /c should still exist
        assert!(cache.get(&key, "/b").is_some());
        assert!(cache.get(&key, "/c").is_some());
    }
}
