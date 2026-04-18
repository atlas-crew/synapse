//! Rule storage and conversion helpers for synapse-pingora.
//!
//! Supports both native WAF rule JSON and the Signal Horizon custom rule format.

use crate::waf::{MatchCondition, MatchValue, WafRule};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMetadata {
    pub external_id: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
    pub conditions: Option<Vec<CustomRuleCondition>>,
    pub actions: Option<Vec<CustomRuleAction>>,
    pub ttl: Option<u64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub hit_count: Option<u64>,
    pub last_hit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRule {
    #[serde(flatten)]
    pub rule: WafRule,
    #[serde(default)]
    pub meta: RuleMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleCondition {
    pub field: String,
    pub operator: String,
    #[serde(default)]
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleInput {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default)]
    pub conditions: Vec<CustomRuleCondition>,
    #[serde(default)]
    pub actions: Vec<CustomRuleAction>,
    #[serde(default)]
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomRuleUpdate {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<u32>,
    pub conditions: Option<Vec<CustomRuleCondition>>,
    pub actions: Option<Vec<CustomRuleAction>>,
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleView {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub enabled: bool,
    pub priority: u32,
    pub conditions: Vec<CustomRuleCondition>,
    pub actions: Vec<CustomRuleAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(rename = "hitCount")]
    pub hit_count: u64,
    #[serde(rename = "lastHit", skip_serializing_if = "Option::is_none")]
    pub last_hit: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

fn default_enabled() -> bool {
    true
}

fn default_priority() -> u32 {
    100
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn derive_rule_id(external_id: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(external_id.as_bytes());
    let digest = hasher.finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    if value == 0 {
        1
    } else {
        value
    }
}

pub fn rule_identifier(rule: &StoredRule) -> String {
    rule.meta
        .external_id
        .clone()
        .unwrap_or_else(|| rule.rule.id.to_string())
}

pub fn matches_rule_id(rule: &StoredRule, rule_id: &str) -> bool {
    if let Some(external) = rule.meta.external_id.as_deref() {
        return external == rule_id;
    }
    rule.rule.id.to_string() == rule_id
}

fn normalize_rule_type(rule_type: &str) -> String {
    rule_type.trim().to_ascii_uppercase()
}

fn default_rule_type(rule: &WafRule) -> String {
    if rule.blocking.unwrap_or(false) {
        "BLOCK".to_string()
    } else {
        "MONITOR".to_string()
    }
}

fn default_actions(rule: &WafRule) -> Vec<CustomRuleAction> {
    vec![CustomRuleAction {
        action_type: if rule.blocking.unwrap_or(false) {
            "block".to_string()
        } else {
            "log".to_string()
        },
        params: None,
    }]
}

fn apply_meta_overrides(meta: &mut RuleMetadata, value: &serde_json::Value) {
    if let Some(created_at) = value.get("createdAt").and_then(|v| v.as_str()) {
        meta.created_at = Some(created_at.to_string());
    } else if let Some(created_at) = value.get("created_at").and_then(|v| v.as_str()) {
        meta.created_at = Some(created_at.to_string());
    }

    if let Some(updated_at) = value.get("updatedAt").and_then(|v| v.as_str()) {
        meta.updated_at = Some(updated_at.to_string());
    } else if let Some(updated_at) = value.get("updated_at").and_then(|v| v.as_str()) {
        meta.updated_at = Some(updated_at.to_string());
    }

    if let Some(hit_count) = value.get("hitCount").and_then(|v| v.as_u64()) {
        meta.hit_count = Some(hit_count);
    } else if let Some(hit_count) = value.get("hit_count").and_then(|v| v.as_u64()) {
        meta.hit_count = Some(hit_count);
    }

    if let Some(last_hit) = value.get("lastHit").and_then(|v| v.as_str()) {
        meta.last_hit = Some(last_hit.to_string());
    } else if let Some(last_hit) = value.get("last_hit").and_then(|v| v.as_str()) {
        meta.last_hit = Some(last_hit.to_string());
    }
}

fn risk_for_type(rule_type: &str, actions: &[CustomRuleAction]) -> f64 {
    if actions
        .iter()
        .any(|a| a.action_type.eq_ignore_ascii_case("block"))
    {
        return 95.0;
    }
    if rule_type.eq_ignore_ascii_case("block") {
        return 90.0;
    }
    if rule_type.eq_ignore_ascii_case("challenge") {
        return 70.0;
    }
    if rule_type.eq_ignore_ascii_case("rate_limit") {
        return 60.0;
    }
    15.0
}

fn blocking_for_rule(rule_type: &str, actions: &[CustomRuleAction]) -> bool {
    if actions
        .iter()
        .any(|a| a.action_type.eq_ignore_ascii_case("block"))
    {
        return true;
    }
    rule_type.eq_ignore_ascii_case("block")
}

fn scalar_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn value_to_match_value(value: &serde_json::Value) -> Option<MatchValue> {
    match value {
        serde_json::Value::String(s) => Some(MatchValue::Str(s.clone())),
        serde_json::Value::Number(n) => n.as_f64().map(MatchValue::Num),
        serde_json::Value::Bool(b) => Some(MatchValue::Bool(*b)),
        serde_json::Value::Array(arr) => {
            let mut converted = Vec::new();
            for item in arr {
                if let Some(v) = value_to_match_value(item) {
                    converted.push(v);
                }
            }
            Some(MatchValue::Arr(converted))
        }
        _ => None,
    }
}

fn base_match_condition(kind: &str, match_value: Option<MatchValue>) -> MatchCondition {
    MatchCondition {
        kind: kind.to_string(),
        match_value,
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
    }
}

fn negate_condition(condition: MatchCondition) -> MatchCondition {
    MatchCondition {
        kind: "boolean".to_string(),
        match_value: Some(MatchValue::Arr(vec![MatchValue::Cond(Box::new(condition))])),
        op: Some("not".to_string()),
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
    }
}

fn operator_condition(operator: &str, value: &serde_json::Value) -> Result<MatchCondition, String> {
    match operator {
        "eq" => {
            let match_value = scalar_to_string(value)
                .map(MatchValue::Str)
                .ok_or_else(|| "eq operator requires scalar value".to_string())?;
            Ok(base_match_condition("equals", Some(match_value)))
        }
        "contains" => {
            let match_value = scalar_to_string(value)
                .map(MatchValue::Str)
                .ok_or_else(|| "contains operator requires scalar value".to_string())?;
            Ok(base_match_condition("contains", Some(match_value)))
        }
        "matches" => {
            let match_value = scalar_to_string(value)
                .map(MatchValue::Str)
                .ok_or_else(|| "matches operator requires scalar value".to_string())?;
            Ok(base_match_condition("regex", Some(match_value)))
        }
        "gt" | "lt" => {
            let number = match value {
                serde_json::Value::Number(n) => n.as_f64(),
                serde_json::Value::String(s) => s.parse::<f64>().ok(),
                _ => None,
            }
            .ok_or_else(|| "compare operator requires numeric value".to_string())?;
            let mut cond = base_match_condition("compare", Some(MatchValue::Num(number)));
            cond.op = Some(operator.to_string());
            Ok(cond)
        }
        "in" => {
            let arr = match value {
                serde_json::Value::Array(items) => items,
                _ => return Err("in operator requires array value".to_string()),
            };
            let mut converted = Vec::new();
            for item in arr {
                if let Some(value) = scalar_to_string(item) {
                    converted.push(MatchValue::Str(value));
                }
            }
            if converted.is_empty() {
                return Err("in operator requires non-empty array".to_string());
            }
            Ok(base_match_condition(
                "hashset",
                Some(MatchValue::Arr(converted)),
            ))
        }
        "ne" => Err("ne operator not supported for WAF rules".to_string()),
        other => Err(format!("Unsupported operator: {}", other)),
    }
}

fn field_condition(
    field: &str,
    operator: &str,
    value: &serde_json::Value,
) -> Result<MatchCondition, String> {
    if operator == "ne" {
        let condition = field_condition(field, "eq", value)?;
        return Ok(negate_condition(condition));
    }

    let field_lower = field.to_lowercase();
    let op_condition = operator_condition(operator, value)?;

    if field_lower == "method" {
        if operator == "eq" {
            if let Some(method) = scalar_to_string(value) {
                return Ok(base_match_condition(
                    "method",
                    Some(MatchValue::Str(method)),
                ));
            }
        }
        if operator == "in" {
            if let serde_json::Value::Array(items) = value {
                let mut methods = Vec::new();
                for item in items {
                    if let Some(method) = scalar_to_string(item) {
                        methods.push(MatchValue::Str(method));
                    }
                }
                if !methods.is_empty() {
                    return Ok(base_match_condition(
                        "method",
                        Some(MatchValue::Arr(methods)),
                    ));
                }
            }
        }
        return Ok(base_match_condition(
            "method",
            Some(MatchValue::Cond(Box::new(op_condition))),
        ));
    }

    if matches!(field_lower.as_str(), "uri" | "path" | "url") {
        return Ok(base_match_condition(
            "uri",
            Some(MatchValue::Cond(Box::new(op_condition))),
        ));
    }

    if field_lower == "args" || field_lower == "query" {
        return Ok(base_match_condition(
            "args",
            Some(MatchValue::Cond(Box::new(op_condition))),
        ));
    }

    if let Some(name) = field_lower.strip_prefix("arg.") {
        let mut cond = base_match_condition(
            "named_argument",
            Some(MatchValue::Cond(Box::new(op_condition))),
        );
        cond.name = Some(name.to_string());
        return Ok(cond);
    }

    if let Some(name) = field_lower.strip_prefix("param.") {
        let mut cond = base_match_condition(
            "named_argument",
            Some(MatchValue::Cond(Box::new(op_condition))),
        );
        cond.name = Some(name.to_string());
        return Ok(cond);
    }

    if let Some(name) = field_lower.strip_prefix("header.") {
        let mut cond =
            base_match_condition("header", Some(MatchValue::Cond(Box::new(op_condition))));
        cond.field = Some(name.to_string());
        cond.direction = Some("c2s".to_string());
        return Ok(cond);
    }

    if let Some(name) = field_lower.strip_prefix("header:") {
        let mut cond =
            base_match_condition("header", Some(MatchValue::Cond(Box::new(op_condition))));
        cond.field = Some(name.to_string());
        cond.direction = Some("c2s".to_string());
        return Ok(cond);
    }

    if field_lower == "body" || field_lower == "request" {
        return Ok(base_match_condition(
            "request",
            Some(MatchValue::Cond(Box::new(op_condition))),
        ));
    }

    let mut cond = base_match_condition("header", Some(MatchValue::Cond(Box::new(op_condition))));
    cond.field = Some(field.to_string());
    cond.direction = Some("c2s".to_string());
    Ok(cond)
}

fn conditions_to_matches(
    conditions: &[CustomRuleCondition],
) -> Result<Vec<MatchCondition>, String> {
    let mut matches = Vec::new();
    for condition in conditions {
        matches.push(field_condition(
            condition.field.as_str(),
            condition.operator.as_str(),
            &condition.value,
        )?);
    }
    if matches.is_empty() {
        return Err("custom rule must include at least one condition".to_string());
    }
    Ok(matches)
}

impl StoredRule {
    pub fn from_custom(custom: CustomRuleInput) -> Result<Self, String> {
        let matches = conditions_to_matches(&custom.conditions)?;
        let rule_id = derive_rule_id(&custom.id);
        let risk = risk_for_type(&custom.rule_type, &custom.actions);
        let blocking = blocking_for_rule(&custom.rule_type, &custom.actions);

        let rule = WafRule {
            id: rule_id,
            description: custom.name.clone(),
            contributing_score: None,
            risk: Some(risk),
            blocking: Some(blocking),
            matches,
        };

        let now = now_rfc3339();
        let meta = RuleMetadata {
            external_id: Some(custom.id),
            name: Some(custom.name),
            rule_type: Some(custom.rule_type),
            enabled: Some(custom.enabled),
            priority: Some(custom.priority),
            conditions: Some(custom.conditions),
            actions: Some(custom.actions),
            ttl: custom.ttl,
            created_at: Some(now.clone()),
            updated_at: Some(now),
            hit_count: Some(0),
            last_hit: None,
        };

        Ok(Self { rule, meta })
    }
}

impl RuleView {
    pub fn from_stored(rule: &StoredRule) -> Self {
        let meta = &rule.meta;
        let id = rule_identifier(rule);
        let name = meta
            .name
            .clone()
            .unwrap_or_else(|| rule.rule.description.clone());
        let rule_type = meta
            .rule_type
            .as_deref()
            .map(normalize_rule_type)
            .unwrap_or_else(|| default_rule_type(&rule.rule));
        let enabled = meta.enabled.unwrap_or(true);
        let priority = meta.priority.unwrap_or(100);
        let conditions = meta.conditions.clone().unwrap_or_default();
        let actions = meta
            .actions
            .clone()
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| default_actions(&rule.rule));
        let ttl = meta.ttl;
        let hit_count = meta.hit_count.unwrap_or(0);
        let last_hit = meta.last_hit.clone();
        let created_at = meta.created_at.clone().unwrap_or_else(now_rfc3339);
        let updated_at = meta
            .updated_at
            .clone()
            .unwrap_or_else(|| created_at.clone());

        Self {
            id,
            name,
            rule_type,
            enabled,
            priority,
            conditions,
            actions,
            ttl,
            hit_count,
            last_hit,
            created_at,
            updated_at,
        }
    }
}

pub fn parse_rule_value(value: serde_json::Value) -> Result<StoredRule, String> {
    if value.get("matches").is_some() {
        let rule: WafRule = serde_json::from_value(value.clone())
            .map_err(|err| format!("invalid waf rule: {}", err))?;
        let mut meta = RuleMetadata::default();
        meta.external_id = Some(rule.id.to_string());
        meta.name = Some(rule.description.clone());
        meta.rule_type = Some(default_rule_type(&rule));
        meta.enabled = Some(true);
        meta.priority = Some(100);
        meta.actions = Some(default_actions(&rule));
        meta.created_at = Some(now_rfc3339());
        meta.updated_at = Some(now_rfc3339());
        apply_meta_overrides(&mut meta, &value);
        Ok(StoredRule { rule, meta })
    } else {
        let custom: CustomRuleInput = serde_json::from_value(value.clone())
            .map_err(|err| format!("invalid custom rule: {}", err))?;
        let mut stored = StoredRule::from_custom(custom)?;
        apply_meta_overrides(&mut stored.meta, &value);
        Ok(stored)
    }
}

pub fn parse_rules_payload(value: serde_json::Value) -> Result<Vec<StoredRule>, String> {
    let serde_json::Value::Array(items) = value else {
        return Err("rules payload must be an array".to_string());
    };

    let mut rules = Vec::with_capacity(items.len());
    for item in items {
        rules.push(parse_rule_value(item)?);
    }
    Ok(rules)
}

pub fn merge_rule_update(
    existing: &StoredRule,
    update: CustomRuleUpdate,
) -> Result<StoredRule, String> {
    let mut meta = existing.meta.clone();
    if meta.created_at.is_none() {
        meta.created_at = Some(now_rfc3339());
    }
    meta.updated_at = Some(now_rfc3339());

    if let Some(name) = update.name {
        meta.name = Some(name);
    }
    if let Some(rule_type) = update.rule_type {
        meta.rule_type = Some(rule_type);
    }
    if let Some(enabled) = update.enabled {
        meta.enabled = Some(enabled);
    }
    if let Some(priority) = update.priority {
        meta.priority = Some(priority);
    }
    if let Some(conditions) = update.conditions {
        meta.conditions = Some(conditions);
    }
    if let Some(actions) = update.actions {
        meta.actions = Some(actions);
    }
    if let Some(ttl) = update.ttl {
        meta.ttl = Some(ttl);
    }

    let has_conditions = meta
        .conditions
        .as_ref()
        .map(|items| !items.is_empty())
        .unwrap_or(false);

    if has_conditions {
        let external_id = meta
            .external_id
            .clone()
            .unwrap_or_else(|| existing.rule.id.to_string());
        let name = meta
            .name
            .clone()
            .unwrap_or_else(|| existing.rule.description.clone());
        let rule_type = meta
            .rule_type
            .clone()
            .unwrap_or_else(|| default_rule_type(&existing.rule));
        let enabled = meta.enabled.unwrap_or(true);
        let priority = meta.priority.unwrap_or(100);
        let conditions = meta.conditions.clone().unwrap_or_default();
        let actions = meta
            .actions
            .clone()
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| default_actions(&existing.rule));

        let custom = CustomRuleInput {
            id: external_id,
            name,
            rule_type,
            enabled,
            priority,
            conditions,
            actions,
            ttl: meta.ttl,
        };

        let mut stored = StoredRule::from_custom(custom)?;
        stored.meta.created_at = meta.created_at.clone();
        stored.meta.updated_at = meta.updated_at.clone();
        stored.meta.hit_count = meta.hit_count;
        stored.meta.last_hit = meta.last_hit.clone();
        return Ok(stored);
    }

    let rule_type = meta
        .rule_type
        .clone()
        .unwrap_or_else(|| default_rule_type(&existing.rule));
    let actions = meta
        .actions
        .clone()
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| default_actions(&existing.rule));

    let mut stored = existing.clone();
    stored.meta = meta.clone();
    stored.rule.description = meta
        .name
        .clone()
        .unwrap_or_else(|| existing.rule.description.clone());
    stored.rule.risk = Some(risk_for_type(&rule_type, &actions));
    stored.rule.blocking = Some(blocking_for_rule(&rule_type, &actions));

    Ok(stored)
}

pub fn rules_hash(rules: &[StoredRule]) -> String {
    let mut views: Vec<RuleView> = rules.iter().map(RuleView::from_stored).collect();
    views.sort_by(|a, b| a.id.cmp(&b.id));

    let payload = serde_json::to_string(&views).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}
