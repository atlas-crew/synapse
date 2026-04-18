//! Rule definitions and deserialization.

use serde::{Deserialize, Serialize};

/// WAF rule definition.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct WafRule {
    pub id: u32,
    #[allow(dead_code)]
    pub description: String,
    #[serde(default)]
    pub contributing_score: Option<f64>,
    #[serde(default)]
    pub risk: Option<f64>,
    #[serde(default)]
    pub blocking: Option<bool>,
    pub matches: Vec<MatchCondition>,
}

impl WafRule {
    /// Get the effective risk score for this rule.
    pub fn effective_risk(&self) -> f64 {
        if let Some(r) = self.risk {
            if r.is_finite() {
                return r;
            }
        }
        if let Some(r) = self.contributing_score {
            if r.is_finite() {
                return r;
            }
        }
        0.0
    }
}

/// Match condition for rule evaluation.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct MatchCondition {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "match", default)]
    pub match_value: Option<MatchValue>,
    #[serde(default)]
    pub op: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub pattern_name: Option<String>,
    #[serde(default)]
    pub violation_kind: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub field_type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub selector: Option<Box<MatchCondition>>,
    #[serde(default)]
    #[allow(dead_code)]
    pub cleanup_after: Option<u64>,
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub timeframe: Option<u64>,
}

/// Match value variants.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum MatchValue {
    Str(String),
    Num(f64),
    Bool(bool),
    Arr(Vec<MatchValue>),
    Cond(Box<MatchCondition>),
    #[allow(dead_code)]
    Json(serde_json::Value),
}

impl MatchValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MatchValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_num(&self) -> Option<f64> {
        match self {
            MatchValue::Num(n) => Some(*n),
            MatchValue::Str(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            MatchValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[MatchValue]> {
        match self {
            MatchValue::Arr(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    pub fn as_cond(&self) -> Option<&MatchCondition> {
        match self {
            MatchValue::Cond(c) => Some(c.as_ref()),
            _ => None,
        }
    }
}

/// Get boolean operands from a condition.
pub fn boolean_operands(condition: &MatchCondition) -> Vec<&MatchCondition> {
    let Some(match_value) = condition.match_value.as_ref() else {
        return Vec::new();
    };
    if let Some(items) = match_value.as_arr() {
        return items.iter().filter_map(|v| v.as_cond()).collect();
    }
    match_value.as_cond().map(|c| vec![c]).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let json = r#"{
            "id": 1,
            "description": "Test rule",
            "risk": 10.0,
            "blocking": true,
            "matches": [
                {"type": "method", "match": "GET"}
            ]
        }"#;

        let rule: WafRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.id, 1);
        assert_eq!(rule.effective_risk(), 10.0);
        assert_eq!(rule.blocking, Some(true));
        assert_eq!(rule.matches.len(), 1);
    }

    #[test]
    fn test_parse_nested_condition() {
        let json = r#"{
            "id": 2,
            "description": "Nested rule",
            "matches": [
                {
                    "type": "uri",
                    "match": {
                        "type": "contains",
                        "match": "admin"
                    }
                }
            ]
        }"#;

        let rule: WafRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.matches[0].kind, "uri");
        let inner = rule.matches[0]
            .match_value
            .as_ref()
            .unwrap()
            .as_cond()
            .unwrap();
        assert_eq!(inner.kind, "contains");
    }
}
