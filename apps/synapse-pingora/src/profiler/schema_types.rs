//! Core types for API schema learning and validation.
//!
//! Provides type definitions for:
//! - Field types and patterns
//! - Schema structures for endpoints
//! - Violation tracking
//!
//! ## Memory Budget
//! ~200 bytes per field schema base + nested schemas

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// FieldType - JSON value types
// ============================================================================

/// JSON field type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// String value
    String,
    /// Numeric value (integer or float)
    Number,
    /// Boolean value
    Boolean,
    /// Null value
    Null,
    /// Nested object
    Object,
    /// Array of values
    Array,
    /// Mixed types observed (schema ambiguity)
    Mixed,
}

impl FieldType {
    /// Infer type from a serde_json Value.
    #[inline]
    pub fn from_json_value(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => FieldType::Null,
            serde_json::Value::Bool(_) => FieldType::Boolean,
            serde_json::Value::Number(_) => FieldType::Number,
            serde_json::Value::String(_) => FieldType::String,
            serde_json::Value::Array(_) => FieldType::Array,
            serde_json::Value::Object(_) => FieldType::Object,
        }
    }

    /// Get the field type as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            FieldType::String => "string",
            FieldType::Number => "number",
            FieldType::Boolean => "boolean",
            FieldType::Null => "null",
            FieldType::Object => "object",
            FieldType::Array => "array",
            FieldType::Mixed => "mixed",
        }
    }
}

// ============================================================================
// PatternType - Common string patterns
// ============================================================================

/// Common string value patterns for semantic understanding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatternType {
    /// UUID format (8-4-4-4-12 hex)
    Uuid,
    /// Email address
    Email,
    /// ISO 8601 datetime
    IsoDate,
    /// HTTP/HTTPS URL
    Url,
    /// IPv4 address
    Ipv4,
    /// IPv6 address
    Ipv6,
    /// JWT token (three dot-separated base64 segments)
    Jwt,
    /// MongoDB ObjectId (24 hex chars)
    ObjectId,
    /// Generic hex string (16+ chars)
    HexString,
    /// Phone number (various formats)
    Phone,
    /// Credit card number pattern
    CreditCard,
}

impl PatternType {
    /// Get the pattern name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternType::Uuid => "uuid",
            PatternType::Email => "email",
            PatternType::IsoDate => "iso-date",
            PatternType::Url => "url",
            PatternType::Ipv4 => "ipv4",
            PatternType::Ipv6 => "ipv6",
            PatternType::Jwt => "jwt",
            PatternType::ObjectId => "objectId",
            PatternType::HexString => "hex",
            PatternType::Phone => "phone",
            PatternType::CreditCard => "credit-card",
        }
    }
}

// ============================================================================
// FieldSchema - Per-field schema information
// ============================================================================

/// Schema information for a single field.
///
/// Tracks type frequencies, constraints, and nested schemas for objects.
/// Memory: ~200 bytes base + nested schemas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    /// Field name (may be dotted for nested fields)
    pub name: String,

    /// Type frequency map (type -> occurrence count)
    pub types: HashMap<FieldType, u32>,

    /// Whether null values have been observed
    pub nullable: bool,

    /// Total observations of this field
    pub seen_count: u32,

    // String constraints
    /// Minimum string length observed
    pub min_length: Option<u32>,
    /// Maximum string length observed
    pub max_length: Option<u32>,
    /// Detected string pattern (uuid, email, etc.)
    pub pattern: Option<PatternType>,

    // Number constraints
    /// Minimum numeric value observed
    pub min_value: Option<f64>,
    /// Maximum numeric value observed
    pub max_value: Option<f64>,

    // Array constraints
    /// Types observed in array items
    pub array_item_types: Option<Vec<FieldType>>,

    // Nested object schema
    /// Schema for nested object fields
    pub object_schema: Option<HashMap<String, FieldSchema>>,
}

impl FieldSchema {
    /// Create a new field schema.
    pub fn new(name: String) -> Self {
        Self {
            name,
            types: HashMap::with_capacity(2),
            nullable: false,
            seen_count: 0,
            min_length: None,
            max_length: None,
            pattern: None,
            min_value: None,
            max_value: None,
            array_item_types: None,
            object_schema: None,
        }
    }

    /// Record a type observation.
    #[inline]
    pub fn record_type(&mut self, field_type: FieldType) {
        *self.types.entry(field_type).or_insert(0) += 1;
        self.seen_count += 1;

        if field_type == FieldType::Null {
            self.nullable = true;
        }
    }

    /// Update string constraints.
    #[inline]
    pub fn update_string_constraints(&mut self, length: u32, pattern: Option<PatternType>) {
        self.min_length = Some(self.min_length.map_or(length, |min| min.min(length)));
        self.max_length = Some(self.max_length.map_or(length, |max| max.max(length)));

        // Only set pattern if not already set (first observation wins)
        if self.pattern.is_none() {
            self.pattern = pattern;
        }
    }

    /// Update numeric constraints.
    #[inline]
    pub fn update_number_constraints(&mut self, value: f64) {
        self.min_value = Some(self.min_value.map_or(value, |min| min.min(value)));
        self.max_value = Some(self.max_value.map_or(value, |max| max.max(value)));
    }

    /// Add array item type.
    #[inline]
    pub fn add_array_item_type(&mut self, item_type: FieldType) {
        let types = self.array_item_types.get_or_insert_with(Vec::new);
        if !types.contains(&item_type) {
            types.push(item_type);
        }
    }

    /// Get the dominant (most frequent) type.
    pub fn dominant_type(&self) -> FieldType {
        self.types
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(t, _)| *t)
            .unwrap_or(FieldType::Mixed)
    }

    /// Get the type frequency ratio for a given type.
    pub fn type_frequency(&self, field_type: FieldType) -> f64 {
        if self.seen_count == 0 {
            return 0.0;
        }
        let count = self.types.get(&field_type).copied().unwrap_or(0);
        count as f64 / self.seen_count as f64
    }

    /// Check if the field has consistent typing (> 95% single type).
    pub fn is_consistent(&self) -> bool {
        if self.seen_count < 5 {
            return true; // Not enough data
        }
        let dominant_freq = self.type_frequency(self.dominant_type());
        dominant_freq >= 0.95
    }
}

// ============================================================================
// EndpointSchema - Full schema for an API endpoint
// ============================================================================

/// Complete schema for an API endpoint.
///
/// Tracks both request and response body schemas with versioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSchema {
    /// Endpoint template (e.g., "/api/users/{id}")
    pub template: String,

    /// Request body schema (field name -> schema)
    pub request_schema: HashMap<String, FieldSchema>,

    /// Response body schema (field name -> schema)
    pub response_schema: HashMap<String, FieldSchema>,

    /// Total sample count (request/response pairs processed)
    pub sample_count: u32,

    /// Last updated timestamp (milliseconds since epoch)
    pub last_updated_ms: u64,

    /// Schema version (incremented on significant changes)
    pub version: u32,
}

impl EndpointSchema {
    /// Create a new endpoint schema.
    pub fn new(template: String, now_ms: u64) -> Self {
        Self {
            template,
            request_schema: HashMap::with_capacity(8),
            response_schema: HashMap::with_capacity(8),
            sample_count: 0,
            last_updated_ms: now_ms,
            version: 0,
        }
    }

    /// Check if schema has enough samples for validation.
    pub fn is_mature(&self, min_samples: u32) -> bool {
        self.sample_count >= min_samples
    }

    /// Get all field names in request schema.
    pub fn request_fields(&self) -> Vec<&str> {
        self.request_schema.keys().map(|s| s.as_str()).collect()
    }

    /// Get all field names in response schema.
    pub fn response_fields(&self) -> Vec<&str> {
        self.response_schema.keys().map(|s| s.as_str()).collect()
    }
}

// ============================================================================
// SchemaViolation - Validation result
// ============================================================================

/// Type of schema violation detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    /// Field not in learned schema
    UnexpectedField,
    /// Required field missing
    MissingField,
    /// Type doesn't match expected
    TypeMismatch,
    /// String too short
    StringTooShort,
    /// String too long
    StringTooLong,
    /// String pattern doesn't match
    PatternMismatch,
    /// Number below expected range
    NumberTooSmall,
    /// Number above expected range
    NumberTooLarge,
    /// Array item type unexpected
    ArrayTypeMismatch,
}

impl ViolationType {
    /// Get violation type as string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ViolationType::UnexpectedField => "unexpected_field",
            ViolationType::MissingField => "missing_field",
            ViolationType::TypeMismatch => "type_mismatch",
            ViolationType::StringTooShort => "string_too_short",
            ViolationType::StringTooLong => "string_too_long",
            ViolationType::PatternMismatch => "pattern_mismatch",
            ViolationType::NumberTooSmall => "number_too_small",
            ViolationType::NumberTooLarge => "number_too_large",
            ViolationType::ArrayTypeMismatch => "array_type_mismatch",
        }
    }

    /// Get default severity for this violation type.
    pub fn default_severity(&self) -> ViolationSeverity {
        match self {
            ViolationType::UnexpectedField => ViolationSeverity::Medium,
            ViolationType::MissingField => ViolationSeverity::Low,
            ViolationType::TypeMismatch => ViolationSeverity::High,
            ViolationType::StringTooShort => ViolationSeverity::Low,
            ViolationType::StringTooLong => ViolationSeverity::Medium,
            ViolationType::PatternMismatch => ViolationSeverity::Medium,
            ViolationType::NumberTooSmall => ViolationSeverity::Low,
            ViolationType::NumberTooLarge => ViolationSeverity::Medium,
            ViolationType::ArrayTypeMismatch => ViolationSeverity::High,
        }
    }

    /// Get default risk score contribution for this violation type.
    pub fn default_score(&self) -> u8 {
        self.default_severity().score()
    }
}

/// Severity level for violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationSeverity {
    /// Informational only
    Info,
    /// Minor deviation from baseline
    Low,
    /// Moderate deviation
    Medium,
    /// Significant deviation
    High,
    /// Critical violation (likely attack)
    Critical,
}

impl ViolationSeverity {
    /// Get numeric score for severity (0-10).
    pub fn score(&self) -> u8 {
        match self {
            ViolationSeverity::Info => 1,
            ViolationSeverity::Low => 2,
            ViolationSeverity::Medium => 4,
            ViolationSeverity::High => 7,
            ViolationSeverity::Critical => 10,
        }
    }

    /// Get severity as string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ViolationSeverity::Info => "info",
            ViolationSeverity::Low => "low",
            ViolationSeverity::Medium => "medium",
            ViolationSeverity::High => "high",
            ViolationSeverity::Critical => "critical",
        }
    }
}

/// A schema violation detected during validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaViolation {
    /// Field path (e.g., "user.email" for nested fields)
    pub field: String,

    /// Type of violation
    pub violation_type: ViolationType,

    /// Severity level
    pub severity: ViolationSeverity,

    /// What was expected
    pub expected: String,

    /// What was actually received
    pub actual: String,
}

impl SchemaViolation {
    /// Create a new schema violation.
    pub fn new(
        field: String,
        violation_type: ViolationType,
        severity: ViolationSeverity,
        expected: String,
        actual: String,
    ) -> Self {
        Self {
            field,
            violation_type,
            severity,
            expected,
            actual,
        }
    }

    /// Create an unexpected field violation.
    pub fn unexpected_field(field: &str) -> Self {
        let v_type = ViolationType::UnexpectedField;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            "field not in schema".to_string(),
            "present".to_string(),
        )
    }

    /// Create a missing field violation.
    pub fn missing_field(field: &str) -> Self {
        let v_type = ViolationType::MissingField;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            "present".to_string(),
            "missing".to_string(),
        )
    }

    /// Create a type mismatch violation.
    pub fn type_mismatch(field: &str, expected: FieldType, actual: FieldType) -> Self {
        let v_type = ViolationType::TypeMismatch;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            expected.as_str().to_string(),
            actual.as_str().to_string(),
        )
    }

    /// Create a pattern mismatch violation.
    pub fn pattern_mismatch(field: &str, expected: PatternType, actual: Option<PatternType>) -> Self {
        let v_type = ViolationType::PatternMismatch;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            expected.as_str().to_string(),
            actual.map_or("unknown".to_string(), |p| p.as_str().to_string()),
        )
    }

    /// Create a string too short violation.
    pub fn string_too_short(field: &str, expected_min: u32, actual: u32) -> Self {
        let v_type = ViolationType::StringTooShort;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            format!(">= {}", expected_min),
            format!("{}", actual),
        )
    }

    /// Create a string too long violation.
    pub fn string_too_long(field: &str, expected_max: u32, actual: u32) -> Self {
        let v_type = ViolationType::StringTooLong;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            format!("<= {}", expected_max),
            format!("{}", actual),
        )
    }

    /// Create a number too small violation.
    pub fn number_too_small(field: &str, expected_min: f64, actual: f64) -> Self {
        let v_type = ViolationType::NumberTooSmall;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            format!(">= {}", expected_min),
            format!("{}", actual),
        )
    }

    /// Create a number too large violation.
    pub fn number_too_large(field: &str, expected_max: f64, actual: f64) -> Self {
        let v_type = ViolationType::NumberTooLarge;
        Self::new(
            field.to_string(),
            v_type,
            v_type.default_severity(),
            format!("<= {}", expected_max),
            format!("{}", actual),
        )
    }
}

// ============================================================================
// ValidationResult - Collection of violations
// ============================================================================

/// Result of schema validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationResult {
    /// List of violations detected
    pub violations: Vec<SchemaViolation>,

    /// Total severity score (sum of violation scores)
    pub total_score: u32,
}

impl ValidationResult {
    /// Create empty result.
    pub fn new() -> Self {
        Self {
            violations: Vec::with_capacity(4),
            total_score: 0,
        }
    }

    /// Add a violation.
    pub fn add(&mut self, violation: SchemaViolation) {
        self.total_score += violation.severity.score() as u32;
        self.violations.push(violation);
    }

    /// Check if validation passed (no violations).
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }

    /// Get highest severity violation.
    pub fn max_severity(&self) -> Option<ViolationSeverity> {
        self.violations.iter().map(|v| v.severity).max()
    }

    /// Get violation count.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: ValidationResult) {
        self.total_score += other.total_score;
        self.violations.extend(other.violations);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_type_from_json() {
        assert_eq!(
            FieldType::from_json_value(&serde_json::json!(null)),
            FieldType::Null
        );
        assert_eq!(
            FieldType::from_json_value(&serde_json::json!(true)),
            FieldType::Boolean
        );
        assert_eq!(
            FieldType::from_json_value(&serde_json::json!(42)),
            FieldType::Number
        );
        assert_eq!(
            FieldType::from_json_value(&serde_json::json!("hello")),
            FieldType::String
        );
        assert_eq!(
            FieldType::from_json_value(&serde_json::json!([1, 2, 3])),
            FieldType::Array
        );
        assert_eq!(
            FieldType::from_json_value(&serde_json::json!({"key": "value"})),
            FieldType::Object
        );
    }

    #[test]
    fn test_field_schema_type_tracking() {
        let mut schema = FieldSchema::new("test".to_string());

        schema.record_type(FieldType::String);
        schema.record_type(FieldType::String);
        schema.record_type(FieldType::Number);

        assert_eq!(schema.seen_count, 3);
        assert_eq!(schema.dominant_type(), FieldType::String);
        assert!((schema.type_frequency(FieldType::String) - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_field_schema_constraints() {
        let mut schema = FieldSchema::new("email".to_string());

        schema.update_string_constraints(10, Some(PatternType::Email));
        schema.update_string_constraints(20, Some(PatternType::Uuid)); // Pattern already set

        assert_eq!(schema.min_length, Some(10));
        assert_eq!(schema.max_length, Some(20));
        assert_eq!(schema.pattern, Some(PatternType::Email)); // First wins
    }

    #[test]
    fn test_field_schema_nullable() {
        let mut schema = FieldSchema::new("optional".to_string());

        schema.record_type(FieldType::String);
        assert!(!schema.nullable);

        schema.record_type(FieldType::Null);
        assert!(schema.nullable);
    }

    #[test]
    fn test_field_schema_number_constraints() {
        let mut schema = FieldSchema::new("price".to_string());

        schema.update_number_constraints(10.0);
        schema.update_number_constraints(50.0);
        schema.update_number_constraints(30.0);

        assert_eq!(schema.min_value, Some(10.0));
        assert_eq!(schema.max_value, Some(50.0));
    }

    #[test]
    fn test_field_schema_array_types() {
        let mut schema = FieldSchema::new("items".to_string());

        schema.add_array_item_type(FieldType::String);
        schema.add_array_item_type(FieldType::Number);
        schema.add_array_item_type(FieldType::String); // Duplicate, ignored

        let types = schema.array_item_types.as_ref().unwrap();
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn test_field_schema_is_consistent() {
        let mut schema = FieldSchema::new("test".to_string());

        // Add 19 strings and 1 number (95% consistent)
        for _ in 0..19 {
            schema.record_type(FieldType::String);
        }
        schema.record_type(FieldType::Number);

        assert!(schema.is_consistent());

        // Add more numbers to break consistency
        for _ in 0..5 {
            schema.record_type(FieldType::Number);
        }
        assert!(!schema.is_consistent());
    }

    #[test]
    fn test_violation_severity_ordering() {
        assert!(ViolationSeverity::Info < ViolationSeverity::Low);
        assert!(ViolationSeverity::Low < ViolationSeverity::Medium);
        assert!(ViolationSeverity::Medium < ViolationSeverity::High);
        assert!(ViolationSeverity::High < ViolationSeverity::Critical);
    }

    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::new();

        result.add(SchemaViolation::unexpected_field("malicious_field"));
        result.add(SchemaViolation::type_mismatch(
            "id",
            FieldType::Number,
            FieldType::String,
        ));

        assert!(!result.is_valid());
        assert_eq!(result.violation_count(), 2);
        assert_eq!(result.max_severity(), Some(ViolationSeverity::High));
    }

    #[test]
    fn test_endpoint_schema_new() {
        let schema = EndpointSchema::new("/api/users".to_string(), 1000);
        assert_eq!(schema.template, "/api/users");
        assert_eq!(schema.sample_count, 0);
        assert!(!schema.is_mature(10));
    }

    #[test]
    fn test_validation_result_merge() {
        let mut result1 = ValidationResult::new();
        result1.add(SchemaViolation::unexpected_field("field1"));

        let mut result2 = ValidationResult::new();
        result2.add(SchemaViolation::missing_field("field2"));

        result1.merge(result2);

        assert_eq!(result1.violation_count(), 2);
    }

    #[test]
    fn test_pattern_type_as_str() {
        assert_eq!(PatternType::Uuid.as_str(), "uuid");
        assert_eq!(PatternType::Email.as_str(), "email");
        assert_eq!(PatternType::Jwt.as_str(), "jwt");
    }

    #[test]
    fn test_violation_type_as_str() {
        assert_eq!(ViolationType::UnexpectedField.as_str(), "unexpected_field");
        assert_eq!(ViolationType::TypeMismatch.as_str(), "type_mismatch");
    }

    #[test]
    fn test_severity_score() {
        assert_eq!(ViolationSeverity::Info.score(), 1);
        assert_eq!(ViolationSeverity::Low.score(), 2);
        assert_eq!(ViolationSeverity::Medium.score(), 4);
        assert_eq!(ViolationSeverity::High.score(), 7);
        assert_eq!(ViolationSeverity::Critical.score(), 10);
    }
}
