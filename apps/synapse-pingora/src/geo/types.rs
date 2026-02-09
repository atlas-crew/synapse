//! Type definitions for geographic analysis and impossible travel detection.
//!
//! Provides types for tracking user logins across geographic locations
//! and detecting account takeover attempts via impossible travel patterns.

use serde::{Deserialize, Serialize};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Default maximum speed (km/h) before flagging as impossible.
/// Commercial jets cruise at ~900 km/h, so 1000 km/h catches unrealistic travel.
pub const DEFAULT_MAX_SPEED_KMH: f64 = 1000.0;

/// Default minimum distance (km) to consider for travel analysis.
/// Short distances are skipped to avoid false positives from GeoIP inaccuracy.
pub const DEFAULT_MIN_DISTANCE_KM: f64 = 50.0;

/// Default history window (hours) to retain login events.
pub const DEFAULT_HISTORY_WINDOW_HOURS: f64 = 24.0;

/// Default maximum login history entries per user.
pub const DEFAULT_MAX_HISTORY_PER_USER: usize = 10;

/// Earth's mean radius in kilometers for haversine calculations.
pub const EARTH_RADIUS_KM: f64 = 6371.0;

// ============================================================================
// Geographic Location
// ============================================================================

/// Geographic location from GeoIP lookup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    /// IP address that was resolved.
    pub ip: String,
    /// Latitude in degrees (-90 to 90).
    pub latitude: f64,
    /// Longitude in degrees (-180 to 180).
    pub longitude: f64,
    /// City name if available.
    pub city: Option<String>,
    /// Full country name.
    pub country: String,
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "GB").
    pub country_code: String,
    /// GeoIP accuracy radius in kilometers.
    pub accuracy_radius_km: u32,
}

impl GeoLocation {
    /// Create a new GeoLocation with required fields.
    pub fn new(
        ip: impl Into<String>,
        latitude: f64,
        longitude: f64,
        country: impl Into<String>,
        country_code: impl Into<String>,
    ) -> Self {
        Self {
            ip: ip.into(),
            latitude,
            longitude,
            city: None,
            country: country.into(),
            country_code: country_code.into(),
            accuracy_radius_km: 50, // Default accuracy
        }
    }

    /// Create with full details including city.
    pub fn with_city(mut self, city: impl Into<String>) -> Self {
        self.city = Some(city.into());
        self
    }

    /// Set accuracy radius.
    pub fn with_accuracy(mut self, accuracy_km: u32) -> Self {
        self.accuracy_radius_km = accuracy_km;
        self
    }
}

// ============================================================================
// Login Event
// ============================================================================

/// Login event for travel analysis.
///
/// Represents a user authentication attempt at a specific location and time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginEvent {
    /// User identifier (user ID, email, or session subject).
    pub user_id: String,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Geographic location of the login.
    pub location: GeoLocation,
    /// Whether the login was successful.
    pub success: bool,
    /// Optional device/client fingerprint for correlation.
    pub device_fingerprint: Option<String>,
}

impl LoginEvent {
    /// Create a new login event.
    pub fn new(user_id: impl Into<String>, timestamp_ms: u64, location: GeoLocation) -> Self {
        Self {
            user_id: user_id.into(),
            timestamp_ms,
            location,
            success: true,
            device_fingerprint: None,
        }
    }

    /// Set success status.
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Set device fingerprint.
    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.device_fingerprint = Some(fingerprint.into());
        self
    }
}

// ============================================================================
// Severity
// ============================================================================

/// Severity level for impossible travel alerts.
///
/// Ordered from least to most severe based on how impossible the travel is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Above threshold but borderline (1000-2000 km/h).
    Low,
    /// Cross-country impossible speed (2000-5000 km/h).
    Medium,
    /// Intercontinental in minutes (5000-10000 km/h).
    High,
    /// Effectively teleportation (>10000 km/h or instant).
    Critical,
}

impl Severity {
    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Travel Alert
// ============================================================================

/// Alert generated when impossible travel is detected.
///
/// Contains full context about the suspicious travel pattern including
/// source/destination locations, timing, and confidence metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TravelAlert {
    /// User ID that triggered the alert.
    pub user_id: String,
    /// Severity based on how impossible the travel is.
    pub severity: Severity,
    /// Location of the previous login.
    pub from_location: GeoLocation,
    /// Timestamp of the previous login (Unix ms).
    pub from_time: u64,
    /// Location of the current login.
    pub to_location: GeoLocation,
    /// Timestamp of the current login (Unix ms).
    pub to_time: u64,
    /// Great-circle distance between locations in kilometers.
    pub distance_km: f64,
    /// Time difference in hours.
    pub time_diff_hours: f64,
    /// Speed required to make the trip (km/h), -1.0 for instant.
    pub required_speed_kmh: f64,
    /// Confidence score (0.0 to 1.0) based on accuracy and context.
    pub confidence: f64,
}

impl TravelAlert {
    /// Create a new travel alert with all context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: impl Into<String>,
        severity: Severity,
        from_location: GeoLocation,
        from_time: u64,
        to_location: GeoLocation,
        to_time: u64,
        distance_km: f64,
        time_diff_hours: f64,
        required_speed_kmh: f64,
        confidence: f64,
    ) -> Self {
        Self {
            user_id: user_id.into(),
            severity,
            from_location,
            from_time,
            to_location,
            to_time,
            distance_km,
            time_diff_hours,
            required_speed_kmh,
            confidence,
        }
    }

    /// Check if this is a high-severity alert (High or Critical).
    pub fn is_high_severity(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}

// ============================================================================
// Travel Configuration
// ============================================================================

/// Configuration for impossible travel detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TravelConfig {
    /// Maximum speed (km/h) before flagging as impossible.
    pub max_speed_kmh: f64,
    /// Minimum distance (km) to analyze (skip short distances).
    pub min_distance_km: f64,
    /// History window in milliseconds.
    pub history_window_ms: u64,
    /// Maximum history entries per user.
    pub max_history_per_user: usize,
}

impl Default for TravelConfig {
    fn default() -> Self {
        Self {
            max_speed_kmh: DEFAULT_MAX_SPEED_KMH,
            min_distance_km: DEFAULT_MIN_DISTANCE_KM,
            history_window_ms: (DEFAULT_HISTORY_WINDOW_HOURS * 3600.0 * 1000.0) as u64,
            max_history_per_user: DEFAULT_MAX_HISTORY_PER_USER,
        }
    }
}

impl TravelConfig {
    /// Create a new configuration with custom values.
    pub fn new(
        max_speed_kmh: f64,
        min_distance_km: f64,
        history_window_hours: f64,
        max_history_per_user: usize,
    ) -> Self {
        Self {
            max_speed_kmh,
            min_distance_km,
            history_window_ms: (history_window_hours * 3600.0 * 1000.0) as u64,
            max_history_per_user,
        }
    }

    /// Get history window in hours.
    pub fn history_window_hours(&self) -> f64 {
        self.history_window_ms as f64 / (3600.0 * 1000.0)
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for the impossible travel detector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TravelStats {
    /// Number of users currently being tracked.
    pub tracked_users: u32,
    /// Total login events processed.
    pub total_logins: u64,
    /// Total alerts generated.
    pub alerts_generated: u64,
    /// Number of whitelisted routes (user-specific).
    pub whitelist_routes: u32,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_location_builder() {
        let loc = GeoLocation::new("1.2.3.4", 40.7128, -74.0060, "United States", "US")
            .with_city("New York")
            .with_accuracy(10);

        assert_eq!(loc.ip, "1.2.3.4");
        assert_eq!(loc.latitude, 40.7128);
        assert_eq!(loc.longitude, -74.0060);
        assert_eq!(loc.city, Some("New York".to_string()));
        assert_eq!(loc.country_code, "US");
        assert_eq!(loc.accuracy_radius_km, 10);
    }

    #[test]
    fn test_login_event_builder() {
        let loc = GeoLocation::new("1.2.3.4", 40.7128, -74.0060, "United States", "US");
        let event = LoginEvent::new("user123", 1000000, loc)
            .with_success(false)
            .with_fingerprint("fp-abc123");

        assert_eq!(event.user_id, "user123");
        assert!(!event.success);
        assert_eq!(event.device_fingerprint, Some("fp-abc123".to_string()));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn test_travel_config_default() {
        let config = TravelConfig::default();
        assert_eq!(config.max_speed_kmh, 1000.0);
        assert_eq!(config.min_distance_km, 50.0);
        assert_eq!(config.max_history_per_user, 10);
        assert!((config.history_window_hours() - 24.0).abs() < 0.001);
    }

    #[test]
    fn test_travel_alert_high_severity() {
        let from = GeoLocation::new("1.1.1.1", 0.0, 0.0, "X", "XX");
        let to = GeoLocation::new("2.2.2.2", 10.0, 10.0, "Y", "YY");

        let alert = TravelAlert::new(
            "user1",
            Severity::High,
            from.clone(),
            1000,
            to.clone(),
            2000,
            1000.0,
            0.5,
            5000.0,
            0.9,
        );

        assert!(alert.is_high_severity());

        let low_alert = TravelAlert::new(
            "user2",
            Severity::Low,
            from,
            1000,
            to,
            2000,
            100.0,
            1.0,
            1100.0,
            0.6,
        );

        assert!(!low_alert.is_high_severity());
    }
}
