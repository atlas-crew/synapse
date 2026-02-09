//! Impossible Travel Detection.
//!
//! Detects account takeover by identifying logins from geographically
//! impossible locations (requiring unrealistic travel speed, e.g., >1000 km/h).
//!
//! This is a key indicator of credential compromise - when the same user
//! appears to log in from locations that would be physically impossible
//! to reach in the elapsed time.

use std::collections::{HashMap, HashSet, VecDeque};

use super::haversine::{haversine_distance, is_valid_coordinates};
use super::types::{GeoLocation, LoginEvent, Severity, TravelAlert, TravelConfig, TravelStats};

// ============================================================================
// Internal Login Record
// ============================================================================

/// Internal representation of a login event for storage.
#[derive(Debug, Clone)]
struct StoredLogin {
    timestamp_ms: u64,
    latitude: f64,
    longitude: f64,
    country_code: String,
    ip: String,
    city: Option<String>,
    accuracy_radius_km: u32,
    device_fingerprint: Option<String>,
}

impl From<&LoginEvent> for StoredLogin {
    fn from(event: &LoginEvent) -> Self {
        Self {
            timestamp_ms: event.timestamp_ms,
            latitude: event.location.latitude,
            longitude: event.location.longitude,
            country_code: event.location.country_code.clone(),
            ip: event.location.ip.clone(),
            city: event.location.city.clone(),
            accuracy_radius_km: event.location.accuracy_radius_km,
            device_fingerprint: event.device_fingerprint.clone(),
        }
    }
}

// ============================================================================
// Impossible Travel Detector
// ============================================================================

/// Detects impossible travel patterns indicating account compromise.
///
/// Tracks login history per user and flags when sequential logins
/// would require unrealistic travel speeds.
///
/// # Example
///
/// ```
/// use synapse_pingora::geo::{
///     ImpossibleTravelDetector, TravelConfig, LoginEvent, GeoLocation,
/// };
///
/// let mut detector = ImpossibleTravelDetector::new(TravelConfig::default());
///
/// // First login in NYC
/// let nyc = GeoLocation::new("1.2.3.4", 40.7128, -74.0060, "USA", "US");
/// let event1 = LoginEvent::new("user123", 0, nyc);
/// assert!(detector.check_login(&event1).is_none()); // First login, no alert
///
/// // Second login in London 10 minutes later - impossible!
/// let london = GeoLocation::new("5.6.7.8", 51.5074, -0.1278, "UK", "GB");
/// let event2 = LoginEvent::new("user123", 600_000, london); // 10 min later
/// let alert = detector.check_login(&event2);
/// assert!(alert.is_some());
/// ```
pub struct ImpossibleTravelDetector {
    /// User ID -> login history (most recent last).
    user_history: HashMap<String, VecDeque<StoredLogin>>,
    /// User ID -> whitelisted country pairs (bidirectional).
    whitelist: HashMap<String, HashSet<(String, String)>>,
    /// Configuration.
    config: TravelConfig,
    /// Total logins processed.
    total_logins: u64,
    /// Total alerts generated.
    alerts_generated: u64,
}

impl ImpossibleTravelDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: TravelConfig) -> Self {
        Self {
            user_history: HashMap::new(),
            whitelist: HashMap::new(),
            config,
            total_logins: 0,
            alerts_generated: 0,
        }
    }

    /// Create a detector with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TravelConfig::default())
    }

    /// Check a login event for impossible travel.
    ///
    /// Returns a [`TravelAlert`] if impossible travel is detected, or `None` otherwise.
    ///
    /// The event is always recorded in the user's history regardless of whether
    /// an alert is generated.
    pub fn check_login(&mut self, event: &LoginEvent) -> Option<TravelAlert> {
        // Validate coordinates before processing
        if !is_valid_coordinates(event.location.latitude, event.location.longitude) {
            // Skip events with invalid coordinates - can't do geographic analysis
            return None;
        }

        self.total_logins += 1;

        // Create internal login record
        let login = StoredLogin::from(event);

        // Get or create user history
        let history = self.user_history.entry(event.user_id.clone()).or_default();

        // Prune old entries (outside window)
        let cutoff = event
            .timestamp_ms
            .saturating_sub(self.config.history_window_ms);
        while let Some(front) = history.front() {
            if front.timestamp_ms < cutoff {
                history.pop_front();
            } else {
                break;
            }
        }

        // Clone the previous login to avoid borrow conflict
        let prev_login = history.back().cloned();

        // Add current login to history
        history.push_back(login.clone());

        // Enforce max history size
        while history.len() > self.config.max_history_per_user {
            history.pop_front();
        }

        // Check against most recent login
        let alert = if let Some(ref prev) = prev_login {
            self.check_travel(prev, &login, &event.user_id, &event.location)
        } else {
            None
        };

        if alert.is_some() {
            self.alerts_generated += 1;
        }

        alert
    }

    /// Check travel between two logins for impossibility.
    fn check_travel(
        &self,
        from: &StoredLogin,
        to: &StoredLogin,
        user_id: &str,
        to_location: &GeoLocation,
    ) -> Option<TravelAlert> {
        // Calculate distance
        let distance = haversine_distance(from.latitude, from.longitude, to.latitude, to.longitude);

        // Skip if below minimum distance threshold
        if distance < self.config.min_distance_km {
            return None;
        }

        // Calculate time difference in hours
        let time_diff_ms = to.timestamp_ms.saturating_sub(from.timestamp_ms);
        let time_diff_hours = time_diff_ms as f64 / (3600.0 * 1000.0);

        // Avoid division by zero - if timestamps are the same, treat as instant
        if time_diff_hours < 0.0001 {
            // Less than ~0.36 seconds - effectively instant, definitely impossible
            let alert = self.build_alert(
                user_id,
                from,
                to,
                to_location,
                distance,
                time_diff_hours,
                f64::INFINITY,
            );
            return Some(alert);
        }

        // Calculate required speed
        let required_speed = distance / time_diff_hours;

        // Check if speed exceeds threshold
        if required_speed > self.config.max_speed_kmh {
            // Check whitelist
            if self.is_whitelisted(user_id, &from.country_code, &to.country_code) {
                return None;
            }

            let alert = self.build_alert(
                user_id,
                from,
                to,
                to_location,
                distance,
                time_diff_hours,
                required_speed,
            );
            return Some(alert);
        }

        None
    }

    /// Build a travel alert with full context.
    fn build_alert(
        &self,
        user_id: &str,
        from: &StoredLogin,
        to: &StoredLogin,
        to_location: &GeoLocation,
        distance: f64,
        time_diff_hours: f64,
        required_speed: f64,
    ) -> TravelAlert {
        let severity = self.calculate_severity(required_speed, distance);
        let confidence = self.calculate_confidence(from, to, required_speed);

        TravelAlert {
            user_id: user_id.to_string(),
            severity,
            from_location: GeoLocation {
                ip: from.ip.clone(),
                latitude: from.latitude,
                longitude: from.longitude,
                city: from.city.clone(),
                country: from.country_code.clone(), // Use code as name (we don't store full name)
                country_code: from.country_code.clone(),
                accuracy_radius_km: from.accuracy_radius_km,
            },
            from_time: from.timestamp_ms,
            to_location: to_location.clone(),
            to_time: to.timestamp_ms,
            distance_km: distance,
            time_diff_hours,
            required_speed_kmh: if required_speed.is_infinite() {
                -1.0 // Use -1 to indicate instant/impossible
            } else {
                required_speed
            },
            confidence,
        }
    }

    /// Calculate severity based on how impossible the travel is.
    fn calculate_severity(&self, speed: f64, distance: f64) -> Severity {
        if speed.is_infinite() || speed > 10000.0 {
            // Effectively teleportation (faster than orbital velocity)
            Severity::Critical
        } else if speed > 5000.0 || distance > 10000.0 {
            // Intercontinental in minutes
            Severity::High
        } else if speed > 2000.0 || distance > 5000.0 {
            // Cross-country impossible speed
            Severity::Medium
        } else {
            // Above threshold but borderline
            Severity::Low
        }
    }

    /// Calculate confidence based on context clues.
    fn calculate_confidence(&self, from: &StoredLogin, to: &StoredLogin, speed: f64) -> f64 {
        let mut confidence: f64 = 0.5;

        // Higher confidence if different countries
        if from.country_code != to.country_code {
            confidence += 0.2;
        }

        // Lower confidence if accuracy radius is large
        let avg_accuracy = (from.accuracy_radius_km + to.accuracy_radius_km) as f64 / 2.0;
        if avg_accuracy > 100.0 {
            confidence -= 0.2;
        } else if avg_accuracy < 25.0 {
            confidence += 0.1;
        }

        // Higher confidence for extreme speeds
        if speed > 5000.0 {
            confidence += 0.15;
        }

        // Same device fingerprint increases confidence (same device, different location)
        if let (Some(fp1), Some(fp2)) = (&from.device_fingerprint, &to.device_fingerprint) {
            if fp1 == fp2 {
                confidence += 0.15;
            }
        }

        // Clamp to [0.0, 1.0]
        confidence.clamp(0.0, 1.0)
    }

    /// Check if a route is whitelisted for a user.
    fn is_whitelisted(&self, user_id: &str, country1: &str, country2: &str) -> bool {
        if let Some(routes) = self.whitelist.get(user_id) {
            // Check both directions
            routes.contains(&(country1.to_string(), country2.to_string()))
                || routes.contains(&(country2.to_string(), country1.to_string()))
        } else {
            false
        }
    }

    /// Add a whitelisted travel route for a user.
    ///
    /// Whitelist is bidirectional (US->DE also allows DE->US).
    pub fn add_whitelist_route(&mut self, user_id: &str, country1: &str, country2: &str) {
        let routes = self.whitelist.entry(user_id.to_string()).or_default();

        // Add both directions for symmetry
        routes.insert((country1.to_string(), country2.to_string()));
        routes.insert((country2.to_string(), country1.to_string()));
    }

    /// Remove a whitelisted route for a user.
    pub fn remove_whitelist_route(&mut self, user_id: &str, country1: &str, country2: &str) {
        if let Some(routes) = self.whitelist.get_mut(user_id) {
            routes.remove(&(country1.to_string(), country2.to_string()));
            routes.remove(&(country2.to_string(), country1.to_string()));
        }
    }

    /// Get login history for a user.
    pub fn get_user_history(&self, user_id: &str) -> Vec<LoginEvent> {
        self.user_history
            .get(user_id)
            .map(|history| {
                history
                    .iter()
                    .map(|stored| LoginEvent {
                        user_id: user_id.to_string(),
                        timestamp_ms: stored.timestamp_ms,
                        location: GeoLocation {
                            ip: stored.ip.clone(),
                            latitude: stored.latitude,
                            longitude: stored.longitude,
                            city: stored.city.clone(),
                            country: stored.country_code.clone(),
                            country_code: stored.country_code.clone(),
                            accuracy_radius_km: stored.accuracy_radius_km,
                        },
                        success: true, // We don't track success in history
                        device_fingerprint: stored.device_fingerprint.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clear all data for a specific user.
    pub fn clear_user(&mut self, user_id: &str) {
        self.user_history.remove(user_id);
        self.whitelist.remove(user_id);
    }

    /// Clear all detector data.
    pub fn clear(&mut self) {
        self.user_history.clear();
        self.whitelist.clear();
        self.total_logins = 0;
        self.alerts_generated = 0;
    }

    /// Get detector statistics.
    pub fn stats(&self) -> TravelStats {
        let whitelist_routes: usize = self.whitelist.values().map(|s| s.len()).sum();

        TravelStats {
            tracked_users: self.user_history.len() as u32,
            total_logins: self.total_logins,
            alerts_generated: self.alerts_generated,
            // Divide by 2 since we store both directions
            whitelist_routes: (whitelist_routes / 2) as u32,
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &TravelConfig {
        &self.config
    }

    /// Update configuration (does not clear existing data).
    pub fn set_config(&mut self, config: TravelConfig) {
        self.config = config;
    }

    /// Get number of tracked users.
    pub fn user_count(&self) -> usize {
        self.user_history.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test login event.
    fn create_test_event(
        user_id: &str,
        timestamp_ms: u64,
        lat: f64,
        lon: f64,
        country_code: &str,
    ) -> LoginEvent {
        LoginEvent {
            user_id: user_id.to_string(),
            timestamp_ms,
            location: GeoLocation {
                ip: "1.2.3.4".to_string(),
                latitude: lat,
                longitude: lon,
                city: Some("Test City".to_string()),
                country: country_code.to_string(),
                country_code: country_code.to_string(),
                accuracy_radius_km: 10,
            },
            success: true,
            device_fingerprint: None,
        }
    }

    /// Helper to create event with fingerprint.
    fn create_event_with_fingerprint(
        user_id: &str,
        timestamp_ms: u64,
        lat: f64,
        lon: f64,
        country_code: &str,
        fingerprint: &str,
    ) -> LoginEvent {
        let mut event = create_test_event(user_id, timestamp_ms, lat, lon, country_code);
        event.device_fingerprint = Some(fingerprint.to_string());
        event
    }

    // ========================================================================
    // Basic Detection Tests
    // ========================================================================

    #[test]
    fn test_first_login_no_alert() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        let event = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        let alert = detector.check_login(&event);

        assert!(alert.is_none(), "First login should not trigger alert");
        assert_eq!(detector.stats().total_logins, 1);
    }

    #[test]
    fn test_normal_travel_no_alert() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // First login in NYC
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        assert!(detector.check_login(&event1).is_none());

        // Second login in NYC 1 hour later (same location)
        let event2 = create_test_event("user1", 3600 * 1000, 40.7128, -74.0060, "US");
        assert!(
            detector.check_login(&event2).is_none(),
            "Same location should not trigger"
        );
    }

    #[test]
    fn test_impossible_travel_detected() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // First login in NYC
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        assert!(detector.check_login(&event1).is_none());

        // Second login in London 10 minutes later (~5570 km)
        // Required speed: 5570 km / (10/60) hours = 33420 km/h - impossible!
        let event2 = create_test_event("user1", 10 * 60 * 1000, 51.5074, -0.1278, "GB");
        let alert = detector.check_login(&event2);

        assert!(alert.is_some(), "Impossible travel should trigger alert");

        let alert = alert.unwrap();
        assert_eq!(alert.user_id, "user1");
        assert_eq!(alert.severity, Severity::Critical); // >10000 km/h
        assert!(alert.distance_km > 5500.0);
        assert!(
            alert.required_speed_kmh > 30000.0,
            "Speed should be >30000 km/h"
        );
        assert!(alert.confidence > 0.5);
    }

    #[test]
    fn test_possible_travel_no_alert() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // First login in NYC
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        assert!(detector.check_login(&event1).is_none());

        // Second login in London 8 hours later (realistic flight time)
        // ~5570 km / 8 hours = 696 km/h (below 1000 km/h threshold)
        let event2 = create_test_event("user1", 8 * 3600 * 1000, 51.5074, -0.1278, "GB");
        assert!(
            detector.check_login(&event2).is_none(),
            "Realistic travel should not trigger"
        );
    }

    #[test]
    fn test_below_min_distance() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // First login
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        assert!(detector.check_login(&event1).is_none());

        // Second login very close by (within 50km) 1 minute later
        // Even though speed would be high, distance is below threshold
        let event2 = create_test_event("user1", 60 * 1000, 40.7500, -74.0100, "US");
        assert!(
            detector.check_login(&event2).is_none(),
            "Below min distance should not trigger"
        );
    }

    #[test]
    fn test_instant_travel() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // First login in NYC
        let event1 = create_test_event("user1", 1000, 40.7128, -74.0060, "US");
        assert!(detector.check_login(&event1).is_none());

        // Second login in London at nearly the same time
        let event2 = create_test_event("user1", 1001, 51.5074, -0.1278, "GB");
        let alert = detector.check_login(&event2);

        assert!(alert.is_some(), "Instant travel should trigger");
        let alert = alert.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.required_speed_kmh, -1.0); // -1 indicates instant
    }

    // ========================================================================
    // Whitelist Tests
    // ========================================================================

    #[test]
    fn test_whitelist_prevents_alert() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // Add whitelist for US <-> GB travel
        detector.add_whitelist_route("user1", "US", "GB");

        // First login in NYC
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        assert!(detector.check_login(&event1).is_none());

        // Second login in London 10 minutes later - would be impossible but whitelisted
        let event2 = create_test_event("user1", 10 * 60 * 1000, 51.5074, -0.1278, "GB");
        assert!(
            detector.check_login(&event2).is_none(),
            "Whitelisted route should not trigger"
        );
    }

    #[test]
    fn test_whitelist_bidirectional() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // Add whitelist US -> GB
        detector.add_whitelist_route("user1", "US", "GB");

        // First login in London
        let event1 = create_test_event("user1", 0, 51.5074, -0.1278, "GB");
        assert!(detector.check_login(&event1).is_none());

        // Second login in NYC - should also be whitelisted (reverse direction)
        let event2 = create_test_event("user1", 10 * 60 * 1000, 40.7128, -74.0060, "US");
        assert!(
            detector.check_login(&event2).is_none(),
            "Reverse direction should also be whitelisted"
        );
    }

    #[test]
    fn test_whitelist_user_specific() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // Whitelist only for user1
        detector.add_whitelist_route("user1", "US", "GB");

        // user2 should still trigger
        let event1 = create_test_event("user2", 0, 40.7128, -74.0060, "US");
        assert!(detector.check_login(&event1).is_none());

        let event2 = create_test_event("user2", 10 * 60 * 1000, 51.5074, -0.1278, "GB");
        assert!(
            detector.check_login(&event2).is_some(),
            "Non-whitelisted user should trigger"
        );
    }

    #[test]
    fn test_remove_whitelist() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        detector.add_whitelist_route("user1", "US", "GB");
        detector.remove_whitelist_route("user1", "US", "GB");

        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event1);

        let event2 = create_test_event("user1", 10 * 60 * 1000, 51.5074, -0.1278, "GB");
        assert!(
            detector.check_login(&event2).is_some(),
            "Removed whitelist should trigger"
        );
    }

    // ========================================================================
    // Severity Tests
    // ========================================================================

    #[test]
    fn test_severity_critical() {
        let detector = ImpossibleTravelDetector::with_defaults();

        // >10000 km/h = Critical
        assert_eq!(
            detector.calculate_severity(15000.0, 5000.0),
            Severity::Critical
        );
        assert_eq!(
            detector.calculate_severity(f64::INFINITY, 1000.0),
            Severity::Critical
        );
    }

    #[test]
    fn test_severity_high() {
        let detector = ImpossibleTravelDetector::with_defaults();

        // >5000 km/h or >10000 km = High
        assert_eq!(detector.calculate_severity(6000.0, 3000.0), Severity::High);
        assert_eq!(detector.calculate_severity(3000.0, 12000.0), Severity::High);
    }

    #[test]
    fn test_severity_medium() {
        let detector = ImpossibleTravelDetector::with_defaults();

        // >2000 km/h or >5000 km = Medium
        assert_eq!(
            detector.calculate_severity(3000.0, 2000.0),
            Severity::Medium
        );
        assert_eq!(
            detector.calculate_severity(1500.0, 6000.0),
            Severity::Medium
        );
    }

    #[test]
    fn test_severity_low() {
        let detector = ImpossibleTravelDetector::with_defaults();

        // Just above threshold = Low
        assert_eq!(detector.calculate_severity(1500.0, 100.0), Severity::Low);
        assert_eq!(detector.calculate_severity(1100.0, 200.0), Severity::Low);
    }

    // ========================================================================
    // Confidence Tests
    // ========================================================================

    #[test]
    fn test_confidence_different_countries() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // Different countries increases confidence
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event1);

        let event2 = create_test_event("user1", 10 * 60 * 1000, 51.5074, -0.1278, "GB");
        let alert = detector.check_login(&event2).unwrap();

        assert!(
            alert.confidence >= 0.7,
            "Different countries should have high confidence"
        );
    }

    #[test]
    fn test_confidence_same_fingerprint() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // Same fingerprint but different location = higher confidence
        let event1 = create_event_with_fingerprint(
            "user1",
            0,
            40.7128,
            -74.0060,
            "US",
            "device-fingerprint-123",
        );
        detector.check_login(&event1);

        let event2 = create_event_with_fingerprint(
            "user1",
            10 * 60 * 1000,
            51.5074,
            -0.1278,
            "GB",
            "device-fingerprint-123",
        );
        let alert = detector.check_login(&event2).unwrap();

        // Should have high confidence due to same fingerprint + different country + high speed
        assert!(
            alert.confidence >= 0.85,
            "Same fingerprint should increase confidence, got {}",
            alert.confidence
        );
    }

    // ========================================================================
    // History Management Tests
    // ========================================================================

    #[test]
    fn test_history_pruning() {
        // Configure short history window (1 hour)
        let config = TravelConfig::new(1000.0, 50.0, 1.0, 10);
        let mut detector = ImpossibleTravelDetector::new(config);

        // Login at time 0
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event1);

        // Login at 2 hours later - first login should be pruned
        let event2 = create_test_event("user1", 2 * 3600 * 1000, 40.7128, -74.0060, "US");
        detector.check_login(&event2);

        let history = detector.get_user_history("user1");
        assert_eq!(history.len(), 1, "Old login should be pruned");
    }

    #[test]
    fn test_max_history_per_user() {
        // Configure max 3 entries per user
        let config = TravelConfig::new(1000.0, 50.0, 24.0, 3);
        let mut detector = ImpossibleTravelDetector::new(config);

        // Add 5 logins
        for i in 0..5 {
            let event = create_test_event("user1", i * 1000, 40.7128, -74.0060, "US");
            detector.check_login(&event);
        }

        let history = detector.get_user_history("user1");
        assert_eq!(history.len(), 3, "Should only keep last 3 entries");
    }

    #[test]
    fn test_clear_user() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        let event = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event);
        detector.add_whitelist_route("user1", "US", "GB");

        detector.clear_user("user1");

        assert!(
            detector.get_user_history("user1").is_empty(),
            "History should be cleared"
        );
        // Whitelist should also be cleared
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event1);
        let event2 = create_test_event("user1", 10 * 60 * 1000, 51.5074, -0.1278, "GB");
        assert!(
            detector.check_login(&event2).is_some(),
            "Whitelist should be cleared"
        );
    }

    #[test]
    fn test_clear_all() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        for i in 0..5 {
            let event = create_test_event(&format!("user{i}"), 0, 40.7128, -74.0060, "US");
            detector.check_login(&event);
        }

        detector.clear();

        assert_eq!(detector.user_count(), 0);
        assert_eq!(detector.stats().total_logins, 0);
        assert_eq!(detector.stats().alerts_generated, 0);
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // First user
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event1);

        // Second user
        let event2 = create_test_event("user2", 0, 51.5074, -0.1278, "GB");
        detector.check_login(&event2);

        let stats = detector.stats();
        assert_eq!(stats.tracked_users, 2);
        assert_eq!(stats.total_logins, 2);
        assert_eq!(stats.alerts_generated, 0);
    }

    #[test]
    fn test_stats_with_alerts() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // Trigger an alert
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event1);

        let event2 = create_test_event("user1", 10 * 60 * 1000, 51.5074, -0.1278, "GB");
        detector.check_login(&event2);

        let stats = detector.stats();
        assert_eq!(stats.tracked_users, 1);
        assert_eq!(stats.total_logins, 2);
        assert_eq!(stats.alerts_generated, 1);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_invalid_coordinates_ignored() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // Invalid latitude
        let mut event = create_test_event("user1", 0, 91.0, 0.0, "XX");
        assert!(detector.check_login(&event).is_none());

        // Invalid longitude
        event.location.latitude = 0.0;
        event.location.longitude = 181.0;
        event.timestamp_ms = 1000;
        assert!(detector.check_login(&event).is_none());

        // NaN
        event.location.latitude = f64::NAN;
        event.location.longitude = 0.0;
        event.timestamp_ms = 2000;
        assert!(detector.check_login(&event).is_none());

        // Should not have tracked these
        assert_eq!(detector.user_count(), 0);
    }

    #[test]
    fn test_multiple_users_independent() {
        let mut detector = ImpossibleTravelDetector::with_defaults();

        // user1 in NYC
        let event1 = create_test_event("user1", 0, 40.7128, -74.0060, "US");
        detector.check_login(&event1);

        // user2 in London
        let event2 = create_test_event("user2", 0, 51.5074, -0.1278, "GB");
        detector.check_login(&event2);

        // user1 in NYC again - should not compare with user2
        let event3 = create_test_event("user1", 10 * 60 * 1000, 40.7128, -74.0060, "US");
        assert!(
            detector.check_login(&event3).is_none(),
            "Should compare within same user only"
        );
    }
}
