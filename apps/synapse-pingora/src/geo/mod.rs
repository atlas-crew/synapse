//! Geographic analysis and impossible travel detection.
//!
//! This module provides geographic anomaly detection capabilities,
//! primarily focused on detecting account takeover attempts through
//! impossible travel patterns.
//!
//! # Overview
//!
//! When a user logs in from two locations in rapid succession, the system
//! calculates whether the required travel speed is physically possible.
//! Commercial jets cruise at ~900 km/h, so speeds above 1000 km/h indicate
//! potential credential compromise.
//!
//! # Components
//!
//! - [`haversine`] - Great-circle distance calculation
//! - [`types`] - Geographic types (GeoLocation, LoginEvent, TravelAlert)
//! - [`impossible_travel`] - Core detection logic
//!
//! # Example
//!
//! ```
//! use synapse_pingora::geo::{
//!     ImpossibleTravelDetector, TravelConfig, LoginEvent, GeoLocation,
//! };
//!
//! let mut detector = ImpossibleTravelDetector::new(TravelConfig::default());
//!
//! // First login in NYC
//! let nyc = GeoLocation::new("1.2.3.4", 40.7128, -74.0060, "USA", "US");
//! let event1 = LoginEvent::new("user123", 0, nyc);
//! detector.check_login(&event1);
//!
//! // Second login in London 10 minutes later - impossible!
//! let london = GeoLocation::new("5.6.7.8", 51.5074, -0.1278, "UK", "GB");
//! let event2 = LoginEvent::new("user123", 600_000, london); // 10 min
//! if let Some(alert) = detector.check_login(&event2) {
//!     println!("Impossible travel detected: {} at {} km/h",
//!         alert.user_id, alert.required_speed_kmh);
//! }
//! ```

mod haversine;
mod impossible_travel;
mod types;

// Re-export public API
pub use haversine::{calculate_speed, haversine_distance, is_valid_coordinates};
pub use impossible_travel::ImpossibleTravelDetector;
pub use types::{
    GeoLocation, LoginEvent, Severity, TravelAlert, TravelConfig, TravelStats,
    DEFAULT_HISTORY_WINDOW_HOURS, DEFAULT_MAX_HISTORY_PER_USER, DEFAULT_MAX_SPEED_KMH,
    DEFAULT_MIN_DISTANCE_KM, EARTH_RADIUS_KM,
};
