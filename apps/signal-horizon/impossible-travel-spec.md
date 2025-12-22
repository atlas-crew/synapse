# Impossible Travel Detection Spec

## Overview

Detect account takeover by identifying logins from geographically impossible locations. User logs in from Florida, then 10 minutes later from Moscow. Unless they're on a rocket, that's not the same person.

**Signal strength:** Very high. Low false positive rate. Clear indicator of credential compromise.

---

## The Math

### Basic Formula

```
distance = haversine(lat1, lon1, lat2, lon2)  // km
time_diff = login2.time - login1.time         // hours
required_speed = distance / time_diff          // km/h

if required_speed > MAX_TRAVEL_SPEED:
    flag as impossible travel
```

### Speed Thresholds

| Transport | Max Speed (km/h) | Notes |
|-----------|------------------|-------|
| Walking | 6 | Not relevant |
| Driving | 150 | Highway speeds |
| Train | 350 | High-speed rail |
| Commercial flight | 900 | Typical cruising |
| Supersonic (future) | 2,000 | Concorde was ~2,180 |

**Conservative threshold: 1,000 km/h**

Catches most impossible travel while allowing for fast flights + airport time.

### Edge Cases

| Scenario | Handling |
|----------|----------|
| VPN / Proxy | Can't distinguish, may false positive |
| Corporate travel | User might actually fly a lot |
| Mobile roaming | GeoIP might be wrong |
| Same city, different GeoIP | Ignore if < 50km |
| Overnight gap | 8+ hours = probably okay |

---

## Data Structures

```rust
#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub ip: IpAddr,
    pub latitude: f64,
    pub longitude: f64,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: String,
    pub country_code: String,
    pub accuracy_radius_km: u32,  // GeoIP confidence
}

#[derive(Debug, Clone)]
pub struct LoginEvent {
    pub user_id: String,
    pub timestamp: DateTime<Utc>,
    pub location: GeoLocation,
    pub success: bool,
    pub auth_method: AuthMethod,
    pub device_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImpossibleTravelAlert {
    pub user_id: String,
    pub severity: Severity,
    
    // First location
    pub from_location: GeoLocation,
    pub from_time: DateTime<Utc>,
    
    // Second location
    pub to_location: GeoLocation,
    pub to_time: DateTime<Utc>,
    
    // Analysis
    pub distance_km: f64,
    pub time_diff_hours: f64,
    pub required_speed_kmh: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Low,      // Suspicious but possible (500-1000 km/h)
    Medium,   // Very unlikely (1000-2000 km/h)
    High,     // Physically impossible (2000-5000 km/h)
    Critical, // Teleportation (>5000 km/h or different continents in minutes)
}
```

---

## Implementation

### Haversine Distance

```rust
use std::f64::consts::PI;

const EARTH_RADIUS_KM: f64 = 6371.0;

/// Calculate distance between two points on Earth
pub fn haversine_distance(
    lat1: f64, lon1: f64,
    lat2: f64, lon2: f64,
) -> f64 {
    let lat1_rad = lat1 * PI / 180.0;
    let lat2_rad = lat2 * PI / 180.0;
    let delta_lat = (lat2 - lat1) * PI / 180.0;
    let delta_lon = (lon2 - lon1) * PI / 180.0;
    
    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    
    EARTH_RADIUS_KM * c
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_haversine() {
        // New York to London
        let distance = haversine_distance(40.7128, -74.0060, 51.5074, -0.1278);
        assert!((distance - 5570.0).abs() < 10.0); // ~5570 km
        
        // Same city
        let distance = haversine_distance(40.7128, -74.0060, 40.7500, -73.9800);
        assert!(distance < 10.0); // < 10 km
    }
}
```

### Travel Detector

```rust
use dashmap::DashMap;
use std::collections::VecDeque;
use std::time::Duration;

const MAX_TRAVEL_SPEED_KMH: f64 = 1000.0;
const MIN_DISTANCE_KM: f64 = 50.0;        // Ignore if same area
const MAX_HISTORY_PER_USER: usize = 10;   // Keep last N logins
const HISTORY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

pub struct ImpossibleTravelDetector {
    // User ID -> recent login locations
    user_history: DashMap<String, VecDeque<LoginEvent>>,
    
    // GeoIP lookup
    geoip: GeoIpDatabase,
    
    // Configuration
    config: TravelConfig,
}

pub struct TravelConfig {
    pub max_speed_kmh: f64,
    pub min_distance_km: f64,
    pub enabled: bool,
    
    // Tuning
    pub ignore_vpn_providers: bool,
    pub trusted_countries: HashSet<String>,  // User's known locations
    pub high_travel_users: HashSet<String>,  // Frequent flyers, raise threshold
}

impl ImpossibleTravelDetector {
    pub fn new(geoip: GeoIpDatabase) -> Self {
        Self {
            user_history: DashMap::new(),
            geoip,
            config: TravelConfig::default(),
        }
    }
    
    /// Record a login and check for impossible travel
    pub fn check_login(&self, event: LoginEvent) -> Option<ImpossibleTravelAlert> {
        if !self.config.enabled || !event.success {
            return None;
        }
        
        let user_id = &event.user_id;
        
        // Get or create user history
        let mut history = self.user_history
            .entry(user_id.clone())
            .or_insert_with(VecDeque::new);
        
        // Clean old entries
        let cutoff = Utc::now() - chrono::Duration::from_std(HISTORY_WINDOW).unwrap();
        while history.front().map(|e| e.timestamp < cutoff).unwrap_or(false) {
            history.pop_front();
        }
        
        // Check against recent logins
        let alert = history.iter()
            .filter_map(|prev| self.check_travel(prev, &event))
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());
        
        // Add to history
        history.push_back(event);
        if history.len() > MAX_HISTORY_PER_USER {
            history.pop_front();
        }
        
        alert
    }
    
    fn check_travel(
        &self,
        from: &LoginEvent,
        to: &LoginEvent,
    ) -> Option<ImpossibleTravelAlert> {
        let distance = haversine_distance(
            from.location.latitude, from.location.longitude,
            to.location.latitude, to.location.longitude,
        );
        
        // Ignore if same area
        if distance < self.config.min_distance_km {
            return None;
        }
        
        let time_diff = to.timestamp
            .signed_duration_since(from.timestamp)
            .num_seconds() as f64 / 3600.0;  // hours
        
        // Ignore if plenty of time passed
        if time_diff <= 0.0 || time_diff > 24.0 {
            return None;
        }
        
        let required_speed = distance / time_diff;
        
        // Check threshold
        let threshold = self.get_threshold_for_user(&to.user_id);
        if required_speed <= threshold {
            return None;
        }
        
        // Calculate severity and confidence
        let severity = self.calculate_severity(required_speed, distance);
        let confidence = self.calculate_confidence(from, to, required_speed);
        
        Some(ImpossibleTravelAlert {
            user_id: to.user_id.clone(),
            severity,
            from_location: from.location.clone(),
            from_time: from.timestamp,
            to_location: to.location.clone(),
            to_time: to.timestamp,
            distance_km: distance,
            time_diff_hours: time_diff,
            required_speed_kmh: required_speed,
            confidence,
        })
    }
    
    fn get_threshold_for_user(&self, user_id: &str) -> f64 {
        if self.config.high_travel_users.contains(user_id) {
            // Frequent flyers get higher threshold
            self.config.max_speed_kmh * 1.5
        } else {
            self.config.max_speed_kmh
        }
    }
    
    fn calculate_severity(&self, speed: f64, distance: f64) -> Severity {
        match speed {
            s if s > 10000.0 => Severity::Critical,  // Teleportation
            s if s > 5000.0 => Severity::Critical,   // Different continents, minutes
            s if s > 2000.0 => Severity::High,       // Faster than any aircraft
            s if s > 1500.0 => Severity::Medium,     // Very unlikely
            _ => Severity::Low,                       // Suspicious
        }
    }
    
    fn calculate_confidence(
        &self,
        from: &LoginEvent,
        to: &LoginEvent,
        speed: f64,
    ) -> f64 {
        let mut confidence = 0.5;
        
        // Higher speed = higher confidence it's impossible
        if speed > 2000.0 { confidence += 0.2; }
        if speed > 5000.0 { confidence += 0.2; }
        
        // Different countries = more confident
        if from.location.country_code != to.location.country_code {
            confidence += 0.1;
        }
        
        // Different continents = very confident
        if !same_continent(&from.location.country_code, &to.location.country_code) {
            confidence += 0.15;
        }
        
        // Same device fingerprint = less confident (might be VPN)
        if from.device_fingerprint == to.device_fingerprint {
            confidence -= 0.2;
        }
        
        // Low GeoIP accuracy = less confident
        let avg_accuracy = (from.location.accuracy_radius_km + to.location.accuracy_radius_km) / 2;
        if avg_accuracy > 100 {
            confidence -= 0.1;
        }
        
        confidence.clamp(0.0, 1.0)
    }
}

fn same_continent(country1: &str, country2: &str) -> bool {
    let continent1 = get_continent(country1);
    let continent2 = get_continent(country2);
    continent1 == continent2
}

fn get_continent(country_code: &str) -> &'static str {
    match country_code {
        "US" | "CA" | "MX" => "NA",
        "BR" | "AR" | "CO" | "CL" | "PE" => "SA",
        "GB" | "DE" | "FR" | "IT" | "ES" | "NL" | "PL" | "UA" | "RU" => "EU",
        "CN" | "JP" | "KR" | "IN" | "ID" | "TH" | "VN" | "PH" | "MY" | "SG" => "AS",
        "AU" | "NZ" => "OC",
        "ZA" | "EG" | "NG" | "KE" => "AF",
        _ => "XX",
    }
}
```

---

## GeoIP Integration

### MaxMind GeoLite2

```rust
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::sync::Arc;

pub struct GeoIpDatabase {
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIpDatabase {
    pub fn new(db_path: &str) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = Reader::open_readfile(db_path)?;
        Ok(Self {
            reader: Arc::new(reader),
        })
    }
    
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        let city: geoip2::City = self.reader.lookup(ip).ok()?;
        
        let location = city.location.as_ref()?;
        let country = city.country.as_ref()?;
        
        Some(GeoLocation {
            ip,
            latitude: location.latitude?,
            longitude: location.longitude?,
            city: city.city
                .and_then(|c| c.names)
                .and_then(|n| n.get("en").copied())
                .map(String::from),
            region: city.subdivisions
                .and_then(|s| s.first())
                .and_then(|s| s.names.as_ref())
                .and_then(|n| n.get("en").copied())
                .map(String::from),
            country: country.names
                .as_ref()
                .and_then(|n| n.get("en").copied())
                .map(String::from)
                .unwrap_or_default(),
            country_code: country.iso_code
                .map(String::from)
                .unwrap_or_default(),
            accuracy_radius_km: location.accuracy_radius.unwrap_or(100) as u32,
        })
    }
}
```

### Caching

```rust
use moka::sync::Cache;
use std::time::Duration;

pub struct CachedGeoIp {
    db: GeoIpDatabase,
    cache: Cache<IpAddr, GeoLocation>,
}

impl CachedGeoIp {
    pub fn new(db: GeoIpDatabase) -> Self {
        let cache = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(3600))  // 1 hour
            .build();
        
        Self { db, cache }
    }
    
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        if let Some(loc) = self.cache.get(&ip) {
            return Some(loc);
        }
        
        let loc = self.db.lookup(ip)?;
        self.cache.insert(ip, loc.clone());
        Some(loc)
    }
}
```

---

## Integration with Synapse

### Auth Endpoint Detection

```rust
impl ImpossibleTravelDetector {
    /// Check if this is an auth endpoint worth tracking
    fn is_auth_endpoint(&self, path: &str, method: &str) -> bool {
        if method != "POST" {
            return false;
        }
        
        let auth_patterns = [
            "/login", "/signin", "/auth", "/oauth", "/token",
            "/session", "/authenticate", "/api/auth", "/api/login",
            "/v1/auth", "/v2/auth", "/api/v1/login", "/api/v2/login",
        ];
        
        let path_lower = path.to_lowercase();
        auth_patterns.iter().any(|p| path_lower.contains(p))
    }
    
    /// Extract user identifier from request
    fn extract_user_id(&self, request: &Request) -> Option<String> {
        // Try common patterns
        
        // 1. From request body (JSON)
        if let Some(body) = &request.body {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
                for field in ["username", "email", "user", "login", "user_id"] {
                    if let Some(val) = json.get(field).and_then(|v| v.as_str()) {
                        return Some(val.to_string());
                    }
                }
            }
        }
        
        // 2. From Authorization header (JWT sub claim)
        if let Some(auth) = request.headers.get("authorization") {
            if let Some(user) = extract_jwt_subject(auth) {
                return Some(user);
            }
        }
        
        // 3. From session cookie
        if let Some(session_user) = self.session_store.get_user(&request) {
            return Some(session_user);
        }
        
        None
    }
}
```

### Hook into Request Flow

```rust
impl Synapse {
    pub async fn analyze(&self, request: &Request) -> AnalysisResult {
        let mut result = AnalysisResult::default();
        
        // ... existing analysis ...
        
        // Check for impossible travel on auth endpoints
        if self.impossible_travel.is_auth_endpoint(&request.path, &request.method) {
            if let Some(user_id) = self.impossible_travel.extract_user_id(request) {
                if let Some(location) = self.geoip.lookup(request.client_ip) {
                    let event = LoginEvent {
                        user_id,
                        timestamp: Utc::now(),
                        location,
                        success: true,  // Will update on response
                        auth_method: AuthMethod::Password,
                        device_fingerprint: request.ja4h_fingerprint.clone(),
                    };
                    
                    if let Some(alert) = self.impossible_travel.check_login(event) {
                        result.risk_signals.push(RiskSignal::ImpossibleTravel(alert));
                        result.risk_delta += match alert.severity {
                            Severity::Critical => 50,
                            Severity::High => 35,
                            Severity::Medium => 20,
                            Severity::Low => 10,
                        };
                    }
                }
            }
        }
        
        result
    }
}
```

---

## Signal Horizon Integration

### Sharing Travel Anomalies

```rust
#[derive(Debug, Clone, Serialize)]
pub struct TravelAnomalySignal {
    pub signal_type: String,  // "impossible_travel"
    pub tenant_id: String,
    pub user_hash: String,    // SHA-256 of user_id
    
    pub from_country: String,
    pub to_country: String,
    pub distance_km: f64,
    pub time_diff_hours: f64,
    pub required_speed_kmh: f64,
    pub severity: Severity,
    pub confidence: f64,
    
    pub timestamp: DateTime<Utc>,
}

impl From<ImpossibleTravelAlert> for TravelAnomalySignal {
    fn from(alert: ImpossibleTravelAlert) -> Self {
        Self {
            signal_type: "impossible_travel".to_string(),
            tenant_id: String::new(),  // Set by sender
            user_hash: sha256(&alert.user_id),
            from_country: alert.from_location.country_code,
            to_country: alert.to_location.country_code,
            distance_km: alert.distance_km,
            time_diff_hours: alert.time_diff_hours,
            required_speed_kmh: alert.required_speed_kmh,
            severity: alert.severity,
            confidence: alert.confidence,
            timestamp: alert.to_time,
        }
    }
}
```

### Cross-Tenant Correlation

Same user (by hash) with impossible travel across tenants = compromised credentials being used across multiple services.

```rust
fn correlate_travel_anomalies(
    signals: &[TravelAnomalySignal],
) -> Vec<CompromisedUserAlert> {
    // Group by user hash
    let mut by_user: HashMap<String, Vec<&TravelAnomalySignal>> = HashMap::new();
    
    for signal in signals {
        by_user.entry(signal.user_hash.clone())
            .or_default()
            .push(signal);
    }
    
    // Users with travel anomalies across multiple tenants
    by_user.into_iter()
        .filter(|(_, signals)| {
            let tenants: HashSet<_> = signals.iter()
                .map(|s| &s.tenant_id)
                .collect();
            tenants.len() >= 2
        })
        .map(|(user_hash, signals)| CompromisedUserAlert {
            user_hash,
            tenant_count: signals.iter().map(|s| &s.tenant_id).collect::<HashSet<_>>().len(),
            signals: signals.into_iter().cloned().collect(),
            severity: Severity::Critical,
        })
        .collect()
}
```

---

## Handling False Positives

### VPN/Proxy Detection

```rust
impl ImpossibleTravelDetector {
    fn is_likely_vpn(&self, location: &GeoLocation) -> bool {
        // Known VPN/datacenter ASNs
        // (Would need ASN data from GeoIP)
        
        // Heuristics:
        // - Datacenter IP ranges
        // - Known VPN provider IPs
        // - Tor exit nodes
        
        false  // Placeholder
    }
    
    fn adjust_confidence_for_vpn(
        &self,
        alert: &mut ImpossibleTravelAlert,
    ) {
        if self.is_likely_vpn(&alert.from_location) || 
           self.is_likely_vpn(&alert.to_location) {
            alert.confidence *= 0.5;  // Halve confidence
        }
    }
}
```

### User Feedback Loop

```rust
/// Track user-confirmed false positives
pub struct TravelWhitelist {
    // User -> set of country pairs they legitimately travel between
    whitelist: DashMap<String, HashSet<(String, String)>>,
}

impl TravelWhitelist {
    pub fn add_route(
        &self,
        user_id: &str,
        country1: &str,
        country2: &str,
    ) {
        self.whitelist
            .entry(user_id.to_string())
            .or_default()
            .insert((country1.to_string(), country2.to_string()));
    }
    
    pub fn is_whitelisted(
        &self,
        user_id: &str,
        country1: &str,
        country2: &str,
    ) -> bool {
        self.whitelist
            .get(user_id)
            .map(|routes| {
                routes.contains(&(country1.to_string(), country2.to_string())) ||
                routes.contains(&(country2.to_string(), country1.to_string()))
            })
            .unwrap_or(false)
    }
}
```

---

## UI Alert

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🚨 IMPOSSIBLE TRAVEL DETECTED                              Severity: HIGH │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  User: john.doe@acme.com                                                   │
│                                                                             │
│  ┌─────────────────────┐         ┌─────────────────────┐                   │
│  │  📍 Miami, FL, US   │  ───▶   │  📍 Moscow, Russia  │                   │
│  │  10:23:15 UTC       │  47min  │  11:10:42 UTC       │                   │
│  └─────────────────────┘         └─────────────────────┘                   │
│                                                                             │
│  Distance: 9,234 km                                                        │
│  Time elapsed: 47 minutes                                                  │
│  Required speed: 11,788 km/h (Mach 9.6)                                    │
│                                                                             │
│  Confidence: 94%                                                           │
│                                                                             │
│  ──────────────────────────────────────────────────────────────────────── │
│                                                                             │
│  Recommended Actions:                                                       │
│  • Force password reset                                                    │
│  • Invalidate all sessions                                                 │
│  • Enable MFA if not already                                               │
│  • Review recent account activity                                          │
│                                                                             │
│              [Force Logout]  [Reset Password]  [Dismiss as VPN]            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Performance

| Operation | Time |
|-----------|------|
| GeoIP lookup (cached) | ~100ns |
| GeoIP lookup (miss) | ~1μs |
| Haversine calculation | ~50ns |
| History check (10 entries) | ~200ns |

**Total overhead: <2μs per auth request**

---

## Configuration

```yaml
impossible_travel:
  enabled: true
  
  # Detection thresholds
  max_speed_kmh: 1000
  min_distance_km: 50
  history_window_hours: 24
  
  # Tuning
  ignore_same_country: false
  ignore_vpn_providers: true
  
  # GeoIP
  geoip_database: "/data/GeoLite2-City.mmdb"
  cache_size: 100000
  cache_ttl_secs: 3600
  
  # Actions
  on_critical:
    - log
    - alert
    - force_mfa
  on_high:
    - log
    - alert
  on_medium:
    - log
```

---

## Implementation Phases

| Phase | Scope | Effort |
|-------|-------|--------|
| 1 | GeoIP integration + caching | 1 day |
| 2 | Core detector (haversine, history) | 2 days |
| 3 | Auth endpoint detection | 1 day |
| 4 | Synapse integration | 1 day |
| 5 | Signal Horizon sharing | 1 day |
| 6 | UI alerts | 1 day |

**Total: ~1 week**

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Detection rate | >95% of actual impossible travel |
| False positive rate | <5% |
| Alert latency | <100ms from login |
| GeoIP cache hit rate | >90% |

---

## What This Enables

| Before | After |
|--------|-------|
| No travel detection | Automatic ATO detection |
| Manual review of logins | Instant alerts |
| Account compromise undetected | "User logged in from 2 continents in 10 minutes" |
| No geographic context | Full location history per user |
| Credential stuffing succeeds silently | Immediate flag on suspicious access |
