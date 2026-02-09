use serde::{Deserialize, Serialize};

/// Response classification for auth coverage tracking
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseClass {
    Success,      // 2xx
    Unauthorized, // 401
    Forbidden,    // 403
    ClientError,  // 4xx (other)
    ServerError,  // 5xx
}

impl ResponseClass {
    pub fn from_status(status: u16) -> Self {
        match status {
            200..=299 => ResponseClass::Success,
            401 => ResponseClass::Unauthorized,
            403 => ResponseClass::Forbidden,
            400..=499 => ResponseClass::ClientError,
            _ => ResponseClass::ServerError,
        }
    }

    pub fn is_auth_denial(&self) -> bool {
        matches!(self, ResponseClass::Unauthorized | ResponseClass::Forbidden)
    }
}

/// Per-endpoint counters maintained at edge
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EndpointCounts {
    pub total: u64,
    pub success: u64,
    pub unauthorized: u64,
    pub forbidden: u64,
    pub other_error: u64,
    pub with_auth: u64,
    pub without_auth: u64,
}

/// Single endpoint's data in the summary payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub endpoint: String,
    pub counts: EndpointCounts,
}

/// Summary payload shipped to Hub every flush interval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCoverageSummary {
    pub timestamp: u64,
    pub sensor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub endpoints: Vec<EndpointSummary>,
    #[serde(default)]
    pub dropped_endpoints: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_class_from_status() {
        assert_eq!(ResponseClass::from_status(200), ResponseClass::Success);
        assert_eq!(ResponseClass::from_status(201), ResponseClass::Success);
        assert_eq!(ResponseClass::from_status(401), ResponseClass::Unauthorized);
        assert_eq!(ResponseClass::from_status(403), ResponseClass::Forbidden);
        assert_eq!(ResponseClass::from_status(404), ResponseClass::ClientError);
        assert_eq!(ResponseClass::from_status(500), ResponseClass::ServerError);
    }

    #[test]
    fn test_is_auth_denial() {
        assert!(ResponseClass::Unauthorized.is_auth_denial());
        assert!(ResponseClass::Forbidden.is_auth_denial());
        assert!(!ResponseClass::Success.is_auth_denial());
        assert!(!ResponseClass::ClientError.is_auth_denial());
    }

    #[test]
    fn test_summary_serialization() {
        let summary = AuthCoverageSummary {
            timestamp: 1234567890,
            sensor_id: "sensor-1".to_string(),
            tenant_id: Some("tenant-abc".to_string()),
            endpoints: vec![EndpointSummary {
                endpoint: "GET /api/users/{id}".to_string(),
                counts: EndpointCounts {
                    total: 100,
                    success: 95,
                    unauthorized: 3,
                    forbidden: 2,
                    ..Default::default()
                },
            }],
            dropped_endpoints: 0,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("sensor-1"));
        assert!(json.contains("tenant-abc"));
    }
}
