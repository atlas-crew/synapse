use crate::admin_server::ApparatusReport;
use crate::horizon::{Severity, SignalType};
use tracing::warn;

/// SignalAdapter - handles version-aware mapping of external signals to internal types.
pub struct SignalAdapter;

impl SignalAdapter {
    /// Map an external report to an internal SignalType.
    pub fn map_type(report: &ApparatusReport) -> SignalType {
        let version = report.version.as_deref().unwrap_or("1.0.0");
        let signal_type = report.signal.signal_type.trim().to_lowercase();

        match version {
            "1.0.0" => Self::map_v1_0_0(&signal_type, &report.sensor_id),
            _ => {
                warn!(
                    version = %version,
                    sensor_id = %report.sensor_id,
                    "Unknown signal report version; falling back to v1.0.0 mapping"
                );
                Self::map_v1_0_0(&signal_type, &report.sensor_id)
            }
        }
    }

    /// Map an external severity string to an internal Severity.
    pub fn map_severity(severity: &str) -> Severity {
        match severity.trim().to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            other => {
                warn!(severity = %other, "Unknown external severity; mapping to Medium");
                Severity::Medium
            }
        }
    }

    fn map_v1_0_0(signal_type: &str, sensor_id: &str) -> SignalType {
        // NOTE: These mappings represent the v1.0.0 "Cutlass" protocol contract.
        // New signal types should be added here or in a new versioned mapping function
        // to maintain backward compatibility with older sensors.
        match signal_type {
            "honeypot_hit" => SignalType::IpThreat,
            "trap_trigger" => SignalType::BotSignature,
            "protocol_probe" => SignalType::TemplateDiscovery,
            "dlp_match" => SignalType::SchemaViolation,
            other => {
                warn!(
                    sensor_id = %sensor_id,
                    signal_type = %other,
                    "Unknown external signal type in v1.0.0; mapping to IpThreat"
                );
                SignalType::IpThreat
            }
        }
    }
}
