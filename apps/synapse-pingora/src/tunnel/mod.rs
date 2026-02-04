//! Signal Horizon tunnel client for remote operations.
//!
//! Provides a sensor-side WebSocket client that authenticates with the
//! Signal Horizon TunnelBroker and routes messages by channel.

mod client;
mod config;
mod error;
mod diag;
mod logs;
mod shell;
mod types;

pub use client::{TunnelClient, TunnelClientHandle, TunnelClientStats};
pub use config::TunnelConfig;
pub use error::TunnelError;
pub use diag::TunnelDiagService;
pub use logs::{
    publish_access_log, publish_internal_log, publish_waf_log, TunnelLogService,
};
pub use shell::TunnelShellService;
pub use types::{
    ConnectionState, LegacyTunnelMessage, TunnelAuthMetadata, TunnelAuthPayload,
    TunnelChannel, TunnelEnvelope,
};
