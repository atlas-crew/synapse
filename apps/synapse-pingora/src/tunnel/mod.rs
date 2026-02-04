//! Signal Horizon tunnel client for remote operations.
//!
//! Provides a sensor-side WebSocket client that authenticates with the
//! Signal Horizon TunnelBroker and routes messages by channel.

mod client;
mod config;
mod error;
mod types;

pub use client::{TunnelClient, TunnelClientStats};
pub use config::TunnelConfig;
pub use error::TunnelError;
pub use types::{
    ConnectionState, LegacyTunnelMessage, TunnelAuthMetadata, TunnelAuthPayload,
    TunnelChannel, TunnelEnvelope,
};
