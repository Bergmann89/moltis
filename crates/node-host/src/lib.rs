//! Headless node host: connects to a gateway as a node and executes commands.
//!
//! Usage: `moltis node run --host <gateway> --token <device-token>`
//!
//! The node host establishes a WebSocket connection to the gateway,
//! authenticates with a device token, and handles structured `system.exec.v1` commands
//! by executing them locally.

pub mod error;
pub mod identity;
pub mod runner;
pub mod service;

pub use {
    error::Error,
    identity::NodeIdentity,
    moltis_protocol::SYSTEM_EXEC_COMMAND,
    runner::{DEFAULT_PONG_DEADLINE_SECS, NodeConfig, NodeHost},
    service::ServiceConfig,
};
