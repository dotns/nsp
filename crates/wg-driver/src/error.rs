//! Error type surfaced by the WireGuard driver.
//!
//! These variants are mapped to HTTP problem+json by the API layer.

use thiserror::Error;

use crate::ipam::IpamError;

#[derive(Debug, Error)]
pub enum WgError {
    #[error("db error: {0}")]
    Db(#[from] nsp_db::DbError),

    #[error("core error: {0}")]
    Core(#[from] nsp_core::CoreError),

    #[error("ipam: {0}")]
    Ipam(#[from] IpamError),

    #[error("userspace data plane: {0}")]
    Userspace(String),

    #[error("peer not found: {0}")]
    NotFound(String),

    #[error("invalid config: {0}")]
    Invalid(String),

    #[error("driver not started")]
    NotStarted,
}

pub type Result<T> = std::result::Result<T, WgError>;
