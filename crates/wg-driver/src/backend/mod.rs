//! WireGuard data-plane backends.
//!
//! Two implementations live behind the [`WgBackend`] trait:
//!
//! - [`userspace::UserspaceBackend`] — the `nsplane` engine.
//!   Runs WireGuard crypto in-process on a TUN device, or on a
//!   user-space TCP/IP stack without one (netstack mode).
//! - [`kernel::KernelBackend`] — drives the in-kernel `wireguard`
//!   module by shelling out to `ip` and `wg` (the standard
//!   `wireguard-tools` package).
//!
//! `WgDriver` keeps all DB / IPAM / iptables / lifecycle bookkeeping
//! and delegates only the data-plane primitives (interface up/down,
//! peer CRUD, stats) to the active backend. Switching backends is a
//! matter of swapping the boxed trait object at construction time.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnetwork::Ipv4Network;

use crate::error::Result;

pub mod kernel;
pub mod lazy;
pub mod netstack;
pub mod userspace;

pub use kernel::KernelBackend;
pub use lazy::{LazyContext, LazyTransport, PeerResolver, NEGATIVE_TTL};
pub use netstack::{NetstackOptions, PortForward, Socks5Auth};
pub use userspace::UserspaceBackend;

/// Selector for which data-plane implementation to construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// In-process WireGuard via `nsplane` + a TUN device.
    Userspace,
    /// In-kernel `wireguard` module driven via `ip` / `wg`.
    Kernel,
    /// In-process WireGuard via `nsplane` + a user-space TCP/IP stack:
    /// no TUN device, no privileges. The host reaches the tunnel
    /// through [`NetstackOptions`].
    Netstack,
    /// Pick `Kernel` when its preconditions are met, otherwise
    /// `Userspace`.
    Auto,
}

impl BackendKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            // Blank string -> kernel (the runtime default). Allows
            // operators to omit the field from older toml files and
            // still pick up the new behaviour.
            "" | "kernel" | "kmod" => Ok(Self::Kernel),
            "userspace" | "nsplane" | "user" => Ok(Self::Userspace),
            "netstack" => Ok(Self::Netstack),
            "auto" => Ok(Self::Auto),
            other => Err(crate::error::WgError::Invalid(format!(
                "unknown wireguard backend `{other}` (expected kernel|userspace|netstack|auto)"
            ))),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Userspace => "userspace",
            Self::Kernel => "kernel",
            Self::Netstack => "netstack",
            Self::Auto => "auto",
        }
    }
}

/// Resolution of [`BackendKind::Auto`] — the kind the operator asked
/// for paired with the kind the driver actually intends to bring up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedBackend {
    pub requested: BackendKind,
    pub effective: BackendKind,
}

/// Parameters handed to the backend on bring-up. Mirrors the subset
/// of `WgConfig` that the data plane actually needs.
#[derive(Debug, Clone)]
pub struct BackendBringUp {
    pub interface: String,
    pub listen_port: u16,
    pub server_private_key: [u8; 32],
    /// Subnet whose first host address is assigned to the interface.
    /// `None` (hybrid mode) leaves the interface without an address.
    pub subnet: Option<Ipv4Network>,
    pub initial_peers: Vec<BackendPeer>,
}

/// Decoded peer ready to be installed on the live interface.
#[derive(Debug, Clone)]
pub struct BackendPeer {
    pub public_key: [u8; 32],
    pub allowed_ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u16>,
    pub preshared_key: Option<[u8; 32]>,
}

/// Live traffic counters fetched from the data plane.
#[derive(Debug, Clone, Default)]
pub struct BackendPeerStats {
    pub public_key: [u8; 32],
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: Option<Duration>,
}

/// Precondition probe shared by all backends.
#[derive(Debug, Clone)]
pub struct BackendAvailability {
    pub available: bool,
    pub reason: Option<String>,
}

impl BackendAvailability {
    pub fn ok() -> Self {
        Self {
            available: true,
            reason: None,
        }
    }

    pub fn missing(reason: impl Into<String>) -> Self {
        Self {
            available: false,
            reason: Some(reason.into()),
        }
    }
}

/// Data-plane operations every backend must implement. The trait
/// stays small on purpose — DB persistence, IPAM, iptables baseline
/// rules and reconcile bookkeeping live in [`crate::WgDriver`].
#[async_trait]
pub trait WgBackend: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> BackendKind;

    /// Bring the interface up with `params.initial_peers` already
    /// installed. Idempotent — calling `up` on a running backend
    /// must succeed without recreating the device.
    async fn up(&self, params: BackendBringUp) -> Result<()>;

    /// Tear the interface down. Idempotent.
    async fn down(&self) -> Result<()>;

    async fn is_running(&self) -> bool;

    /// Install or replace a peer. Backends must accept calls before
    /// `up` only when the implementation supports it; the driver
    /// guards this with its own state check.
    async fn add_or_update_peer(&self, peer: BackendPeer) -> Result<()>;

    async fn remove_peer(&self, public_key: &[u8; 32]) -> Result<()>;

    /// Snapshot of every live peer's traffic counters. Backends
    /// return an empty list when no peer is installed.
    async fn list_peer_stats(&self) -> Result<Vec<BackendPeerStats>>;

    /// Probe whether the backend can run on this host. Used by
    /// `/api/wg/status` and by `BackendKind::Auto` resolution.
    fn availability(&self) -> BackendAvailability;

    /// Whether the driver should load every persisted peer into
    /// [`BackendBringUp::initial_peers`] before calling `up`. Defaults
    /// to `true` (kernel + eager userspace). The lazy userspace
    /// backend returns `false` so spawn_real skips the up-front DB
    /// scan and Vec construction; peers come in on demand instead.
    fn eager_seed_peers(&self) -> bool {
        true
    }
}

/// Construct the right backend for `kind`. `Auto` falls back to
/// userspace when the kernel probe fails. The returned [`ResolvedBackend`]
/// records both the requested and the effective kind so callers can
/// surface that distinction in logs / status views.
///
/// `resolver`:
/// - `Some(_)` activates lazy peer mode for the userspace backend —
///   peers are looked up on the fly via the resolver when their
///   handshake init arrives. Ignored for the kernel backend, which
///   always eager-loads every peer.
/// - `None` keeps the legacy eager userspace behaviour. Useful in
///   tests that don't care about persistence.
///
/// `netstack` is what the `Netstack` kind serves on the host; the other
/// kinds ignore it.
pub fn build(
    kind: BackendKind,
    resolver: Option<Arc<dyn PeerResolver>>,
    netstack: NetstackOptions,
) -> (Arc<dyn WgBackend>, ResolvedBackend) {
    let userspace = || match resolver.clone() {
        Some(r) => UserspaceBackend::lazy(r),
        None => UserspaceBackend::new(),
    };
    let make_userspace = || -> Arc<dyn WgBackend> { Arc::new(userspace()) };
    match kind {
        BackendKind::Userspace => (
            make_userspace(),
            ResolvedBackend {
                requested: kind,
                effective: BackendKind::Userspace,
            },
        ),
        BackendKind::Netstack => (
            Arc::new(userspace().with_netstack(netstack)),
            ResolvedBackend {
                requested: kind,
                effective: BackendKind::Netstack,
            },
        ),
        BackendKind::Kernel => (
            Arc::new(KernelBackend::new()),
            ResolvedBackend {
                requested: kind,
                effective: BackendKind::Kernel,
            },
        ),
        BackendKind::Auto => {
            let kernel = KernelBackend::new();
            if kernel.availability().available {
                (
                    Arc::new(kernel),
                    ResolvedBackend {
                        requested: kind,
                        effective: BackendKind::Kernel,
                    },
                )
            } else {
                (
                    make_userspace(),
                    ResolvedBackend {
                        requested: kind,
                        effective: BackendKind::Userspace,
                    },
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kind_accepts_known_aliases() {
        // Blank / unset defaults to kernel.
        assert_eq!(BackendKind::parse("").unwrap(), BackendKind::Kernel);
        assert_eq!(BackendKind::parse("KERNEL").unwrap(), BackendKind::Kernel);
        assert_eq!(BackendKind::parse("kmod").unwrap(), BackendKind::Kernel);
        assert_eq!(
            BackendKind::parse("userspace").unwrap(),
            BackendKind::Userspace
        );
        assert_eq!(
            BackendKind::parse("USERSPACE").unwrap(),
            BackendKind::Userspace
        );
        assert_eq!(BackendKind::parse("auto").unwrap(), BackendKind::Auto);
        assert_eq!(
            BackendKind::parse("Netstack").unwrap(),
            BackendKind::Netstack
        );
        assert!(BackendKind::parse("xdp").is_err());
    }
}
