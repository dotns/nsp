//! Driver-facing types. Plain data, no I/O.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

/// Per-user WG enablement and rotation input. `public_key` is optional:
/// when `Some`, the server registers the supplied client public key
/// verbatim and never touches a client private key; when `None`, the
/// server generates a disposable keypair, returns the private half once
/// in [`PeerSecrets::private_key`], and stores only the public half.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCreate {
    /// Optional 32-byte client public key (base64). When absent the
    /// server generates a fresh keypair.
    #[serde(default, with = "crate::serde_base64_pubkey_opt")]
    pub public_key: Option<[u8; 32]>,
    /// When set, allocate / install a pre-shared key on top of the
    /// keypair.
    #[serde(default)]
    pub preshared: bool,
    /// Advisory display name. Unused at enable time when the server
    /// derives the name from the user row.
    #[serde(default)]
    pub name: Option<String>,
    /// Explicit `allowed_ip`. Required when no subnet is configured.
    #[serde(default)]
    pub ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub endpoint: Option<SocketAddr>,
    #[serde(default)]
    pub keepalive: Option<u16>,
}

/// What a driver caller sees about a peer. All byte fields are base64 encoded
/// via `serde_with`-style manual wrappers in the API layer; here we stay in
/// the native types.
///
/// `rx_bytes` / `tx_bytes` are the live counters reported by the data
/// plane — they reset every time the interface is rebuilt. The
/// `total_*` counterparts are persisted across restarts by the
/// traffic sampler and reflect the aggregate since the peer was first
/// observed.
#[derive(Debug, Clone)]
pub struct PeerView {
    pub id: String,
    pub user_id: Option<String>,
    pub name: Option<String>,
    pub public_key: PublicKey,
    pub allowed_ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u16>,
    pub has_psk: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_secs: Option<u64>,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
}

/// Exported when a peer is created or rotated — contains one-shot
/// material the server cannot re-derive. `private_key` is populated
/// only when the server generated the client keypair because the
/// caller did not supply a public key.
#[derive(Debug, Clone, Default)]
pub struct PeerSecrets {
    pub private_key: Option<[u8; 32]>,
    pub preshared_key: Option<[u8; 32]>,
}

/// Driver status for `/api/wg/status`.
#[derive(Debug, Clone, Serialize)]
pub struct WgStatus {
    pub running: bool,
    pub interface: String,
    pub listen_port: u16,
    pub subnet: String,
    pub server_public_key: String,
    pub total_peers: u64,
    pub endpoint_host: Option<String>,
    /// Whether preconditions for running the driver are currently met.
    /// `false` indicates a missing prerequisite (TUN device, capability).
    pub available: bool,
    /// Human-readable explanation when `available` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Effective data-plane backend in use: `kernel`, `userspace` or
    /// `netstack`.
    pub backend: String,
}
