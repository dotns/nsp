//! In-kernel WireGuard backend.
//!
//! Drives the upstream `wireguard` Linux kernel module **directly via
//! netlink** (genetlink for WireGuard config + rtnetlink for interface
//! lifecycle and addresses). No `wg`, no `ip`, no shelling out — every
//! operation is one or more `AF_NETLINK` round trips.
//!
//! The heavy lifting is delegated to
//! [`defguard_wireguard_rs::WGApi<Kernel>`], which packages the
//! netlink message construction and provides a small, consistent
//! handle that maps cleanly onto our [`WgBackend`] trait.
//!
//! Because the underlying API is synchronous, every call is moved
//! onto a dedicated blocking thread via `tokio::task::spawn_blocking`
//! so the async runtime stays unblocked.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use defguard_wireguard_rs::{
    key::Key as DfKey, net::IpAddrMask, peer::Peer as DfPeer, InterfaceConfiguration, Kernel,
    WGApi, WireguardInterfaceApi,
};
use ipnetwork::Ipv4Network;
use tokio::sync::Mutex;

use crate::error::{Result, WgError};

use super::{
    BackendAvailability, BackendBringUp, BackendKind, BackendPeer, BackendPeerStats, WgBackend,
};

/// Kernel backend handle. Wraps the synchronous netlink API behind a
/// `Mutex` (`create_interface` needs `&mut self` per the trait
/// definition) and serialises every call onto the blocking thread
/// pool so the tokio runtime never stalls on a netlink syscall.
pub struct KernelBackend {
    state: Mutex<KernelState>,
}

#[derive(Default)]
struct KernelState {
    api: Option<Arc<Mutex<WGApi<Kernel>>>>,
    interface: Option<String>,
}

impl KernelBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for KernelBackend {
    fn default() -> Self {
        Self {
            state: Mutex::new(KernelState::default()),
        }
    }
}

impl std::fmt::Debug for KernelBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelBackend").finish()
    }
}

#[async_trait]
impl WgBackend for KernelBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Kernel
    }

    async fn up(&self, params: BackendBringUp) -> Result<()> {
        {
            let guard = self.state.lock().await;
            if guard.api.is_some() {
                return Ok(());
            }
        }

        let interface = params.interface.clone();
        let api = new_api(interface.clone())?;
        let api = Arc::new(Mutex::new(api));

        // 1. Best-effort tear-down of any leftover interface from a
        //    crashed previous run. We ignore errors because "no such
        //    device" is the common case.
        let cleanup = api.clone();
        let _ = blocking(move || {
            let api = cleanup.blocking_lock();
            api.remove_interface()
        })
        .await;

        // 2. Create the WireGuard interface (RTM_NEWLINK type=wireguard).
        let create = api.clone();
        blocking(move || {
            let mut api = create.blocking_lock();
            api.create_interface()
        })
        .await
        .map_err(|e| WgError::Invalid(format!("create interface: {e}")))?;

        // Wrap the rest of bring-up so a failure during configuration
        // tears the freshly-created interface down rather than
        // leaving a half-configured device behind.
        if let Err(err) = configure(&api, &params).await {
            let cleanup = api.clone();
            let _ = blocking(move || {
                let api = cleanup.blocking_lock();
                api.remove_interface()
            })
            .await;
            return Err(err);
        }

        let mut guard = self.state.lock().await;
        guard.api = Some(api);
        guard.interface = Some(interface);
        Ok(())
    }

    async fn down(&self) -> Result<()> {
        let api = {
            let mut guard = self.state.lock().await;
            guard.interface = None;
            guard.api.take()
        };
        let Some(api) = api else { return Ok(()) };
        let _ = blocking(move || {
            let api = api.blocking_lock();
            api.remove_interface()
        })
        .await;
        Ok(())
    }

    async fn is_running(&self) -> bool {
        self.state.lock().await.api.is_some()
    }

    async fn add_or_update_peer(&self, peer: BackendPeer) -> Result<()> {
        let api = self.api().await?;
        let df_peer = peer_to_defguard(&peer)?;
        blocking(move || {
            let api = api.blocking_lock();
            api.configure_peer(&df_peer)
        })
        .await
        .map_err(|e| WgError::Invalid(format!("configure peer: {e}")))
    }

    async fn remove_peer(&self, public_key: &[u8; 32]) -> Result<()> {
        let api = self.api().await?;
        let key = DfKey::new(*public_key);
        blocking(move || {
            let api = api.blocking_lock();
            api.remove_peer(&key)
        })
        .await
        .map_err(|e| WgError::Invalid(format!("remove peer: {e}")))
    }

    async fn list_peer_stats(&self) -> Result<Vec<BackendPeerStats>> {
        let Some(api) = self.try_api().await else {
            return Ok(Vec::new());
        };
        let host = blocking(move || {
            let api = api.blocking_lock();
            api.read_interface_data()
        })
        .await
        .map_err(|e| WgError::Invalid(format!("read interface data: {e}")))?;

        let now = SystemTime::now();
        let stats = host
            .peers
            .into_values()
            .map(|p| BackendPeerStats {
                public_key: p.public_key.as_array(),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                last_handshake: p
                    .last_handshake
                    .and_then(|t| now.duration_since(t).ok())
                    .filter(|d| !d.is_zero()),
            })
            .collect();
        Ok(stats)
    }

    fn availability(&self) -> BackendAvailability {
        // The kernel module exposes its presence through `/sys/module`.
        // Some distros ship the older out-of-tree wireguard-go shim
        // under a different module name — accept that variant too.
        let module_present = Path::new("/sys/module/wireguard").exists()
            || Path::new("/sys/module/wireguard_linux_compat").exists();
        if !module_present {
            return BackendAvailability::missing("wireguard kernel module not loaded");
        }
        match has_cap_net_admin() {
            Some(true) | None => BackendAvailability::ok(),
            Some(false) => BackendAvailability::missing("CAP_NET_ADMIN missing"),
        }
    }
}

impl KernelBackend {
    async fn api(&self) -> Result<Arc<Mutex<WGApi<Kernel>>>> {
        self.try_api().await.ok_or(WgError::NotStarted)
    }

    async fn try_api(&self) -> Option<Arc<Mutex<WGApi<Kernel>>>> {
        self.state.lock().await.api.clone()
    }
}

async fn configure(api: &Arc<Mutex<WGApi<Kernel>>>, params: &BackendBringUp) -> Result<()> {
    let cfg = build_interface_config(params)?;
    let api = api.clone();
    blocking(move || {
        let api = api.blocking_lock();
        api.configure_interface(&cfg)
    })
    .await
    .map_err(|e| WgError::Invalid(format!("configure interface: {e}")))
}

fn build_interface_config(params: &BackendBringUp) -> Result<InterfaceConfiguration> {
    let mut peers = Vec::with_capacity(params.initial_peers.len());
    for peer in &params.initial_peers {
        peers.push(peer_to_defguard(peer)?);
    }
    let addresses = match params.subnet {
        Some(subnet) => {
            let host_ip = host_ip_for_subnet(subnet);
            let mask = format!("{}/{}", host_ip, subnet.prefix());
            vec![IpAddrMask::from_str(&mask)
                .map_err(|e| WgError::Invalid(format!("parse host address `{mask}`: {e}")))?]
        }
        None => Vec::new(),
    };
    Ok(InterfaceConfiguration {
        name: params.interface.clone(),
        // defguard's WGApi<Kernel> accepts both base64 and base16
        // private keys; base64 matches the rest of our codebase.
        prvkey: B64.encode(params.server_private_key),
        addresses,
        port: params.listen_port,
        peers,
        mtu: None,
        fwmark: None,
    })
}

fn peer_to_defguard(peer: &BackendPeer) -> Result<DfPeer> {
    let pubkey = DfKey::new(peer.public_key);
    let mut p = DfPeer::new(pubkey);
    let allowed = format!("{}/32", peer.allowed_ip);
    let mask = IpAddrMask::from_str(&allowed)
        .map_err(|e| WgError::Invalid(format!("peer allowed_ip `{allowed}`: {e}")))?;
    p.allowed_ips.push(mask);
    if let Some(endpoint) = peer.endpoint {
        p.endpoint = Some(endpoint);
    }
    if let Some(k) = peer.keepalive {
        p.persistent_keepalive_interval = Some(k);
    }
    if let Some(psk) = peer.preshared_key {
        p.preshared_key = Some(DfKey::new(psk));
    }
    Ok(p)
}

fn new_api(ifname: String) -> Result<WGApi<Kernel>> {
    WGApi::<Kernel>::new(ifname)
        .map_err(|e| WgError::Invalid(format!("init wireguard kernel api: {e}")))
}

async fn blocking<F, T, E>(work: F) -> std::result::Result<T, E>
where
    F: FnOnce() -> std::result::Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static + std::fmt::Display,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(res) => res,
        Err(join) => {
            // A panicking netlink call should never silently
            // succeed — bubble the panic up as a backend error.
            tracing::error!(target: "nsp::wg::kernel", %join, "blocking task panicked");
            // Re-raise by re-panicking with the original payload.
            std::panic::resume_unwind(join.into_panic());
        }
    }
}

pub(super) fn host_ip_for_subnet(subnet: Ipv4Network) -> std::net::Ipv4Addr {
    // Mirror wg-quick: pick the first usable address for non-trivial
    // prefixes, fall back to the network address for /31 and /32.
    if subnet.prefix() >= 31 {
        subnet.network()
    } else {
        let net = u32::from(subnet.network());
        std::net::Ipv4Addr::from(net + 1)
    }
}

fn has_cap_net_admin() -> Option<bool> {
    const CAP_NET_ADMIN_BIT: u64 = 1 << 12;
    let data = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in data.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            let hex = hex.trim();
            let bits = u64::from_str_radix(hex, 16).ok()?;
            return Some(bits & CAP_NET_ADMIN_BIT != 0);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddr};

    fn fake_pubkey(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn sample_peer() -> BackendPeer {
        BackendPeer {
            public_key: fake_pubkey(7),
            allowed_ip: "10.66.66.5".parse().unwrap(),
            endpoint: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 51820))),
            keepalive: Some(25),
            preshared_key: Some([9u8; 32]),
        }
    }

    #[test]
    fn build_interface_config_carries_subnet_addr() {
        let subnet: Ipv4Network = "10.66.66.0/24".parse().unwrap();
        let cfg = build_interface_config(&BackendBringUp {
            interface: "wg-test".into(),
            listen_port: 51820,
            server_private_key: [3u8; 32],
            subnet: Some(subnet),
            initial_peers: vec![sample_peer()],
        })
        .expect("build cfg");

        assert_eq!(cfg.name, "wg-test");
        assert_eq!(cfg.port, 51820);
        assert_eq!(cfg.addresses.len(), 1);
        assert_eq!(cfg.addresses[0].to_string(), "10.66.66.1/24");
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].allowed_ips.len(), 1);
        assert_eq!(cfg.peers[0].allowed_ips[0].to_string(), "10.66.66.5/32");
        assert_eq!(
            cfg.peers[0].endpoint,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 51820)))
        );
        assert_eq!(cfg.peers[0].persistent_keepalive_interval, Some(25));
        assert!(cfg.peers[0].preshared_key.is_some());
    }

    #[test]
    fn build_interface_config_omits_address_in_hybrid_mode() {
        let cfg = build_interface_config(&BackendBringUp {
            interface: "wg-test".into(),
            listen_port: 51820,
            server_private_key: [1u8; 32],
            subnet: None,
            initial_peers: vec![],
        })
        .expect("build cfg");
        assert!(cfg.addresses.is_empty());
        assert!(cfg.peers.is_empty());
    }

    #[test]
    fn host_ip_for_subnet_picks_first_usable_address() {
        let subnet: Ipv4Network = "10.66.66.0/24".parse().unwrap();
        assert_eq!(
            host_ip_for_subnet(subnet),
            "10.66.66.1".parse::<Ipv4Addr>().unwrap()
        );
        let tiny: Ipv4Network = "192.168.5.7/32".parse().unwrap();
        assert_eq!(
            host_ip_for_subnet(tiny),
            "192.168.5.7".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn peer_to_defguard_round_trips_fields() {
        let peer = sample_peer();
        let df = peer_to_defguard(&peer).expect("convert");
        assert_eq!(df.public_key.as_array(), peer.public_key);
        assert_eq!(df.allowed_ips[0].to_string(), "10.66.66.5/32");
        assert_eq!(df.endpoint, peer.endpoint);
        assert_eq!(df.persistent_keepalive_interval, Some(25));
        assert_eq!(
            df.preshared_key.as_ref().map(|k| k.as_array()),
            Some([9u8; 32])
        );
    }

    /// Live netlink smoke test: exercises the full bring-up /
    /// configure / tear-down cycle against the real kernel module.
    /// Requires `CAP_NET_ADMIN` and the wireguard module loaded —
    /// `#[ignore]`'d by default and intended to be run in CI under
    /// a privileged container with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN and the wireguard kernel module; run with `--ignored`"]
    async fn kernel_bringup_and_teardown_against_real_module() {
        if !crate::backend::kernel::has_cap_net_admin().unwrap_or(false) {
            eprintln!("skipping: CAP_NET_ADMIN missing");
            return;
        }
        if !std::path::Path::new("/sys/module/wireguard").exists() {
            eprintln!("skipping: wireguard kernel module not loaded");
            return;
        }
        let backend = KernelBackend::new();
        let subnet: Ipv4Network = "10.99.99.0/24".parse().unwrap();
        backend
            .up(BackendBringUp {
                interface: "wgkerntest0".into(),
                listen_port: 51850,
                server_private_key: [42u8; 32],
                subnet: Some(subnet),
                initial_peers: vec![sample_peer()],
            })
            .await
            .expect("bring up real interface");
        assert!(backend.is_running().await);

        let stats = backend.list_peer_stats().await.expect("read stats");
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].public_key, fake_pubkey(7));

        backend.down().await.expect("tear down");
        assert!(!backend.is_running().await);
    }
}
