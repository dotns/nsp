//! Userspace backend backed by `dotns/nsplane`.
//!
//! Owns a single nsplane [`Engine`] for the lifetime of the backend.
//! The engine runs all crypto in-process between a local side and a
//! UDP transport. The local side is either
//!
//! - a TUN device (`nsplane-tun`; [`BackendKind::Userspace`]), whose
//!   address, MTU and link state are configured through `ip`, or
//! - a user-space TCP/IP stack (`nsplane-netstack`;
//!   [`BackendKind::Netstack`], see [`UserspaceBackend::with_netstack`]),
//!   which needs no TUN device or privileges; the host reaches the
//!   tunnel through the SOCKS5 listener and port forwards of
//!   [`super::netstack`].
//!
//! Two modes are supported:
//!
//! - **Eager** ([`UserspaceBackend::new`]): every peer in
//!   `BackendBringUp::initial_peers` is loaded into the engine at
//!   bring-up time.
//! - **Lazy** ([`UserspaceBackend::lazy`]): the engine starts with no
//!   peers; inbound handshake inits trigger a [`PeerResolver`] lookup
//!   that installs the peer on the fly. See [`super::lazy`] for the
//!   transport wrapper that drives this.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnetwork::Ipv4Network;
use nsplane::{
    Engine, EngineBuilder, EngineHandle, PacketSink, PacketSource, PeerStats, TransportId,
    UdpTransport,
};
use nsplane_netstack::{NetStack, NetStackConfig};
use nsplane_tun::Tun;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Result, WgError};

use super::lazy::{peer_to_nsplane, AddPeerCallback, LazyContext, LazyTransport, PeerResolver};
use super::netstack::{local_side, NetstackOptions, Services};
use super::{
    BackendAvailability, BackendBringUp, BackendKind, BackendPeer, BackendPeerStats, WgBackend,
};

/// Id of the engine's single UDP transport.
const UDP_TRANSPORT: TransportId = TransportId::new(0);

/// MTU of the local side: the usual WireGuard value, leaving room for
/// the outer IPv6 + UDP + WireGuard headers on a 1500-byte link.
const LOCAL_MTU: u16 = 1420;

/// How often the eviction loop runs in lazy mode. The same tick also
/// prunes the negative resolver cache.
const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

/// Idle threshold after which a lazily-installed peer is removed from
/// the live engine. Three minutes covers the WireGuard rekey window
/// (REKEY_AFTER_TIME = 120s + REJECT_AFTER_TIME = 180s) — anything
/// older has no live session and would re-handshake before data
/// flows again, so dropping it is safe.
const EVICTION_IDLE: Duration = Duration::from_secs(180);

struct EvictionTask {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

struct Running {
    /// Kept alive here: dropping the engine aborts its tasks.
    engine: Engine,
    handle: EngineHandle,
    lazy: Option<(Arc<LazyContext>, EvictionTask)>,
    /// The netstack listeners, in netstack mode.
    services: Option<Services>,
}

pub struct UserspaceBackend {
    /// `Some` selects lazy mode.
    resolver: Option<Arc<dyn PeerResolver>>,
    /// `Some` replaces the TUN device with a user-space TCP/IP stack.
    netstack: Option<NetstackOptions>,
    running: RwLock<Option<Running>>,
}

impl std::fmt::Debug for UserspaceBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = if self.resolver.is_some() {
            "lazy"
        } else {
            "eager"
        };
        f.debug_struct("UserspaceBackend")
            .field("mode", &kind)
            .field("netstack", &self.netstack)
            .finish()
    }
}

impl Default for UserspaceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl UserspaceBackend {
    /// Eager mode — all peers are installed at bring-up from
    /// `BackendBringUp::initial_peers`.
    pub fn new() -> Self {
        Self {
            resolver: None,
            netstack: None,
            running: RwLock::new(None),
        }
    }

    /// Lazy mode — peers are looked up on demand via `resolver` when
    /// their handshake init arrives. `BackendBringUp::initial_peers`
    /// is ignored; it is the resolver's job to surface peers from
    /// persistence on a per-pubkey basis.
    pub fn lazy(resolver: Arc<dyn PeerResolver>) -> Self {
        Self {
            resolver: Some(resolver),
            netstack: None,
            running: RwLock::new(None),
        }
    }

    /// Netstack mode — a user-space TCP/IP stack takes the place of the
    /// TUN device, serving `options` on the host. Needs a subnet: the
    /// stack owns its first host address.
    #[must_use]
    pub fn with_netstack(mut self, options: NetstackOptions) -> Self {
        self.netstack = Some(options);
        self
    }

    /// Snapshot of the live [`LazyContext`], if the backend is up in
    /// lazy mode. Useful for tests + status views.
    pub async fn lazy_context(&self) -> Option<Arc<LazyContext>> {
        self.running
            .read()
            .await
            .as_ref()
            .and_then(|r| r.lazy.as_ref().map(|(ctx, _)| Arc::clone(ctx)))
    }

    async fn handle(&self) -> Option<(EngineHandle, Option<Arc<LazyContext>>)> {
        self.running.read().await.as_ref().map(|r| {
            (
                r.handle.clone(),
                r.lazy.as_ref().map(|(ctx, _)| Arc::clone(ctx)),
            )
        })
    }
}

#[async_trait]
impl WgBackend for UserspaceBackend {
    fn kind(&self) -> BackendKind {
        if self.netstack.is_some() {
            BackendKind::Netstack
        } else {
            BackendKind::Userspace
        }
    }

    async fn up(&self, params: BackendBringUp) -> Result<()> {
        let mut slot = self.running.write().await;
        if slot.is_some() {
            return Ok(());
        }

        // `[::]` binds dual-stack, falling back to IPv4 only on hosts
        // without IPv6.
        let listen = SocketAddr::from((Ipv6Addr::UNSPECIFIED, params.listen_port));
        let udp = UdpTransport::bind(UDP_TRANSPORT, listen)
            .map_err(|e| WgError::Userspace(format!("bind udp {listen}: {e}")))?;
        let secret = StaticSecret::from(params.server_private_key);
        let ctx = self
            .resolver
            .as_ref()
            .map(|r| LazyContext::new(secret.clone(), Arc::clone(r)));

        let (engine, services) = match &self.netstack {
            None => {
                let tun = Tun::create(&params.interface).map_err(|e| {
                    WgError::Userspace(format!("create tun `{}`: {e}", params.interface))
                })?;
                let name = tun.name().unwrap_or_else(|_| params.interface.clone());
                configure_link(&name, params.subnet).await?;
                let (source, sink) = tun
                    .split()
                    .map_err(|e| WgError::Userspace(format!("open tun `{name}`: {e}")))?;
                (build_engine(source, sink, udp, secret, ctx.as_ref())?, None)
            }
            Some(options) => {
                let subnet = params.subnet.ok_or_else(|| {
                    WgError::Invalid("the netstack backend needs a wireguard subnet".into())
                })?;
                let addr = super::kernel::host_ip_for_subnet(subnet);
                let (stack, net) = NetStack::new(NetStackConfig::new(
                    vec![(IpAddr::V4(addr), subnet.prefix())],
                    LOCAL_MTU,
                ));
                let services = Services::start(&net, options).await?;
                let (source, sink) = local_side(stack, addr, LOCAL_MTU);
                let engine = build_engine(source, sink, udp, secret, ctx.as_ref())?;
                (engine, Some(services))
            }
        };
        let handle = engine.handle();

        let lazy = match ctx {
            Some(ctx) => {
                let installer: Arc<dyn AddPeerCallback> = Arc::new(HandleInstaller {
                    handle: handle.clone(),
                });
                ctx.install_add_peer(installer)?;
                let eviction = spawn_eviction(handle.clone(), Arc::clone(&ctx));
                Some((ctx, eviction))
            }
            None => {
                for peer in &params.initial_peers {
                    handle
                        .add_or_update_peer(peer_to_nsplane(peer, UDP_TRANSPORT))
                        .await
                        .map_err(|e| WgError::Userspace(format!("add peer: {e}")))?;
                }
                None
            }
        };

        *slot = Some(Running {
            engine,
            handle,
            lazy,
            services,
        });
        Ok(())
    }

    async fn down(&self) -> Result<()> {
        let Some(running) = self.running.write().await.take() else {
            return Ok(());
        };
        if let Some((_, task)) = running.lazy {
            task.cancel.cancel();
            let _ = task.handle.await;
        }
        if let Some(services) = running.services {
            services.stop().await;
        }
        // Shutdown only fails when the engine already stopped.
        let _ = running.handle.shutdown().await;
        if let Err(err) = running.engine.wait().await {
            tracing::warn!(target: "nsp::wg", %err, "userspace engine exited abnormally");
        }
        Ok(())
    }

    async fn is_running(&self) -> bool {
        self.running.read().await.is_some()
    }

    async fn add_or_update_peer(&self, peer: BackendPeer) -> Result<()> {
        let Some((handle, ctx)) = self.handle().await else {
            return Err(WgError::NotStarted);
        };
        handle
            .add_or_update_peer(peer_to_nsplane(&peer, UDP_TRANSPORT))
            .await
            .map_err(|e| WgError::Userspace(format!("add peer: {e}")))?;
        if let Some(ctx) = ctx {
            ctx.note_installed(peer.public_key);
        }
        Ok(())
    }

    async fn remove_peer(&self, public_key: &[u8; 32]) -> Result<()> {
        let Some((handle, ctx)) = self.handle().await else {
            return Err(WgError::NotStarted);
        };
        handle
            .remove_peer(PublicKey::from(*public_key))
            .await
            .map_err(|e| WgError::Userspace(format!("remove peer: {e}")))?;
        if let Some(ctx) = ctx {
            ctx.forget_installed(public_key);
        }
        Ok(())
    }

    async fn list_peer_stats(&self) -> Result<Vec<BackendPeerStats>> {
        let Some((handle, _)) = self.handle().await else {
            return Ok(Vec::new());
        };
        let peers = handle
            .peers()
            .await
            .map_err(|e| WgError::Userspace(format!("list peers: {e}")))?;
        Ok(peers.iter().map(to_backend_stats).collect())
    }

    fn availability(&self) -> BackendAvailability {
        if self.netstack.is_some() {
            return BackendAvailability::ok();
        }
        if !Path::new("/dev/net/tun").exists() {
            return BackendAvailability::missing("tun device unavailable");
        }
        match has_cap_net_admin() {
            Some(true) | None => BackendAvailability::ok(),
            Some(false) => BackendAvailability::missing("CAP_NET_ADMIN missing"),
        }
    }

    fn eager_seed_peers(&self) -> bool {
        self.resolver.is_none()
    }
}

fn build_engine<Src: PacketSource, Snk: PacketSink>(
    source: Src,
    sink: Snk,
    udp: UdpTransport,
    secret: StaticSecret,
    lazy: Option<&Arc<LazyContext>>,
) -> Result<Engine> {
    let builder = EngineBuilder::new(source, sink).private_key(secret);
    match lazy {
        Some(ctx) => builder.transport(LazyTransport::new(udp, Arc::clone(ctx))),
        None => builder.transport(udp),
    }
    .build()
    .map_err(|e| WgError::Userspace(format!("build engine: {e}")))
}

/// Assign the server address (subnet mode), set the MTU and bring the
/// link up. Hybrid mode (`subnet == None`) leaves the interface
/// without an address, matching the kernel backend.
async fn configure_link(name: &str, subnet: Option<Ipv4Network>) -> Result<()> {
    if let Some(subnet) = subnet {
        let addr = format!(
            "{}/{}",
            super::kernel::host_ip_for_subnet(subnet),
            subnet.prefix()
        );
        ip(&["address", "add", &addr, "dev", name]).await?;
    }
    ip(&[
        "link",
        "set",
        "dev",
        name,
        "mtu",
        &LOCAL_MTU.to_string(),
        "up",
    ])
    .await
}

/// Runs `ip <args>`; "File exists" (already configured) is fine.
async fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .map_err(|e| WgError::Userspace(format!("run `ip`: {e}")))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() || stderr.contains("File exists") {
        Ok(())
    } else {
        Err(WgError::Userspace(format!(
            "`ip {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )))
    }
}

fn spawn_eviction(handle: EngineHandle, ctx: Arc<LazyContext>) -> EvictionTask {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(EVICTION_INTERVAL) => {}
            }
            evict_idle(&handle, &ctx).await;
        }
    });
    EvictionTask {
        cancel,
        handle: task,
    }
}

async fn evict_idle(handle: &EngineHandle, ctx: &Arc<LazyContext>) {
    let Ok(peers) = handle.peers().await else {
        return;
    };
    for ps in peers {
        let idle_too_long = match ps.last_handshake {
            Some(d) => d > EVICTION_IDLE,
            None => true,
        };
        if !idle_too_long {
            continue;
        }
        if let Err(err) = handle.remove_peer(ps.public_key).await {
            tracing::warn!(target: "nsp::wg::lazy", %err, "evict idle peer failed");
            continue;
        }
        ctx.forget_installed(ps.public_key.as_bytes());
        tracing::debug!(
            target: "nsp::wg::lazy",
            "evicted idle peer (no handshake within {}s)",
            EVICTION_IDLE.as_secs(),
        );
    }
    let pruned = ctx.prune_negative();
    if pruned > 0 {
        tracing::trace!(
            target: "nsp::wg::lazy",
            pruned,
            "pruned expired negative-cache entries",
        );
    }
}

/// Wire bytes (handshakes, keepalives, data), like the kernel's
/// `rx_bytes` / `tx_bytes`.
fn to_backend_stats(ps: &PeerStats) -> BackendPeerStats {
    BackendPeerStats {
        public_key: ps.public_key.to_bytes(),
        rx_bytes: ps.rx,
        tx_bytes: ps.tx,
        last_handshake: ps.last_handshake,
    }
}

/// Hands a freshly-resolved peer to the live engine.
struct HandleInstaller {
    handle: EngineHandle,
}

#[async_trait]
impl AddPeerCallback for HandleInstaller {
    async fn add(&self, peer: BackendPeer) -> Result<()> {
        self.handle
            .add_or_update_peer(peer_to_nsplane(&peer, UDP_TRANSPORT))
            .await
            .map_err(|e| WgError::Userspace(format!("lazy add_peer: {e}")))
    }
}

/// Read `/proc/self/status` and return whether `CAP_NET_ADMIN` (bit 12) is
/// set in the effective capability mask. Returns `None` on non-Linux hosts
/// or when the probe cannot read the status file.
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
