//! WireGuard driver.
//!
//! Wraps a pluggable data-plane backend (see [`backend::WgBackend`])
//! with:
//!
//! - A server keypair persisted (encrypted) in `server_config`.
//! - A per-`/24` IPAM allocator ([`ipam::Ipam`]).
//! - A `wg_peers` repository bridge ([`nsp_db::WgRepo`]) storing only
//!   each peer's public material.
//!
//! Two backends ship in-tree:
//!
//! - [`backend::UserspaceBackend`] — the `dotns/nsplane` engine.
//!   Creates a TUN device and runs WireGuard crypto
//!   inside the process.
//! - [`backend::KernelBackend`] — drives the in-kernel `wireguard`
//!   module via `wg` and `ip` (the `wireguard-tools` package).
//!
//! The [`WgDriver`] value is a cheap handle (`Arc` internally). On
//! [`spawn_real`] it loads the persisted server key, reseeds IPAM
//! from the DB, and asks the backend to bring the interface up. The
//! backend is kept alive for the lifetime of the driver and never
//! reconstructed; peer CRUD goes through the live data plane.
//!
//! The driver does not persist a client peer's private key. Callers may
//! supply a public key on enable / rotate, in which case the server
//! registers it verbatim; otherwise the server generates a fresh keypair,
//! returns the private half once in [`PeerSecrets::private_key`], and
//! discards it.

#![forbid(unsafe_code)]

pub mod backend;
pub mod error;
pub mod ipam;
pub mod model;
pub mod traffic;

pub(crate) mod serde_base64_pubkey_opt {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let raw = Option::<String>::deserialize(d)?;
        let Some(s) = raw else { return Ok(None) };
        let bytes = B64
            .decode(s.trim())
            .map_err(|e| serde::de::Error::custom(format!("public_key base64: {e}")))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Some)
            .map_err(|_| serde::de::Error::custom("public_key must decode to exactly 32 bytes"))
    }
}

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ipnetwork::Ipv4Network;
use nsp_core::crypto::{DataKey, MasterKey};
use nsp_core::driver::{Driver, DriverStatus, ProtocolKind};
use nsp_core::reconciler::ReconcileTarget;
use nsp_db::{Pool, ServerConfigRepo, WgPeerInsert, WgPeerRow, WgRepo, WgTrafficRepo};
pub use nsp_db::{WgTrafficSample, WgTrafficSummary};
use nsp_netctl::{IptablesManager, RuleSpec, Source};
use rand::RngCore as _;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub use backend::{
    BackendBringUp, BackendKind, BackendPeer, BackendPeerStats, KernelBackend, NetstackOptions,
    PeerResolver, PortForward, ResolvedBackend, Socks5Auth, UserspaceBackend, WgBackend,
};
pub use error::{Result, WgError};
pub use ipam::{Ipam, IpamError};
pub use model::{PeerCreate, PeerSecrets, PeerView, WgStatus};

const SERVER_PRIVATE_KEY: &str = "wg_server_private_key";
const SERVER_PUBLIC_KEY: &str = "wg_server_public_key";

/// Static configuration for the driver. Only the bits that cannot change
/// at runtime live here (interface name, UDP port, WAN override). The
/// mutable settings — `subnet` and `endpoint_host` — are kept inside the
/// driver and reachable through [`WgDriver::set_subnet`] /
/// [`WgDriver::set_endpoint_host`] for hot reload.
#[derive(Debug, Clone)]
pub struct WgConfig {
    pub interface: String,
    pub listen_port: u16,
    /// Initial subnet seed. `None` means hybrid mode (explicit per-peer IPs).
    pub subnet: Option<Ipv4Network>,
    /// Initial public host for client exports. `None` falls back to
    /// `0.0.0.0:<listen_port>`.
    pub endpoint_host: Option<String>,
    /// Egress interface for the baseline MASQUERADE rule. When `None` the
    /// driver falls back to `/proc/net/route` autodetection, and finally to
    /// `eth0`.
    pub wan_interface: Option<String>,
    /// Which data-plane to bring up: in-process userspace
    /// (`nsplane` on TUN or on a user-space stack), in-kernel
    /// `wireguard` module, or auto-detect.
    pub backend: BackendKind,
    /// Host-side access to the tunnel for [`BackendKind::Netstack`].
    pub netstack: NetstackOptions,
}

impl WgConfig {
    /// Parse a `WgConfig` from [`nsp_core::config::WireguardConfig`]
    /// plus the configured domain. Treats a blank `subnet` string as
    /// `None` so operators can opt into the explicit-IP mode purely via
    /// config.
    pub fn from_core(
        config: &nsp_core::config::WireguardConfig,
        domain: Option<String>,
    ) -> Result<Self> {
        let subnet = if config.subnet.trim().is_empty() {
            None
        } else {
            let parsed: Ipv4Network = config
                .subnet
                .parse()
                .map_err(|e| WgError::Invalid(format!("subnet `{}`: {e}", config.subnet)))?;
            Some(parsed)
        };
        let socks5 = config
            .netstack
            .socks5
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse()
                    .map_err(|e| WgError::Invalid(format!("netstack socks5 `{s}`: {e}")))
            })
            .transpose()?;
        let forwards = |specs: &[String]| {
            specs
                .iter()
                .filter(|s| !s.trim().is_empty())
                .map(|s| PortForward::parse_spec(s))
                .collect::<Result<Vec<_>>>()
                .map(|specs| specs.into_iter().flatten().collect::<Vec<_>>())
        };
        let socks5_auth = match (
            config.netstack.socks5_username.as_deref(),
            &config.netstack.socks5_password,
        ) {
            (None, None) => None,
            (Some(username), Some(password)) if !username.is_empty() => Some(Socks5Auth {
                username: username.to_owned(),
                password: password.clone(),
            }),
            _ => {
                return Err(WgError::Invalid(
                    "netstack socks5 auth needs both a username and a password".into(),
                ))
            }
        };
        Ok(Self {
            interface: config.interface.clone(),
            listen_port: config.port,
            subnet,
            endpoint_host: domain,
            wan_interface: config.wan_interface.clone(),
            backend: BackendKind::parse(&config.backend)?,
            netstack: NetstackOptions {
                socks5,
                socks5_auth,
                forwards: forwards(&config.netstack.forwards)?,
                udp_forwards: forwards(&config.netstack.udp_forwards)?,
            },
        })
    }
}

/// Handle used by API routes and the controller. Cheap to clone.
#[derive(Clone)]
pub struct WgDriver {
    inner: Arc<WgDriverInner>,
}

struct WgDriverInner {
    cfg: WgConfig,
    db: Pool,
    master_key: Arc<MasterKey>,
    backend: Arc<dyn WgBackend>,
    /// Records what the operator asked for vs what was actually
    /// brought up. Set once at construction time.
    resolved_backend: ResolvedBackend,
    /// Tracks whether the driver has issued a successful `up` to the
    /// backend. The backend's own `is_running` mirrors this for its
    /// own bookkeeping; the driver-level flag is the source of truth
    /// for everything else (status views, reconciler triggers).
    started: RwLock<bool>,
    /// Live subnet. Seeded from `cfg.subnet`; mutated via
    /// [`WgDriver::set_subnet`] at hot-reload time.
    subnet: RwLock<Option<Ipv4Network>>,
    /// Live endpoint host. Seeded from `cfg.endpoint_host`; mutated via
    /// [`WgDriver::set_endpoint_host`].
    endpoint_host: RwLock<Option<String>>,
    ipam: Mutex<Option<Ipam>>,
    availability_cache: RwLock<Option<(Instant, Availability)>>,
    /// When set, baseline MASQUERADE / FORWARD rules are registered through
    /// the manager on `spawn_real` and removed on `stop`. `None` in tests or
    /// in environments without iptables.
    iptables: RwLock<Option<Arc<dyn IptablesManager>>>,
    /// Reconciler wake handle. Populated once at bootstrap so the driver
    /// can wake the background task after `spawn_real` completes.
    reconcile_notify: RwLock<Option<Arc<Notify>>>,
    /// Background traffic sampler. Spawned in `spawn_real`, cancelled
    /// in `stop`. The cancel token and join handle are kept together
    /// so a stop can both signal and await the loop.
    traffic_sampler: Mutex<Option<TrafficSampler>>,
}

struct TrafficSampler {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// Preflight precondition report. `available == false` means at least one
/// dependency is missing; `reason` holds a short human-readable message.
#[derive(Debug, Clone)]
pub struct Availability {
    pub available: bool,
    pub reason: Option<String>,
}

const AVAILABILITY_TTL: Duration = Duration::from_secs(10);

impl std::fmt::Debug for WgDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgDriver")
            .field("interface", &self.inner.cfg.interface)
            .field("listen_port", &self.inner.cfg.listen_port)
            .field("backend", &self.inner.resolved_backend.effective.label())
            .finish()
    }
}

impl WgDriver {
    /// Build a driver handle. Does not touch the network or the DB; call
    /// [`WgDriver::spawn_real`] before issuing CRUD.
    ///
    /// The userspace backend is constructed in **lazy peer** mode: at
    /// `spawn_real` time the nsplane engine starts with no peers, and
    /// inbound handshake inits trigger an indexed `wg_peers` lookup
    /// to install the peer on the fly. This keeps memory bounded
    /// even with hundreds of thousands of registered users — only the
    /// actively-handshaking subset stays resident in the engine.
    pub fn new(cfg: WgConfig, db: Pool, master_key: Arc<MasterKey>) -> Self {
        let resolver: Arc<dyn PeerResolver> =
            Arc::new(DbPeerResolver::new(db.clone(), Arc::clone(&master_key)));
        let (backend, picked) = backend::build(cfg.backend, Some(resolver), cfg.netstack.clone());
        Self::with_backend(cfg, db, master_key, backend, picked)
    }

    /// Construct with an explicit backend instance. Mostly useful in tests
    /// where a mocked-out [`WgBackend`] is preferable to the real one.
    pub fn with_backend(
        cfg: WgConfig,
        db: Pool,
        master_key: Arc<MasterKey>,
        backend: Arc<dyn WgBackend>,
        resolved: ResolvedBackend,
    ) -> Self {
        let subnet = cfg.subnet;
        let endpoint_host = cfg.endpoint_host.clone();
        Self {
            inner: Arc::new(WgDriverInner {
                cfg,
                db,
                master_key,
                backend,
                resolved_backend: resolved,
                started: RwLock::new(false),
                subnet: RwLock::new(subnet),
                endpoint_host: RwLock::new(endpoint_host),
                ipam: Mutex::new(None),
                availability_cache: RwLock::new(None),
                iptables: RwLock::new(None),
                reconcile_notify: RwLock::new(None),
                traffic_sampler: Mutex::new(None),
            }),
        }
    }

    /// Current live subnet, if set.
    pub async fn subnet(&self) -> Option<Ipv4Network> {
        *self.inner.subnet.read().await
    }

    /// Current public endpoint host used in client config exports.
    pub async fn endpoint_host(&self) -> Option<String> {
        self.inner.endpoint_host.read().await.clone()
    }

    /// Update the live public endpoint host. Subsequent client-config
    /// exports use the new value.
    pub async fn set_endpoint_host(&self, host: Option<String>) {
        let trimmed = host.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
        *self.inner.endpoint_host.write().await = trimmed;
    }

    /// Update the live subnet and rebuild IPAM from the current DB
    /// rows. Callers (the settings API) are expected to have verified
    /// that no peers conflict with the new subnet via
    /// [`WgDriver::peers_outside_subnet`] before calling; this method
    /// applies the change unconditionally.
    pub async fn set_subnet(&self, subnet: Option<Ipv4Network>) -> Result<()> {
        *self.inner.subnet.write().await = subnet;
        // Rebuild IPAM from DB peers so pre-existing in-subnet leases
        // stay marked. Peers whose allowed_ip is outside the new range
        // (callers should have rejected this already) are dropped from
        // the allocator with a warning.
        self.seed_ipam().await?;
        // Refresh baseline iptables so the MASQUERADE source network
        // matches the new subnet. Best-effort: failures are logged but
        // do not abort the reload.
        if *self.inner.started.read().await {
            if let Some(mgr) = self.inner.iptables.read().await.clone() {
                if let Err(err) = mgr.remove_by_source(Source::WgDriver).await {
                    tracing::warn!(target: "nsp::wg", %err, "remove old baseline iptables rules");
                }
            }
            self.install_baseline_rules().await;
        }
        Ok(())
    }

    /// List ids of peers whose `allowed_ip` does not fit within
    /// `target`. When `target` is `None` every persisted peer is
    /// reported. Used by the settings API to surface 409 bodies.
    pub async fn peers_outside_subnet(&self, target: Option<Ipv4Network>) -> Result<Vec<String>> {
        let rows = WgRepo::new(&self.inner.db).list().await?;
        let mut out = Vec::new();
        for row in rows {
            let Ok(ip) = row.allowed_ip.parse::<Ipv4Addr>() else {
                out.push(row.id);
                continue;
            };
            let fits = match target {
                Some(net) => net.contains(ip),
                None => false,
            };
            if !fits {
                out.push(row.id);
            }
        }
        Ok(out)
    }

    /// Configured interface name (`wg0`).
    pub fn interface(&self) -> &str {
        &self.inner.cfg.interface
    }

    /// Effective backend kind (after `auto` resolution).
    pub fn backend_kind(&self) -> BackendKind {
        self.inner.resolved_backend.effective
    }

    /// Backend kind originally requested by the operator — useful in
    /// logs to flag `auto -> kernel` vs `auto -> userspace` paths.
    pub fn requested_backend_kind(&self) -> BackendKind {
        self.inner.resolved_backend.requested
    }

    /// Attach an iptables manager. When set, `spawn_real` registers the
    /// baseline MASQUERADE + FORWARD rules under `Source::WgDriver`, and
    /// `stop` removes every rule owned by that source. Must be called before
    /// `spawn_real` for the rules to be installed.
    pub async fn set_iptables(&self, mgr: Arc<dyn IptablesManager>) {
        *self.inner.iptables.write().await = Some(mgr);
    }

    /// Register the reconciler wake handle. Called once at wiring time
    /// by `nsp::main`. After a successful `spawn_real` the driver
    /// pokes this notifier so the reconciler re-scans the DB.
    pub async fn set_reconcile_notify(&self, notify: Arc<Notify>) {
        *self.inner.reconcile_notify.write().await = Some(notify);
    }

    async fn notify_reconciler(&self) {
        if let Some(n) = self.inner.reconcile_notify.read().await.as_ref() {
            n.notify_one();
        }
    }

    /// Load/generate the server keypair and bring up the device. Idempotent
    /// — calling `spawn_real` after a successful spawn is a no-op.
    #[tracing::instrument(skip(self), fields(iface = %self.inner.cfg.interface, port = self.inner.cfg.listen_port, backend = %self.backend_kind().label()))]
    pub async fn spawn_real(&self) -> Result<()> {
        if *self.inner.started.read().await {
            return Ok(());
        }

        let (private_key_bytes, _public_key) = self.load_or_generate_server_keys().await?;

        // Initialise IPAM from persisted peers before touching the device:
        // if the device build fails we still have a consistent in-memory view.
        self.seed_ipam().await?;

        // Lazy backends pull peers on demand; skip the up-front DB
        // scan + Vec build entirely so the driver doesn't churn 100k+
        // rows through memory on a 100k-user deployment.
        let eager_seed = self.inner.backend.eager_seed_peers();
        let initial_peers = if eager_seed {
            let repo = WgRepo::new(&self.inner.db);
            let persisted = repo.list().await?;
            let mut v = Vec::with_capacity(persisted.len());
            for row in &persisted {
                v.push(peer_row_to_backend(row, self.data_key())?);
            }
            v
        } else {
            Vec::new()
        };
        let initial_count = initial_peers.len();

        let bringup = BackendBringUp {
            interface: self.inner.cfg.interface.clone(),
            listen_port: self.inner.cfg.listen_port,
            server_private_key: *private_key_bytes,
            subnet: *self.inner.subnet.read().await,
            initial_peers,
        };
        self.inner.backend.up(bringup).await?;

        *self.inner.started.write().await = true;

        // Install baseline iptables rules after the device is live so routes
        // return sensible 503s during the brief window between TUN up and
        // rules present. Failures here are logged but not fatal: the device
        // still forwards; only NAT / FORWARD policy is missing.
        self.install_baseline_rules().await;
        self.start_traffic_sampler().await;

        tracing::info!(
            target: "nsp::wg",
            seeded_peers = initial_count,
            eager_seed,
            backend = %self.backend_kind().label(),
            "WireGuard device up"
        );
        // Wake the reconciler so any enablements queued while the
        // device was down get applied through the normal sync path.
        self.notify_reconciler().await;
        Ok(())
    }

    async fn install_baseline_rules(&self) {
        // No interface to forward or masquerade in netstack mode.
        if self.backend_kind() == BackendKind::Netstack {
            return;
        }
        let Some(mgr) = self.inner.iptables.read().await.clone() else {
            return;
        };
        let wan = resolve_wan_interface(self.inner.cfg.wan_interface.as_deref());
        let iface = &self.inner.cfg.interface;
        let mut rules = Vec::with_capacity(3);
        if let Some(subnet) = *self.inner.subnet.read().await {
            rules.push(
                RuleSpec::new(
                    "nat",
                    "POSTROUTING",
                    format!("-s {subnet} -o {wan} -j MASQUERADE"),
                )
                .with_comment(format!("wg-driver {iface} masquerade")),
            );
        }
        rules.push(
            RuleSpec::new(
                "filter",
                "FORWARD",
                format!("-i {iface} -o {wan} -j ACCEPT"),
            )
            .with_comment(format!("wg-driver {iface} forward out")),
        );
        rules.push(
            RuleSpec::new(
                "filter",
                "FORWARD",
                format!("-i {wan} -o {iface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"),
            )
            .with_comment(format!("wg-driver {iface} forward in")),
        );
        if let Err(err) = mgr
            .register(Source::WgDriver, rules, Default::default())
            .await
        {
            tracing::warn!(target: "nsp::wg", %err, "register baseline iptables rules failed");
        }
    }

    /// Prepare in-memory state (IPAM + keys) without touching the
    /// data plane. Used by tests and by `GET /api/wg/status` smoke
    /// paths so that the server can report sensible values even when
    /// the kernel module / TUN device is unavailable.
    #[tracing::instrument(skip(self), fields(iface = %self.inner.cfg.interface))]
    pub async fn prepare(&self) -> Result<()> {
        self.load_or_generate_server_keys().await?;
        self.seed_ipam().await?;
        Ok(())
    }

    /// Whether the data plane is currently live. The config `enabled`
    /// flag only controls the initial boot; after that the state
    /// reflects the most recent `spawn_real` / `stop` pair.
    pub async fn is_running(&self) -> bool {
        *self.inner.started.read().await
    }

    /// Bring the data plane down and release any kernel resources.
    /// Idempotent: repeated calls on an already-stopped driver are a
    /// no-op.
    ///
    /// The runtime lifecycle is decoupled from boot-time config. Once
    /// the API has called `stop`, the driver stays stopped
    /// (`is_running` returns false) until an explicit `spawn_real`
    /// restarts it, regardless of what `config.wireguard.enabled`
    /// said at startup.
    #[tracing::instrument(skip(self))]
    pub async fn stop(&self) -> Result<()> {
        let was_started = {
            let mut guard = self.inner.started.write().await;
            let prev = *guard;
            *guard = false;
            prev
        };
        if !was_started {
            return Ok(());
        }
        self.stop_traffic_sampler().await;
        self.inner.backend.down().await?;

        if let Some(mgr) = self.inner.iptables.read().await.clone() {
            if let Err(err) = mgr.remove_by_source(Source::WgDriver).await {
                tracing::warn!(target: "nsp::wg", %err, "remove baseline iptables rules failed");
            }
        }

        tracing::info!(target: "nsp::wg", "WireGuard device stopped");
        Ok(())
    }

    async fn start_traffic_sampler(&self) {
        let mut slot = self.inner.traffic_sampler.lock().await;
        if slot.is_some() {
            return;
        }
        let cancel = CancellationToken::new();
        let handle = traffic::spawn_loop(
            self.inner.db.clone(),
            self.inner.backend.clone(),
            cancel.clone(),
        );
        *slot = Some(TrafficSampler { cancel, handle });
    }

    async fn stop_traffic_sampler(&self) {
        let sampler = self.inner.traffic_sampler.lock().await.take();
        if let Some(s) = sampler {
            s.cancel.cancel();
            let _ = s.handle.await;
        }
    }

    /// Take one traffic sample synchronously, bypassing the periodic
    /// loop. Used by tests and by callers that want to force a refresh
    /// before reading the persisted totals.
    pub async fn sample_traffic_now(&self) -> Result<usize> {
        traffic::sample_once(&self.inner.db, self.inner.backend.as_ref()).await
    }

    /// Cumulative traffic summary for one peer. Returns `None` when
    /// the peer exists but has never been sampled.
    pub async fn traffic_summary(&self, peer_id: &str) -> Result<Option<WgTrafficSummary>> {
        Ok(WgTrafficRepo::new(&self.inner.db).get(peer_id).await?)
    }

    /// Hour-bucketed traffic samples for one peer. `since_ts = 0`
    /// returns the full retained history. `limit <= 0` falls back to
    /// 168 hours (one week).
    pub async fn traffic_samples(
        &self,
        peer_id: &str,
        since_ts: i64,
        limit: i64,
    ) -> Result<Vec<WgTrafficSample>> {
        Ok(WgTrafficRepo::new(&self.inner.db)
            .list_samples(peer_id, since_ts, limit)
            .await?)
    }

    /// Current status snapshot for `/api/wg/status`.
    #[tracing::instrument(skip(self))]
    pub async fn status_view(&self) -> Result<WgStatus> {
        let (_priv, public) = self.load_or_generate_server_keys().await?;
        let running = *self.inner.started.read().await;
        let total_peers = WgRepo::new(&self.inner.db).list().await?.len() as u64;
        let availability = self.availability().await;
        let subnet = self
            .inner
            .subnet
            .read()
            .await
            .map(|n| n.to_string())
            .unwrap_or_default();
        let endpoint_host = self.inner.endpoint_host.read().await.clone();
        Ok(WgStatus {
            running,
            interface: self.inner.cfg.interface.clone(),
            listen_port: self.inner.cfg.listen_port,
            subnet,
            server_public_key: B64.encode(public.as_bytes()),
            total_peers,
            endpoint_host,
            available: availability.available,
            reason: availability.reason,
            backend: self.backend_kind().label().to_owned(),
        })
    }

    /// Cached precondition probe. Forwards to the active backend's
    /// availability check (TUN + CAP_NET_ADMIN for userspace; kernel
    /// module + `wg`/`ip` + CAP_NET_ADMIN for kernel). Result is
    /// cached for a short TTL to avoid spamming syscalls on
    /// status-polling endpoints.
    pub async fn availability(&self) -> Availability {
        {
            let cache = self.inner.availability_cache.read().await;
            if let Some((at, cached)) = cache.as_ref() {
                if at.elapsed() < AVAILABILITY_TTL {
                    return cached.clone();
                }
            }
        }
        // Running implies the probe already succeeded at spawn, so we can
        // report available without re-syscalling.
        let fresh = if *self.inner.started.read().await {
            Availability {
                available: true,
                reason: None,
            }
        } else {
            let probe = self.inner.backend.availability();
            Availability {
                available: probe.available,
                reason: probe.reason,
            }
        };
        *self.inner.availability_cache.write().await = Some((Instant::now(), fresh.clone()));
        fresh
    }

    /// List all peers. Live traffic stats are filled in from the device when
    /// the driver is running; otherwise the stats fields are zero.
    #[tracing::instrument(skip(self))]
    pub async fn list_peers(&self) -> Result<Vec<PeerView>> {
        let rows = WgRepo::new(&self.inner.db).list().await?;
        let stats = self.peer_stats_map().await;
        let totals = self.traffic_totals_map().await;
        rows.into_iter()
            .map(|row| row_into_view(row, &stats, &totals))
            .collect()
    }

    /// Fetch a single peer by id.
    #[tracing::instrument(skip(self))]
    pub async fn get_peer(&self, id: &str) -> Result<PeerView> {
        let row = WgRepo::new(&self.inner.db)
            .get(id)
            .await?
            .ok_or_else(|| WgError::NotFound(id.to_owned()))?;
        let stats = self.peer_stats_map().await;
        let totals = self.traffic_totals_map().await;
        row_into_view(row, &stats, &totals)
    }

    /// Create a new peer — generate keypair, allocate (or accept) an IP,
    /// persist, and (if the device is live) install it.
    ///
    /// Hybrid IPAM:
    /// * `req.ip = Some(ip)` -> validate RFC1918, reject DB collisions,
    ///   and mark the address in IPAM when the subnet is set.
    /// * `req.ip = None` + subnet set -> auto-allocate from IPAM.
    /// * `req.ip = None` + subnet unset -> [`WgError::Invalid`] (the
    ///   caller must provide an explicit IP).
    #[tracing::instrument(skip(self, req), fields(name = ?req.name))]
    pub async fn add_peer(&self, req: PeerCreate) -> Result<(PeerView, PeerSecrets)> {
        let (ip, reserved_in_ipam) = self.acquire_peer_ip(req.ip).await?;

        // Any downstream failure must release anything we marked in IPAM,
        // regardless of whether it came from the allocator or from the
        // caller's explicit IP.
        let outcome = self.add_peer_after_ip(req, ip).await;
        if outcome.is_err() && reserved_in_ipam {
            let mut ipam = self.inner.ipam.lock().await;
            if let Some(ipam) = ipam.as_mut() {
                let _ = ipam.release(ip);
            }
        }
        outcome
    }

    /// Resolve the target IP for a new peer. Returns the address plus a
    /// flag marking whether the address is reserved in IPAM on behalf of
    /// this call (so the caller knows to `release` it on downstream
    /// rollback). True for both auto-allocated addresses and explicit
    /// IPs that fall inside a configured subnet.
    async fn acquire_peer_ip(&self, requested: Option<Ipv4Addr>) -> Result<(Ipv4Addr, bool)> {
        match requested {
            Some(ip) => {
                if !is_rfc1918(ip) {
                    return Err(WgError::Invalid(format!(
                        "peer ip `{ip}` is not in RFC1918 space"
                    )));
                }
                // Collision check against persisted peers.
                if peer_ip_in_use(&self.inner.db, ip).await? {
                    return Err(WgError::Invalid(format!("peer ip `{ip}` already in use")));
                }
                // If a subnet exists and the IP fits, reserve it in
                // IPAM so auto-allocation cannot race to it later.
                let mut reserved = false;
                let mut ipam_guard = self.inner.ipam.lock().await;
                if let Some(ipam) = ipam_guard.as_mut() {
                    if ipam.subnet().contains(ip) {
                        ipam.mark_used(ip)?;
                        reserved = true;
                    }
                }
                Ok((ip, reserved))
            }
            None => {
                let mut ipam_guard = self.inner.ipam.lock().await;
                let ipam = ipam_guard.as_mut().ok_or_else(|| {
                    WgError::Invalid("explicit peer ip required when wg_subnet is unset".into())
                })?;
                let ip = ipam.allocate()?;
                Ok((ip, true))
            }
        }
    }

    async fn add_peer_after_ip(
        &self,
        req: PeerCreate,
        ip: Ipv4Addr,
    ) -> Result<(PeerView, PeerSecrets)> {
        let (public_key_bytes, client_private) = resolve_client_keypair(req.public_key)?;

        let preshared = if req.preshared {
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            Some(buf)
        } else {
            None
        };

        let key = self.data_key();
        let preshared_key_enc = match preshared.as_ref() {
            Some(psk) => Some(key.seal(psk)?),
            None => None,
        };

        let insert = WgPeerInsert {
            id: Uuid::now_v7().to_string(),
            user_id: None,
            name: req.name.clone(),
            public_key: public_key_bytes,
            preshared_key_enc,
            allowed_ip: ip.to_string(),
            endpoint: req.endpoint.map(|a| a.to_string()),
            keepalive: req.keepalive.map(i64::from),
        };
        let row = WgRepo::new(&self.inner.db).insert(insert).await?;

        if *self.inner.started.read().await {
            let peer = peer_row_to_backend(&row, self.data_key())?;
            self.inner.backend.add_or_update_peer(peer).await?;
        }

        let stats = self.peer_stats_map().await;
        let totals = self.traffic_totals_map().await;
        let view = row_into_view(row, &stats, &totals)?;
        Ok((
            view,
            PeerSecrets {
                private_key: client_private,
                preshared_key: preshared,
            },
        ))
    }

    /// Enable WG for `user_id`: allocate a peer, persist it under the
    /// user, and (if the device is live) install it. Returns the new
    /// peer view + one-shot secrets.
    ///
    /// `client_public_key`:
    /// * `Some(pk)` — the caller supplies their own public key; the
    ///   server stores it verbatim and returns `private_key: None`.
    /// * `None` — the server generates a fresh keypair and returns the
    ///   private half exactly once. The private half is never persisted.
    ///
    /// Idempotent against repeated enablement: if a peer already exists
    /// for the user it is returned unchanged with empty secrets. Call
    /// [`WgDriver::rotate_user_wg`] to mint fresh material.
    ///
    /// Requires `wg_subnet` to be set; when the driver is in hybrid
    /// (explicit-IP) mode this call returns [`WgError::Invalid`].
    /// Operators in that mode must provision peers via
    /// [`WgDriver::add_peer`] with an explicit `ip`.
    #[tracing::instrument(skip(self, client_public_key))]
    pub async fn enable_user_wg(
        &self,
        user_id: &str,
        client_public_key: Option<[u8; 32]>,
    ) -> Result<(PeerView, Option<PeerSecrets>)> {
        let repo = WgRepo::new(&self.inner.db);
        if let Some(row) = repo.get_by_user(user_id).await? {
            let stats = self.peer_stats_map().await;
            let totals = self.traffic_totals_map().await;
            let view = row_into_view(row, &stats, &totals)?;
            return Ok((view, None));
        }

        let ip = {
            let mut ipam = self.inner.ipam.lock().await;
            let ipam = ipam.as_mut().ok_or_else(|| {
                WgError::Invalid(
                    "wg_subnet is unset; set a subnet before enabling WG for users".into(),
                )
            })?;
            ipam.allocate()?
        };

        let outcome = self
            .enable_user_wg_after_ip(user_id, ip, client_public_key)
            .await;
        if outcome.is_err() {
            let mut ipam = self.inner.ipam.lock().await;
            if let Some(ipam) = ipam.as_mut() {
                let _ = ipam.release(ip);
            }
        }
        outcome.map(|(v, s)| (v, Some(s)))
    }

    async fn enable_user_wg_after_ip(
        &self,
        user_id: &str,
        ip: Ipv4Addr,
        client_public_key: Option<[u8; 32]>,
    ) -> Result<(PeerView, PeerSecrets)> {
        let user = nsp_db::UsersRepo::new(&self.inner.db)
            .get(user_id)
            .await?
            .ok_or_else(|| WgError::NotFound(user_id.to_owned()))?;
        let (public_key_bytes, client_private) = resolve_client_keypair(client_public_key)?;

        let mut preshared_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut preshared_bytes);

        let key = self.data_key();
        let preshared_key_enc = Some(key.seal(&preshared_bytes)?);

        let insert = WgPeerInsert {
            id: Uuid::now_v7().to_string(),
            user_id: Some(user_id.to_owned()),
            name: Some(user.name),
            public_key: public_key_bytes,
            preshared_key_enc,
            allowed_ip: ip.to_string(),
            endpoint: None,
            keepalive: None,
        };
        let row = WgRepo::new(&self.inner.db)
            .enable_user(user_id, insert)
            .await?;

        if *self.inner.started.read().await {
            let peer = peer_row_to_backend(&row, self.data_key())?;
            self.inner.backend.add_or_update_peer(peer).await?;
        }

        let stats = self.peer_stats_map().await;
        let totals = self.traffic_totals_map().await;
        let view = row_into_view(row, &stats, &totals)?;
        Ok((
            view,
            PeerSecrets {
                private_key: client_private,
                preshared_key: Some(preshared_bytes),
            },
        ))
    }

    /// Disable WG for `user_id`: remove the peer row (if any), pull it
    /// from the live device, release its IP, and clear
    /// `users.wg_enabled`. Idempotent when no peer is attached.
    #[tracing::instrument(skip(self))]
    pub async fn disable_user_wg(&self, user_id: &str) -> Result<()> {
        let repo = WgRepo::new(&self.inner.db);
        let existing = repo.get_by_user(user_id).await?;
        if let Some(row) = existing.as_ref() {
            if *self.inner.started.read().await {
                let _ = self.inner.backend.remove_peer(&row.public_key).await;
            }
        }
        repo.disable_user(user_id).await?;
        if let Some(row) = existing {
            if let Ok(ip) = row.allowed_ip.parse::<Ipv4Addr>() {
                let mut ipam = self.inner.ipam.lock().await;
                if let Some(ipam) = ipam.as_mut() {
                    let _ = ipam.release(ip);
                }
            }
        }
        Ok(())
    }

    /// Converge the live device toward the `wg_peers` table. Adds any
    /// missing peers, removes any live peers without a matching DB
    /// row. No-op when the device is stopped — the next `spawn_real`
    /// builds from DB directly.
    #[tracing::instrument(skip(self))]
    pub async fn sync_from_db(&self) -> Result<()> {
        if !*self.inner.started.read().await {
            return Ok(());
        }

        let rows = WgRepo::new(&self.inner.db).list().await?;
        let desired: std::collections::HashMap<[u8; 32], WgPeerRow> =
            rows.into_iter().map(|r| (r.public_key, r)).collect();

        let live_keys: Vec<[u8; 32]> = self
            .inner
            .backend
            .list_peer_stats()
            .await?
            .into_iter()
            .map(|s| s.public_key)
            .collect();

        for pk_bytes in &live_keys {
            if !desired.contains_key(pk_bytes) {
                if let Err(err) = self.inner.backend.remove_peer(pk_bytes).await {
                    tracing::warn!(target: "nsp::wg", %err, "reconcile: remove orphan peer");
                }
            }
        }

        for (pk_bytes, row) in &desired {
            if live_keys.iter().any(|b| b == pk_bytes) {
                continue;
            }
            match peer_row_to_backend(row, self.data_key()) {
                Ok(peer) => {
                    if let Err(err) = self.inner.backend.add_or_update_peer(peer).await {
                        tracing::warn!(target: "nsp::wg", peer_id = %row.id, %err, "reconcile: install peer");
                    }
                }
                Err(err) => {
                    tracing::warn!(target: "nsp::wg", peer_id = %row.id, %err, "reconcile: decode peer row");
                }
            }
        }
        Ok(())
    }

    /// Remove a peer by id. Releases its IP back to IPAM.
    #[tracing::instrument(skip(self))]
    pub async fn remove_peer(&self, id: &str) -> Result<()> {
        let repo = WgRepo::new(&self.inner.db);
        let Some(row) = repo.get(id).await? else {
            return Err(WgError::NotFound(id.to_owned()));
        };

        if *self.inner.started.read().await {
            self.inner.backend.remove_peer(&row.public_key).await?;
        }

        if !repo.delete(id).await? {
            return Err(WgError::NotFound(id.to_owned()));
        }

        if let Ok(ip) = row.allowed_ip.parse::<Ipv4Addr>() {
            let mut ipam = self.inner.ipam.lock().await;
            if let Some(ipam) = ipam.as_mut() {
                let _ = ipam.release(ip);
            }
        }
        Ok(())
    }

    /// Rotate the keypair of the peer attached to `user_id`. IP and
    /// metadata stay the same. `client_public_key` follows the same
    /// rules as [`WgDriver::enable_user_wg`].
    #[tracing::instrument(skip(self, client_public_key))]
    pub async fn rotate_user_wg(
        &self,
        user_id: &str,
        client_public_key: Option<[u8; 32]>,
    ) -> Result<(PeerView, PeerSecrets)> {
        let repo = WgRepo::new(&self.inner.db);
        let Some(old) = repo.get_by_user(user_id).await? else {
            return Err(WgError::NotFound(user_id.to_owned()));
        };

        let (public_key_bytes, client_private) = resolve_client_keypair(client_public_key)?;

        let key = self.data_key();
        let new_preshared = old.preshared_key_enc.as_ref().map(|_| {
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            buf
        });
        let new_psk_enc = match new_preshared.as_ref() {
            Some(psk) => Some(key.seal(psk)?),
            None => None,
        };

        let row = repo
            .rotate_keys(&old.id, public_key_bytes, new_psk_enc)
            .await?
            .ok_or_else(|| WgError::NotFound(old.id.clone()))?;

        if *self.inner.started.read().await {
            let _ = self.inner.backend.remove_peer(&old.public_key).await;
            let peer = peer_row_to_backend(&row, self.data_key())?;
            self.inner.backend.add_or_update_peer(peer).await?;
        }

        let stats = self.peer_stats_map().await;
        let totals = self.traffic_totals_map().await;
        let view = row_into_view(row, &stats, &totals)?;
        Ok((
            view,
            PeerSecrets {
                private_key: client_private,
                preshared_key: new_preshared,
            },
        ))
    }

    async fn load_or_generate_server_keys(&self) -> Result<(Zeroizing<[u8; 32]>, PublicKey)> {
        let repo = ServerConfigRepo::new(&self.inner.db);
        let key = self.data_key();

        if let Some(enc) = repo.get(SERVER_PRIVATE_KEY).await? {
            let plain = key.open(&enc)?;
            let arr = <[u8; 32]>::try_from(plain.as_slice())
                .map_err(|_| WgError::Invalid("stored server key length != 32".into()))?;
            let public = PublicKey::from(&StaticSecret::from(arr));
            return Ok((Zeroizing::new(arr), public));
        }

        let secret = new_static_secret();
        let private_bytes = secret.to_bytes();
        let public = PublicKey::from(&secret);
        let enc = key.seal(&private_bytes)?;
        repo.set(SERVER_PRIVATE_KEY, &enc).await?;
        repo.set(SERVER_PUBLIC_KEY, public.as_bytes()).await?;
        tracing::info!(
            target: "nsp::wg",
            public_key = %B64.encode(public.as_bytes()),
            "generated WG server keypair"
        );
        Ok((Zeroizing::new(private_bytes), public))
    }

    async fn seed_ipam(&self) -> Result<()> {
        let Some(subnet) = *self.inner.subnet.read().await else {
            // Hybrid mode: no auto-allocator, callers must provide IPs.
            *self.inner.ipam.lock().await = None;
            return Ok(());
        };
        let rows = WgRepo::new(&self.inner.db).list().await?;
        let mut ipam = Ipam::new(subnet)?;
        for row in &rows {
            if let Ok(ip) = row.allowed_ip.parse::<Ipv4Addr>() {
                // Skip out-of-subnet entries (stale config) with a warning.
                match ipam.mark_used(ip) {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(target: "nsp::wg", peer_id = %row.id, %ip, %e, "skipping stale peer ip")
                    }
                }
            }
        }
        *self.inner.ipam.lock().await = Some(ipam);
        Ok(())
    }

    async fn peer_stats_map(&self) -> std::collections::HashMap<[u8; 32], BackendPeerStats> {
        if !*self.inner.started.read().await {
            return Default::default();
        }
        match self.inner.backend.list_peer_stats().await {
            Ok(stats) => stats.into_iter().map(|s| (s.public_key, s)).collect(),
            Err(err) => {
                tracing::warn!(target: "nsp::wg", %err, "fetch peer stats");
                Default::default()
            }
        }
    }

    async fn traffic_totals_map(&self) -> std::collections::HashMap<String, WgTrafficSummary> {
        match WgTrafficRepo::new(&self.inner.db).list_summary().await {
            Ok(rows) => rows.into_iter().map(|s| (s.peer_id.clone(), s)).collect(),
            Err(err) => {
                tracing::warn!(target: "nsp::wg", %err, "load persisted traffic totals");
                Default::default()
            }
        }
    }

    fn data_key(&self) -> DataKey {
        self.inner.master_key.data_key()
    }
}

#[async_trait]
impl ReconcileTarget for WgDriver {
    fn name(&self) -> &'static str {
        "wg"
    }

    async fn sync_from_db(&self) -> std::result::Result<(), String> {
        WgDriver::sync_from_db(self)
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl Driver for WgDriver {
    fn protocol(&self) -> ProtocolKind {
        ProtocolKind::WireGuard
    }

    async fn spawn(&self) -> nsp_core::Result<()> {
        // The `Driver` trait is a lightweight lifecycle hook shared with
        // `ss-driver`; we preload keys + IPAM so the API reports sensible
        // status, but leave the data-plane bring-up to the caller via
        // `WgDriver::spawn_real`. Startup may want to degrade gracefully
        // if the kernel module / TUN isn't available (e.g. unprivileged
        // CI); the caller makes that call.
        self.prepare()
            .await
            .map_err(|e| nsp_core::CoreError::Internal(format!("wg prepare: {e}")))
    }

    async fn status(&self) -> nsp_core::Result<DriverStatus> {
        let running = *self.inner.started.read().await;
        let active = WgRepo::new(&self.inner.db)
            .list()
            .await
            .map_err(|e| nsp_core::CoreError::Internal(format!("wg list: {e}")))?
            .len() as u64;
        Ok(DriverStatus {
            protocol: ProtocolKind::WireGuard,
            running,
            listen_port: Some(self.inner.cfg.listen_port),
            active_clients: active,
        })
    }

    async fn shutdown(&self) -> nsp_core::Result<()> {
        let was_started = {
            let mut guard = self.inner.started.write().await;
            let prev = *guard;
            *guard = false;
            prev
        };
        if was_started {
            self.inner
                .backend
                .down()
                .await
                .map_err(|e| nsp_core::CoreError::Internal(format!("wg down: {e}")))?;
        }
        Ok(())
    }
}

fn row_into_view(
    row: WgPeerRow,
    stats: &std::collections::HashMap<[u8; 32], BackendPeerStats>,
    totals: &std::collections::HashMap<String, WgTrafficSummary>,
) -> Result<PeerView> {
    let ip = row
        .allowed_ip
        .parse::<Ipv4Addr>()
        .map_err(|e| WgError::Invalid(format!("allowed_ip `{}`: {e}", row.allowed_ip)))?;
    let endpoint = row
        .endpoint
        .as_ref()
        .and_then(|s| s.parse::<SocketAddr>().ok());
    let keepalive = row.keepalive.map(|k| k.clamp(0, u16::MAX as i64) as u16);

    let (rx_bytes, tx_bytes, last_handshake_secs) = match stats.get(&row.public_key) {
        Some(s) => (
            s.rx_bytes,
            s.tx_bytes,
            s.last_handshake.map(|d| d.as_secs()),
        ),
        None => (0, 0, None),
    };
    let (total_rx, total_tx) = match totals.get(&row.id) {
        Some(t) => (t.total_rx_bytes, t.total_tx_bytes),
        None => (0, 0),
    };

    Ok(PeerView {
        id: row.id,
        user_id: row.user_id,
        name: row.name,
        public_key: PublicKey::from(row.public_key),
        allowed_ip: ip,
        endpoint,
        keepalive,
        has_psk: row.preshared_key_enc.is_some(),
        created_at: row.created_at,
        updated_at: row.updated_at,
        rx_bytes,
        tx_bytes,
        last_handshake_secs,
        total_rx_bytes: total_rx,
        total_tx_bytes: total_tx,
    })
}

/// SQLite-backed [`PeerResolver`] that the userspace backend uses to
/// fetch peers on demand. Holds an `Arc<MasterKey>` so the cached
/// `DataKey` stays bound to the live key rotation, and a clone of the
/// SQLite pool so resolves can run on the runtime without holding the
/// driver handle.
#[derive(Debug)]
struct DbPeerResolver {
    pool: Pool,
    master_key: Arc<MasterKey>,
}

impl DbPeerResolver {
    fn new(pool: Pool, master_key: Arc<MasterKey>) -> Self {
        Self { pool, master_key }
    }
}

#[async_trait]
impl PeerResolver for DbPeerResolver {
    async fn resolve(&self, public_key: [u8; 32]) -> Result<Option<BackendPeer>> {
        let row = WgRepo::new(&self.pool)
            .find_by_public_key(&public_key)
            .await?;
        match row {
            Some(row) => Ok(Some(peer_row_to_backend(&row, self.master_key.data_key())?)),
            None => Ok(None),
        }
    }
}

fn peer_row_to_backend(row: &WgPeerRow, key: DataKey) -> Result<BackendPeer> {
    let allowed_ip: Ipv4Addr = row
        .allowed_ip
        .parse()
        .map_err(|e| WgError::Invalid(format!("peer allowed_ip: {e}")))?;
    let endpoint = row
        .endpoint
        .as_ref()
        .and_then(|s| s.parse::<SocketAddr>().ok());
    let preshared_key = match row.preshared_key_enc.as_ref() {
        Some(enc) => {
            let bytes = key.open(enc)?;
            let arr = <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| WgError::Invalid("PSK length != 32".into()))?;
            Some(arr)
        }
        None => None,
    };
    let keepalive = row.keepalive.map(|k| k.clamp(0, u16::MAX as i64) as u16);
    Ok(BackendPeer {
        public_key: row.public_key,
        allowed_ip,
        endpoint,
        keepalive,
        preshared_key,
    })
}

fn new_static_secret() -> StaticSecret {
    StaticSecret::random_from_rng(rand::thread_rng())
}

/// Settle on the client keypair based on caller intent. If the caller
/// supplied a public key, use it verbatim; otherwise generate a fresh
/// keypair and return the private half for one-shot delivery.
fn resolve_client_keypair(
    caller_public_key: Option<[u8; 32]>,
) -> Result<([u8; 32], Option<[u8; 32]>)> {
    match caller_public_key {
        Some(pk) => Ok((pk, None)),
        None => {
            let secret = new_static_secret();
            let public = PublicKey::from(&secret);
            Ok((public.to_bytes(), Some(secret.to_bytes())))
        }
    }
}

/// Resolve the egress interface name. Priority:
///   1. `override` — value from config.
///   2. `/proc/net/route` — first entry with a default route (`Destination` =
///      `00000000`).
///   3. Static fallback `eth0` so tests / containers without `/proc/net/route`
///      still end up with a usable rule.
fn resolve_wan_interface(override_name: Option<&str>) -> String {
    if let Some(name) = override_name {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    detect_default_route_interface().unwrap_or_else(|| "eth0".to_owned())
}

fn detect_default_route_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let iface = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000" {
            return Some(iface.to_owned());
        }
    }
    None
}

/// Whether `ip` falls in one of the RFC1918 private ranges.
fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}

/// Check whether any persisted peer already owns `ip`.
async fn peer_ip_in_use(db: &Pool, ip: Ipv4Addr) -> Result<bool> {
    let s = ip.to_string();
    let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM wg_peers WHERE allowed_ip = ? LIMIT 1")
        .bind(&s)
        .fetch_optional(db)
        .await
        .map_err(|e| WgError::Db(nsp_db::DbError::Sqlx(e)))?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn master_key() -> Arc<MasterKey> {
        let gen = MasterKey::generate();
        let b64 = SecretString::from(gen.to_base64());
        Arc::new(MasterKey::from_base64(&b64).unwrap())
    }

    async fn pool() -> Pool {
        let dir = std::env::temp_dir().join(format!(
            "nsp-wg-test-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        nsp_db::open(&path).await.expect("open db")
    }

    fn cfg() -> WgConfig {
        WgConfig {
            interface: "wg-test".into(),
            listen_port: 51820,
            subnet: Some("10.66.66.0/24".parse().unwrap()),
            endpoint_host: Some("vpn.example.com".into()),
            wan_interface: None,
            backend: BackendKind::Userspace,
            netstack: NetstackOptions::default(),
        }
    }

    fn cfg_no_subnet() -> WgConfig {
        WgConfig {
            interface: "wg-test".into(),
            listen_port: 51820,
            subnet: None,
            endpoint_host: Some("vpn.example.com".into()),
            wan_interface: None,
            backend: BackendKind::Userspace,
            netstack: NetstackOptions::default(),
        }
    }

    #[tokio::test]
    async fn prepare_generates_server_key_once() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);

        driver.prepare().await.expect("prepare");
        let first = driver.status_view().await.expect("status");

        driver.prepare().await.expect("prepare twice");
        let second = driver.status_view().await.expect("status again");

        assert_eq!(first.server_public_key, second.server_public_key);
        assert_eq!(second.total_peers, 0);
        assert_eq!(second.subnet, "10.66.66.0/24");
        assert_eq!(second.backend, "userspace");
    }

    #[tokio::test]
    async fn add_and_remove_peer_roundtrip_through_db() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);
        driver.prepare().await.unwrap();

        let (view, secrets) = driver
            .add_peer(PeerCreate {
                name: Some("alpha".into()),
                preshared: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(view.name.as_deref(), Some("alpha"));
        assert!(view.has_psk);
        assert_eq!(view.allowed_ip.to_string(), "10.66.66.2");
        // Server generated the keypair, so the one-shot private key is Some.
        assert!(secrets.private_key.is_some());
        assert!(secrets.preshared_key.is_some());

        let listed = driver.list_peers().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, view.id);

        let status = driver.status_view().await.unwrap();
        assert_eq!(status.total_peers, 1);

        driver.remove_peer(&view.id).await.unwrap();
        let listed = driver.list_peers().await.unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn add_peer_with_caller_public_key_omits_private_key() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);
        driver.prepare().await.unwrap();

        let caller_pub = [7u8; 32];
        let (view, secrets) = driver
            .add_peer(PeerCreate {
                public_key: Some(caller_pub),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(view.public_key.as_bytes(), &caller_pub);
        assert!(secrets.private_key.is_none());
    }

    #[tokio::test]
    async fn rotate_user_wg_changes_public_key_keeps_ip() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool.clone(), mk);
        driver.prepare().await.unwrap();

        let users = nsp_db::UsersRepo::new(&pool);
        users.create("user-1", "alice", None).await.unwrap();

        let (view, initial) = driver.enable_user_wg("user-1", None).await.unwrap();
        let initial = initial.expect("first enable returns secrets");
        assert!(initial.private_key.is_some());
        let original_ip = view.allowed_ip;
        let original_pk = view.public_key;

        let (rotated, new_secrets) = driver.rotate_user_wg("user-1", None).await.unwrap();
        assert_eq!(rotated.allowed_ip, original_ip);
        assert_ne!(rotated.public_key.as_bytes(), original_pk.as_bytes());
        assert!(new_secrets.private_key.is_some());
    }

    #[tokio::test]
    async fn rotate_user_wg_accepts_caller_public_key() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool.clone(), mk);
        driver.prepare().await.unwrap();

        let users = nsp_db::UsersRepo::new(&pool);
        users.create("user-2", "bob", None).await.unwrap();

        let (_, _) = driver.enable_user_wg("user-2", None).await.unwrap();
        let caller_pub = [11u8; 32];
        let (rotated, secrets) = driver
            .rotate_user_wg("user-2", Some(caller_pub))
            .await
            .unwrap();

        assert_eq!(rotated.public_key.as_bytes(), &caller_pub);
        assert!(secrets.private_key.is_none());
    }

    #[tokio::test]
    async fn remove_of_unknown_peer_is_not_found() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);
        driver.prepare().await.unwrap();
        let err = driver.remove_peer("nope").await.unwrap_err();
        assert!(matches!(err, WgError::NotFound(_)));
    }

    #[tokio::test]
    async fn stop_is_idempotent_without_spawn() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);

        assert!(!driver.is_running().await);
        driver.stop().await.expect("first stop is a no-op");
        driver.stop().await.expect("second stop is still a no-op");
        assert!(!driver.is_running().await);
    }

    #[tokio::test]
    async fn hybrid_mode_requires_explicit_ip() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg_no_subnet(), pool, mk);
        driver.prepare().await.unwrap();

        // Auto-allocation is disabled -> error.
        let err = driver.add_peer(PeerCreate::default()).await.unwrap_err();
        assert!(matches!(err, WgError::Invalid(_)));

        // Explicit RFC1918 IP works.
        let (view, _) = driver
            .add_peer(PeerCreate {
                ip: Some("10.100.0.5".parse().unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(view.allowed_ip.to_string(), "10.100.0.5");

        // Non-RFC1918 IP rejected.
        let err = driver
            .add_peer(PeerCreate {
                ip: Some("8.8.8.8".parse().unwrap()),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(err, WgError::Invalid(_)));

        // Duplicate IP rejected.
        let err = driver
            .add_peer(PeerCreate {
                ip: Some("10.100.0.5".parse().unwrap()),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(err, WgError::Invalid(_)));
    }

    #[tokio::test]
    async fn explicit_ip_in_subnet_consumes_ipam_slot() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);
        driver.prepare().await.unwrap();

        driver
            .add_peer(PeerCreate {
                ip: Some("10.66.66.2".parse().unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();

        // Next auto-allocation should skip .2 because the explicit IP
        // claimed it in IPAM.
        let (next, _) = driver.add_peer(PeerCreate::default()).await.unwrap();
        assert_eq!(next.allowed_ip.to_string(), "10.66.66.3");
    }

    #[tokio::test]
    async fn peers_outside_subnet_reports_conflicts() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg_no_subnet(), pool, mk);
        driver.prepare().await.unwrap();

        let (keeper, _) = driver
            .add_peer(PeerCreate {
                ip: Some("10.66.66.42".parse().unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();
        let (mover, _) = driver
            .add_peer(PeerCreate {
                ip: Some("192.168.10.5".parse().unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();

        let target: Ipv4Network = "10.66.66.0/24".parse().unwrap();
        let conflicts = driver.peers_outside_subnet(Some(target)).await.unwrap();
        assert_eq!(conflicts, vec![mover.id.clone()]);

        // With an empty target every peer is "outside".
        let all = driver.peers_outside_subnet(None).await.unwrap();
        assert!(all.contains(&keeper.id));
        assert!(all.contains(&mover.id));
    }

    #[tokio::test]
    async fn set_subnet_rebuilds_ipam() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);
        driver.prepare().await.unwrap();

        // With the default /24 subnet auto-allocate lands at .2 / .3.
        let (_, _) = driver.add_peer(PeerCreate::default()).await.unwrap();

        // Move to a different /24: pre-existing peer (.2) is outside
        // the new range. Caller would have rejected this at 409, but the
        // setter itself must still run cleanly and reseed IPAM.
        let new_subnet: Ipv4Network = "10.200.0.0/24".parse().unwrap();
        driver.set_subnet(Some(new_subnet)).await.unwrap();
        assert_eq!(driver.subnet().await, Some(new_subnet));

        // Next auto-allocation comes from the new subnet.
        let (fresh, _) = driver.add_peer(PeerCreate::default()).await.unwrap();
        assert!(fresh.allowed_ip.to_string().starts_with("10.200.0."));

        // Clearing the subnet moves into hybrid mode.
        driver.set_subnet(None).await.unwrap();
        assert_eq!(driver.subnet().await, None);
        let err = driver.add_peer(PeerCreate::default()).await.unwrap_err();
        assert!(matches!(err, WgError::Invalid(_)));
    }

    #[tokio::test]
    async fn set_endpoint_host_updates_status_view() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);
        driver.prepare().await.unwrap();

        driver
            .set_endpoint_host(Some("new.example.com".into()))
            .await;
        let status = driver.status_view().await.unwrap();
        assert_eq!(status.endpoint_host.as_deref(), Some("new.example.com"));

        driver.set_endpoint_host(None).await;
        let status = driver.status_view().await.unwrap();
        assert!(status.endpoint_host.is_none());
    }

    #[test]
    fn from_core_parses_userspace_backend() {
        let core = nsp_core::config::WireguardConfig {
            backend: "userspace".into(),
            ..Default::default()
        };
        let wg = WgConfig::from_core(&core, None).unwrap();
        assert_eq!(wg.backend, BackendKind::Userspace);
    }

    #[test]
    fn from_core_default_is_kernel() {
        let core = nsp_core::config::WireguardConfig::default();
        let wg = WgConfig::from_core(&core, None).unwrap();
        assert_eq!(wg.backend, BackendKind::Kernel);
    }

    #[test]
    fn from_core_parses_netstack_options() {
        let core = nsp_core::config::WireguardConfig {
            backend: "netstack".into(),
            netstack: nsp_core::config::WireguardNetstackConfig {
                socks5: Some("127.0.0.1:1081".into()),
                socks5_username: Some("alice".into()),
                socks5_password: Some("s3cret".into()),
                forwards: vec![
                    "127.0.0.1:8080=10.255.0.2:80".into(),
                    " ".into(),
                    "127.0.0.2:22,443=10.255.0.2".into(),
                ],
                udp_forwards: vec!["127.0.0.1:5353=10.255.0.2:53".into()],
            },
            ..Default::default()
        };
        let wg = WgConfig::from_core(&core, None).unwrap();
        assert_eq!(wg.backend, BackendKind::Netstack);
        assert_eq!(wg.netstack.socks5, Some("127.0.0.1:1081".parse().unwrap()));
        assert_eq!(
            wg.netstack.forwards[0],
            PortForward {
                listen: "127.0.0.1:8080".parse().unwrap(),
                target: "10.255.0.2:80".parse().unwrap(),
            }
        );
        assert_eq!(wg.netstack.forwards.len(), 3);
        assert_eq!(
            wg.netstack.forwards[2].target,
            "10.255.0.2:443".parse().unwrap()
        );
        assert_eq!(
            wg.netstack.udp_forwards[0].target,
            "10.255.0.2:53".parse().unwrap()
        );
        assert_eq!(
            wg.netstack.socks5_auth.map(|a| a.username),
            Some("alice".into())
        );
    }

    #[test]
    fn from_core_rejects_bad_netstack_options() {
        let mut core = nsp_core::config::WireguardConfig::default();
        core.netstack.socks5 = Some("localhost:1081".into());
        assert!(WgConfig::from_core(&core, None).is_err());
        core.netstack.socks5 = None;
        core.netstack.forwards = vec!["127.0.0.1:8080".into()];
        assert!(WgConfig::from_core(&core, None).is_err());
        core.netstack.forwards.clear();
        core.netstack.udp_forwards = vec!["nonsense".into()];
        assert!(WgConfig::from_core(&core, None).is_err());
        core.netstack.udp_forwards.clear();
        core.netstack.socks5_username = Some("alice".into());
        assert!(
            WgConfig::from_core(&core, None).is_err(),
            "username without password"
        );
    }

    #[test]
    fn from_core_rejects_unknown_backend() {
        let core = nsp_core::config::WireguardConfig {
            backend: "xdp".into(),
            ..Default::default()
        };
        assert!(WgConfig::from_core(&core, None).is_err());
    }

    /// Backend stub that returns a canned `list_peer_stats` payload.
    /// Used to drive [`traffic::sample_once`] without a live data plane.
    #[derive(Debug)]
    struct CannedBackend {
        stats: tokio::sync::RwLock<Vec<BackendPeerStats>>,
    }

    impl CannedBackend {
        fn new() -> Self {
            Self {
                stats: tokio::sync::RwLock::new(Vec::new()),
            }
        }

        async fn set_stats(&self, stats: Vec<BackendPeerStats>) {
            *self.stats.write().await = stats;
        }
    }

    #[async_trait]
    impl WgBackend for CannedBackend {
        fn kind(&self) -> BackendKind {
            BackendKind::Userspace
        }
        async fn up(&self, _params: backend::BackendBringUp) -> Result<()> {
            Ok(())
        }
        async fn down(&self) -> Result<()> {
            Ok(())
        }
        async fn is_running(&self) -> bool {
            true
        }
        async fn add_or_update_peer(&self, _peer: BackendPeer) -> Result<()> {
            Ok(())
        }
        async fn remove_peer(&self, _public_key: &[u8; 32]) -> Result<()> {
            Ok(())
        }
        async fn list_peer_stats(&self) -> Result<Vec<BackendPeerStats>> {
            Ok(self.stats.read().await.clone())
        }
        fn availability(&self) -> backend::BackendAvailability {
            backend::BackendAvailability::ok()
        }
    }

    #[tokio::test]
    async fn sample_traffic_now_persists_totals_and_samples() {
        let pool = pool().await;
        let mk = master_key();
        let backend = Arc::new(CannedBackend::new());
        let resolved = ResolvedBackend {
            requested: BackendKind::Userspace,
            effective: BackendKind::Userspace,
        };
        let driver = WgDriver::with_backend(
            cfg(),
            pool.clone(),
            mk,
            backend.clone() as Arc<dyn WgBackend>,
            resolved,
        );
        driver.prepare().await.unwrap();

        let caller_pub = [42u8; 32];
        let (view, _) = driver
            .add_peer(PeerCreate {
                public_key: Some(caller_pub),
                ..Default::default()
            })
            .await
            .unwrap();

        // Inject a stats reading and trigger one sweep.
        backend
            .set_stats(vec![BackendPeerStats {
                public_key: caller_pub,
                rx_bytes: 1_500,
                tx_bytes: 2_500,
                last_handshake: Some(std::time::Duration::from_secs(30)),
            }])
            .await;
        let recorded = driver.sample_traffic_now().await.unwrap();
        assert_eq!(recorded, 1);

        let summary = driver
            .traffic_summary(&view.id)
            .await
            .unwrap()
            .expect("summary present after sample");
        assert_eq!(summary.total_rx_bytes, 1_500);
        assert_eq!(summary.total_tx_bytes, 2_500);

        let listed = driver.list_peers().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].total_rx_bytes, 1_500);
        assert_eq!(listed[0].total_tx_bytes, 2_500);

        // Second sweep with a higher counter accumulates an
        // additional delta into the cumulative total.
        backend
            .set_stats(vec![BackendPeerStats {
                public_key: caller_pub,
                rx_bytes: 4_000,
                tx_bytes: 5_000,
                last_handshake: None,
            }])
            .await;
        driver.sample_traffic_now().await.unwrap();
        let summary = driver.traffic_summary(&view.id).await.unwrap().unwrap();
        assert_eq!(summary.total_rx_bytes, 4_000);
        assert_eq!(summary.total_tx_bytes, 5_000);

        let samples = driver.traffic_samples(&view.id, 0, 10).await.unwrap();
        // Both samples land in the same hour bucket.
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].rx_bytes, 4_000);
        assert_eq!(samples[0].tx_bytes, 5_000);
    }

    #[tokio::test]
    async fn userspace_default_is_lazy_and_skips_eager_seed() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool, mk);
        // The lazy userspace backend must opt out of eager peer
        // seeding so spawn_real avoids the up-front DB scan.
        assert!(!driver.inner.backend.eager_seed_peers());
        assert_eq!(driver.backend_kind(), BackendKind::Userspace);
    }

    #[tokio::test]
    async fn db_peer_resolver_round_trips_inserted_peer() {
        let pool = pool().await;
        let mk = master_key();
        let driver = WgDriver::new(cfg(), pool.clone(), Arc::clone(&mk));
        driver.prepare().await.unwrap();

        // Persist a peer through the normal API; the row will land in
        // wg_peers with an encrypted PSK if requested.
        let caller_pub = [9u8; 32];
        let (view, _) = driver
            .add_peer(PeerCreate {
                public_key: Some(caller_pub),
                preshared: true,
                ..Default::default()
            })
            .await
            .unwrap();

        let resolver = DbPeerResolver::new(pool.clone(), mk);
        let hit = resolver.resolve(caller_pub).await.unwrap();
        let peer = hit.expect("resolver must surface the persisted peer");
        assert_eq!(peer.public_key, caller_pub);
        assert_eq!(peer.allowed_ip, view.allowed_ip);
        assert!(
            peer.preshared_key.is_some(),
            "PSK must round-trip via DataKey"
        );

        let miss = resolver.resolve([0xAB; 32]).await.unwrap();
        assert!(miss.is_none(), "unknown pubkeys must yield None");
    }
}
