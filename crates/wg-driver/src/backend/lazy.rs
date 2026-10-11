//! Lazy peer resolution for the userspace backend.
//!
//! In lazy mode the nsplane engine is brought up with **no peers**.
//! Inbound handshake-init packets are inspected on the UDP recv path
//! by [`LazyTransport`]: when the embedded static public key is not
//! yet installed on the engine, an async task queries the configured
//! [`PeerResolver`] (usually a SQLite-backed lookup) and — on a hit —
//! calls `EngineHandle::add_or_update_peer` so the next handshake
//! retransmit lands on a fully-installed peer.
//!
//! This lets a single device serve a huge user base while keeping only
//! the actively-handshaking peers resident in memory. The kernel
//! backend keeps eager-loading because in-kernel WG already scales
//! peer lookup at near-zero cost.
//!
//! ## Lifecycle
//!
//! 1. Construct a [`LazyContext`] holding the server keys + resolver.
//! 2. Wrap the UDP transport with [`LazyTransport`].
//! 3. Build the engine with no peers.
//! 4. Install an [`AddPeerCallback`] on the context that forwards to
//!    the engine handle. Handshake inits that arrive before this are
//!    ignored by the wrapper; the client retries them.
//!
//! ## DOS surface
//!
//! `parse_handshake_anon` succeeds for any 32-byte payload encrypted
//! with the (public) server static key, so an attacker can craft
//! handshake inits with arbitrary pubkeys to force DB scans. The
//! [`LazyContext`] caches negative resolutions for [`NEGATIVE_TTL`] to
//! keep that to one DB lookup per unique forged pubkey per minute. The
//! negative cache is pruned by the eviction task; it does not grow
//! unbounded between sweeps but it is not capped per-tick.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nsplane::{AllowedIp, Ecn, PacketBuf, Path, PathMtuReport, Peer, Transport, TransportId};
use nsplane_core::noise::handshake::parse_handshake_anon;
use nsplane_core::noise::{Packet, Tunn};
use tokio::sync::{mpsc, OnceCell};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Result, WgError};

use super::BackendPeer;

/// Default TTL for negative resolution cache entries — pubkeys that
/// the resolver reported as unknown. Inbound handshake retries within
/// this window are silently dropped without hitting the DB.
pub const NEGATIVE_TTL: Duration = Duration::from_mins(1);

/// Resolves a peer's persisted material from a public key. The
/// userspace backend's lazy flow consults this on every previously-
/// unseen handshake init.
#[async_trait]
pub trait PeerResolver: Send + Sync + std::fmt::Debug {
    /// Look up the peer with `public_key` in persistent storage.
    ///
    /// `Ok(Some(peer))` installs the peer on the live device.
    /// `Ok(None)` is cached as "unknown" for [`NEGATIVE_TTL`].
    /// `Err(_)` is logged and not cached — the next retry will retry.
    async fn resolve(&self, public_key: [u8; 32]) -> Result<Option<BackendPeer>>;
}

/// Type-erased shim that lets [`LazyContext`] call
/// `EngineHandle::add_or_update_peer` (or a test recorder).
#[async_trait]
pub(crate) trait AddPeerCallback: Send + Sync {
    async fn add(&self, peer: BackendPeer) -> Result<()>;
}

/// Shared state between the wrapped UDP recv tasks and the rest of
/// the backend (eviction loop, post-build wiring).
pub struct LazyContext {
    server_private: StaticSecret,
    server_public: PublicKey,
    resolver: Arc<dyn PeerResolver>,
    /// Set of pubkeys we have already installed on the device.
    /// Consulted as a fast-path: if present, the inbound packet skips
    /// resolution entirely. Mutated when we install or evict.
    installed: StdRwLock<HashSet<[u8; 32]>>,
    /// Pubkeys the resolver reported as unknown, and when. Pruned by
    /// the eviction task.
    negative: StdMutex<HashMap<[u8; 32], Instant>>,
    /// Pubkeys with an in-flight resolve task. Used to single-flight
    /// duplicate handshake inits during the resolve window.
    in_flight: StdMutex<HashSet<[u8; 32]>>,
    /// Filled after the engine is built so the recv path can install peers.
    /// Until populated, the wrapper drops handshake inits silently
    /// (the WG client will retry).
    add_peer: OnceCell<Arc<dyn AddPeerCallback>>,
    negative_ttl: Duration,
}

impl std::fmt::Debug for LazyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyContext")
            .field("resolver", &self.resolver)
            .field(
                "installed_count",
                &self.installed.read().map(|s| s.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

impl LazyContext {
    pub fn new(server_private: StaticSecret, resolver: Arc<dyn PeerResolver>) -> Arc<Self> {
        let server_public = PublicKey::from(&server_private);
        Arc::new(Self {
            server_private,
            server_public,
            resolver,
            installed: StdRwLock::new(HashSet::new()),
            negative: StdMutex::new(HashMap::new()),
            in_flight: StdMutex::new(HashSet::new()),
            add_peer: OnceCell::new(),
            negative_ttl: NEGATIVE_TTL,
        })
    }

    /// Wire the engine-backed installer. Called once, right after the
    /// engine is built.
    pub(crate) fn install_add_peer(&self, cb: Arc<dyn AddPeerCallback>) -> Result<()> {
        self.add_peer
            .set(cb)
            .map_err(|_| WgError::Invalid("lazy add_peer already installed".into()))
    }

    /// Snapshot of currently-installed pubkeys.
    pub fn installed_keys(&self) -> Vec<[u8; 32]> {
        self.installed
            .read()
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Mark a pubkey as installed without going through the lazy
    /// resolve flow. Used when the operator explicitly adds a peer
    /// via the API so the recv-path fast-path skips redundant work.
    pub fn note_installed(&self, pubkey: [u8; 32]) {
        if let Ok(mut s) = self.installed.write() {
            s.insert(pubkey);
        }
    }

    /// Drop a pubkey from the installed mirror. Called by the
    /// eviction task after it removes the peer from the live engine,
    /// and by the explicit `remove_peer` path.
    pub fn forget_installed(&self, pubkey: &[u8; 32]) {
        if let Ok(mut s) = self.installed.write() {
            s.remove(pubkey);
        }
    }

    /// Borrow the resolver. Useful for building a fresh
    /// [`LazyContext`] on `up()` after a previous `down()` cleared
    /// the slot.
    pub fn resolver(&self) -> Arc<dyn PeerResolver> {
        Arc::clone(&self.resolver)
    }

    /// Prune negative-cache entries older than [`Self::negative_ttl`].
    /// Returns the number of entries dropped.
    pub fn prune_negative(&self) -> usize {
        let Ok(mut neg) = self.negative.lock() else {
            return 0;
        };
        let before = neg.len();
        neg.retain(|_, ts| ts.elapsed() < self.negative_ttl);
        before - neg.len()
    }

    /// Inspect a freshly-received UDP packet and, when it is a
    /// handshake init for an unknown pubkey, spawn a resolve+install
    /// task. The packet itself is left untouched and will continue
    /// downstream into the engine.
    fn try_register(self: &Arc<Self>, packet: &[u8]) {
        // No installer wired up yet — nothing we can do with a hit.
        if self.add_peer.get().is_none() {
            return;
        }
        let Some(pubkey) = parse_init_pubkey(packet, &self.server_private, &self.server_public)
        else {
            return;
        };

        if self
            .installed
            .read()
            .map(|s| s.contains(&pubkey))
            .unwrap_or(false)
        {
            return;
        }

        if let Ok(neg) = self.negative.lock() {
            if let Some(ts) = neg.get(&pubkey) {
                if ts.elapsed() < self.negative_ttl {
                    return;
                }
            }
        }

        if let Ok(mut flight) = self.in_flight.lock() {
            if !flight.insert(pubkey) {
                return;
            }
        } else {
            return;
        }

        let ctx = Arc::clone(self);
        tokio::spawn(async move {
            ctx.resolve_and_install(pubkey).await;
        });
    }

    async fn resolve_and_install(self: Arc<Self>, pubkey: [u8; 32]) {
        let outcome = self.resolver.resolve(pubkey).await;
        match outcome {
            Ok(Some(peer)) => {
                if let Some(cb) = self.add_peer.get() {
                    match cb.add(peer).await {
                        Ok(()) => {
                            if let Ok(mut s) = self.installed.write() {
                                s.insert(pubkey);
                            }
                            if let Ok(mut neg) = self.negative.lock() {
                                neg.remove(&pubkey);
                            }
                            tracing::debug!(
                                target: "nsp::wg::lazy",
                                pubkey = %hex_short(&pubkey),
                                "peer installed via lazy resolver",
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                target: "nsp::wg::lazy",
                                %err,
                                pubkey = %hex_short(&pubkey),
                                "lazy add_peer failed",
                            );
                        }
                    }
                }
            }
            Ok(None) => {
                if let Ok(mut neg) = self.negative.lock() {
                    neg.insert(pubkey, Instant::now());
                }
                tracing::trace!(
                    target: "nsp::wg::lazy",
                    pubkey = %hex_short(&pubkey),
                    "lazy resolve: unknown peer",
                );
            }
            Err(err) => {
                tracing::warn!(
                    target: "nsp::wg::lazy",
                    %err,
                    pubkey = %hex_short(&pubkey),
                    "lazy resolve failed",
                );
            }
        }
        if let Ok(mut flight) = self.in_flight.lock() {
            flight.remove(&pubkey);
        }
    }
}

fn hex_short(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(8);
    for b in &bytes[..4] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode the embedded peer static public key from a handshake init
/// packet. Returns `None` if the datagram is not a well-formed
/// handshake init or AEAD-open fails.
pub(crate) fn parse_init_pubkey(
    packet: &[u8],
    server_private: &StaticSecret,
    server_public: &PublicKey,
) -> Option<[u8; 32]> {
    let Ok(Packet::HandshakeInit(init)) = Tunn::parse_incoming_packet(packet) else {
        return None;
    };
    let half = parse_handshake_anon(server_private, server_public, &init).ok()?;
    Some(half.peer_static_public)
}

/// Convert a [`BackendPeer`] into the engine's peer config.
///
/// The engine treats `None` as "leave unchanged" on update, so the
/// preshared key and keepalive are always set explicitly (zero
/// removes them) to give `add_or_update_peer` replace semantics. A
/// missing endpoint keeps whatever path the peer roamed to.
pub(crate) fn peer_to_nsplane(peer: &BackendPeer, transport: TransportId) -> Peer {
    let mut p = Peer::new(PublicKey::from(peer.public_key));
    p.allowed_ips = vec![AllowedIp {
        addr: IpAddr::V4(peer.allowed_ip),
        cidr: 32,
    }];
    p.replace_allowed_ips = true;
    p.preshared_key = Some(peer.preshared_key.unwrap_or([0; 32]));
    p.persistent_keepalive = Some(peer.keepalive.unwrap_or(0));
    p.path = peer.endpoint.map(|addr| Path {
        transport,
        addr,
        ecn: Ecn::NotEct,
    });
    p
}

/// Wraps a [`Transport`] to run [`LazyContext::try_register`] on every
/// inbound datagram before handing it to the engine. Everything else
/// is forwarded to the inner transport unchanged.
pub struct LazyTransport<T: Transport> {
    inner: T,
    ctx: Arc<LazyContext>,
}

impl<T: Transport> LazyTransport<T> {
    pub fn new(inner: T, ctx: Arc<LazyContext>) -> Self {
        Self { inner, ctx }
    }
}

impl<T: Transport> Transport for LazyTransport<T> {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        let (len, path) = self.inner.recv(buf).await?;
        self.ctx.try_register(&buf.as_packet()[..len]);
        Ok((len, path))
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        self.inner.send(datagram, to).await
    }

    async fn recv_batch(
        &self,
        buf: &mut PacketBuf,
        datagrams: &mut VecDeque<(Path, PacketBuf)>,
    ) -> io::Result<()> {
        let start = datagrams.len();
        let result = self.inner.recv_batch(buf, datagrams).await;
        for (_, datagram) in datagrams.range(start..) {
            self.ctx.try_register(datagram.as_packet());
        }
        result
    }

    async fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        self.inner.send_batch(datagrams, sent, failed).await
    }

    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        self.inner.try_send_batch(datagrams, sent, failed)
    }

    fn path_mtu_reports(&self) -> Option<mpsc::Receiver<PathMtuReport>> {
        self.inner.path_mtu_reports()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A resolver that hands back a hard-coded mapping. Useful in
    /// unit tests to drive the lazy flow without a real DB.
    #[derive(Debug, Default)]
    pub struct MapResolver {
        pub map: std::sync::Mutex<HashMap<[u8; 32], BackendPeer>>,
        pub hits: std::sync::atomic::AtomicUsize,
        pub misses: std::sync::atomic::AtomicUsize,
    }

    impl MapResolver {
        pub fn insert(&self, public_key: [u8; 32], peer: BackendPeer) {
            self.map.lock().unwrap().insert(public_key, peer);
        }
    }

    #[async_trait]
    impl PeerResolver for MapResolver {
        async fn resolve(&self, public_key: [u8; 32]) -> Result<Option<BackendPeer>> {
            let hit = self.map.lock().unwrap().get(&public_key).cloned();
            if hit.is_some() {
                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                self.misses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(hit)
        }
    }

    /// Capturing installer — records the peers add_peer was called with.
    #[derive(Debug, Default)]
    struct Recorder {
        peers: tokio::sync::Mutex<Vec<BackendPeer>>,
    }

    #[async_trait]
    impl AddPeerCallback for Recorder {
        async fn add(&self, peer: BackendPeer) -> Result<()> {
            self.peers.lock().await.push(peer);
            Ok(())
        }
    }

    fn dummy_peer(public_key: [u8; 32]) -> BackendPeer {
        BackendPeer {
            public_key,
            allowed_ip: Ipv4Addr::new(10, 0, 0, 1),
            endpoint: None,
            keepalive: None,
            preshared_key: None,
        }
    }

    fn build_init_packet(
        client_priv: &StaticSecret,
        server_pub: &PublicKey,
    ) -> (Vec<u8>, [u8; 32]) {
        // Route through the public Tunn API to get a real handshake
        // init instead of re-implementing the noise dance.
        use nsplane_core::noise::TunnResult;
        let client_pub = PublicKey::from(client_priv);
        let mut tunn = Tunn::new(client_priv.clone(), *server_pub, None, None, 1, None);
        let mut buf = vec![0u8; 256];
        let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut buf, true)
        else {
            panic!("handshake init must produce a packet");
        };
        (init.to_vec(), *client_pub.as_bytes())
    }

    #[tokio::test]
    async fn try_register_installs_known_peer() {
        let server_priv = StaticSecret::random();
        let resolver = Arc::new(MapResolver::default());
        let ctx = LazyContext::new(server_priv.clone(), resolver.clone());
        let recorder = Arc::new(Recorder::default());
        ctx.install_add_peer(recorder.clone()).unwrap();

        let client_priv = StaticSecret::random();
        let server_pub = PublicKey::from(&server_priv);
        let (packet, pubkey) = build_init_packet(&client_priv, &server_pub);
        resolver.insert(pubkey, dummy_peer(pubkey));

        ctx.try_register(&packet);
        // Spawned task runs on the same runtime; yield until it
        // finishes by sleeping a tick.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if recorder.peers.lock().await.len() == 1 {
                break;
            }
        }
        let peers = recorder.peers.lock().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, pubkey);
        assert_eq!(resolver.hits.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(ctx.installed_keys().contains(&pubkey));
    }

    #[tokio::test]
    async fn unknown_peer_lands_in_negative_cache() {
        let server_priv = StaticSecret::random();
        let resolver = Arc::new(MapResolver::default());
        let ctx = LazyContext::new(server_priv.clone(), resolver.clone());
        let recorder = Arc::new(Recorder::default());
        ctx.install_add_peer(recorder.clone()).unwrap();

        let client_priv = StaticSecret::random();
        let server_pub = PublicKey::from(&server_priv);
        let (packet, pubkey) = build_init_packet(&client_priv, &server_pub);

        ctx.try_register(&packet);
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if resolver.misses.load(std::sync::atomic::Ordering::Relaxed) == 1 {
                break;
            }
        }
        assert_eq!(
            resolver.misses.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert!(recorder.peers.lock().await.is_empty());
        assert!(ctx.negative.lock().unwrap().contains_key(&pubkey));

        // Replays within the TTL must NOT trigger another DB lookup.
        ctx.try_register(&packet);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            resolver.misses.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn parse_init_rejects_non_handshake_packets() {
        let server_priv = StaticSecret::random();
        let server_pub = PublicKey::from(&server_priv);
        let mut buf = vec![0u8; 148];
        // Type byte = 4 (data), not handshake init.
        buf[0] = 4;
        assert!(parse_init_pubkey(&buf, &server_priv, &server_pub).is_none());
    }
}
