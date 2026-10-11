//! Runtime configuration for nsp.
//!
//! Layering (loaded in `nsp::main`, highest precedence last):
//! `Defaults -> /etc/nsp/nsp.toml -> NSP_* env / CLI args`.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Fully resolved configuration after figment merging.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProxyConfig {
    /// HTTP / TLS listener binding.
    #[serde(default)]
    pub http: HttpConfig,
    /// TLS / ACME settings.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Persistent state location.
    #[serde(default)]
    pub storage: StorageConfig,
    /// Master-key + auth material.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Shadowsocks data plane (stub in M1).
    #[serde(default)]
    pub shadowsocks: ShadowsocksConfig,
    /// WireGuard data plane (stub in M1).
    #[serde(default)]
    pub wireguard: WireguardConfig,
    /// SOCKS5 + HTTP CONNECT proxy data plane.
    #[serde(default)]
    pub proxy: ProxyServerConfig,
    /// Structured logging.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Observability (Prometheus /metrics).
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// SQLite online backup scheduler.
    #[serde(default)]
    pub backup: BackupConfig,
    /// Reverse-API control-center poller. When `enabled = true` the binary
    /// periodically pulls settings + user list from a remote control plane
    /// and reconciles them into the local SQLite database.
    #[serde(default)]
    pub control: ControlConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpConfig {
    pub listen: SocketAddr,
    pub domain: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 443)),
            domain: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub db_path: PathBuf,
    pub work_dir: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("/work/data/proxy.db"),
            work_dir: PathBuf::from("/work"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// 32-byte master key, base64-encoded. Required at runtime; optional in
    /// deserialization so that `--generate-key` and default configs work.
    #[serde(
        default,
        deserialize_with = "de_opt_secret",
        serialize_with = "ser_opt_secret"
    )]
    pub master_key: Option<SecretString>,
    /// Admin password; consumed on first startup then discarded.
    #[serde(
        default,
        deserialize_with = "de_opt_secret",
        serialize_with = "ser_opt_secret"
    )]
    pub admin_password: Option<SecretString>,
    /// JWT lifetime in seconds.
    #[serde(default = "default_jwt_ttl")]
    pub jwt_ttl_secs: u64,
    /// Explicit local-development escape hatch for running without a master key.
    #[serde(default)]
    pub allow_insecure_no_master_key: bool,
    /// Lockdown stance for the `/api/*` surface. Independent of
    /// any control-center configuration; see `docs/api-lockdown.md`.
    #[serde(default)]
    pub api: ApiMode,
}

/// What the `/api/*` admin surface is allowed to do. Set via the
/// node's local environment (`NSP_API`) — never via the
/// reverse-API control center, which bypasses the API entirely
/// and writes through repos directly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum ApiMode {
    /// (Default) Full read/write admin surface. The bundled SPA
    /// works as expected.
    #[default]
    Enabled,
    /// Read-only: only `GET` / `HEAD` / `OPTIONS` are accepted on
    /// `/api/*`. All other methods return `403 Forbidden`. The SPA
    /// still loads and shows current state but cannot mutate it.
    Readonly,
    /// Fully disabled: the HTTP listener is not bound at all. The
    /// admin port doesn't appear in `ss -lntp` / `nmap` output.
    /// Background tasks (control poller, backup, metrics
    /// refresher) keep running until SIGINT/SIGTERM.
    Disabled,
}

impl ApiMode {
    #[must_use]
    pub fn allows_writes(self) -> bool {
        matches!(self, Self::Enabled)
    }

    #[must_use]
    pub fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// True when the binary should bind the HTTP listener (admin
    /// API + SPA static assets) at startup. False only for
    /// `Disabled`. Kept as a method so the gating decision lives
    /// next to the enum and can be tested without a full main.
    ///
    /// **Independent of any control-center configuration.** A node
    /// with `NSP_CONTROL=false` and `NSP_API=disabled` runs truly
    /// headless (background tasks only). A node with
    /// `NSP_CONTROL=true` and `NSP_API=enabled` runs both an
    /// inbound admin surface AND an outbound poller.
    #[must_use]
    pub fn binds_listener(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            master_key: None,
            admin_password: None,
            jwt_ttl_secs: default_jwt_ttl(),
            allow_insecure_no_master_key: false,
            api: ApiMode::default(),
        }
    }
}

fn default_jwt_ttl() -> u64 {
    15 * 60
}

fn de_opt_secret<'de, D>(d: D) -> Result<Option<SecretString>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(d)?.map(SecretString::from))
}

fn ser_opt_secret<S>(value: &Option<SecretString>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // The config loader serializes defaults (always `None`) as the bottom
    // layer for figment merging. Any other caller attempting to serialize a
    // populated secret is a bug: fail loudly rather than silently drop it.
    match value {
        None => s.serialize_none(),
        Some(_) => Err(serde::ser::Error::custom(
            "refusing to serialize populated SecretString",
        )),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowsocksConfig {
    pub enabled: bool,
    pub bind: IpAddr,
    pub port: u16,
    /// Debounce window (ms) for coalescing apply bursts.
    #[serde(default = "default_ss_apply_debounce_ms")]
    pub apply_debounce_ms: u64,
}

impl Default for ShadowsocksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: IpAddr::from([0, 0, 0, 0]),
            port: 4433,
            apply_debounce_ms: default_ss_apply_debounce_ms(),
        }
    }
}

fn default_ss_apply_debounce_ms() -> u64 {
    500
}

/// SOCKS5 + HTTP CONNECT proxy. Disabled by default — exposing a proxy
/// on a public interface is a high-blast-radius decision and the
/// operator must opt in explicitly.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyServerConfig {
    pub enabled: bool,
    pub bind: IpAddr,
    pub socks5_port: u16,
    pub http_port: u16,
    /// Debounce window (ms) for coalescing apply bursts.
    #[serde(default = "default_proxy_apply_debounce_ms")]
    pub apply_debounce_ms: u64,
    /// Also reject RFC1918 / IPv6 ULA CONNECT destinations. Default
    /// `false`: typical deployment lets users reach LAN / WG-internal
    /// hosts. Flip to `true` for "public internet only".
    #[serde(default)]
    pub block_private_destinations: bool,
    /// Global concurrent-connection ceiling shared across both
    /// listeners. `0` falls back to the driver default.
    #[serde(default = "default_proxy_max_inflight")]
    pub max_inflight: usize,
}

impl Default for ProxyServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: IpAddr::from([0, 0, 0, 0]),
            socks5_port: 1080,
            http_port: 8080,
            apply_debounce_ms: default_proxy_apply_debounce_ms(),
            block_private_destinations: false,
            max_inflight: default_proxy_max_inflight(),
        }
    }
}

fn default_proxy_apply_debounce_ms() -> u64 {
    500
}

fn default_proxy_max_inflight() -> usize {
    4096
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireguardConfig {
    pub enabled: bool,
    pub port: u16,
    pub subnet: String,
    pub interface: String,
    /// Egress interface used by the baseline MASQUERADE rule. Leave unset to
    /// let the driver auto-detect the default-route interface at spawn time.
    #[serde(default)]
    pub wan_interface: Option<String>,
    /// Data-plane backend selector: `kernel` (in-kernel `wireguard`
    /// module driven via netlink, **default**), `userspace` (in-process
    /// nsplane + TUN), `netstack` (in-process nsplane + user-space
    /// TCP/IP stack, no TUN), or `auto` (prefer kernel, fall back to
    /// userspace when its preconditions are missing).
    #[serde(default = "default_wg_backend")]
    pub backend: String,
    /// How the host reaches the tunnel with the `netstack` backend.
    #[serde(default)]
    pub netstack: WireguardNetstackConfig,
}

/// Host-side access to the tunnel for the `netstack` backend, which
/// has no TUN device. The stack owns the subnet's first host address.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WireguardNetstackConfig {
    /// SOCKS5 listener (`ip:port`) whose CONNECT and UDP ASSOCIATE
    /// requests are served inside the tunnel. Unset disables it.
    #[serde(default)]
    pub socks5: Option<String>,
    /// SOCKS5 username (RFC 1929). With `socks5_password` set, clients
    /// must authenticate; without both the listener takes anyone, so
    /// bind it to loopback or a trusted network.
    #[serde(default)]
    pub socks5_username: Option<String>,
    /// SOCKS5 password, see `socks5_username`.
    #[serde(
        default,
        deserialize_with = "de_opt_secret",
        serialize_with = "ser_opt_secret"
    )]
    pub socks5_password: Option<SecretString>,
    /// TCP port forwards, `listen=target`: connections to the local
    /// `listen` address are relayed to `target` inside the tunnel.
    /// `127.0.0.1:8080=10.255.0.2:80` maps one port;
    /// `127.0.0.2:22,80,8000-8100=10.255.0.2` maps every listed port to
    /// the same port of the target; `127.0.0.2:8000-8009=10.255.0.2:9000-9009`
    /// maps the lists in order. Each port is one listener.
    #[serde(default)]
    pub forwards: Vec<String>,
    /// UDP port forwards, same syntax as `forwards`: datagrams to the
    /// local `listen` address are relayed to `target` inside the
    /// tunnel, and its replies back to their sender.
    #[serde(default)]
    pub udp_forwards: Vec<String>,
}

impl Default for WireguardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 51820,
            subnet: "10.255.0.0/16".to_owned(),
            interface: "wg0".to_owned(),
            wan_interface: None,
            backend: default_wg_backend(),
            netstack: WireguardNetstackConfig::default(),
        }
    }
}

fn default_wg_backend() -> String {
    "kernel".to_owned()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            json: true,
        }
    }
}

/// TLS source selection. `acme` takes priority when `enabled=true`, otherwise
/// static `cert_path`/`key_path` apply; when both are absent the binary
/// falls back to a self-signed cert (dev only).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TlsConfig {
    /// When false, serve plaintext HTTP. Intended for local development or
    /// deployments that terminate TLS before nsp.
    pub enabled: bool,
    /// Static PEM cert (fallback when ACME is disabled).
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    /// Static PEM private key (paired with `cert_path`).
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// ACME client config.
    #[serde(default)]
    pub acme: AcmeConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// When false, rustls-acme is not started.
    pub enabled: bool,
    /// `mailto:` contact passed to Let's Encrypt.
    #[serde(default)]
    pub email: Option<String>,
    /// Extra domains to request certs for. Defaults to `[http.domain]`.
    #[serde(default)]
    pub domains: Vec<String>,
    /// When true (default) request against Let's Encrypt production. When
    /// false, the staging directory is used — safe for tests.
    #[serde(default = "default_acme_production")]
    pub production: bool,
    /// Cache dir for certificate + account material. Writable by the process.
    #[serde(default = "default_acme_cache")]
    pub cache_dir: PathBuf,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: None,
            domains: Vec::new(),
            production: default_acme_production(),
            cache_dir: default_acme_cache(),
        }
    }
}

fn default_acme_production() -> bool {
    true
}

fn default_acme_cache() -> PathBuf {
    PathBuf::from("/work/data/acme")
}

/// Prometheus `/metrics` endpoint settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// When false, register a global recorder but do not expose the route.
    pub enabled: bool,
    /// Optional static bearer token. When `Some`, `/metrics` authenticates
    /// callers via `Authorization: Bearer <token>`; when `None` the route
    /// reuses the admin JWT middleware used by `/api/*`.
    #[serde(
        default,
        deserialize_with = "de_opt_secret",
        serialize_with = "ser_opt_secret"
    )]
    pub bearer_token: Option<SecretString>,
    /// How often background collectors refresh WG peer / DB pool gauges.
    #[serde(default = "default_metrics_refresh_ms")]
    pub refresh_ms: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bearer_token: None,
            refresh_ms: default_metrics_refresh_ms(),
        }
    }
}

fn default_metrics_refresh_ms() -> u64 {
    15_000
}

/// SQLite online-backup scheduler.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupConfig {
    /// When false, the backup task is not spawned.
    pub enabled: bool,
    /// Interval between backups (seconds). Default: hourly.
    #[serde(default = "default_backup_interval_secs")]
    pub interval_secs: u64,
    /// Directory to write `nsp-YYYYMMDD-HH.sqlite` snapshots into.
    #[serde(default = "default_backup_dir")]
    pub dir: PathBuf,
    /// Retention window in days. Files older than this are pruned.
    #[serde(default = "default_backup_retention_days")]
    pub retention_days: u32,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_backup_interval_secs(),
            dir: default_backup_dir(),
            retention_days: default_backup_retention_days(),
        }
    }
}

fn default_backup_interval_secs() -> u64 {
    3_600
}

fn default_backup_dir() -> PathBuf {
    PathBuf::from("/work/data/backups")
}

fn default_backup_retention_days() -> u32 {
    7
}

/// Reverse-API ("control center") poller.
///
/// When `enabled = true`, the binary periodically pulls a snapshot of
/// settings + user list + iptables rules from a remote control plane
/// and reconciles them into the local SQLite database. The poller is
/// a pure pull model: the control center never reaches into nsp
/// directly, only nsp reaches out — which keeps the deployment
/// behind NAT firewall friendly.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlConfig {
    /// Master switch. Defaults off so existing installs are unaffected.
    pub enabled: bool,
    /// Base URL of the control center, e.g. `https://control.example.com`.
    /// The poller appends `/api/v1/nodes/{node_id}/...` to this base.
    #[serde(default)]
    pub url: Option<String>,
    /// Bearer token sent in `Authorization: Bearer <token>` to authenticate
    /// the node against the control center.
    #[serde(
        default,
        deserialize_with = "de_opt_secret",
        serialize_with = "ser_opt_secret"
    )]
    pub token: Option<SecretString>,
    /// Logical identifier of this node within the control plane. Required
    /// when `enabled = true`.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Poll interval in seconds.
    #[serde(default = "default_control_interval_secs")]
    pub interval_secs: u64,
    /// Per-request timeout in seconds.
    #[serde(default = "default_control_timeout_secs")]
    pub timeout_secs: u64,
    /// Interval between `POST /status` reports. Independent from
    /// `interval_secs` (which paces `/config`) so observability data
    /// can be pushed at a different cadence than configuration sync.
    /// Defaults to the same value as `interval_secs`.
    #[serde(default = "default_control_status_interval_secs")]
    pub status_interval_secs: u64,
    /// What to do with local resources (users, control-source iptables
    /// rules) that are absent from a Full server snapshot.
    /// Server-driven `mode: "replace"` always overrides this on a
    /// per-response basis.
    #[serde(default)]
    pub conflict_policy: ConflictPolicy,
}

/// How to resolve conflicts between local resources and a Full
/// snapshot from the control center. Applies uniformly to users
/// AND control-source iptables rules — a single operator decision
/// for all reconciled resources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum ConflictPolicy {
    /// Additive merge: keep local resources that are absent from the
    /// snapshot. Safe default — the operator can pre-create resources
    /// locally and the control center won't delete them. The server
    /// can still force a hard alignment via `mode: "replace"` per
    /// response.
    #[default]
    Keep,
    /// Authoritative: delete local resources that are absent from
    /// the snapshot. Equivalent to the server sending `mode: "replace"`
    /// on every Full snapshot.
    Prune,
}

impl ConflictPolicy {
    /// True when the policy says "delete local extras."
    #[must_use]
    pub fn prunes(self) -> bool {
        matches!(self, Self::Prune)
    }
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            token: None,
            node_id: None,
            interval_secs: default_control_interval_secs(),
            timeout_secs: default_control_timeout_secs(),
            status_interval_secs: default_control_status_interval_secs(),
            conflict_policy: ConflictPolicy::default(),
        }
    }
}

fn default_control_interval_secs() -> u64 {
    60
}

fn default_control_timeout_secs() -> u64 {
    10
}

fn default_control_status_interval_secs() -> u64 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_mode_default_is_enabled() {
        assert_eq!(ApiMode::default(), ApiMode::Enabled);
    }

    #[test]
    fn api_mode_binds_listener_only_when_not_disabled() {
        assert!(ApiMode::Enabled.binds_listener());
        assert!(ApiMode::Readonly.binds_listener());
        assert!(!ApiMode::Disabled.binds_listener());
    }

    #[test]
    fn api_mode_writes_only_when_enabled() {
        assert!(ApiMode::Enabled.allows_writes());
        assert!(!ApiMode::Readonly.allows_writes());
        assert!(!ApiMode::Disabled.allows_writes());
    }

    /// The two switches — `security.api` (inbound admin surface)
    /// and `control.enabled` (outbound reverse-API poller) — must
    /// be fully independent. Operators should be able to pick any
    /// of the six combinations without one implying the other.
    /// This test pins the independence at the config-default
    /// level so a future "convenience" link between them gets
    /// caught.
    #[test]
    fn api_and_control_are_independent_switches() {
        // Default: control off, api enabled.
        let cfg = ProxyConfig::default();
        assert!(!cfg.control.enabled);
        assert_eq!(cfg.security.api, ApiMode::Enabled);

        // Disabling the api must not enable control, or vice versa.
        let mut cfg = ProxyConfig::default();
        cfg.security.api = ApiMode::Disabled;
        assert!(!cfg.control.enabled, "api change leaked into control");

        let mut cfg = ProxyConfig::default();
        cfg.control.enabled = true;
        assert_eq!(
            cfg.security.api,
            ApiMode::Enabled,
            "control change leaked into api"
        );

        // All six combinations are valid configurations.
        for &(api, ctl) in &[
            (ApiMode::Enabled, false),
            (ApiMode::Enabled, true),
            (ApiMode::Readonly, false),
            (ApiMode::Readonly, true),
            (ApiMode::Disabled, false),
            (ApiMode::Disabled, true),
        ] {
            let mut cfg = ProxyConfig::default();
            cfg.security.api = api;
            cfg.control.enabled = ctl;
            assert_eq!(cfg.security.api, api);
            assert_eq!(cfg.control.enabled, ctl);
        }
    }
}
