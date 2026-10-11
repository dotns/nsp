//! CLI + config loader.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use figment::{
    providers::{Format, Serialized, Toml},
    Figment,
};
use nsp_core::config::{ApiMode, ConflictPolicy, ProxyConfig};
use secrecy::SecretString;

#[derive(Debug, Parser)]
#[command(name = "nsp", version, about = "Self-hosted proxy control plane")]
pub struct Cli {
    #[command(flatten)]
    pub serve: ServeArgs,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand, Clone)]
pub enum Command {
    /// Start the HTTP/TLS server (default).
    Serve(Box<ServeArgs>),
    /// Generate a random 32-byte master key (base64) and print it to stdout.
    GenerateKey,
}

#[derive(Debug, Args, Clone)]
pub struct ServeArgs {
    /// Override the configuration file path.
    #[arg(long, env = "NSP_CONFIG", default_value = "/etc/nsp/nsp.toml")]
    pub config: PathBuf,

    /// Override the listener. Accepts a port or socket address.
    #[arg(long, env = "NSP_LISTEN")]
    pub listen: Option<String>,

    /// Override `http.domain`.
    #[arg(long, env = "NSP_DOMAIN")]
    pub domain: Option<String>,

    /// Override `tls.enabled`.
    #[arg(long, env = "NSP_TLS")]
    pub tls_enabled: Option<bool>,

    /// Override `tls.cert_path`.
    #[arg(long, env = "NSP_TLS_CERT")]
    pub tls_cert_path: Option<PathBuf>,

    /// Override `tls.key_path`.
    #[arg(long, env = "NSP_TLS_KEY")]
    pub tls_key_path: Option<PathBuf>,

    /// Override `tls.acme.enabled`.
    #[arg(long, env = "NSP_ACME")]
    pub tls_acme_enabled: Option<bool>,

    /// Override `tls.acme.email`.
    #[arg(long, env = "NSP_ACME_EMAIL")]
    pub tls_acme_email: Option<String>,

    /// Override `tls.acme.domains`.
    #[arg(long, env = "NSP_ACME_DOMAINS", value_delimiter = ',')]
    pub tls_acme_domains: Vec<String>,

    /// Override `tls.acme.production`.
    #[arg(long, env = "NSP_ACME_PRODUCTION")]
    pub tls_acme_production: Option<bool>,

    /// Override `tls.acme.cache_dir`.
    #[arg(long, env = "NSP_ACME_CACHE")]
    pub tls_acme_cache_dir: Option<PathBuf>,

    /// Override `storage.db_path`.
    #[arg(long, env = "NSP_DB")]
    pub storage_db_path: Option<PathBuf>,

    /// Override `storage.work_dir`.
    #[arg(long, env = "NSP_WORK_DIR")]
    pub storage_work_dir: Option<PathBuf>,

    /// Override `security.master_key`.
    #[arg(long, env = "NSP_MASTER_KEY")]
    pub security_master_key: Option<String>,

    /// Override `security.admin_password`.
    #[arg(long, env = "NSP_ADMIN_PASSWORD")]
    pub security_admin_password: Option<String>,

    /// Override `security.jwt_ttl_secs`.
    #[arg(long, env = "NSP_JWT_TTL")]
    pub security_jwt_ttl_secs: Option<u64>,

    /// Allow startup without a master key. Local development only.
    #[arg(long, env = "NSP_ALLOW_INSECURE_NO_MASTER_KEY")]
    pub allow_insecure_no_master_key: Option<bool>,

    /// Override `security.api`. `enabled` (default) is the full
    /// read/write admin surface; `readonly` blocks all writes;
    /// `disabled` skips the listener bind entirely. This is a
    /// purely local operator decision, independent of the
    /// reverse-API control center.
    #[arg(long, env = "NSP_API", value_enum)]
    pub security_api: Option<ApiMode>,

    /// Override `wireguard.enabled`.
    #[arg(long, env = "NSP_WG")]
    pub wireguard_enabled: Option<bool>,

    /// Override `wireguard.port`.
    #[arg(long, env = "NSP_WG_PORT")]
    pub wireguard_port: Option<u16>,

    /// Override `wireguard.subnet`.
    #[arg(long, env = "NSP_WG_SUBNET")]
    pub wireguard_subnet: Option<String>,

    /// Override `wireguard.interface`.
    #[arg(long, env = "NSP_WG_INTERFACE")]
    pub wireguard_interface: Option<String>,

    /// Override `wireguard.backend`. Accepted values: `kernel`,
    /// `userspace`, `netstack`, `auto`. Defaults to `kernel`.
    #[arg(long, env = "NSP_WG_BACKEND")]
    pub wireguard_backend: Option<String>,

    /// Override `wireguard.netstack.socks5` (`ip:port`).
    #[arg(long, env = "NSP_WG_SOCKS5")]
    pub wireguard_netstack_socks5: Option<String>,

    /// Override `wireguard.netstack.forwards`: `listen=target` TCP
    /// forwards, `;`-separated in the env var (`,` lists ports).
    #[arg(long, env = "NSP_WG_FORWARDS", value_delimiter = ';')]
    pub wireguard_netstack_forward: Vec<String>,

    /// Override `wireguard.netstack.udp_forwards`: `listen=target` UDP
    /// forwards, `;`-separated in the env var (`,` lists ports).
    #[arg(long, env = "NSP_WG_UDP_FORWARDS", value_delimiter = ';')]
    pub wireguard_netstack_udp_forward: Vec<String>,

    /// Override `wireguard.netstack.socks5_username`.
    #[arg(long, env = "NSP_WG_SOCKS5_USERNAME")]
    pub wireguard_netstack_socks5_username: Option<String>,

    /// Override `wireguard.netstack.socks5_password`.
    #[arg(long, env = "NSP_WG_SOCKS5_PASSWORD", hide_env_values = true)]
    pub wireguard_netstack_socks5_password: Option<String>,

    /// Override `shadowsocks.enabled`.
    #[arg(long, env = "NSP_SS")]
    pub shadowsocks_enabled: Option<bool>,

    /// Override `shadowsocks.bind`.
    #[arg(long, env = "NSP_SS_BIND")]
    pub shadowsocks_bind: Option<IpAddr>,

    /// Override `shadowsocks.port`.
    #[arg(long, env = "NSP_SS_PORT")]
    pub shadowsocks_port: Option<u16>,

    /// Override `shadowsocks.apply_debounce_ms`.
    #[arg(long, env = "NSP_SS_DEBOUNCE_MS")]
    pub shadowsocks_apply_debounce_ms: Option<u64>,

    /// Override `proxy.enabled`.
    #[arg(long, env = "NSP_PROXY")]
    pub proxy_enabled: Option<bool>,

    /// Override `proxy.bind`.
    #[arg(long, env = "NSP_PROXY_BIND")]
    pub proxy_bind: Option<IpAddr>,

    /// Override `proxy.socks5_port`.
    #[arg(long, env = "NSP_PROXY_SOCKS5_PORT")]
    pub proxy_socks5_port: Option<u16>,

    /// Override `proxy.http_port`.
    #[arg(long, env = "NSP_PROXY_HTTP_PORT")]
    pub proxy_http_port: Option<u16>,

    /// Override `proxy.apply_debounce_ms`.
    #[arg(long, env = "NSP_PROXY_DEBOUNCE_MS")]
    pub proxy_apply_debounce_ms: Option<u64>,

    /// Override `proxy.block_private_destinations`.
    #[arg(long, env = "NSP_PROXY_BLOCK_PRIVATE")]
    pub proxy_block_private_destinations: Option<bool>,

    /// Override `proxy.max_inflight`.
    #[arg(long, env = "NSP_PROXY_MAX_INFLIGHT")]
    pub proxy_max_inflight: Option<usize>,

    /// Override `logging.level`.
    #[arg(long, env = "NSP_LOG")]
    pub logging_level: Option<String>,

    /// Override `logging.json`.
    #[arg(long, env = "NSP_JSON_LOGS")]
    pub logging_json: Option<bool>,

    /// Override `metrics.enabled`.
    #[arg(long, env = "NSP_METRICS")]
    pub metrics_enabled: Option<bool>,

    /// Override `metrics.bearer_token`.
    #[arg(long, env = "NSP_METRICS_TOKEN")]
    pub metrics_bearer_token: Option<String>,

    /// Override `metrics.refresh_ms`.
    #[arg(long, env = "NSP_METRICS_REFRESH_MS")]
    pub metrics_refresh_ms: Option<u64>,

    /// Override `backup.enabled`.
    #[arg(long, env = "NSP_BACKUP")]
    pub backup_enabled: Option<bool>,

    /// Override `backup.interval_secs`.
    #[arg(long, env = "NSP_BACKUP_INTERVAL_SECS")]
    pub backup_interval_secs: Option<u64>,

    /// Override `backup.dir`.
    #[arg(long, env = "NSP_BACKUP_DIR")]
    pub backup_dir: Option<PathBuf>,

    /// Override `backup.retention_days`.
    #[arg(long, env = "NSP_BACKUP_RETENTION_DAYS")]
    pub backup_retention_days: Option<u32>,

    /// Override `control.enabled`. When true, nsp polls the configured
    /// control center for settings + user snapshots.
    #[arg(long, env = "NSP_CONTROL")]
    pub control_enabled: Option<bool>,

    /// Override `control.url`. Base URL of the control center, e.g.
    /// `https://control.example.com`.
    #[arg(long, env = "NSP_CONTROL_URL")]
    pub control_url: Option<String>,

    /// Override `control.token`. Bearer token sent to the control center.
    #[arg(long, env = "NSP_CONTROL_TOKEN")]
    pub control_token: Option<String>,

    /// Override `control.node_id`. Logical identifier of this node.
    #[arg(long, env = "NSP_CONTROL_NODE_ID")]
    pub control_node_id: Option<String>,

    /// Override `control.interval_secs`.
    #[arg(long, env = "NSP_CONTROL_INTERVAL_SECS")]
    pub control_interval_secs: Option<u64>,

    /// Override `control.timeout_secs`.
    #[arg(long, env = "NSP_CONTROL_TIMEOUT_SECS")]
    pub control_timeout_secs: Option<u64>,

    /// Override `control.status_interval_secs`. Cadence of the
    /// `POST /status` observability reports. Defaults to the same
    /// value as `interval_secs`.
    #[arg(long, env = "NSP_CONTROL_STATUS_INTERVAL_SECS")]
    pub control_status_interval_secs: Option<u64>,

    /// Override `control.conflict_policy`. Decides what happens to
    /// local resources (users, control-source iptables rules) that
    /// the server didn't include in a Full snapshot. `keep` (default)
    /// preserves them; `prune` deletes them. Server-driven
    /// `mode: "replace"` always wins per response.
    #[arg(long, env = "NSP_CONTROL_CONFLICT_POLICY", value_enum)]
    pub control_conflict_policy: Option<ConflictPolicy>,
}

/// Merge defaults -> TOML (if present) -> env-backed CLI args -> CLI overrides.
pub fn load_config(args: &ServeArgs) -> anyhow::Result<ProxyConfig> {
    let defaults = ProxyConfig::default();
    let mut fig = Figment::from(Serialized::defaults(&defaults));

    if args.config.exists() {
        fig = fig.merge(Toml::file(&args.config));
    }

    let mut cfg: ProxyConfig = fig.extract().context("extract config")?;

    if let Some(ref listen) = args.listen {
        apply_listen(&mut cfg, listen)?;
    }
    if let Some(ref domain) = args.domain {
        cfg.http.domain = Some(domain.clone());
    }
    if let Some(enabled) = args.tls_enabled {
        cfg.tls.enabled = enabled;
    }
    if let Some(ref p) = args.tls_cert_path {
        cfg.tls.cert_path = Some(p.clone());
    }
    if let Some(ref p) = args.tls_key_path {
        cfg.tls.key_path = Some(p.clone());
    }
    if let Some(enabled) = args.tls_acme_enabled {
        cfg.tls.acme.enabled = enabled;
    }
    if let Some(ref email) = args.tls_acme_email {
        cfg.tls.acme.email = Some(email.clone());
    }
    if !args.tls_acme_domains.is_empty() {
        cfg.tls.acme.domains.clone_from(&args.tls_acme_domains);
    }
    if let Some(production) = args.tls_acme_production {
        cfg.tls.acme.production = production;
    }
    if let Some(ref p) = args.tls_acme_cache_dir {
        cfg.tls.acme.cache_dir.clone_from(p);
    }
    if let Some(ref p) = args.storage_db_path {
        cfg.storage.db_path.clone_from(p);
    }
    if let Some(ref p) = args.storage_work_dir {
        cfg.storage.work_dir.clone_from(p);
    }
    if let Some(ref k) = args.security_master_key {
        cfg.security.master_key = Some(SecretString::from(k.clone()));
    }
    if let Some(ref password) = args.security_admin_password {
        cfg.security.admin_password = Some(SecretString::from(password.clone()));
    }
    if let Some(ttl) = args.security_jwt_ttl_secs {
        cfg.security.jwt_ttl_secs = ttl;
    }
    if let Some(allow) = args.allow_insecure_no_master_key {
        cfg.security.allow_insecure_no_master_key = allow;
    }
    if let Some(mode) = args.security_api {
        cfg.security.api = mode;
    }
    if let Some(enabled) = args.wireguard_enabled {
        cfg.wireguard.enabled = enabled;
    }
    if let Some(port) = args.wireguard_port {
        cfg.wireguard.port = port;
    }
    if let Some(ref subnet) = args.wireguard_subnet {
        cfg.wireguard.subnet.clone_from(subnet);
    }
    if let Some(ref interface) = args.wireguard_interface {
        cfg.wireguard.interface.clone_from(interface);
    }
    if let Some(ref backend) = args.wireguard_backend {
        cfg.wireguard.backend.clone_from(backend);
    }
    if let Some(ref socks5) = args.wireguard_netstack_socks5 {
        cfg.wireguard.netstack.socks5 = Some(socks5.clone());
    }
    if !args.wireguard_netstack_forward.is_empty() {
        cfg.wireguard.netstack.forwards = args.wireguard_netstack_forward.clone();
    }
    if !args.wireguard_netstack_udp_forward.is_empty() {
        cfg.wireguard.netstack.udp_forwards = args.wireguard_netstack_udp_forward.clone();
    }
    if let Some(ref username) = args.wireguard_netstack_socks5_username {
        cfg.wireguard.netstack.socks5_username = Some(username.clone());
    }
    if let Some(ref password) = args.wireguard_netstack_socks5_password {
        cfg.wireguard.netstack.socks5_password = Some(SecretString::from(password.clone()));
    }
    if let Some(enabled) = args.shadowsocks_enabled {
        cfg.shadowsocks.enabled = enabled;
    }
    if let Some(bind) = args.shadowsocks_bind {
        cfg.shadowsocks.bind = bind;
    }
    if let Some(port) = args.shadowsocks_port {
        cfg.shadowsocks.port = port;
    }
    if let Some(ms) = args.shadowsocks_apply_debounce_ms {
        cfg.shadowsocks.apply_debounce_ms = ms;
    }
    if let Some(enabled) = args.proxy_enabled {
        cfg.proxy.enabled = enabled;
    }
    if let Some(bind) = args.proxy_bind {
        cfg.proxy.bind = bind;
    }
    if let Some(port) = args.proxy_socks5_port {
        cfg.proxy.socks5_port = port;
    }
    if let Some(port) = args.proxy_http_port {
        cfg.proxy.http_port = port;
    }
    if let Some(ms) = args.proxy_apply_debounce_ms {
        cfg.proxy.apply_debounce_ms = ms;
    }
    if let Some(block) = args.proxy_block_private_destinations {
        cfg.proxy.block_private_destinations = block;
    }
    if let Some(cap) = args.proxy_max_inflight {
        cfg.proxy.max_inflight = cap;
    }
    if let Some(ref level) = args.logging_level {
        cfg.logging.level.clone_from(level);
    }
    if let Some(json) = args.logging_json {
        cfg.logging.json = json;
    }
    if let Some(enabled) = args.metrics_enabled {
        cfg.metrics.enabled = enabled;
    }
    if let Some(ref token) = args.metrics_bearer_token {
        cfg.metrics.bearer_token = Some(SecretString::from(token.clone()));
    }
    if let Some(ms) = args.metrics_refresh_ms {
        cfg.metrics.refresh_ms = ms;
    }
    if let Some(enabled) = args.backup_enabled {
        cfg.backup.enabled = enabled;
    }
    if let Some(secs) = args.backup_interval_secs {
        cfg.backup.interval_secs = secs;
    }
    if let Some(ref dir) = args.backup_dir {
        cfg.backup.dir.clone_from(dir);
    }
    if let Some(days) = args.backup_retention_days {
        cfg.backup.retention_days = days;
    }
    if let Some(enabled) = args.control_enabled {
        cfg.control.enabled = enabled;
    }
    if let Some(ref url) = args.control_url {
        cfg.control.url = Some(url.clone());
    }
    if let Some(ref token) = args.control_token {
        cfg.control.token = Some(SecretString::from(token.clone()));
    }
    if let Some(ref id) = args.control_node_id {
        cfg.control.node_id = Some(id.clone());
    }
    if let Some(secs) = args.control_interval_secs {
        cfg.control.interval_secs = secs;
    }
    if let Some(secs) = args.control_timeout_secs {
        cfg.control.timeout_secs = secs;
    }
    if let Some(secs) = args.control_status_interval_secs {
        cfg.control.status_interval_secs = secs;
    }
    if let Some(policy) = args.control_conflict_policy {
        cfg.control.conflict_policy = policy;
    }
    Ok(cfg)
}

fn apply_listen(cfg: &mut ProxyConfig, listen: &str) -> anyhow::Result<()> {
    let listen = listen.trim();
    if let Ok(port) = listen.parse::<u16>() {
        cfg.http.listen.set_port(port);
        return Ok(());
    }

    let addr = listen
        .parse::<SocketAddr>()
        .with_context(|| format!("parse --listen value `{listen}` as port or socket address"))?;
    cfg.http.listen = addr;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::Cli;

    #[test]
    fn forwards_split_on_semicolons_so_commas_list_ports() {
        let cli = Cli::try_parse_from([
            "nsp",
            "--wireguard-netstack-forward",
            "127.0.0.1:8080=10.255.0.2:80;127.0.0.2:22,443=10.255.0.2",
            "--wireguard-netstack-udp-forward",
            "127.0.0.2:53,5353=10.255.0.2",
        ])
        .unwrap();
        assert_eq!(
            cli.serve.wireguard_netstack_forward,
            [
                "127.0.0.1:8080=10.255.0.2:80",
                "127.0.0.2:22,443=10.255.0.2"
            ]
        );
        assert_eq!(
            cli.serve.wireguard_netstack_udp_forward,
            ["127.0.0.2:53,5353=10.255.0.2"]
        );
    }
}
