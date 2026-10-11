//! nsp binary entry point.
//!
//! Loads config (defaults -> toml -> NSP_* env / CLI), initialises tracing, opens
//! the SQLite pool, bootstraps admin if needed, spawns the (stub) data-plane
//! drivers, and serves the axum router over TLS until a shutdown signal.

#![forbid(unsafe_code)]

mod backup;
mod cli;
mod control;
mod observability;
mod server;
mod tls;
mod tracing_init;

use std::sync::Arc;

use anyhow::{anyhow, Context};
use clap::Parser as _;
use nsp_core::{
    auth,
    crypto::MasterKey,
    driver::Driver,
    reconciler::{ReconcileTarget, ReconcilerConfig},
    spawn_reconciler,
};
use nsp_netctl::{DefaultManager, IptablesManager, ProcessBackend};
use nsp_proxy_driver::{ProxyDriver, ProxyDriverConfig};
use nsp_ss_driver::{SsDriver, SsDriverConfig};
use nsp_wg_driver::{BackendKind, WgConfig, WgDriver};
use secrecy::{ExposeSecret, SecretString};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    match cli
        .command
        .unwrap_or_else(|| cli::Command::Serve(Box::new(cli.serve.clone())))
    {
        cli::Command::Serve(args) => run_serve(*args).await,
        cli::Command::GenerateKey => run_generate_key(),
    }
}

fn run_generate_key() -> anyhow::Result<()> {
    let k = MasterKey::generate();
    println!("{}", k.to_base64());
    Ok(())
}

async fn run_serve(args: cli::ServeArgs) -> anyhow::Result<()> {
    let mut config = cli::load_config(&args).context("load config")?;
    tracing_init::init(&config.logging).context("init tracing")?;
    tracing::info!(version = VERSION, "nsp starting");

    // Install the rustls `ring` provider once, up front. The TLS listener
    // builder also calls this lazily, but the control-center poller's
    // reqwest client needs a default provider available before its first
    // request, regardless of whether inbound TLS is enabled.
    tls::install_default_crypto_provider();

    // Install the Prometheus recorder as early as possible so subsequent
    // metric calls (e.g. driver start-up counters) find a recorder.
    let mut obs =
        observability::Observability::install(&config.metrics).context("install metrics")?;
    observability::note_config_reload("startup");

    let master_key = Arc::new(
        config
            .security
            .master_key
            .as_ref()
            .map(MasterKey::from_base64)
            .transpose()
            .context("decode master key")?
            .unwrap_or_else(MasterKey::disabled),
    );
    if master_key.encryption_enabled() {
        tracing::info!("data-at-rest encryption enabled");
    } else if config.security.allow_insecure_no_master_key {
        tracing::warn!(
            "data-at-rest encryption and production JWT signing are disabled by explicit dev override"
        );
    } else {
        return Err(anyhow!(
            "NSP_MASTER_KEY is required; set NSP_ALLOW_INSECURE_NO_MASTER_KEY=true only for local development"
        ));
    }

    let pool = nsp_db::open(&config.storage.db_path)
        .await
        .context("open sqlite")?;

    bootstrap_admin(&pool, config.security.admin_password.as_ref())
        .await
        .context("bootstrap admin")?;

    // Overlay the settings singleton onto the loaded config. Once a user
    // has edited /api/settings the DB row takes precedence over toml; the
    // toml still provides defaults for fields the user hasn't set.
    hydrate_config_from_settings(&pool, &mut config).await?;

    // Probe for the `iptables` binary. When present, construct the unified
    // rule manager and reconcile any persisted rules that may be missing
    // from the kernel after a crash restart. A missing or unusable backend
    // is not fatal: the HTTP routes return 503 when `state.iptables` is
    // `None`.
    //
    // The netstack WireGuard backend needs no host networking (and
    // typically runs without the privileges iptables needs), so the
    // manager is skipped altogether.
    let netstack = config.wireguard.enabled
        && matches!(
            BackendKind::parse(&config.wireguard.backend),
            Ok(BackendKind::Netstack)
        );
    let iptables: Option<Arc<dyn IptablesManager>> = if netstack {
        tracing::info!("iptables manager disabled: netstack wireguard backend");
        None
    } else {
        match probe_iptables(&pool).await {
            Ok(mgr) => Some(mgr),
            Err(err) => {
                tracing::warn!(%err, "iptables manager disabled");
                None
            }
        }
    };

    let wg: Option<WgDriver> = if config.wireguard.enabled {
        let wg_cfg = WgConfig::from_core(&config.wireguard, config.http.domain.clone())
            .context("build wg config")?;
        let wg = WgDriver::new(wg_cfg, pool.clone(), master_key.clone());
        if let Some(mgr) = iptables.clone() {
            wg.set_iptables(mgr).await;
        }
        tracing::info!(
            requested = wg.requested_backend_kind().label(),
            effective = wg.backend_kind().label(),
            "wireguard backend selected",
        );
        match wg.spawn_real().await {
            Ok(()) => tracing::info!("wireguard driver up"),
            Err(err) => {
                tracing::warn!(
                    %err,
                    "wireguard spawn_real failed (likely missing kernel module / NET_ADMIN); falling back to prepare-only mode"
                );
                wg.spawn().await.context("prepare wg driver")?;
            }
        }
        Some(wg)
    } else {
        tracing::info!("wireguard driver disabled by config");
        None
    };

    // The api lockdown switch and the control-center poller are
    // **independent**. Log both up front so an operator can
    // immediately see which combination is in effect without
    // hunting through later log lines. See `docs/api-lockdown.md`
    // for all six valid combinations.
    tracing::info!(
        api = ?config.security.api,
        listener_will_bind = config.security.api.binds_listener(),
        control_enabled = config.control.enabled,
        "admin surface configured",
    );

    let mut app_state = nsp_api::AppState::new(
        pool.clone(),
        master_key.clone(),
        config.security.jwt_ttl_secs,
        VERSION,
    )
    .with_api_mode(config.security.api);
    if let Some(wg) = wg.clone() {
        app_state = app_state.with_wg(wg);
    }
    if let Some(mgr) = iptables.clone() {
        app_state = app_state.with_iptables(mgr);
    }

    let ss_driver: Option<SsDriver> = if config.shadowsocks.enabled {
        let domain = config
            .http
            .domain
            .clone()
            .unwrap_or_else(|| config.shadowsocks.bind.to_string());
        let ss_cfg = SsDriverConfig::new(
            config.shadowsocks.bind,
            config.shadowsocks.port,
            domain,
            config.shadowsocks.apply_debounce_ms,
        );
        let ss = SsDriver::new(ss_cfg, pool.clone(), master_key.clone());
        ss.spawn().await.context("spawn ss driver")?;
        app_state = app_state.with_ss_driver(ss.clone());
        Some(ss)
    } else {
        tracing::info!("shadowsocks driver disabled by config");
        None
    };

    let proxy_driver: Option<ProxyDriver> = if config.proxy.enabled {
        let host = config
            .http
            .domain
            .clone()
            .unwrap_or_else(|| config.proxy.bind.to_string());
        let mut proxy_cfg = ProxyDriverConfig::new(
            config.proxy.bind,
            config.proxy.socks5_port,
            config.proxy.http_port,
            host,
            config.proxy.apply_debounce_ms,
        );
        proxy_cfg.block_private_destinations = config.proxy.block_private_destinations;
        proxy_cfg.max_inflight = config.proxy.max_inflight;
        let proxy = ProxyDriver::new(proxy_cfg, pool.clone(), master_key);
        match proxy.start().await {
            Ok(()) => tracing::info!("proxy driver up"),
            Err(err) => {
                // Refuse to fail the whole startup when the proxy
                // ports are unavailable — the operator can fix the
                // bind via /api/settings or env and restart, but other
                // protocols should keep working in the meantime.
                tracing::warn!(%err, "proxy spawn failed; driver registered in paused state");
            }
        }
        app_state = app_state.with_proxy(proxy.clone());
        Some(proxy)
    } else {
        tracing::info!("proxy driver disabled by config");
        None
    };

    // Background reconciler: converges drivers toward the DB-desired
    // state whenever the API writes or a driver comes up. Drivers are
    // handed the notifier so they can wake the loop after `start`.
    let mut reconcile_targets: Vec<Arc<dyn ReconcileTarget>> = Vec::new();
    if let Some(ss) = ss_driver.clone() {
        reconcile_targets.push(Arc::new(ss) as Arc<dyn ReconcileTarget>);
    }
    if let Some(wg) = wg.clone() {
        reconcile_targets.push(Arc::new(wg) as Arc<dyn ReconcileTarget>);
    }
    if let Some(p) = proxy_driver.clone() {
        reconcile_targets.push(Arc::new(p) as Arc<dyn ReconcileTarget>);
    }
    let reconciler = spawn_reconciler(reconcile_targets, ReconcilerConfig::default());
    let notify = reconciler.notify_handle();
    if let Some(ss) = ss_driver.as_ref() {
        ss.set_reconcile_notify(notify.clone()).await;
    }
    if let Some(wg) = wg.as_ref() {
        wg.set_reconcile_notify(notify.clone()).await;
    }
    if let Some(p) = proxy_driver.as_ref() {
        p.set_reconcile_notify(notify.clone()).await;
    }
    app_state = app_state.with_reconciler(reconciler);

    let state = Arc::new(app_state);
    let bind_listener = config.security.api.binds_listener();

    // Start gauge refresher once drivers are up. Independent of
    // the listener: gauges feed the in-process Prometheus recorder
    // either way; the `/metrics` route is only attached below when
    // we're actually binding a listener to expose it.
    if obs.enabled {
        obs.spawn_refresher(pool.clone(), ss_driver.clone(), wg.clone())
            .context("spawn metrics refresher")?;
    }

    // Hourly SQLite backup.
    let backup_task = if config.backup.enabled {
        tracing::info!(
            dir = %config.backup.dir.display(),
            interval_secs = config.backup.interval_secs,
            retention_days = config.backup.retention_days,
            "backup scheduler enabled"
        );
        Some(backup::spawn(pool.clone(), config.backup.clone()))
    } else {
        tracing::info!("backup scheduler disabled by config");
        None
    };

    // Reverse-API control-center poller. Each tick POSTs a
    // self-report (cursor + content hashes + service state) and
    // reconciles the response into local DB + iptables. Disabled by
    // default; enabled with NSP_CONTROL=true plus URL/NODE_ID/TOKEN.
    // See docs/control-center.md for the full protocol. **Note:**
    // independent of `security.api` — either, both, or
    // neither can be on.
    let control_task = control::spawn(
        pool.clone(),
        config.control.clone(),
        state.reconciler.clone(),
        iptables.clone(),
        ss_driver.clone(),
        wg.clone(),
    );

    let result = if bind_listener {
        // Build the router only when we'll actually bind a
        // listener. In `Disabled` mode the entire router (and the
        // metrics route, and the SPA static assets) is skipped so
        // there is genuinely nothing inbound on this process.
        let router = nsp_api::router(state.clone());
        let router = router.layer(axum::middleware::from_fn(observability::track_http));
        let router = if obs.enabled {
            observability::attach_metrics_route(
                router,
                obs.handle.clone(),
                obs.auth.clone(),
                state.clone(),
            )
        } else {
            router
        };

        let acceptor = tls::build(&config.http, &config.tls)
            .await
            .context("listener setup")?;
        tracing::info!(
            mode = acceptor.kind(),
            protocol = acceptor.protocol(),
            api = ?config.security.api,
            "listener mode selected",
        );
        server::serve(
            config.http.listen,
            acceptor,
            router,
            pool,
            ss_driver,
            wg,
            proxy_driver,
        )
        .await
    } else {
        // Headless mode (`api = "disabled"`): no router, no
        // listener, no port bound. `nmap` / `ss -lntp` will not see
        // the admin port at all. The process is kept alive by the
        // background tasks (control poller, backup, metrics
        // refresher) until SIGINT/SIGTERM. This decision is purely
        // local — independent of whether the control center is
        // configured. A node with `NSP_CONTROL=false` and
        // `NSP_API=disabled` runs as a passive data plane with no
        // admin channel at all (legitimate, if unusual).
        tracing::info!("api=disabled — listener not bound; admin port is not present on this host");
        server::wait_for_shutdown_signal(pool, ss_driver, wg, proxy_driver).await
    };

    if let Some(t) = backup_task {
        t.abort();
    }
    if let Some(t) = control_task {
        t.abort();
    }

    // Hold `obs` (and its renewal task) alive for the whole server lifetime.
    drop(obs);
    result
}

/// Probe `iptables -V`. When present, construct the manager and run an
/// initial `reconcile` so crash-recovered rows re-appear in the kernel.
async fn probe_iptables(pool: &nsp_db::Pool) -> anyhow::Result<Arc<dyn IptablesManager>> {
    let output = tokio::process::Command::new("iptables")
        .arg("-V")
        .output()
        .await
        .context("spawn iptables -V")?;
    if !output.status.success() {
        return Err(anyhow!("iptables -V exit {:?}", output.status.code()));
    }
    let backend = Arc::new(ProcessBackend::new());
    let mgr: Arc<dyn IptablesManager> = Arc::new(DefaultManager::new(backend, pool.clone()));
    match mgr.reconcile().await {
        Ok(report) => tracing::info!(
            reinserted = report.reinserted,
            pruned = report.pruned,
            kept = report.kept,
            "iptables reconcile complete"
        ),
        Err(err) => tracing::warn!(%err, "iptables reconcile failed on boot"),
    }
    Ok(mgr)
}

/// Overlay persisted settings onto `config`. Any field the user has set in
/// the singleton row takes precedence over its toml / CLI value; when the
/// row is still pristine (first boot) we push the toml `wg_subnet` back
/// into the row so subsequent boots see a consistent source of truth.
async fn hydrate_config_from_settings(
    pool: &nsp_db::Pool,
    config: &mut nsp_core::config::ProxyConfig,
) -> anyhow::Result<()> {
    use nsp_db::{SettingsPatch, SettingsRepo};

    let repo = SettingsRepo::new(pool);
    let row = repo.get().await?;

    // On first boot the row carries seeded defaults (ss/wg ports) but no
    // subnet / domain. Seed those from toml so the `/api/settings` view is
    // correct on the first UI load.
    let mut seed = SettingsPatch::default();
    if row.wg_subnet.is_none() && !config.wireguard.subnet.trim().is_empty() {
        seed.wg_subnet = Some(Some(config.wireguard.subnet.clone()));
    }
    if row.domain.is_none() {
        if let Some(d) = config.http.domain.as_ref() {
            seed.domain = Some(Some(d.clone()));
        }
    }
    let row = if seed.is_empty() {
        row
    } else {
        repo.patch(seed).await?
    };

    if let Some(d) = row.domain.as_ref() {
        config.http.domain = Some(d.clone());
    }
    if let Some(s) = row.wg_subnet.as_ref() {
        config.wireguard.subnet = s.clone();
    } else {
        config.wireguard.subnet = String::new();
    }
    if let Ok(port) = u16::try_from(row.ss_listen_port) {
        config.shadowsocks.port = port;
    }
    if let Ok(port) = u16::try_from(row.wg_listen_port) {
        config.wireguard.port = port;
    }
    Ok(())
}

async fn bootstrap_admin(
    pool: &nsp_db::Pool,
    password: Option<&SecretString>,
) -> anyhow::Result<()> {
    use nsp_db::{SettingsPatch, SettingsRepo};

    let settings = SettingsRepo::new(pool);
    let row = settings.get().await?;
    if row.admin_password_hash.is_some() {
        tracing::info!("admin credentials already set");
        return Ok(());
    }
    let Some(password) = password else {
        tracing::warn!(
            "no admin password configured yet; set NSP_ADMIN_PASSWORD or POST /api/auth/bootstrap in a future release"
        );
        return Ok(());
    };
    if password.expose_secret().trim().is_empty() {
        return Err(anyhow!("admin bootstrap password is empty"));
    }
    let phc = auth::hash_password(password).context("hash admin password")?;
    settings
        .patch(SettingsPatch {
            admin_password_hash: Some(phc),
            ..Default::default()
        })
        .await?;
    tracing::info!("admin bootstrap password installed");
    Ok(())
}
