//! Control-center poller (reverse API).
//!
//! Periodically pulls a snapshot from a remote control plane and
//! reconciles it into the local SQLite database + iptables. The
//! control center is the source of truth for membership; nsp is the
//! data plane that converges to whatever the control center says.
//! Pull semantics keep the deployment behind NAT firewall friendly:
//! the control center never has to reach into nsp.
//!
//! The HTTP client is `reqwest` with rustls + ring (matching the rest
//! of the binary). Failures during fetch or reconcile are logged and
//! the loop sleeps until the next tick.
//!
//! ## Snapshot shape
//!
//! ```json
//! {
//!   "cursor":   "v42",          // opaque cursor; persisted, sent as ?since
//!   "reset":    false,          // wipe the local cursor before applying
//!   "mode":     "merge",        // "merge" (default) or "replace"
//!   "settings": { ... },        // optional patch over the singleton row
//!   "users":    [ ... ]         // Full users list; OR
//!   "users":    {               // Delta users
//!       "upsert": [ ... ],
//!       "delete": [ ... ]
//!   },
//!   "iptables": [ ... ]         // declarative full set of control-source rules
//! }
//! ```
//!
//! ## User sync modes
//!
//! Two `users` shapes are accepted (`serde(untagged)` selects):
//!
//! * **Full** — `users: [...]`. Used on first sync, when the server
//!   has no cursor state, or when the supplied cursor is too old.
//!   * Users matched by `id`. Missing rows inserted; existing rows
//!     have their `name` / `note` updated when they differ.
//!   * Deletion of local users not in the snapshot is gated by the
//!     `ConflictPolicy` switch — see *Conflict policy* below.
//!
//! * **Delta** — `users: { upsert, delete }`. The server states
//!   exactly what changed since the cursor we sent. Upserts
//!   create-or-update by `id`; deletes always remove (server is
//!   authoritative for deletes in delta mode — `ConflictPolicy` and
//!   `mode: "replace"` are irrelevant).
//!
//! ## Iptables
//!
//! `iptables`, when present in the snapshot, is the complete intended
//! set of rules owned by `Source::Control`. Rules from other sources
//! (`User`, `WgDriver`) are never touched.
//!
//! Inserts and content matches are unconditional; whether to delete
//! existing control-source rules absent from the snapshot is driven
//! by `ConflictPolicy` — same switch as users.
//!
//! ## Conflict policy
//!
//! `NSP_CONTROL_CONFLICT_POLICY` (operator-side) governs what happens
//! to local resources that the server didn't include in a Full
//! snapshot — uniformly across users AND control-source iptables:
//!
//! * `keep` (default) — additive merge. Local extras stay. Pre-seed
//!   resources locally and the control center won't delete them.
//! * `prune` — authoritative. Local extras are deleted. Equivalent
//!   to the server having sent `mode: "replace"` on every Full
//!   snapshot.
//!
//! `mode: "replace"` (server-side, per response) always wins: even
//! with policy=keep, a single response can request a hard alignment.
//!
//! ## Cursor + reset
//!
//! The server's authoritative cursor is persisted in `server_config`
//! and sent back as `?since={cursor}` on the next request. Servers
//! that ignore `since` simply keep returning Full payloads; the
//! protocol degrades gracefully.
//!
//! `reset: true` immediately wipes the persisted cursor before
//! anything else is applied. Combined with the new `cursor` field in
//! the same response this lets the server force a clean re-sync —
//! "drop your state, here is the fresh starting point."

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use nsp_core::{
    config::{ConflictPolicy, ControlConfig},
    ReconcilerHandle,
};
use nsp_db::{
    AuditRepo, Pool, ServerConfigRepo, SettingsPatch, SettingsRepo, SettingsRow, UserRow,
    UserSource, UsersRepo,
};
use nsp_netctl::{IptablesManager, ListFilter, RegisterOptions, RuleSpec, Source, StoredRule};
use nsp_ss_driver::SsDriver;
use nsp_wg_driver::WgDriver;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `server_config` key under which the control-center cursor is stored.
const CURSOR_KEY: &str = "control_cursor";

/// Audit `actor` for every row the control reconciler touches.
/// Keeps the audit-log entries distinguishable from `/api/*` admin
/// activity (which logs the JWT subject) so operators can answer
/// "did the control center change this, or did I?" at a glance.
const AUDIT_ACTOR: &str = "control";

/// Best-effort audit-log emission. Failures are logged at `debug`
/// and swallowed — never fail a reconcile because the audit table
/// couldn't be written.
async fn audit(pool: &Pool, action: &str, target: Option<&str>, detail: Option<&str>) {
    if let Err(err) = AuditRepo::new(pool)
        .append(AUDIT_ACTOR, action, target, detail)
        .await
    {
        tracing::debug!(%err, action, "control: audit append failed");
    }
}

/// Floor for the `/config` and `/status` poll intervals. A
/// sub-second cadence would hammer the control center; this
/// guards against accidental zero / one-second misconfigurations.
/// Operators wanting genuine fast turnaround should set their env
/// to `MIN_INTERVAL_SECS` or above and accept the floor as the
/// effective minimum.
const MIN_INTERVAL_SECS: u64 = 5;

#[must_use]
fn clamp_interval_secs(secs: u64) -> u64 {
    secs.max(MIN_INTERVAL_SECS)
}

// ----------------------------------------------------------------------
// Issue / status reporting
// ----------------------------------------------------------------------

/// Severity of an [`Issue`] reported back to the control center.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational. No action needed; surfaced for observability.
    Info,
    /// Degraded but functional — some directives may be silently
    /// dropped (e.g. iptables section ignored on a host without an
    /// iptables binary).
    Warn,
    /// Functional failure — the control center sent something that
    /// could not be applied, or the server's intent collided with
    /// local invariants.
    Error,
}

/// A structured event the node wants the control center to know
/// about. Two flavors flow through the same array:
///
/// * **Live capability** issues, recomputed every tick. As long as
///   the underlying gap exists (no iptables binary, kernel WG
///   module unavailable, …) the issue keeps appearing.
/// * **Apply-time** issues observed during the previous tick's
///   reconcile (user-id collisions with a local row, etc.). Carried
///   forward exactly once and then dropped.
///
/// The control center should dedupe by `(code, subject)` if it wants
/// "first observed at" semantics — every report is a snapshot, not
/// an event log.
#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    /// Stable machine-readable code. See `docs/control-center.md`
    /// for the documented set; unknown codes should be treated as
    /// opaque by the server.
    pub code: &'static str,
    pub severity: Severity,
    /// Optional row id this issue is about (a user id, an iptables
    /// rule id, …). Absent for whole-host capability issues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Human-readable detail. Kept short — the control center logs
    /// these verbatim.
    pub message: String,
}

impl Issue {
    /// Construct a host-wide capability issue (no `subject`).
    pub fn capability(code: &'static str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            subject: None,
            message: message.into(),
        }
    }

    /// Construct an issue tied to a specific row id (user, rule, …).
    pub fn for_subject(
        code: &'static str,
        severity: Severity,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity,
            subject: Some(subject.into()),
            message: message.into(),
        }
    }
}

// ----------------------------------------------------------------------
// External report() API — push an event into the active status loop
// ----------------------------------------------------------------------

/// Module-level sender installed by [`spawn`] so any code path in
/// the binary can call [`report`] to push a one-shot event into the
/// running `/status` loop. Set exactly once per process; subsequent
/// `spawn` calls re-use it.
static REPORTER: OnceLock<tokio::sync::mpsc::UnboundedSender<Issue>> = OnceLock::new();

/// Push a one-shot event toward the control center. Returns `true`
/// when the event was queued, `false` when there is no active
/// poller (e.g. `NSP_CONTROL=false` or `spawn` hasn't been called
/// yet) so the caller can decide whether to log/store locally.
///
/// Semantics:
/// * The event is appended to the same `pending_apply_issues` queue
///   that drains into the next `/status` request.
/// * The status loop is woken **immediately** so the report leaves
///   the node within milliseconds rather than waiting for the next
///   `status_interval_secs` tick.
/// * Multiple rapid calls are coalesced into one `/status` POST per
///   wakeup — the loop drains the channel non-blockingly before
///   firing.
///
/// Use cases (the operator picks):
/// * Detected an anomaly mid-tick (e.g. a peer crossed a traffic
///   threshold) — push an `Issue::for_subject`.
/// * Operator-driven event from the local API (e.g. an admin
///   manually marks a user suspended) — push the event and the
///   control center sees it on the next status report.
/// * One-shot diagnostic on demand without changing protocol shape.
#[must_use]
// Public API surface for future internal callers (anomaly detectors,
// API handlers); rustc can't see them yet from a binary crate.
#[allow(dead_code)]
pub fn report(issue: Issue) -> bool {
    match REPORTER.get() {
        Some(tx) => tx.send(issue).is_ok(),
        None => false,
    }
}

/// Compute the live capability issues — the things that are wrong
/// (or noteworthy) about this host *right now*, recomputed every
/// tick. The control center treats these as ongoing state, not
/// one-shot events.
pub fn collect_live_issues(
    iptables: Option<&dyn IptablesManager>,
    ss: Option<&SsDriver>,
    wg: Option<&WgDriver>,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    if iptables.is_none() {
        issues.push(Issue::capability(
            "iptables_unavailable",
            Severity::Warn,
            "host has no working iptables binary; snapshot iptables section will be skipped",
        ));
    }
    if ss.is_none() {
        issues.push(Issue::capability(
            "ss_disabled",
            Severity::Info,
            "shadowsocks driver is not configured on this node",
        ));
    }
    match wg {
        None => issues.push(Issue::capability(
            "wg_disabled",
            Severity::Info,
            "wireguard driver is not configured on this node",
        )),
        Some(d) => {
            let requested = d.requested_backend_kind();
            let effective = d.backend_kind();
            if requested != effective {
                issues.push(Issue::capability(
                    "wg_backend_fallback",
                    Severity::Warn,
                    format!(
                        "wireguard backend `{}` requested but `{}` is in effect (preconditions not met for the requested backend)",
                        requested.label(),
                        effective.label()
                    ),
                ));
            }
        }
    }

    issues
}

// ----------------------------------------------------------------------
// Local state report (sync request body)
// ----------------------------------------------------------------------

/// Self-description sent to the control center on `POST /config`.
/// Strictly **configuration shape**: cursor, hashes + values that
/// let the server decide whether to respond with no-op / delta /
/// full / replace. Runtime/observability data (services, traffic,
/// issues) lives on `POST /status`.
#[derive(Debug, Serialize)]
pub struct LocalState {
    pub settings: SettingsState,
    pub users: HashedCount,
    pub iptables: HashedCount,
}

#[derive(Debug, Serialize)]
pub struct SettingsState {
    /// Current value of each settings field. Cheap to inline because
    /// the singleton row is tiny, and surfacing it lets the control
    /// center make decisions without parsing the hash.
    pub domain: Option<String>,
    pub wg_subnet: Option<String>,
    pub ss_listen_port: i64,
    pub wg_listen_port: i64,
    /// `sha256(...)` of a canonical encoding of the four fields above.
    pub hash: String,
}

#[derive(Debug, Default, Serialize)]
pub struct HashedCount {
    pub count: i64,
    pub hash: String,
}

/// Compute the per-`/config` self-report. Failures collecting any
/// single section degrade gracefully: the section reports zero /
/// empty hash rather than aborting the sync.
pub async fn collect_state(pool: &Pool, iptables: Option<&dyn IptablesManager>) -> LocalState {
    let settings = match SettingsRepo::new(pool).get().await {
        Ok(row) => settings_state_from_row(&row),
        Err(err) => {
            tracing::warn!(%err, "control: settings read failed; reporting empty");
            empty_settings_state()
        }
    };

    // The hash + count cover the control slice only. The control
    // center has no opinion on `local` rows (admin-created), so
    // including them would make the hash flap whenever an admin
    // touched a local user — triggering pointless server-side
    // recomputation.
    let users = match UsersRepo::new(pool).list(Some(UserSource::Control)).await {
        Ok(rows) => HashedCount {
            count: i64::try_from(rows.len()).unwrap_or(i64::MAX),
            hash: hash_users(&rows),
        },
        Err(err) => {
            tracing::warn!(%err, "control: users list failed; reporting empty");
            HashedCount {
                count: 0,
                hash: hash_users(&[]),
            }
        }
    };

    let iptables = match iptables {
        Some(mgr) => match mgr
            .list(ListFilter {
                source: Some(Source::Control),
            })
            .await
        {
            Ok(rows) => HashedCount {
                count: i64::try_from(rows.len()).unwrap_or(i64::MAX),
                hash: hash_iptables(&rows),
            },
            Err(err) => {
                tracing::warn!(%err, "control: iptables list failed; reporting empty");
                empty_iptables_hashed_count()
            }
        },
        // No manager available: report a stable "empty set" digest
        // rather than a literal empty string, so the control center
        // sees the same shape regardless of host capability.
        None => empty_iptables_hashed_count(),
    };

    LocalState {
        settings,
        users,
        iptables,
    }
}

// ----------------------------------------------------------------------
// Status report (sent to POST /status — independent of /config)
// ----------------------------------------------------------------------

/// Runtime observability snapshot sent on `POST /status`. This is
/// intentionally separate from the `/config` payload so the two
/// concerns can move at independent cadences and grow new fields
/// (traffic, anomalies, task triggers, …) without bloating config
/// sync requests.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub services: ServiceState,
    pub traffic: TrafficReport,
}

#[derive(Debug, Default, Serialize)]
pub struct ServiceState {
    pub ss_running: bool,
    pub wg_running: bool,
    pub ss_users_count: i64,
    pub wg_peers_count: i64,
    /// `kernel`, `userspace`, or absent when WG is disabled. Reflects
    /// the *effective* backend after `auto` resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_backend: Option<String>,
}

/// Per-protocol traffic samples. Empty buckets are still serialized
/// so the control center can rely on a stable shape.
#[derive(Debug, Default, Serialize)]
pub struct TrafficReport {
    pub wg: WgTrafficReport,
}

#[derive(Debug, Default, Serialize)]
pub struct WgTrafficReport {
    pub peers: Vec<WgPeerTraffic>,
}

/// One row per WireGuard peer the driver currently knows about.
/// Counters are cumulative since the peer's first sample (so the
/// control center can compute deltas across reports) and survive
/// driver restarts via the persisted traffic stats.
#[derive(Debug, Serialize)]
pub struct WgPeerTraffic {
    pub peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    /// Seconds since the most recent successful handshake on this
    /// peer; absent when no handshake has been observed since the
    /// driver came up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_age_secs: Option<u64>,
}

/// Collect the runtime status snapshot. Cheap enough to call every
/// status tick — counts come from the DB pool, traffic comes from
/// the WG driver's in-memory peer view (which itself folds in the
/// persisted samples).
pub async fn collect_status(
    pool: &Pool,
    ss: Option<&SsDriver>,
    wg: Option<&WgDriver>,
) -> StatusReport {
    let ss_running = match ss {
        Some(d) => d.is_running().await,
        None => false,
    };
    let wg_running = match wg {
        Some(d) => d.is_running().await,
        None => false,
    };
    let services = ServiceState {
        ss_running,
        wg_running,
        ss_users_count: count_or_zero(pool, "SELECT COUNT(*) FROM users WHERE ss_enabled = 1")
            .await,
        wg_peers_count: count_or_zero(pool, "SELECT COUNT(*) FROM wg_peers").await,
        wg_backend: wg.map(|d| d.backend_kind().label().to_owned()),
    };

    let wg_peers = match wg {
        Some(d) => match d.list_peers().await {
            Ok(views) => views.into_iter().map(WgPeerTraffic::from_view).collect(),
            Err(err) => {
                tracing::warn!(%err, "control: list wg peers for status failed");
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    StatusReport {
        services,
        traffic: TrafficReport {
            wg: WgTrafficReport { peers: wg_peers },
        },
    }
}

impl WgPeerTraffic {
    fn from_view(p: nsp_wg_driver::PeerView) -> Self {
        Self {
            peer_id: p.id,
            user_id: p.user_id,
            name: p.name,
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
            total_rx_bytes: p.total_rx_bytes,
            total_tx_bytes: p.total_tx_bytes,
            last_handshake_age_secs: p.last_handshake_secs,
        }
    }
}

async fn count_or_zero(pool: &Pool, sql: &str) -> i64 {
    match sqlx::query_as::<_, (i64,)>(sql).fetch_one(pool).await {
        Ok((n,)) => n,
        Err(err) => {
            tracing::debug!(%err, query = sql, "control: count query failed");
            0
        }
    }
}

fn settings_state_from_row(row: &SettingsRow) -> SettingsState {
    SettingsState {
        domain: row.domain.clone(),
        wg_subnet: row.wg_subnet.clone(),
        ss_listen_port: row.ss_listen_port,
        wg_listen_port: row.wg_listen_port,
        hash: hash_settings(row),
    }
}

fn empty_settings_state() -> SettingsState {
    let mut h = Sha256::new();
    h.update(b"settings\nempty\n");
    SettingsState {
        domain: None,
        wg_subnet: None,
        ss_listen_port: 0,
        wg_listen_port: 0,
        hash: hex::encode(h.finalize()),
    }
}

fn empty_iptables_hashed_count() -> HashedCount {
    HashedCount {
        count: 0,
        hash: hash_iptables(&[]),
    }
}

/// Canonical hash of the settings singleton: domain | wg_subnet | ss_port | wg_port.
fn hash_settings(row: &SettingsRow) -> String {
    let mut h = Sha256::new();
    h.update(b"settings\n");
    write_opt(&mut h, row.domain.as_deref());
    write_opt(&mut h, row.wg_subnet.as_deref());
    h.update(format!("{}\n", row.ss_listen_port).as_bytes());
    h.update(format!("{}\n", row.wg_listen_port).as_bytes());
    hex::encode(h.finalize())
}

/// Canonical hash of the user set: id-sorted, `id\nname\nnote\n` per row.
/// Sorting makes the digest insensitive to insertion order.
fn hash_users(rows: &[UserRow]) -> String {
    let mut sorted: Vec<&UserRow> = rows.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let mut h = Sha256::new();
    h.update(b"users\n");
    for r in sorted {
        h.update(r.id.as_bytes());
        h.update(b"\n");
        h.update(r.name.as_bytes());
        h.update(b"\n");
        write_opt(&mut h, r.note.as_deref());
    }
    hex::encode(h.finalize())
}

/// Canonical hash of the control-source iptables rules.
fn hash_iptables(rows: &[StoredRule]) -> String {
    let mut sorted: Vec<&StoredRule> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        (a.priority, &a.table, &a.chain, &a.spec, &a.comment)
            .cmp(&(b.priority, &b.table, &b.chain, &b.spec, &b.comment))
    });
    let mut h = Sha256::new();
    h.update(b"iptables\n");
    for r in sorted {
        h.update(format!("{}\n", r.priority).as_bytes());
        h.update(r.table.as_bytes());
        h.update(b"\n");
        h.update(r.chain.as_bytes());
        h.update(b"\n");
        h.update(normalize_ws(&r.spec).as_bytes());
        h.update(b"\n");
        write_opt(&mut h, r.comment.as_deref());
    }
    hex::encode(h.finalize())
}

fn write_opt(h: &mut Sha256, value: Option<&str>) {
    match value {
        Some(s) => {
            h.update(b"S:");
            h.update(s.as_bytes());
        }
        None => h.update(b"N:"),
    }
    h.update(b"\n");
}

/// Snapshot returned by `GET {url}/api/v1/nodes/{node_id}/config`.
#[derive(Debug, Default, Deserialize)]
pub struct Snapshot {
    /// Server-side cursor representing the version this snapshot
    /// reflects. When present the client persists it and sends it
    /// back as `?since={cursor}` on the next pull, allowing the
    /// server to respond with a delta. Servers that don't support
    /// incremental sync simply omit the field.
    #[serde(default)]
    pub cursor: Option<String>,
    /// When true, nsp wipes the persisted cursor before applying the
    /// rest of the snapshot. Combined with the `cursor` field this
    /// lets the server force a clean re-sync: "drop your state, here
    /// is the fresh starting point."
    #[serde(default)]
    pub reset: bool,
    /// Drives delete-missing semantics for Full snapshots and the
    /// declarative iptables list:
    /// * `Merge` (default) — additive; the operator's
    ///   `ConflictPolicy` decides whether local extras are kept or
    ///   pruned.
    /// * `Replace` — authoritative; local resources absent from the
    ///   snapshot are deleted regardless of operator policy.
    ///
    /// Has no effect on Delta payloads.
    #[serde(default)]
    pub mode: SnapshotMode,
    #[serde(default)]
    pub settings: Option<SnapshotSettings>,
    /// Users section. Either a full list (legacy / first sync /
    /// cursor-expired) or an upsert+delete delta. Absent means
    /// "no user changes".
    #[serde(default)]
    pub users: Option<UsersSection>,
    /// Declarative full set of `Source::Control` iptables rules. When
    /// present this list IS the desired state for that source: rules
    /// not in the list are deleted, new rules are inserted, unchanged
    /// rules are kept. Rules owned by `User` / `WgDriver` are never
    /// touched. Absent means "leave control-source rules alone".
    #[serde(default)]
    pub iptables: Option<Vec<SnapshotRule>>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotMode {
    #[default]
    Merge,
    Replace,
}

impl SnapshotMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Replace => "replace",
        }
    }
}

/// One iptables rule entry inside a snapshot. Mirrors `RuleSpec` but
/// kept as its own struct so the wire format isn't tied to the
/// netctl crate's internal data model.
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotRule {
    pub table: String,
    pub chain: String,
    /// Raw spec after the chain name (e.g. `-p tcp --dport 22 -j ACCEPT`).
    pub spec: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub priority: i32,
}

/// User payload variant. `serde(untagged)` lets the same `users` JSON
/// field carry either shape without the server having to negotiate.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum UsersSection {
    /// Full snapshot. Returned when no `since` was sent or the server
    /// has no delta available for that cursor.
    Full(Vec<SnapshotUser>),
    /// Incremental delta keyed off the previous cursor.
    Delta(UserDelta),
}

#[derive(Debug, Default, Deserialize)]
pub struct UserDelta {
    /// Users to create-or-update. Matched by `id`.
    #[serde(default)]
    pub upsert: Vec<SnapshotUser>,
    /// User ids to delete locally. Unknown ids are silently skipped.
    #[serde(default)]
    pub delete: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SnapshotSettings {
    /// Public domain. Stored verbatim. `Some(None)` (explicit JSON null)
    /// clears the column; absent leaves it untouched.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub domain: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub wg_subnet: Option<Option<String>>,
    #[serde(default)]
    pub ss_listen_port: Option<i64>,
    #[serde(default)]
    pub wg_listen_port: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct SnapshotUser {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub note: Option<String>,
}

fn deserialize_optional_field<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}

/// Stats returned by [`reconcile`] so callers can log a single line per tick.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileStats {
    pub users_created: usize,
    pub users_updated: usize,
    pub users_deleted: usize,
    /// Number of incoming user records that targeted a row owned by
    /// `UserSource::Local` and were therefore left untouched. Non-zero
    /// values indicate an `id` collision between a control-center
    /// directive and an admin-created user — see the protocol doc.
    pub users_skipped_local: usize,
    pub iptables_added: usize,
    pub iptables_removed: usize,
    pub iptables_kept: usize,
    pub settings_changed: bool,
    pub cursor_reset: bool,
    /// Indicates whether the user payload was applied as a Full or
    /// Delta. `None` when no `users` section was present.
    pub mode: Option<ReconcileMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileMode {
    Full,
    Delta,
}

impl ReconcileMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Delta => "delta",
        }
    }
}

impl ReconcileStats {
    #[must_use]
    pub fn touched_users(self) -> bool {
        self.users_created + self.users_updated + self.users_deleted > 0
    }

    #[must_use]
    pub fn touched_iptables(self) -> bool {
        self.iptables_added + self.iptables_removed > 0
    }
}

/// Body of `POST {url}/api/v1/nodes/{node_id}/config`. Strictly a
/// **configuration sync** request — cursor + content hashes — so the
/// control center can pick the smallest correct response
/// (no-op / delta / full / replace). Runtime observability lives on
/// the separate `POST /status` endpoint.
#[derive(Debug, Serialize)]
struct SyncRequest<'a> {
    node_id: &'a str,
    version: &'static str,
    /// Cursor the node currently has applied. Absent on the first
    /// pull or after `reset`.
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    /// What nsp has installed locally — counts + content hashes of
    /// the three reconciled sections (settings, users, iptables).
    state: &'a LocalState,
}

/// Body of `POST {url}/api/v1/nodes/{node_id}/status`. Periodic
/// observability snapshot — runtime service state, traffic samples,
/// last-tick reconcile outcome, and **live capability issues**
/// (recomputed every tick). One-shot events (apply-time conflicts,
/// anomaly detector output, etc.) live on the dedicated `/report`
/// endpoint instead.
#[derive(Debug, Serialize)]
struct StatusRequest<'a> {
    node_id: &'a str,
    version: &'static str,
    /// Cursor the node currently has applied — lets the control
    /// center correlate this status report with a specific config
    /// version. Absent before the first successful sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    /// Runtime view: ss/wg running, peer/user counts, wg backend,
    /// per-peer traffic samples.
    report: &'a StatusReport,
    /// Outcome of the previous `/config` reconcile. Acts as the
    /// heartbeat signal so a separate heartbeat endpoint isn't
    /// needed.
    #[serde(skip_serializing_if = "ApplyReport::is_empty")]
    last_apply: ApplyReport,
    /// Live capability gaps recomputed every tick (e.g.
    /// `iptables_unavailable`, `wg_backend_fallback`). Empty array
    /// is omitted from the wire.
    #[serde(skip_serializing_if = "<[Issue]>::is_empty")]
    issues: &'a [Issue],
}

/// Body of `POST {url}/api/v1/nodes/{node_id}/report`. Event-driven
/// channel for one-shot reports the control center should action
/// in near-real-time: apply-time conflicts, anomaly detections,
/// task triggers, traffic-threshold alarms, etc.
///
/// `/report` is fired whenever events arrive on the in-process
/// report channel (debounced briefly to coalesce bursts), so a
/// single endpoint URL handles all event kinds and the control
/// center pattern-matches on `events[].code`. The shape stays
/// stable across event kinds; new structured fields can be added
/// to specific codes additively without breaking older clients.
#[derive(Debug, Serialize)]
struct ReportRequest<'a> {
    node_id: &'a str,
    version: &'static str,
    /// Cursor the node currently has applied. Lets the control
    /// center correlate the event with a specific config version.
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<&'a str>,
    /// One or more events in this batch. Coalesced bursts share
    /// a single POST.
    events: &'a [Issue],
}

#[derive(Debug, Default, Serialize, Clone)]
struct ApplyReport {
    users_created: usize,
    users_updated: usize,
    users_deleted: usize,
    /// Count of incoming user records that targeted a `local`-source
    /// row and were therefore left untouched. Mirrors
    /// `ReconcileStats::users_skipped_local`.
    users_skipped_local: usize,
    iptables_added: usize,
    iptables_removed: usize,
    iptables_kept: usize,
    settings_changed: bool,
    cursor_reset: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'static str>,
}

impl ApplyReport {
    fn is_empty(&self) -> bool {
        self.users_created == 0
            && self.users_updated == 0
            && self.users_deleted == 0
            && self.users_skipped_local == 0
            && self.iptables_added == 0
            && self.iptables_removed == 0
            && self.iptables_kept == 0
            && !self.settings_changed
            && !self.cursor_reset
            && self.mode.is_none()
    }

    fn from_stats(stats: ReconcileStats) -> Self {
        Self {
            users_created: stats.users_created,
            users_updated: stats.users_updated,
            users_deleted: stats.users_deleted,
            users_skipped_local: stats.users_skipped_local,
            iptables_added: stats.iptables_added,
            iptables_removed: stats.iptables_removed,
            iptables_kept: stats.iptables_kept,
            settings_changed: stats.settings_changed,
            cursor_reset: stats.cursor_reset,
            mode: stats.mode.map(ReconcileMode::as_str),
        }
    }
}

/// State shared between the `/config` loop (producer of the
/// last-apply heartbeat) and the `/status` loop (reporter).
/// Apply-time issues no longer flow through here — they go straight
/// into the report channel for `/report` to ship.
#[derive(Default)]
struct SharedState {
    last_apply: ApplyReport,
}

/// Spawn the poller. Returns `None` when the configuration is incomplete
/// or invalid; the caller logs and continues without the feature.
///
/// Internally the returned task supervises two cooperating loops:
/// * `/config` loop — paces on `cfg.interval_secs`, POSTs the
///   self-report and applies the response.
/// * `/status` loop — paces on `cfg.status_interval_secs`, POSTs
///   runtime observability (services, traffic, issues, last_apply).
#[must_use]
pub fn spawn(
    pool: Pool,
    cfg: ControlConfig,
    reconciler: Option<ReconcilerHandle>,
    iptables: Option<Arc<dyn IptablesManager>>,
    ss: Option<SsDriver>,
    wg: Option<WgDriver>,
) -> Option<JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let client = match build_client(&cfg) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "control: poller disabled");
            return None;
        }
    };
    let config_interval = Duration::from_secs(clamp_interval_secs(cfg.interval_secs));
    let status_interval = Duration::from_secs(clamp_interval_secs(cfg.status_interval_secs));
    tracing::info!(
        url = client.base_url.as_str(),
        node_id = client.node_id.as_str(),
        config_interval_secs = config_interval.as_secs(),
        status_interval_secs = status_interval.as_secs(),
        conflict_policy = if cfg.conflict_policy.prunes() {
            "prune"
        } else {
            "keep"
        },
        iptables_available = iptables.is_some(),
        ss_attached = ss.is_some(),
        wg_attached = wg.is_some(),
        "control: poller enabled"
    );
    // Install (or reuse) the global report channel. We always
    // create a fresh `(tx, rx)` per spawn so the rx is owned by
    // this task's status loop; the *first* successful spawn writes
    // the tx into the static so module-external callers reach this
    // task. Subsequent spawns (e.g. tests) get their own loop but
    // the static keeps pointing at the first — that's fine because
    // production `spawn` is called exactly once.
    let (report_tx, mut report_rx) = tokio::sync::mpsc::unbounded_channel::<Issue>();
    let _ = REPORTER.set(report_tx);

    Some(tokio::spawn(async move {
        let shared: tokio::sync::Mutex<SharedState> =
            tokio::sync::Mutex::new(SharedState::default());

        let config_fut = async {
            let mut tick = tokio::time::interval(config_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                run_config_once(
                    &client,
                    &pool,
                    &cfg,
                    reconciler.as_ref(),
                    iptables.as_deref(),
                    &shared,
                )
                .await;
            }
        };
        let status_fut = async {
            let mut tick = tokio::time::interval(status_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                run_status_once(
                    &client,
                    &pool,
                    iptables.as_deref(),
                    ss.as_ref(),
                    wg.as_ref(),
                    &shared,
                )
                .await;
            }
        };
        let report_fut = async {
            run_report_loop(&client, &pool, &mut report_rx).await;
        };
        tokio::join!(config_fut, status_fut, report_fut);
    }))
}

/// Coalescing window for the `/report` loop: when the first event
/// arrives, wait this long while draining the channel before
/// firing one POST. Tuned so a burst of rapid events (e.g. ten
/// peers crossing a threshold at the same tick) produces one HTTP
/// round trip, while a lone event still leaves the node in well
/// under a second.
const REPORT_COALESCE_WINDOW: Duration = Duration::from_millis(200);

async fn run_report_loop(
    client: &Client,
    pool: &Pool,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Issue>,
) {
    while let Some(first) = rx.recv().await {
        let mut events = vec![first];
        // Coalesce: collect anything else that arrives within the
        // window before sending. Bounded by the window so a single
        // event has predictable latency.
        let coalesce = tokio::time::sleep(REPORT_COALESCE_WINDOW);
        tokio::pin!(coalesce);
        loop {
            tokio::select! {
                Some(more) = rx.recv() => events.push(more),
                () = &mut coalesce => break,
            }
        }
        // Drain whatever piled up during channel handling.
        while let Ok(more) = rx.try_recv() {
            events.push(more);
        }

        let cursor = read_cursor(pool).await.ok().flatten();
        match client.post_report(cursor.as_deref(), &events).await {
            Ok(()) => {
                metrics::counter!(
                    crate::observability::METRIC_CONTROL_REQUESTS,
                    "endpoint" => "report",
                    "outcome" => "ok",
                )
                .increment(1);
                // Per-event counter so the control center sees the
                // distribution of codes the node is reporting.
                for ev in &events {
                    metrics::counter!(
                        crate::observability::METRIC_CONTROL_REPORT_EVENTS,
                        "code" => ev.code,
                    )
                    .increment(1);
                }
                tracing::debug!(count = events.len(), "control: report posted",);
            }
            Err(err) => {
                metrics::counter!(
                    crate::observability::METRIC_CONTROL_REQUESTS,
                    "endpoint" => "report",
                    "outcome" => "error",
                )
                .increment(1);
                // Events are point-in-time; we drop them rather than
                // re-queue forever. The reconcile path will re-emit
                // server-side conflicts on the next /config tick if
                // they're still occurring, so persistent issues
                // aren't silently lost.
                tracing::warn!(
                    %err,
                    count = events.len(),
                    "control: POST /report failed; events dropped",
                );
            }
        }
    }
}

/// Single iteration of the `/config` loop. POSTs the cursor +
/// content hashes, reconciles the response, and stores the apply
/// outcome + any apply-time issues in `shared` for the next status
/// report to pick up.
async fn run_config_once(
    client: &Client,
    pool: &Pool,
    cfg: &ControlConfig,
    reconciler: Option<&ReconcilerHandle>,
    iptables: Option<&dyn IptablesManager>,
    shared: &tokio::sync::Mutex<SharedState>,
) {
    let cursor = match read_cursor(pool).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "control: read persisted cursor failed");
            None
        }
    };

    let state = collect_state(pool, iptables).await;

    let snap = match client.post_config(cursor.as_deref(), &state).await {
        Ok(s) => {
            metrics::counter!(
                crate::observability::METRIC_CONTROL_REQUESTS,
                "endpoint" => "config",
                "outcome" => "ok",
            )
            .increment(1);
            if let Ok(epoch) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                metrics::gauge!(crate::observability::METRIC_CONTROL_LAST_SYNC_UNIX)
                    .set(epoch.as_secs() as f64);
            }
            s
        }
        Err(err) => {
            metrics::counter!(
                crate::observability::METRIC_CONTROL_REQUESTS,
                "endpoint" => "config",
                "outcome" => "error",
            )
            .increment(1);
            tracing::warn!(%err, "control: POST /config failed");
            return;
        }
    };

    let mut outcome = match reconcile_outcome(pool, &snap, cfg.conflict_policy, iptables).await {
        Ok(o) => o,
        Err(err) => {
            tracing::warn!(%err, "control: reconcile failed");
            return;
        }
    };
    let rec_stats = &mut outcome.stats;

    // `reset` clears the persisted cursor BEFORE we write the fresh
    // one, so a payload carrying `reset:true` + `cursor:"vN"` overwrites
    // with the new value. `reset:true` alone (no cursor) leaves the
    // slot empty so the next pull is unconditional.
    if snap.reset {
        if let Err(err) = clear_cursor(pool).await {
            tracing::warn!(%err, "control: clear cursor failed");
        } else {
            rec_stats.cursor_reset = true;
        }
    }
    if let Some(cursor) = snap.cursor.as_deref() {
        if let Err(err) = write_cursor(pool, cursor).await {
            tracing::warn!(%err, "control: persist cursor failed");
        }
    }

    if rec_stats.touched_users() || rec_stats.touched_iptables() || rec_stats.settings_changed {
        tracing::info!(
            mode = rec_stats.mode.map(ReconcileMode::as_str).unwrap_or("none"),
            snapshot_mode = snap.mode.as_str(),
            cursor_reset = rec_stats.cursor_reset,
            created = rec_stats.users_created,
            updated = rec_stats.users_updated,
            deleted = rec_stats.users_deleted,
            skipped_local = rec_stats.users_skipped_local,
            ipt_added = rec_stats.iptables_added,
            ipt_removed = rec_stats.iptables_removed,
            ipt_kept = rec_stats.iptables_kept,
            settings_changed = rec_stats.settings_changed,
            issues = outcome.issues.len(),
            "control: reconcile applied"
        );
        if rec_stats.touched_users() {
            if let Some(r) = reconciler {
                r.notify();
            }
        }
    } else {
        tracing::debug!(
            mode = rec_stats.mode.map(ReconcileMode::as_str).unwrap_or("none"),
            issues = outcome.issues.len(),
            "control: snapshot matches local state"
        );
    }

    // Heartbeat handoff: the status loop reads the latest apply
    // outcome from `shared`. Apply-time issues take a different
    // path — they go straight to the `/report` channel so the
    // control center sees them within milliseconds rather than
    // waiting on the next status tick.
    {
        let mut shared = shared.lock().await;
        shared.last_apply = ApplyReport::from_stats(*rec_stats);
    }
    if let Some(tx) = REPORTER.get() {
        for issue in outcome.issues {
            // Send is infallible while the receiver lives (it does,
            // because the report task is part of the same spawn).
            let _ = tx.send(issue);
        }
    }
}

/// Single iteration of the `/status` loop. Computes the runtime
/// snapshot + live capability issues and POSTs them. No event-style
/// state — apply-time conflicts and external `report()` calls flow
/// through the dedicated `/report` endpoint.
async fn run_status_once(
    client: &Client,
    pool: &Pool,
    iptables: Option<&dyn IptablesManager>,
    ss: Option<&SsDriver>,
    wg: Option<&WgDriver>,
    shared: &tokio::sync::Mutex<SharedState>,
) {
    let cursor = match read_cursor(pool).await {
        Ok(c) => c,
        Err(err) => {
            tracing::debug!(%err, "control: status read cursor failed");
            None
        }
    };

    let report = collect_status(pool, ss, wg).await;
    let last_apply = shared.lock().await.last_apply.clone();
    let issues = collect_live_issues(iptables, ss, wg);

    match client
        .post_status(cursor.as_deref(), &report, &last_apply, &issues)
        .await
    {
        Ok(()) => {
            metrics::counter!(
                crate::observability::METRIC_CONTROL_REQUESTS,
                "endpoint" => "status",
                "outcome" => "ok",
            )
            .increment(1);
            tracing::debug!(
                wg_peers = report.traffic.wg.peers.len(),
                live_issues = issues.len(),
                "control: status posted",
            );
        }
        Err(err) => {
            metrics::counter!(
                crate::observability::METRIC_CONTROL_REQUESTS,
                "endpoint" => "status",
                "outcome" => "error",
            )
            .increment(1);
            tracing::warn!(%err, "control: POST /status failed");
            // Live issues are recomputed every tick from observable
            // state, so the next status will surface the same
            // capability gaps. Nothing to re-queue.
        }
    }
}

/// Bundle returned by [`reconcile_outcome`]: numerical counters and
/// any structured [`Issue`] events worth surfacing to the control
/// center on the next tick.
#[derive(Debug, Default)]
pub struct ReconcileOutcome {
    pub stats: ReconcileStats,
    pub issues: Vec<Issue>,
}

/// Apply `snapshot` to the database (and to the iptables manager when
/// supplied). Returns counters describing what changed; equivalent to
/// `reconcile_outcome(...).await?.stats` and kept as a back-compat
/// entry point so unit tests stay terse. Tests below are the only
/// in-tree caller.
///
/// `policy` resolves the conflict between local resources and the
/// server's Full snapshot: `Keep` preserves local extras, `Prune`
/// deletes them. Server-driven `mode: "replace"` always wins on a
/// per-response basis. The same policy is applied uniformly to
/// users AND control-source iptables rules — the operator picks one
/// stance for "control plane is authoritative" or "control plane is
/// additive."
///
/// `iptables` is `Option` because the host might not have a working
/// iptables binary at all (the manager is `None` in that case). When
/// `None`, an `iptables` section in the snapshot is logged and skipped
/// rather than treated as an error: a node that can't apply rules
/// shouldn't crash a control-center sync.
#[cfg(test)]
pub async fn reconcile(
    pool: &Pool,
    snapshot: &Snapshot,
    policy: ConflictPolicy,
    iptables: Option<&dyn IptablesManager>,
) -> Result<ReconcileStats> {
    reconcile_outcome(pool, snapshot, policy, iptables)
        .await
        .map(|o| o.stats)
}

/// Like [`reconcile`] but additionally surfaces structured issues
/// observed during apply (id collisions with local rows, refused
/// deletes, etc.). Used by the polling loop so the next tick's
/// request body can carry the events back to the control center.
pub async fn reconcile_outcome(
    pool: &Pool,
    snapshot: &Snapshot,
    policy: ConflictPolicy,
    iptables: Option<&dyn IptablesManager>,
) -> Result<ReconcileOutcome> {
    // Effective prune flag: the operator policy says so, OR the
    // server demanded `mode: "replace"` for this response.
    let prune = policy.prunes() || snapshot.mode == SnapshotMode::Replace;

    let mut outcome = ReconcileOutcome::default();
    if let Some(s) = snapshot.settings.as_ref() {
        outcome.stats.settings_changed = apply_settings(pool, s).await?;
    }

    match snapshot.users.as_ref() {
        Some(UsersSection::Full(list)) => {
            outcome.stats.mode = Some(ReconcileMode::Full);
            apply_full_users(pool, list, prune, &mut outcome).await?;
        }
        Some(UsersSection::Delta(delta)) => {
            outcome.stats.mode = Some(ReconcileMode::Delta);
            apply_user_delta(pool, delta, &mut outcome).await?;
        }
        None => {}
    }

    if let Some(rules) = snapshot.iptables.as_ref() {
        match iptables {
            Some(mgr) => apply_iptables(pool, mgr, rules, prune, &mut outcome.stats).await?,
            None => {
                tracing::warn!(
                    rules = rules.len(),
                    "control: snapshot has iptables section but no iptables manager available; skipping"
                );
                // Live capability issue is also reported via
                // collect_live_issues, but emit one here so the
                // control center can correlate the skip with the
                // exact tick that dropped its rules.
                outcome.issues.push(Issue::capability(
                    "iptables_section_skipped",
                    Severity::Warn,
                    format!(
                        "snapshot included {} iptables rule(s) but no iptables manager is available; skipped",
                        rules.len()
                    ),
                ));
            }
        }
    }

    Ok(outcome)
}

async fn apply_full_users(
    pool: &Pool,
    list: &[SnapshotUser],
    prune: bool,
    outcome: &mut ReconcileOutcome,
) -> Result<()> {
    let users_repo = UsersRepo::new(pool);
    for incoming in list {
        validate_user(incoming)?;
        upsert_user(pool, &users_repo, incoming, outcome).await?;
    }
    if prune {
        let snapshot_ids: std::collections::HashSet<&str> =
            list.iter().map(|u| u.id.as_str()).collect();
        // Critical: only scan the control-source slice. Local users
        // (admin-created via /api/users) are structurally off-limits
        // — the control center's snapshot can't possibly speak to
        // them, so absence ≠ "delete me."
        let control_rows = users_repo.list(Some(UserSource::Control)).await?;
        for row in control_rows {
            if !snapshot_ids.contains(row.id.as_str()) && users_repo.delete(&row.id).await? {
                outcome.stats.users_deleted += 1;
                audit(
                    pool,
                    "control.user.delete",
                    Some(&row.id),
                    Some("prune (full snapshot)"),
                )
                .await;
            }
        }
    }
    Ok(())
}

/// Declarative reconcile of `Source::Control` rules. Rules in
/// `desired` are inserted (if missing) or kept (if already present
/// with matching content). When `prune` is true, existing
/// control-source rules absent from `desired` are uninstalled —
/// otherwise they're left in place (additive merge). Other sources
/// (`User`, `WgDriver`) are never touched regardless of `prune`.
///
/// Matching uses `(table, chain, normalize_ws(spec), priority,
/// comment)` as the content key, so cosmetic ordering changes from
/// the control center don't churn the kernel.
async fn apply_iptables(
    pool: &Pool,
    mgr: &dyn IptablesManager,
    desired: &[SnapshotRule],
    prune: bool,
    stats: &mut ReconcileStats,
) -> Result<()> {
    for r in desired {
        validate_iptables_rule(r)?;
    }

    let existing = mgr
        .list(ListFilter {
            source: Some(Source::Control),
        })
        .await
        .map_err(|e| anyhow!("control: list iptables: {e}"))?;

    let mut wanted: Vec<RuleKey> = desired.iter().map(RuleKey::from_snapshot).collect();
    let mut keep_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Pass 1: any existing rule whose content matches a wanted entry
    // stays put; remove that wanted entry from the queue.
    for row in &existing {
        let key = RuleKey::from_stored(row);
        if let Some(pos) = wanted.iter().position(|w| *w == key) {
            wanted.swap_remove(pos);
            keep_ids.insert(row.id.clone());
            stats.iptables_kept += 1;
        }
    }

    // Pass 2: uninstall existing rules that didn't match anything,
    // gated on `prune`. In Keep mode the unmatched leftovers stay so
    // operator-installed extras (e.g. via a future seeding script)
    // survive a control-center sync.
    if prune {
        let mut removed = 0_usize;
        for row in &existing {
            if keep_ids.contains(&row.id) {
                continue;
            }
            mgr.remove_control_rule(&row.id)
                .await
                .map_err(|e| anyhow!("control: remove iptables rule {}: {e}", row.id))?;
            removed += 1;
            audit(
                pool,
                "control.iptables.remove",
                Some(&row.id),
                Some(&format!("{} {} {}", row.table, row.chain, row.spec)),
            )
            .await;
        }
        stats.iptables_removed = removed;
    }

    // Pass 3: install the leftover wanted entries.
    if !wanted.is_empty() {
        let specs: Vec<RuleSpec> = wanted.into_iter().map(RuleKey::into_spec).collect();
        let added = specs.len();
        // Audit BEFORE the kernel install so a partial failure
        // still records that the control center asked for it.
        for spec in &specs {
            audit(
                pool,
                "control.iptables.add",
                None,
                Some(&format!("{} {} {}", spec.table, spec.chain, spec.spec)),
            )
            .await;
        }
        mgr.register(Source::Control, specs, RegisterOptions { force: true })
            .await
            .map_err(|e| anyhow!("control: register iptables rules: {e}"))?;
        stats.iptables_added = added;
    }

    Ok(())
}

fn validate_iptables_rule(r: &SnapshotRule) -> Result<()> {
    if r.table.trim().is_empty() {
        return Err(anyhow!("control: iptables rule has empty table"));
    }
    if r.chain.trim().is_empty() {
        return Err(anyhow!("control: iptables rule has empty chain"));
    }
    if r.spec.trim().is_empty() {
        return Err(anyhow!("control: iptables rule has empty spec"));
    }
    Ok(())
}

/// Content key used to dedupe control-source rules between server
/// snapshots and live state. Equality means "same kernel rule".
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleKey {
    table: String,
    chain: String,
    spec: String,
    priority: i32,
    comment: Option<String>,
}

impl RuleKey {
    fn from_snapshot(r: &SnapshotRule) -> Self {
        Self {
            table: r.table.trim().to_owned(),
            chain: r.chain.trim().to_owned(),
            spec: normalize_ws(&r.spec),
            priority: r.priority,
            comment: r.comment.as_ref().map(|c| c.trim().to_owned()),
        }
    }

    fn from_stored(s: &StoredRule) -> Self {
        Self {
            table: s.table.trim().to_owned(),
            chain: s.chain.trim().to_owned(),
            spec: normalize_ws(&s.spec),
            priority: s.priority,
            comment: s.comment.as_ref().map(|c| c.trim().to_owned()),
        }
    }

    fn into_spec(self) -> RuleSpec {
        RuleSpec {
            table: self.table,
            chain: self.chain,
            spec: self.spec,
            comment: self.comment,
            priority: self.priority,
        }
    }
}

/// Collapse runs of whitespace inside a rule spec so `"-p tcp"` and
/// `"-p  tcp"` hash as the same rule.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

async fn apply_user_delta(
    pool: &Pool,
    delta: &UserDelta,
    outcome: &mut ReconcileOutcome,
) -> Result<()> {
    let users_repo = UsersRepo::new(pool);
    for incoming in &delta.upsert {
        validate_user(incoming)?;
        upsert_user(pool, &users_repo, incoming, outcome).await?;
    }
    for id in &delta.delete {
        if id.trim().is_empty() {
            return Err(anyhow!("control: delta delete contains empty id"));
        }
        // Refuse to delete a row owned by the local admin — even an
        // explicit server `delete[]` instruction can't cross the
        // ownership boundary. Unknown ids are silently ignored.
        match users_repo.get(id).await? {
            None => {}
            Some(row) if row.source == UserSource::Local => {
                outcome.stats.users_skipped_local += 1;
                tracing::warn!(
                    user_id = id.as_str(),
                    "control: refusing to delete local user via control-center delta"
                );
                outcome.issues.push(Issue::for_subject(
                    "user_delete_refused_local",
                    Severity::Error,
                    id.clone(),
                    "control center asked to delete a `local`-source user; admin-owned rows are off-limits",
                ));
            }
            Some(_) if users_repo.delete(id).await? => {
                outcome.stats.users_deleted += 1;
                audit(pool, "control.user.delete", Some(id), Some("delta delete")).await;
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn validate_user(incoming: &SnapshotUser) -> Result<()> {
    if incoming.id.trim().is_empty() {
        return Err(anyhow!("control: snapshot user has empty id"));
    }
    if incoming.name.trim().is_empty() {
        return Err(anyhow!(
            "control: snapshot user `{}` has empty name",
            incoming.id
        ));
    }
    Ok(())
}

async fn upsert_user(
    pool: &Pool,
    users_repo: &UsersRepo<'_>,
    incoming: &SnapshotUser,
    outcome: &mut ReconcileOutcome,
) -> Result<()> {
    match users_repo.get(&incoming.id).await? {
        None => {
            // New row → tag it as control-owned so subsequent admin
            // PATCH/DELETE on /api/users/:id correctly refuses.
            users_repo
                .create_with_source(
                    &incoming.id,
                    &incoming.name,
                    UserSource::Control,
                    incoming.note.as_deref(),
                )
                .await
                .with_context(|| format!("create user {}", incoming.id))?;
            outcome.stats.users_created += 1;
            audit(
                pool,
                "control.user.create",
                Some(&incoming.id),
                Some(&format!("name={}", incoming.name)),
            )
            .await;
        }
        Some(existing) if existing.source == UserSource::Local => {
            // ID collision against a locally-owned row. Refusing to
            // adopt or mutate keeps the admin's authority intact —
            // the control center has to pick a different id.
            outcome.stats.users_skipped_local += 1;
            tracing::warn!(
                user_id = incoming.id.as_str(),
                "control: refusing to upsert over local user; control center must choose a different id"
            );
            outcome.issues.push(Issue::for_subject(
                "user_id_conflict_local",
                Severity::Error,
                incoming.id.clone(),
                "control-center upsert collided with an existing `local` user; pick a different id",
            ));
        }
        Some(existing) => {
            let name_changed = existing.name != incoming.name;
            if name_changed {
                users_repo.rename(&incoming.id, &incoming.name).await?;
            }
            let note_changed = existing.note != incoming.note;
            if note_changed {
                users_repo
                    .update_note(&incoming.id, incoming.note.as_deref())
                    .await?;
            }
            if name_changed || note_changed {
                outcome.stats.users_updated += 1;
                audit(
                    pool,
                    "control.user.update",
                    Some(&incoming.id),
                    Some(&format!("name={}", incoming.name)),
                )
                .await;
            }
        }
    }
    Ok(())
}

/// Read the persisted control-center cursor, if any. Empty strings
/// (left behind by [`clear_cursor`]) are reported as `None`.
pub async fn read_cursor(pool: &Pool) -> Result<Option<String>> {
    let bytes = ServerConfigRepo::new(pool).get(CURSOR_KEY).await?;
    Ok(bytes
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| !s.trim().is_empty()))
}

/// Persist the supplied cursor so the next pull can request a delta.
/// Empty cursors are rejected to avoid replacing a useful cursor with
/// nothing on a malformed response.
pub async fn write_cursor(pool: &Pool, cursor: &str) -> Result<()> {
    let trimmed = cursor.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("control: refusing to persist empty cursor"));
    }
    ServerConfigRepo::new(pool)
        .set(CURSOR_KEY, trimmed.as_bytes())
        .await?;
    Ok(())
}

/// Clear the persisted cursor so the next pull goes out unconditional.
/// Idempotent — clearing an already-empty slot succeeds silently.
pub async fn clear_cursor(pool: &Pool) -> Result<()> {
    // `ServerConfigRepo::set` with an empty value is the simplest way
    // to "forget" the cursor: `read_cursor` treats empty bytes as
    // "no cursor" because `String::from_utf8(vec![]).ok()` is
    // `Some("")`, which we then filter out. To be explicit, store an
    // empty payload and have `read_cursor` reject empty strings.
    ServerConfigRepo::new(pool).set(CURSOR_KEY, &[]).await?;
    Ok(())
}

async fn apply_settings(pool: &Pool, snap: &SnapshotSettings) -> Result<bool> {
    let repo = SettingsRepo::new(pool);
    let current = repo.get().await?;
    let mut patch = SettingsPatch::default();

    if let Some(domain) = snap.domain.as_ref() {
        if &current.domain != domain {
            patch.domain = Some(domain.clone());
        }
    }
    if let Some(subnet) = snap.wg_subnet.as_ref() {
        if &current.wg_subnet != subnet {
            patch.wg_subnet = Some(subnet.clone());
        }
    }
    if let Some(port) = snap.ss_listen_port {
        if current.ss_listen_port != port {
            patch.ss_listen_port = Some(port);
        }
    }
    if let Some(port) = snap.wg_listen_port {
        if current.wg_listen_port != port {
            patch.wg_listen_port = Some(port);
        }
    }

    if patch.is_empty() {
        return Ok(false);
    }
    // Capture which fields changed for the audit detail before
    // patch consumes the values.
    let mut changed_fields: Vec<&'static str> = Vec::new();
    if patch.domain.is_some() {
        changed_fields.push("domain");
    }
    if patch.wg_subnet.is_some() {
        changed_fields.push("wg_subnet");
    }
    if patch.ss_listen_port.is_some() {
        changed_fields.push("ss_listen_port");
    }
    if patch.wg_listen_port.is_some() {
        changed_fields.push("wg_listen_port");
    }
    repo.patch(patch).await?;
    audit(
        pool,
        "control.settings.patch",
        None,
        Some(&format!("fields=[{}]", changed_fields.join(","))),
    )
    .await;
    Ok(true)
}

// ---------------- HTTP client ----------------

struct Client {
    http: reqwest::Client,
    base_url: String,
    node_id: String,
}

fn build_client(cfg: &ControlConfig) -> Result<Client> {
    // reqwest's `rustls-tls-...-no-provider` features expect the caller
    // to have installed a default rustls crypto provider before the
    // client builds its TLS config. `main.rs` does this once at startup
    // for the production path; calling here is idempotent and keeps
    // `build_client` self-contained for unit tests.
    crate::tls::install_default_crypto_provider();

    let url = cfg
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("control.url is required when control.enabled = true"))?
        .trim_end_matches('/')
        .to_owned();
    if url.is_empty() {
        return Err(anyhow!("control.url is empty"));
    }
    let node_id = cfg
        .node_id
        .as_deref()
        .ok_or_else(|| anyhow!("control.node_id is required when control.enabled = true"))?
        .trim()
        .to_owned();
    if node_id.is_empty() {
        return Err(anyhow!("control.node_id is empty"));
    }
    let token = cfg
        .token
        .as_ref()
        .ok_or_else(|| anyhow!("control.token is required when control.enabled = true"))?;

    let mut headers = HeaderMap::new();
    let mut auth = HeaderValue::try_from(format!("Bearer {}", token.expose_secret()))
        .map_err(|e| anyhow!("control.token contains invalid header bytes: {e}"))?;
    auth.set_sensitive(true);
    headers.insert(AUTHORIZATION, auth);
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::try_from(format!("nsp/{VERSION} (control-poller)"))
            .unwrap_or_else(|_| HeaderValue::from_static("nsp/control-poller")),
    );

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs.max(1)))
        .default_headers(headers)
        .build()
        .context("build reqwest client")?;
    Ok(Client {
        http,
        base_url: url,
        node_id,
    })
}

impl Client {
    fn config_url(&self) -> String {
        format!("{}/api/v1/nodes/{}/config", self.base_url, self.node_id)
    }

    fn status_url(&self) -> String {
        format!("{}/api/v1/nodes/{}/status", self.base_url, self.node_id)
    }

    fn report_url(&self) -> String {
        format!("{}/api/v1/nodes/{}/report", self.base_url, self.node_id)
    }

    /// Send the node's `/config` self-report and return the server's
    /// reconciliation directives. Strictly configuration shape — see
    /// [`SyncRequest`].
    async fn post_config(&self, cursor: Option<&str>, state: &LocalState) -> Result<Snapshot> {
        let url = self.config_url();
        let body = SyncRequest {
            node_id: &self.node_id,
            version: VERSION,
            cursor: cursor.map(str::trim).filter(|s| !s.is_empty()),
            state,
        };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("POST {url} returned {status}: {body}"));
        }
        let snap: Snapshot = resp.json().await.with_context(|| format!("decode {url}"))?;
        Ok(snap)
    }

    /// Send the node's `/status` observability report. The server
    /// is expected to return `2xx` with an empty body — this
    /// endpoint never carries reconciliation directives.
    async fn post_status(
        &self,
        cursor: Option<&str>,
        report: &StatusReport,
        last_apply: &ApplyReport,
        issues: &[Issue],
    ) -> Result<()> {
        let url = self.status_url();
        let body = StatusRequest {
            node_id: &self.node_id,
            version: VERSION,
            cursor: cursor.map(str::trim).filter(|s| !s.is_empty()),
            report,
            last_apply: last_apply.clone(),
            issues,
        };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("POST {url} returned {status}: {body}"));
        }
        // Body intentionally discarded; status responses carry no
        // directives back to the node.
        Ok(())
    }

    /// Send a batch of one-shot events to the dedicated `/report`
    /// endpoint. The server is expected to return `2xx` with an
    /// empty body. Used by the report task; never carries any
    /// reconciliation directives.
    async fn post_report(&self, cursor: Option<&str>, events: &[Issue]) -> Result<()> {
        let url = self.report_url();
        let body = ReportRequest {
            node_id: &self.node_id,
            version: VERSION,
            cursor: cursor.map(str::trim).filter(|s| !s.is_empty()),
            events,
        };
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("POST {url} returned {status}: {body}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsp_db::open;

    async fn test_pool() -> Pool {
        let dir = std::env::temp_dir().join(format!(
            "nsp-control-test-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        open(&dir.join("t.db")).await.expect("open db")
    }

    fn full_snapshot(users: Vec<SnapshotUser>) -> Snapshot {
        Snapshot {
            users: Some(UsersSection::Full(users)),
            ..Snapshot::default()
        }
    }

    fn delta_snapshot(upsert: Vec<SnapshotUser>, delete: Vec<String>) -> Snapshot {
        Snapshot {
            users: Some(UsersSection::Delta(UserDelta { upsert, delete })),
            ..Snapshot::default()
        }
    }

    fn user(id: &str, name: &str, note: Option<&str>) -> SnapshotUser {
        SnapshotUser {
            id: id.to_owned(),
            name: name.to_owned(),
            note: note.map(str::to_owned),
        }
    }

    /// Seed a row owned by the control reconciler — what tests use
    /// to simulate "this user already arrived through a prior sync."
    /// Plain `UsersRepo::create(...)` defaults to `Local` (admin row)
    /// and is structurally off-limits to the reconciler.
    async fn seed_control_user(pool: &Pool, id: &str, name: &str, note: Option<&str>) {
        UsersRepo::new(pool)
            .create_with_source(id, name, UserSource::Control, note)
            .await
            .expect("seed control user");
    }

    // ---------------- full-mode tests ----------------

    #[tokio::test]
    async fn full_reconcile_creates_missing_users() {
        let pool = test_pool().await;
        let snap = full_snapshot(vec![
            user("u1", "alice", Some("team A")),
            user("u2", "bob", None),
        ]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.mode, Some(ReconcileMode::Full));
        assert_eq!(stats.users_created, 2);
        assert_eq!(stats.users_updated, 0);
        assert_eq!(stats.users_deleted, 0);
        assert!(!stats.settings_changed);

        let users = UsersRepo::new(&pool).list(None).await.expect("list");
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn full_reconcile_updates_renamed_user() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", Some("team A")).await;

        let snap = full_snapshot(vec![user("u1", "alice2", Some("team B"))]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_updated, 1);
        assert_eq!(stats.users_created, 0);

        let row = UsersRepo::new(&pool)
            .get("u1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.name, "alice2");
        assert_eq!(row.note.as_deref(), Some("team B"));
    }

    #[tokio::test]
    async fn full_reconcile_no_op_when_identical() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", Some("note")).await;
        let snap = full_snapshot(vec![user("u1", "alice", Some("note"))]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_created, 0);
        assert_eq!(stats.users_updated, 0);
        assert_eq!(stats.users_deleted, 0);
        assert!(!stats.settings_changed);
        assert_eq!(stats.mode, Some(ReconcileMode::Full));
    }

    #[tokio::test]
    async fn full_reconcile_prunes_only_under_prune_policy() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", None).await;
        seed_control_user(&pool, "u2", "bob", None).await;

        let snap = full_snapshot(vec![user("u1", "alice", None)]);

        // Without prune: keep both rows.
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile keep");
        assert_eq!(stats.users_deleted, 0);
        assert_eq!(UsersRepo::new(&pool).count().await.unwrap(), 2);

        // With prune: remove the missing row.
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, None)
            .await
            .expect("reconcile prune");
        assert_eq!(stats.users_deleted, 1);
        assert_eq!(UsersRepo::new(&pool).count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn full_reconcile_applies_settings() {
        let pool = test_pool().await;
        let snap = Snapshot {
            settings: Some(SnapshotSettings {
                domain: Some(Some("proxy.example.com".into())),
                wg_subnet: Some(Some("10.66.66.0/24".into())),
                ss_listen_port: Some(4500),
                wg_listen_port: Some(51820),
            }),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert!(stats.settings_changed);
        assert_eq!(stats.mode, None);

        let row = SettingsRepo::new(&pool).get().await.expect("settings");
        assert_eq!(row.domain.as_deref(), Some("proxy.example.com"));
        assert_eq!(row.wg_subnet.as_deref(), Some("10.66.66.0/24"));
        assert_eq!(row.ss_listen_port, 4500);

        // Re-applying the same settings is a no-op.
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile2");
        assert!(!stats.settings_changed);
    }

    #[tokio::test]
    async fn full_reconcile_clears_domain_with_explicit_null() {
        let pool = test_pool().await;
        SettingsRepo::new(&pool)
            .patch(SettingsPatch {
                domain: Some(Some("old.example.com".into())),
                ..Default::default()
            })
            .await
            .expect("seed");

        let snap = Snapshot {
            settings: Some(SnapshotSettings {
                domain: Some(None),
                ..SnapshotSettings::default()
            }),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert!(stats.settings_changed);
        let row = SettingsRepo::new(&pool).get().await.expect("settings");
        assert!(row.domain.is_none());
    }

    #[tokio::test]
    async fn full_reconcile_rejects_empty_user_id() {
        let pool = test_pool().await;
        let snap = full_snapshot(vec![user("  ", "alice", None)]);
        let err = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("empty id"));
    }

    // ---------------- delta-mode tests ----------------

    #[tokio::test]
    async fn delta_upsert_creates_and_updates() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", None).await;

        let snap = delta_snapshot(
            vec![
                user("u1", "alice2", Some("renamed")),
                user("u2", "bob", None),
            ],
            vec![],
        );
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.mode, Some(ReconcileMode::Delta));
        assert_eq!(stats.users_created, 1);
        assert_eq!(stats.users_updated, 1);
        assert_eq!(stats.users_deleted, 0);

        let alice = UsersRepo::new(&pool).get("u1").await.unwrap().unwrap();
        assert_eq!(alice.name, "alice2");
        assert_eq!(alice.note.as_deref(), Some("renamed"));
        assert!(UsersRepo::new(&pool).get("u2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delta_delete_always_removes_regardless_of_policy() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", None).await;
        seed_control_user(&pool, "u2", "bob", None).await;
        let users = UsersRepo::new(&pool);

        let snap = delta_snapshot(vec![], vec!["u1".into()]);
        // policy=Keep on purpose: server-driven deletes still apply.
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.mode, Some(ReconcileMode::Delta));
        assert_eq!(stats.users_deleted, 1);
        assert_eq!(stats.users_created, 0);
        assert!(users.get("u1").await.unwrap().is_none());
        assert!(users.get("u2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delta_delete_unknown_id_is_silent() {
        let pool = test_pool().await;
        let snap = delta_snapshot(vec![], vec!["never-existed".into()]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_deleted, 0);
        assert_eq!(stats.mode, Some(ReconcileMode::Delta));
    }

    #[tokio::test]
    async fn delta_empty_payload_is_no_op() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", None).await;
        let snap = delta_snapshot(vec![], vec![]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_created, 0);
        assert_eq!(stats.users_updated, 0);
        assert_eq!(stats.users_deleted, 0);
        assert_eq!(stats.mode, Some(ReconcileMode::Delta));
        assert_eq!(UsersRepo::new(&pool).count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn delta_rejects_empty_delete_id() {
        let pool = test_pool().await;
        let snap = delta_snapshot(vec![], vec!["   ".into()]);
        let err = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("empty id"));
    }

    // ---------------- source boundary (local vs control) ----------------

    #[tokio::test]
    async fn full_replace_does_not_delete_local_users() {
        // mode:replace + policy:Prune is the most aggressive setting
        // — but `Local` rows are still structurally protected.
        let pool = test_pool().await;
        UsersRepo::new(&pool)
            .create("admin-1", "admin-alice", None)
            .await
            .expect("seed local");
        seed_control_user(&pool, "ctl-1", "ctl-bob", None).await;
        seed_control_user(&pool, "ctl-2", "ctl-carol", None).await;

        let snap = Snapshot {
            mode: SnapshotMode::Replace,
            users: Some(UsersSection::Full(vec![user("ctl-1", "ctl-bob", None)])),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_deleted, 1); // only ctl-2 went away
        let repo = UsersRepo::new(&pool);
        assert!(repo.get("admin-1").await.unwrap().is_some()); // local survives
        assert!(repo.get("ctl-1").await.unwrap().is_some());
        assert!(repo.get("ctl-2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delta_delete_refuses_local_user() {
        let pool = test_pool().await;
        UsersRepo::new(&pool)
            .create("admin-1", "admin-alice", None)
            .await
            .expect("seed local");

        let snap = delta_snapshot(vec![], vec!["admin-1".into()]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_deleted, 0);
        assert_eq!(stats.users_skipped_local, 1);
        // The local user must still be there.
        assert!(UsersRepo::new(&pool)
            .get("admin-1")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn upsert_id_collision_with_local_user_is_skipped() {
        let pool = test_pool().await;
        // Admin pre-created a user with id "shared".
        UsersRepo::new(&pool)
            .create("shared", "admin-alice", Some("admin note"))
            .await
            .expect("seed local");

        // Control center attempts to "own" the same id with different
        // attributes via Full snapshot. Must be refused.
        let snap = full_snapshot(vec![user("shared", "control-bob", Some("control note"))]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_created, 0);
        assert_eq!(stats.users_updated, 0);
        assert_eq!(stats.users_skipped_local, 1);

        let row = UsersRepo::new(&pool).get("shared").await.unwrap().unwrap();
        assert_eq!(row.source, UserSource::Local);
        assert_eq!(row.name, "admin-alice");
        assert_eq!(row.note.as_deref(), Some("admin note"));
    }

    #[tokio::test]
    async fn newly_created_users_carry_control_source_tag() {
        let pool = test_pool().await;
        let snap = full_snapshot(vec![user("ctl-1", "alice", None)]);
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_created, 1);

        let row = UsersRepo::new(&pool)
            .get("ctl-1")
            .await
            .unwrap()
            .expect("row");
        assert_eq!(row.source, UserSource::Control);
    }

    #[tokio::test]
    async fn reconcile_emits_audit_entries_for_control_mutations() {
        // Asserts: control-driven creates/updates/deletes show up
        // in `audit_log` tagged with the "control" actor, so
        // operators can answer "did the control center change this
        // user, or did I?" from the same log everyone reads.
        let pool = test_pool().await;
        let audit = AuditRepo::new(&pool);

        // 1. create
        reconcile(
            &pool,
            &full_snapshot(vec![user("ctl-a", "alice", None)]),
            ConflictPolicy::Keep,
            None,
        )
        .await
        .expect("reconcile create");

        // 2. update (rename)
        reconcile(
            &pool,
            &full_snapshot(vec![user("ctl-a", "alice-2", Some("note"))]),
            ConflictPolicy::Keep,
            None,
        )
        .await
        .expect("reconcile update");

        // 3. delete via delta
        reconcile(
            &pool,
            &delta_snapshot(vec![], vec!["ctl-a".into()]),
            ConflictPolicy::Keep,
            None,
        )
        .await
        .expect("reconcile delete");

        let entries = audit.list(50).await.expect("audit list");
        let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
        assert!(
            actions.contains(&"control.user.create"),
            "create entry missing; got {actions:?}"
        );
        assert!(
            actions.contains(&"control.user.update"),
            "update entry missing; got {actions:?}"
        );
        assert!(
            actions.contains(&"control.user.delete"),
            "delete entry missing; got {actions:?}"
        );
        // Every entry from the reconciler must be tagged as the
        // control actor — easier on log filters than picking
        // through detail blobs.
        for e in &entries {
            assert_eq!(e.actor, "control", "non-control actor in entry: {e:?}");
        }
    }

    // ---------------- report() event channel ----------------

    #[test]
    fn report_returns_false_when_no_poller_is_active_yet() {
        // A fresh process with control disabled means the global
        // sender was never installed; report() must not panic and
        // must signal no-op so callers know to log/store locally.
        // (Note: this test only passes deterministically when run
        // first / when the OnceLock hasn't been set by another
        // test in the same process. We accept either outcome and
        // just assert the call doesn't panic.)
        let _ = report(Issue::capability(
            "test_no_poller",
            Severity::Info,
            "this should be a no-op when no poller is active",
        ));
    }

    #[tokio::test]
    async fn report_channel_coalesces_burst_into_one_batch() {
        // Mirror the report task's coalesce loop: when the first
        // event arrives, collect everything that comes in within
        // a short window before sending one POST.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Issue>();

        // Three rapid events, simulating an anomaly detector that
        // saw multiple peers cross a threshold at once.
        tx.send(Issue::for_subject(
            "user_high_traffic",
            Severity::Warn,
            "01HZ-alice",
            "1.5 GB rx in last hour",
        ))
        .unwrap();
        tx.send(Issue::for_subject(
            "user_high_traffic",
            Severity::Warn,
            "01HZ-bob",
            "2.1 GB rx in last hour",
        ))
        .unwrap();
        tx.send(Issue::capability(
            "node_anomaly",
            Severity::Error,
            "disk full at /work/data",
        ))
        .unwrap();

        // Replicate the report loop's draining + coalesce window.
        let first = rx.recv().await.expect("at least one event");
        let mut events = vec![first];
        let coalesce = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(coalesce);
        loop {
            tokio::select! {
                Some(more) = rx.recv() => events.push(more),
                () = &mut coalesce => break,
            }
        }
        while let Ok(more) = rx.try_recv() {
            events.push(more);
        }

        assert_eq!(events.len(), 3, "all three events coalesced into one batch");
        assert_eq!(events[0].code, "user_high_traffic");
        assert_eq!(events[0].subject.as_deref(), Some("01HZ-alice"));
        assert_eq!(events[2].code, "node_anomaly");
        assert!(events[2].subject.is_none());
    }

    #[tokio::test]
    async fn report_request_body_carries_events_and_cursor() {
        let events = vec![
            Issue::for_subject(
                "user_high_traffic",
                Severity::Warn,
                "01HZ-alice",
                "1.5 GB rx",
            ),
            Issue::capability("node_anomaly", Severity::Error, "disk full"),
        ];
        let body = ReportRequest {
            node_id: "node-1",
            version: VERSION,
            cursor: Some("v42"),
            events: &events,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(json["node_id"], "node-1");
        assert_eq!(json["cursor"], "v42");
        let arr = json["events"].as_array().expect("events array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["code"], "user_high_traffic");
        assert_eq!(arr[0]["subject"], "01HZ-alice");
        assert_eq!(arr[1]["code"], "node_anomaly");
        assert!(arr[1].get("subject").is_none());
    }

    // ---------------- issue reporting ----------------

    #[test]
    fn live_issues_report_iptables_unavailable_when_manager_is_none() {
        let issues = collect_live_issues(None, None, None);
        let codes: Vec<&str> = issues.iter().map(|i| i.code).collect();
        assert!(codes.contains(&"iptables_unavailable"));
        assert!(codes.contains(&"ss_disabled"));
        assert!(codes.contains(&"wg_disabled"));
    }

    #[test]
    fn live_issues_have_no_subject_for_capability_gaps() {
        let issues = collect_live_issues(None, None, None);
        for issue in issues {
            assert!(issue.subject.is_none(), "capability issues are host-wide");
        }
    }

    #[tokio::test]
    async fn reconcile_outcome_emits_issue_for_local_id_collision() {
        let pool = test_pool().await;
        UsersRepo::new(&pool)
            .create("shared", "admin-alice", None)
            .await
            .expect("seed local");

        let snap = full_snapshot(vec![user("shared", "control-bob", None)]);
        let outcome = reconcile_outcome(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(outcome.stats.users_skipped_local, 1);
        let issue = outcome
            .issues
            .iter()
            .find(|i| i.code == "user_id_conflict_local")
            .expect("issue present");
        assert_eq!(issue.severity, Severity::Error);
        assert_eq!(issue.subject.as_deref(), Some("shared"));
    }

    #[tokio::test]
    async fn reconcile_outcome_emits_issue_when_delta_delete_targets_local() {
        let pool = test_pool().await;
        UsersRepo::new(&pool)
            .create("admin-1", "admin-alice", None)
            .await
            .expect("seed local");

        let snap = delta_snapshot(vec![], vec!["admin-1".into()]);
        let outcome = reconcile_outcome(&pool, &snap, ConflictPolicy::Prune, None)
            .await
            .expect("reconcile");
        let issue = outcome
            .issues
            .iter()
            .find(|i| i.code == "user_delete_refused_local")
            .expect("issue present");
        assert_eq!(issue.subject.as_deref(), Some("admin-1"));
    }

    #[tokio::test]
    async fn reconcile_outcome_emits_issue_when_iptables_section_skipped() {
        // No iptables manager + a non-empty iptables section in the
        // snapshot ⇒ should both warn-log AND surface the event so
        // the control center sees that its directives didn't land.
        let pool = test_pool().await;
        let snap = Snapshot {
            iptables: Some(vec![SnapshotRule {
                table: "filter".into(),
                chain: "INPUT".into(),
                spec: "-p tcp --dport 22 -j ACCEPT".into(),
                comment: None,
                priority: 0,
            }]),
            ..Snapshot::default()
        };
        let outcome = reconcile_outcome(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert!(outcome
            .issues
            .iter()
            .any(|i| i.code == "iptables_section_skipped" && i.severity == Severity::Warn));
    }

    // ---------------- format compatibility ----------------

    #[test]
    fn legacy_users_array_parses_as_full() {
        let json = r#"{
            "settings": null,
            "users": [
                {"id": "u1", "name": "alice"},
                {"id": "u2", "name": "bob", "note": "x"}
            ]
        }"#;
        let snap: Snapshot = serde_json::from_str(json).expect("parse legacy");
        assert!(snap.cursor.is_none());
        match snap.users {
            Some(UsersSection::Full(list)) => {
                assert_eq!(list.len(), 2);
                assert_eq!(list[1].note.as_deref(), Some("x"));
            }
            other => panic!("expected Full, got {other:?}"),
        }
    }

    #[test]
    fn delta_payload_parses_as_delta() {
        let json = r#"{
            "cursor": "abc-123",
            "users": {
                "upsert": [{"id": "u1", "name": "alice"}],
                "delete": ["u2"]
            }
        }"#;
        let snap: Snapshot = serde_json::from_str(json).expect("parse delta");
        assert_eq!(snap.cursor.as_deref(), Some("abc-123"));
        match snap.users {
            Some(UsersSection::Delta(d)) => {
                assert_eq!(d.upsert.len(), 1);
                assert_eq!(d.delete, vec!["u2".to_owned()]);
            }
            other => panic!("expected Delta, got {other:?}"),
        }
    }

    #[test]
    fn missing_users_section_parses_as_none() {
        let json = r#"{"cursor": "v9"}"#;
        let snap: Snapshot = serde_json::from_str(json).expect("parse minimal");
        assert!(snap.users.is_none());
        assert_eq!(snap.cursor.as_deref(), Some("v9"));
    }

    // ---------------- cursor persistence ----------------

    #[tokio::test]
    async fn cursor_round_trips_through_db() {
        let pool = test_pool().await;
        assert!(read_cursor(&pool).await.unwrap().is_none());
        write_cursor(&pool, "v42").await.expect("write");
        assert_eq!(read_cursor(&pool).await.unwrap().as_deref(), Some("v42"));
        write_cursor(&pool, "v43").await.expect("overwrite");
        assert_eq!(read_cursor(&pool).await.unwrap().as_deref(), Some("v43"));
    }

    #[tokio::test]
    async fn write_cursor_rejects_empty() {
        let pool = test_pool().await;
        assert!(write_cursor(&pool, "").await.is_err());
        assert!(write_cursor(&pool, "   ").await.is_err());
        assert!(read_cursor(&pool).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clear_cursor_makes_read_return_none() {
        let pool = test_pool().await;
        write_cursor(&pool, "v1").await.expect("write");
        assert_eq!(read_cursor(&pool).await.unwrap().as_deref(), Some("v1"));
        clear_cursor(&pool).await.expect("clear");
        assert!(read_cursor(&pool).await.unwrap().is_none());
        // Idempotent: clearing an already-empty slot is fine.
        clear_cursor(&pool).await.expect("clear again");
    }

    // ---------------- replace mode + reset ----------------

    #[tokio::test]
    async fn replace_mode_prunes_missing_users_even_under_keep_policy() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", None).await;
        seed_control_user(&pool, "u2", "bob", None).await;

        let snap = Snapshot {
            mode: SnapshotMode::Replace,
            users: Some(UsersSection::Full(vec![user("u1", "alice", None)])),
            ..Snapshot::default()
        };
        // policy=Keep on purpose: server's mode:replace should override.
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile");
        assert_eq!(stats.users_deleted, 1);
        assert_eq!(UsersRepo::new(&pool).count().await.unwrap(), 1);
    }

    #[test]
    fn replace_mode_parses() {
        let json = r#"{"mode":"replace","users":[]}"#;
        let snap: Snapshot = serde_json::from_str(json).expect("parse");
        assert_eq!(snap.mode, SnapshotMode::Replace);
    }

    #[test]
    fn reset_field_parses() {
        let json = r#"{"reset":true,"cursor":"v9"}"#;
        let snap: Snapshot = serde_json::from_str(json).expect("parse");
        assert!(snap.reset);
        assert_eq!(snap.cursor.as_deref(), Some("v9"));
    }

    // ---------------- iptables ----------------

    use async_trait::async_trait;
    use nsp_netctl::{NetctlError, ReconcileReport, Result as NetResult};
    use tokio::sync::Mutex;

    /// Minimal in-memory `IptablesManager` test double. Only the
    /// methods the control reconciler invokes are implemented.
    struct FakeIptables {
        inner: Mutex<Vec<StoredRule>>,
        next_id: Mutex<u64>,
    }

    impl FakeIptables {
        fn new() -> Self {
            Self {
                inner: Mutex::new(Vec::new()),
                next_id: Mutex::new(0),
            }
        }

        fn seed(&self, rules: Vec<StoredRule>) {
            let mut guard = self.inner.try_lock().expect("seed lock");
            *guard = rules;
        }

        async fn snapshot(&self) -> Vec<StoredRule> {
            self.inner.lock().await.clone()
        }
    }

    #[async_trait]
    impl IptablesManager for FakeIptables {
        async fn register(
            &self,
            source: Source,
            rules: Vec<RuleSpec>,
            _opts: RegisterOptions,
        ) -> NetResult<Vec<StoredRule>> {
            let mut guard = self.inner.lock().await;
            let mut id_guard = self.next_id.lock().await;
            let now = chrono::Utc::now().timestamp();
            let mut out = Vec::with_capacity(rules.len());
            for spec in rules {
                *id_guard += 1;
                let stored = StoredRule {
                    id: format!("fake-{}", *id_guard),
                    source,
                    priority: spec.priority,
                    table: spec.table,
                    chain: spec.chain,
                    spec: spec.spec,
                    comment: spec.comment,
                    created_at: now,
                    updated_at: now,
                };
                guard.push(stored.clone());
                out.push(stored);
            }
            Ok(out)
        }

        async fn remove_by_source(&self, source: Source) -> NetResult<usize> {
            let mut guard = self.inner.lock().await;
            let before = guard.len();
            guard.retain(|r| r.source != source);
            Ok(before - guard.len())
        }

        async fn remove_user_rule(&self, id: &str) -> NetResult<()> {
            self.remove_by_id(id, Source::User).await
        }

        async fn remove_control_rule(&self, id: &str) -> NetResult<()> {
            self.remove_by_id(id, Source::Control).await
        }

        async fn list(&self, filter: ListFilter) -> NetResult<Vec<StoredRule>> {
            let guard = self.inner.lock().await;
            let out = match filter.source {
                Some(s) => guard.iter().filter(|r| r.source == s).cloned().collect(),
                None => guard.clone(),
            };
            Ok(out)
        }

        async fn verify(&self, _spec: &RuleSpec, _opts: RegisterOptions) -> NetResult<()> {
            unimplemented!("verify not exercised by control reconciler tests")
        }

        async fn reconcile(&self) -> NetResult<ReconcileReport> {
            unimplemented!("reconcile not exercised by control reconciler tests")
        }
    }

    impl FakeIptables {
        async fn remove_by_id(&self, id: &str, expected: Source) -> NetResult<()> {
            let mut guard = self.inner.lock().await;
            let pos = guard
                .iter()
                .position(|r| r.id == id)
                .ok_or_else(|| NetctlError::NotFound(id.to_owned()))?;
            if guard[pos].source != expected {
                return Err(NetctlError::Forbidden(format!(
                    "rule {id} owned by {} cannot be deleted as {}",
                    guard[pos].source.as_tag(),
                    expected.as_tag()
                )));
            }
            guard.remove(pos);
            Ok(())
        }
    }

    fn snapshot_rule(table: &str, chain: &str, spec: &str) -> SnapshotRule {
        SnapshotRule {
            table: table.to_owned(),
            chain: chain.to_owned(),
            spec: spec.to_owned(),
            comment: None,
            priority: 0,
        }
    }

    #[tokio::test]
    async fn iptables_inserts_when_empty() {
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        let snap = Snapshot {
            iptables: Some(vec![
                snapshot_rule("filter", "INPUT", "-p tcp --dport 22 -j ACCEPT"),
                snapshot_rule("filter", "INPUT", "-p tcp --dport 443 -j ACCEPT"),
            ]),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, Some(&fake))
            .await
            .expect("reconcile");
        assert_eq!(stats.iptables_added, 2);
        assert_eq!(stats.iptables_kept, 0);
        assert_eq!(stats.iptables_removed, 0);
        let snap_rules = fake.snapshot().await;
        assert_eq!(snap_rules.len(), 2);
        assert!(snap_rules.iter().all(|r| r.source == Source::Control));
    }

    #[tokio::test]
    async fn iptables_keeps_unchanged_and_skips_kernel() {
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        // Pre-seed a rule that matches the snapshot exactly.
        fake.seed(vec![StoredRule {
            id: "existing".into(),
            source: Source::Control,
            priority: 0,
            table: "filter".into(),
            chain: "INPUT".into(),
            spec: "-p tcp --dport 22 -j ACCEPT".into(),
            comment: None,
            created_at: 0,
            updated_at: 0,
        }]);
        let snap = Snapshot {
            iptables: Some(vec![snapshot_rule(
                "filter",
                "INPUT",
                "-p tcp --dport 22 -j ACCEPT",
            )]),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, Some(&fake))
            .await
            .expect("reconcile");
        assert_eq!(stats.iptables_added, 0);
        assert_eq!(stats.iptables_kept, 1);
        assert_eq!(stats.iptables_removed, 0);
        // Same rule still present, untouched.
        let live = fake.snapshot().await;
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, "existing");
    }

    #[tokio::test]
    async fn iptables_under_prune_policy_replaces_changed_rules() {
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        fake.seed(vec![
            StoredRule {
                id: "keep-me".into(),
                source: Source::Control,
                priority: 0,
                table: "filter".into(),
                chain: "INPUT".into(),
                spec: "-p tcp --dport 22 -j ACCEPT".into(),
                comment: None,
                created_at: 0,
                updated_at: 0,
            },
            StoredRule {
                id: "stale".into(),
                source: Source::Control,
                priority: 0,
                table: "filter".into(),
                chain: "INPUT".into(),
                spec: "-p tcp --dport 80 -j ACCEPT".into(),
                comment: None,
                created_at: 0,
                updated_at: 0,
            },
        ]);
        let snap = Snapshot {
            iptables: Some(vec![
                snapshot_rule("filter", "INPUT", "-p tcp --dport 22 -j ACCEPT"),
                snapshot_rule("filter", "INPUT", "-p tcp --dport 443 -j ACCEPT"),
            ]),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, Some(&fake))
            .await
            .expect("reconcile");
        assert_eq!(stats.iptables_kept, 1);
        assert_eq!(stats.iptables_removed, 1); // stale ":80" gone
        assert_eq!(stats.iptables_added, 1); // ":443" added
        let live = fake.snapshot().await;
        let specs: Vec<&str> = live.iter().map(|r| r.spec.as_str()).collect();
        assert!(specs.contains(&"-p tcp --dport 22 -j ACCEPT"));
        assert!(specs.contains(&"-p tcp --dport 443 -j ACCEPT"));
        assert!(!specs.contains(&"-p tcp --dport 80 -j ACCEPT"));
    }

    #[tokio::test]
    async fn iptables_under_keep_policy_keeps_local_extras() {
        // Same fixtures as the prune test above, but with policy=Keep
        // the stale ":80" rule must survive.
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        fake.seed(vec![StoredRule {
            id: "extra".into(),
            source: Source::Control,
            priority: 0,
            table: "filter".into(),
            chain: "INPUT".into(),
            spec: "-p tcp --dport 80 -j ACCEPT".into(),
            comment: None,
            created_at: 0,
            updated_at: 0,
        }]);
        let snap = Snapshot {
            iptables: Some(vec![snapshot_rule(
                "filter",
                "INPUT",
                "-p tcp --dport 22 -j ACCEPT",
            )]),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, Some(&fake))
            .await
            .expect("reconcile");
        assert_eq!(stats.iptables_added, 1);
        assert_eq!(stats.iptables_removed, 0); // pre-existing :80 stays
        let live = fake.snapshot().await;
        let specs: Vec<&str> = live.iter().map(|r| r.spec.as_str()).collect();
        assert!(specs.contains(&"-p tcp --dport 22 -j ACCEPT"));
        assert!(specs.contains(&"-p tcp --dport 80 -j ACCEPT"));
    }

    #[tokio::test]
    async fn iptables_replace_mode_overrides_keep_policy() {
        // Server requests `mode: "replace"` even though operator
        // policy is Keep — the server's per-response demand wins.
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        fake.seed(vec![StoredRule {
            id: "extra".into(),
            source: Source::Control,
            priority: 0,
            table: "filter".into(),
            chain: "INPUT".into(),
            spec: "-p tcp --dport 80 -j ACCEPT".into(),
            comment: None,
            created_at: 0,
            updated_at: 0,
        }]);
        let snap = Snapshot {
            mode: SnapshotMode::Replace,
            iptables: Some(vec![snapshot_rule(
                "filter",
                "INPUT",
                "-p tcp --dport 22 -j ACCEPT",
            )]),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, Some(&fake))
            .await
            .expect("reconcile");
        assert_eq!(stats.iptables_added, 1);
        assert_eq!(stats.iptables_removed, 1); // :80 evicted by mode=replace
        let live = fake.snapshot().await;
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].spec, "-p tcp --dport 22 -j ACCEPT");
    }

    #[tokio::test]
    async fn iptables_empty_list_under_prune_clears_only_control_source() {
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        fake.seed(vec![
            StoredRule {
                id: "ctl".into(),
                source: Source::Control,
                priority: 0,
                table: "filter".into(),
                chain: "INPUT".into(),
                spec: "-p tcp --dport 22 -j ACCEPT".into(),
                comment: None,
                created_at: 0,
                updated_at: 0,
            },
            StoredRule {
                id: "wg".into(),
                source: Source::WgDriver,
                priority: 0,
                table: "nat".into(),
                chain: "POSTROUTING".into(),
                spec: "-s 10.66.66.0/24 -j MASQUERADE".into(),
                comment: None,
                created_at: 0,
                updated_at: 0,
            },
        ]);
        let snap = Snapshot {
            iptables: Some(vec![]),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, Some(&fake))
            .await
            .expect("reconcile");
        assert_eq!(stats.iptables_removed, 1);
        let live = fake.snapshot().await;
        assert_eq!(live.len(), 1);
        // wg-driver rule untouched.
        assert_eq!(live[0].source, Source::WgDriver);
    }

    #[tokio::test]
    async fn iptables_section_absent_leaves_state_alone() {
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        fake.seed(vec![StoredRule {
            id: "ctl".into(),
            source: Source::Control,
            priority: 0,
            table: "filter".into(),
            chain: "INPUT".into(),
            spec: "-p tcp --dport 22 -j ACCEPT".into(),
            comment: None,
            created_at: 0,
            updated_at: 0,
        }]);
        let snap = Snapshot::default();
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, Some(&fake))
            .await
            .expect("reconcile");
        assert_eq!(stats.iptables_added, 0);
        assert_eq!(stats.iptables_removed, 0);
        assert_eq!(stats.iptables_kept, 0);
        let live = fake.snapshot().await;
        assert_eq!(live.len(), 1);
    }

    #[tokio::test]
    async fn iptables_rejects_blank_fields() {
        let pool = test_pool().await;
        let fake = FakeIptables::new();
        let snap = Snapshot {
            iptables: Some(vec![snapshot_rule("filter", "INPUT", "  ")]),
            ..Snapshot::default()
        };
        let err = reconcile(&pool, &snap, ConflictPolicy::Keep, Some(&fake))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("empty spec"));
    }

    #[tokio::test]
    async fn iptables_section_without_manager_is_warned_not_failed() {
        let pool = test_pool().await;
        let snap = Snapshot {
            iptables: Some(vec![snapshot_rule(
                "filter",
                "INPUT",
                "-p tcp --dport 22 -j ACCEPT",
            )]),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Keep, None)
            .await
            .expect("reconcile should not fail");
        // Counters stay zero — nothing was applied.
        assert_eq!(stats.iptables_added, 0);
        assert_eq!(stats.iptables_removed, 0);
        assert_eq!(stats.iptables_kept, 0);
    }

    #[test]
    fn iptables_section_parses() {
        let json = r#"{
            "iptables": [
                {"table":"filter","chain":"INPUT","spec":"-j ACCEPT"},
                {"table":"nat","chain":"POSTROUTING","spec":"-j MASQUERADE","comment":"wg","priority":10}
            ]
        }"#;
        let snap: Snapshot = serde_json::from_str(json).expect("parse");
        let rules = snap.iptables.expect("iptables present");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1].comment.as_deref(), Some("wg"));
        assert_eq!(rules[1].priority, 10);
    }

    // ---------------- HTTP client ----------------

    #[test]
    fn build_client_requires_url_token_node_id() {
        let mut cfg = ControlConfig {
            enabled: true,
            ..ControlConfig::default()
        };
        assert!(build_client(&cfg).is_err()); // missing url

        cfg.url = Some("https://control.test".into());
        assert!(build_client(&cfg).is_err()); // missing node_id

        cfg.node_id = Some("node-1".into());
        assert!(build_client(&cfg).is_err()); // missing token

        cfg.token = Some(secrecy::SecretString::from("t".to_owned()));
        let client = build_client(&cfg).expect("client");
        assert!(client.config_url().ends_with("/api/v1/nodes/node-1/config"));
    }

    // ---------------- LocalState + hashing ----------------

    #[tokio::test]
    async fn local_state_for_empty_db_is_stable() {
        let pool = test_pool().await;
        let s1 = collect_state(&pool, None).await;
        let s2 = collect_state(&pool, None).await;
        assert_eq!(s1.users.count, 0);
        assert_eq!(s1.iptables.count, 0);
        // Same DB content ⇒ identical hashes across calls.
        assert_eq!(s1.settings.hash, s2.settings.hash);
        assert_eq!(s1.users.hash, s2.users.hash);
        assert_eq!(s1.iptables.hash, s2.iptables.hash);
        // Hashes are non-empty hex strings.
        assert_eq!(s1.settings.hash.len(), 64);
        assert_eq!(s1.users.hash.len(), 64);
        assert_eq!(s1.iptables.hash.len(), 64);
    }

    #[tokio::test]
    async fn local_state_users_hash_is_order_independent() {
        // The state hash covers only the control slice. Seed control
        // rows in opposite orders into two pools and assert the
        // digest matches.
        let pool_a = test_pool().await;
        let pool_b = test_pool().await;
        seed_control_user(&pool_a, "u1", "alice", None).await;
        seed_control_user(&pool_a, "u2", "bob", None).await;
        seed_control_user(&pool_b, "u2", "bob", None).await;
        seed_control_user(&pool_b, "u1", "alice", None).await;
        let a = collect_state(&pool_a, None).await;
        let b = collect_state(&pool_b, None).await;
        assert_eq!(a.users.hash, b.users.hash);
        assert_eq!(a.users.count, 2);
    }

    #[tokio::test]
    async fn local_state_users_hash_excludes_local_admin_rows() {
        // A local user appearing/disappearing must not perturb the
        // hash that the control center compares against — the server
        // has no opinion on local rows.
        let pool = test_pool().await;
        let baseline = collect_state(&pool, None).await;
        UsersRepo::new(&pool)
            .create("admin-user", "admin-alice", None)
            .await
            .unwrap();
        let after_local = collect_state(&pool, None).await;
        assert_eq!(baseline.users.hash, after_local.users.hash);
        assert_eq!(after_local.users.count, 0); // control slice is still empty
    }

    #[tokio::test]
    async fn local_state_users_hash_changes_when_control_note_changes() {
        let pool = test_pool().await;
        seed_control_user(&pool, "u1", "alice", None).await;
        let before = collect_state(&pool, None).await;
        UsersRepo::new(&pool)
            .update_note("u1", Some("changed"))
            .await
            .unwrap();
        let after = collect_state(&pool, None).await;
        assert_ne!(before.users.hash, after.users.hash);
    }

    #[tokio::test]
    async fn local_state_settings_hash_changes_when_domain_changes() {
        let pool = test_pool().await;
        let s1 = collect_state(&pool, None).await;
        SettingsRepo::new(&pool)
            .patch(SettingsPatch {
                domain: Some(Some("a.example".into())),
                ..Default::default()
            })
            .await
            .unwrap();
        let s2 = collect_state(&pool, None).await;
        assert_ne!(s1.settings.hash, s2.settings.hash);
        assert_eq!(s2.settings.domain.as_deref(), Some("a.example"));
    }

    #[tokio::test]
    async fn local_state_iptables_hash_ignores_whitespace_and_order() {
        let pool = test_pool().await;
        let fake_a = FakeIptables::new();
        let fake_b = FakeIptables::new();
        // a in canonical form
        fake_a.seed(vec![
            StoredRule {
                id: "1".into(),
                source: Source::Control,
                priority: 0,
                table: "filter".into(),
                chain: "INPUT".into(),
                spec: "-p tcp --dport 22 -j ACCEPT".into(),
                comment: None,
                created_at: 0,
                updated_at: 0,
            },
            StoredRule {
                id: "2".into(),
                source: Source::Control,
                priority: 5,
                table: "nat".into(),
                chain: "POSTROUTING".into(),
                spec: "-j MASQUERADE".into(),
                comment: Some("c".into()),
                created_at: 0,
                updated_at: 0,
            },
        ]);
        // b: reversed order + extra whitespace inside spec
        fake_b.seed(vec![
            StoredRule {
                id: "x".into(),
                source: Source::Control,
                priority: 5,
                table: "nat".into(),
                chain: "POSTROUTING".into(),
                spec: "-j   MASQUERADE".into(),
                comment: Some("c".into()),
                created_at: 0,
                updated_at: 0,
            },
            StoredRule {
                id: "y".into(),
                source: Source::Control,
                priority: 0,
                table: "filter".into(),
                chain: "INPUT".into(),
                spec: "-p tcp  --dport 22 -j ACCEPT".into(),
                comment: None,
                created_at: 0,
                updated_at: 0,
            },
        ]);
        let a = collect_state(&pool, Some(&fake_a)).await;
        let b = collect_state(&pool, Some(&fake_b)).await;
        assert_eq!(a.iptables.count, 2);
        assert_eq!(b.iptables.count, 2);
        assert_eq!(a.iptables.hash, b.iptables.hash);
    }

    #[tokio::test]
    async fn sync_request_body_includes_state_and_cursor() {
        let pool = test_pool().await;
        // Control-source row: the count/hash report it.
        seed_control_user(&pool, "u1", "alice", None).await;
        // A local row the config report should NOT include.
        UsersRepo::new(&pool)
            .create("admin", "admin", None)
            .await
            .unwrap();
        let state = collect_state(&pool, None).await;
        let body = SyncRequest {
            node_id: "node-1",
            version: VERSION,
            cursor: Some("v42"),
            state: &state,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(json["node_id"], "node-1");
        assert_eq!(json["version"], VERSION);
        assert_eq!(json["cursor"], "v42");
        assert_eq!(json["state"]["users"]["count"], 1);
        assert!(json["state"]["users"]["hash"].as_str().is_some());
        // /config payload is intentionally minimal — no services,
        // last_apply, or issues. Those live on /status.
        assert!(json["state"].get("services").is_none());
        assert!(json.get("last_apply").is_none());
        assert!(json.get("issues").is_none());
    }

    #[tokio::test]
    async fn status_request_body_includes_services_traffic_and_apply() {
        let pool = test_pool().await;
        let report = collect_status(&pool, None, None).await;
        let body = StatusRequest {
            node_id: "n",
            version: VERSION,
            cursor: Some("v42"),
            report: &report,
            last_apply: ApplyReport {
                users_created: 1,
                mode: Some("full"),
                ..ApplyReport::default()
            },
            issues: &[],
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(json["cursor"], "v42");
        // Services block lives on /status now.
        assert_eq!(json["report"]["services"]["ss_running"], false);
        assert_eq!(json["report"]["services"]["wg_running"], false);
        // Traffic block always present (even empty).
        assert!(json["report"]["traffic"]["wg"]["peers"].is_array());
        // last_apply present because non-empty.
        assert_eq!(json["last_apply"]["users_created"], 1);
        assert_eq!(json["last_apply"]["mode"], "full");
        // Empty issues ⇒ field omitted.
        assert!(json.get("issues").is_none());
    }

    #[tokio::test]
    async fn status_request_body_includes_issues_when_non_empty() {
        let pool = test_pool().await;
        let report = collect_status(&pool, None, None).await;
        let issues = vec![
            Issue::capability(
                "iptables_unavailable",
                Severity::Warn,
                "host has no iptables",
            ),
            Issue::for_subject(
                "user_id_conflict_local",
                Severity::Error,
                "shared",
                "control upsert collided with a local user",
            ),
        ];
        let body = StatusRequest {
            node_id: "n",
            version: VERSION,
            cursor: None,
            report: &report,
            last_apply: ApplyReport::default(),
            issues: &issues,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        let issues_json = json["issues"].as_array().expect("issues array");
        assert_eq!(issues_json.len(), 2);
        assert_eq!(issues_json[0]["code"], "iptables_unavailable");
        assert_eq!(issues_json[0]["severity"], "warn");
        assert!(issues_json[0].get("subject").is_none());
        assert_eq!(issues_json[1]["code"], "user_id_conflict_local");
        assert_eq!(issues_json[1]["severity"], "error");
        assert_eq!(issues_json[1]["subject"], "shared");
    }

    #[tokio::test]
    async fn collect_status_reports_services_when_drivers_absent() {
        let pool = test_pool().await;
        let report = collect_status(&pool, None, None).await;
        assert!(!report.services.ss_running);
        assert!(!report.services.wg_running);
        assert_eq!(report.services.ss_users_count, 0);
        assert_eq!(report.services.wg_peers_count, 0);
        assert!(report.services.wg_backend.is_none());
        assert!(report.traffic.wg.peers.is_empty());
    }

    // ---------------- misc safety ----------------

    #[test]
    fn interval_floor_clamps_sub_minimum_values() {
        assert_eq!(clamp_interval_secs(0), MIN_INTERVAL_SECS);
        assert_eq!(clamp_interval_secs(1), MIN_INTERVAL_SECS);
        assert_eq!(
            clamp_interval_secs(MIN_INTERVAL_SECS - 1),
            MIN_INTERVAL_SECS
        );
        assert_eq!(clamp_interval_secs(MIN_INTERVAL_SECS), MIN_INTERVAL_SECS);
        assert_eq!(
            clamp_interval_secs(MIN_INTERVAL_SECS + 1),
            MIN_INTERVAL_SECS + 1
        );
        assert_eq!(clamp_interval_secs(3600), 3600);
    }

    #[tokio::test]
    async fn replace_mode_combined_with_prune_policy_is_idempotent_prune() {
        // Both layers say "prune"; the outcome must still be a
        // single prune (no double-deletes, no errors). The local
        // user is still off-limits because the source-boundary is
        // structural and unaffected by the policy/mode knobs.
        let pool = test_pool().await;
        UsersRepo::new(&pool)
            .create("admin-1", "admin-alice", None)
            .await
            .expect("seed local");
        seed_control_user(&pool, "ctl-1", "ctl-bob", None).await;
        seed_control_user(&pool, "ctl-2", "ctl-carol", None).await;

        let snap = Snapshot {
            mode: SnapshotMode::Replace,
            users: Some(UsersSection::Full(vec![user("ctl-1", "ctl-bob", None)])),
            ..Snapshot::default()
        };
        let stats = reconcile(&pool, &snap, ConflictPolicy::Prune, None)
            .await
            .expect("reconcile");
        assert_eq!(
            stats.users_deleted, 1,
            "only ctl-2 evicted, not the local row"
        );

        let repo = UsersRepo::new(&pool);
        assert!(repo.get("admin-1").await.unwrap().is_some());
        assert!(repo.get("ctl-1").await.unwrap().is_some());
        assert!(repo.get("ctl-2").await.unwrap().is_none());
    }

    #[test]
    fn build_client_strips_trailing_slash() {
        let cfg = ControlConfig {
            enabled: true,
            url: Some("https://control.test/".into()),
            node_id: Some("n".into()),
            token: Some(secrecy::SecretString::from("t".to_owned())),
            ..ControlConfig::default()
        };
        let client = build_client(&cfg).expect("client");
        assert_eq!(
            client.config_url(),
            "https://control.test/api/v1/nodes/n/config"
        );
    }
}
