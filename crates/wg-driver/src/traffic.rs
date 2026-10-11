//! Per-peer traffic sampler.
//!
//! The data plane only exposes counters that are cumulative since the
//! interface came up. To survive interface restarts and to power the
//! `/api/users/:id/wg/traffic` view, the driver folds those counters
//! into a SQLite-backed running total plus an hour-bucketed time
//! series.
//!
//! Wiring lives in [`WgDriver::spawn_real`]: a tokio task started
//! after a successful bring-up polls every [`SAMPLE_INTERVAL`] and
//! delegates to [`WgDriver::sample_traffic_now`]. The task is
//! cancelled in [`WgDriver::stop`]. All persistence and delta
//! computation happen inside [`nsp_db::WgTrafficRepo`]; the sampler
//! is intentionally a thin loop over `list_peer_stats()`.

use std::sync::Arc;
use std::time::Duration;

use nsp_db::{Pool, WgRepo, WgTrafficRepo};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backend::WgBackend;
use crate::error::Result;

/// How often the sampler folds backend counters into the DB.
pub const SAMPLE_INTERVAL: Duration = Duration::from_mins(1);

/// Take one sample: fetch live stats from the backend, look up each
/// public key in the persisted `wg_peers` rows, and record the deltas
/// in the traffic tables.
///
/// Returns the number of peers whose counters were folded in. Errors
/// from individual peer records are logged and skipped so a single
/// bad row never aborts the rest of the sweep.
pub(crate) async fn sample_once(db: &Pool, backend: &dyn WgBackend) -> Result<usize> {
    let stats = backend.list_peer_stats().await?;
    if stats.is_empty() {
        return Ok(0);
    }
    let rows = WgRepo::new(db).list().await?;
    let mut by_pubkey: std::collections::HashMap<[u8; 32], String> =
        rows.into_iter().map(|r| (r.public_key, r.id)).collect();
    let now = chrono::Utc::now().timestamp();
    let repo = WgTrafficRepo::new(db);
    let mut recorded = 0usize;
    for s in stats {
        let Some(peer_id) = by_pubkey.remove(&s.public_key) else {
            // Live peer without a persisted row — usually means a
            // sync race. The reconciler will catch this on the next
            // pass; nothing to record here.
            continue;
        };
        let last_handshake_at = s.last_handshake.and_then(|d| {
            // Snap to wall-clock seconds so the value lines up with
            // other timestamps in the schema.
            let secs = i64::try_from(d.as_secs()).ok()?;
            Some(now.saturating_sub(secs))
        });
        match repo
            .record(&peer_id, s.rx_bytes, s.tx_bytes, last_handshake_at, now)
            .await
        {
            Ok(outcome) => {
                if outcome.counter_reset {
                    tracing::debug!(
                        target: "nsp::wg::traffic",
                        %peer_id,
                        "counter reset detected (interface rebuilt); restarting from raw value"
                    );
                }
                recorded += 1;
            }
            Err(err) => {
                tracing::warn!(
                    target: "nsp::wg::traffic",
                    %peer_id,
                    %err,
                    "record traffic sample failed"
                );
            }
        }
    }
    Ok(recorded)
}

/// Spawn the periodic sampler. The returned token, when cancelled,
/// stops the loop on its next tick boundary; the join handle resolves
/// shortly after.
pub(crate) fn spawn_loop(
    db: Pool,
    backend: Arc<dyn WgBackend>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Fire one immediate sample so the DB shows progress before
        // the first interval elapses.
        if let Err(err) = sample_once(&db, backend.as_ref()).await {
            tracing::debug!(target: "nsp::wg::traffic", %err, "initial sample failed");
        }
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; consume it so the next
        // real sample is one interval away.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    if let Err(err) = sample_once(&db, backend.as_ref()).await {
                        tracing::debug!(target: "nsp::wg::traffic", %err, "sample failed");
                    }
                }
            }
        }
    })
}
