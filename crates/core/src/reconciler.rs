//! Background reconciler that converges protocol drivers toward the
//! DB-desired state.
//!
//! The API layer updates the database atomically and then calls
//! [`ReconcilerHandle::notify`]. A single long-lived task wakes on
//! notify, on a periodic tick, or on driver start-complete; after a
//! short debounce it asks every registered [`ReconcileTarget`] to
//! `sync_from_db`. When a driver is stopped, sync is still attempted
//! but the target is expected to return cheaply — the desired state
//! stays persisted and the next start-up triggers a full resync.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::select;
use tokio::sync::Notify;
use tokio::time::{interval, sleep, MissedTickBehavior};

/// A single protocol driver capable of walking its in-memory state
/// toward the DB-desired set. Implementations must be idempotent: the
/// reconciler may invoke `sync_from_db` repeatedly with nothing to do.
#[async_trait]
pub trait ReconcileTarget: Send + Sync + 'static {
    /// Short identifier used for logs and metrics.
    fn name(&self) -> &'static str;

    /// Compute the diff between DB and driver state and apply it.
    async fn sync_from_db(&self) -> std::result::Result<(), String>;
}

/// Runtime knobs for the reconciler loop. Defaults: 30 s tick, 500 ms debounce.
#[derive(Debug, Clone, Copy)]
pub struct ReconcilerConfig {
    pub tick_interval: Duration,
    pub debounce: Duration,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(30),
            debounce: Duration::from_millis(500),
        }
    }
}

/// Handle returned by [`spawn`]. Clone and share across the app.
#[derive(Clone)]
pub struct ReconcilerHandle {
    notify: Arc<Notify>,
}

impl ReconcilerHandle {
    /// Return the raw [`Notify`] so driver crates can wake the loop
    /// on start-complete without depending on this module's surface.
    pub fn notify_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    /// Wake the reconciler once. Safe to call from sync or async
    /// context, idempotent under burst.
    pub fn notify(&self) {
        self.notify.notify_one();
    }
}

/// Spawn the long-lived reconcile task. Returns immediately with a
/// handle that can be cloned into the API layer.
pub fn spawn(targets: Vec<Arc<dyn ReconcileTarget>>, config: ReconcilerConfig) -> ReconcilerHandle {
    let notify = Arc::new(Notify::new());
    let handle = ReconcilerHandle {
        notify: Arc::clone(&notify),
    };
    tokio::spawn(run_loop(targets, config, notify));
    handle
}

async fn run_loop(
    targets: Vec<Arc<dyn ReconcileTarget>>,
    config: ReconcilerConfig,
    notify: Arc<Notify>,
) {
    let mut tick = interval(config.tick_interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Skip the first immediate tick — we want the first sync to come
    // from an explicit notify (driver start-complete or API write).
    tick.tick().await;

    loop {
        select! {
            _ = notify.notified() => {
                if !config.debounce.is_zero() {
                    sleep(config.debounce).await;
                }
            }
            _ = tick.tick() => {}
        }

        for target in &targets {
            match target.sync_from_db().await {
                Ok(()) => {
                    tracing::debug!(target = target.name(), "reconcile applied");
                }
                Err(err) => {
                    tracing::warn!(target = target.name(), error = %err, "reconcile failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;

    struct CountingTarget {
        name: &'static str,
        count: AtomicUsize,
        fail_until: AtomicUsize,
        delay: Mutex<Duration>,
    }

    impl CountingTarget {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                count: AtomicUsize::new(0),
                fail_until: AtomicUsize::new(0),
                delay: Mutex::new(Duration::ZERO),
            })
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl ReconcileTarget for CountingTarget {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn sync_from_db(&self) -> std::result::Result<(), String> {
            let d = { *self.delay.lock().await };
            if !d.is_zero() {
                sleep(d).await;
            }
            let n = self.count.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= self.fail_until.load(Ordering::Relaxed) {
                return Err(format!("fail {n}"));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn notify_triggers_sync_after_debounce() {
        let tgt = CountingTarget::new("t");
        let handle = spawn(
            vec![tgt.clone() as Arc<dyn ReconcileTarget>],
            ReconcilerConfig {
                tick_interval: Duration::from_mins(1),
                debounce: Duration::from_millis(10),
            },
        );
        handle.notify();
        sleep(Duration::from_millis(100)).await;
        assert_eq!(tgt.count(), 1);
    }

    #[tokio::test]
    async fn multiple_notifies_coalesce() {
        let tgt = CountingTarget::new("t");
        let handle = spawn(
            vec![tgt.clone() as Arc<dyn ReconcileTarget>],
            ReconcilerConfig {
                tick_interval: Duration::from_mins(1),
                debounce: Duration::from_millis(50),
            },
        );
        for _ in 0..5 {
            handle.notify();
        }
        sleep(Duration::from_millis(150)).await;
        let first = tgt.count();
        assert!((1..=2).contains(&first), "first count {first}");
    }

    #[tokio::test]
    async fn failures_are_logged_and_loop_continues() {
        let tgt = CountingTarget::new("t");
        tgt.fail_until.store(2, Ordering::Relaxed);
        let handle = spawn(
            vec![tgt.clone() as Arc<dyn ReconcileTarget>],
            ReconcilerConfig {
                tick_interval: Duration::from_mins(1),
                debounce: Duration::from_millis(5),
            },
        );
        for _ in 0..5 {
            handle.notify();
            sleep(Duration::from_millis(30)).await;
        }
        assert!(tgt.count() >= 3, "count {}", tgt.count());
    }

    #[tokio::test]
    async fn periodic_tick_fires_without_notify() {
        let tgt = CountingTarget::new("t");
        let _handle = spawn(
            vec![tgt.clone() as Arc<dyn ReconcileTarget>],
            ReconcilerConfig {
                tick_interval: Duration::from_millis(50),
                debounce: Duration::from_millis(5),
            },
        );
        sleep(Duration::from_millis(180)).await;
        assert!(tgt.count() >= 2, "count {}", tgt.count());
    }
}
