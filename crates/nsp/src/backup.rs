//! Hourly SQLite online backup.
//!
//! We issue `VACUUM INTO` against a fresh output path under
//! `backup.dir`. `VACUUM INTO` runs at the same snapshot the pool sees, so
//! it is safe to run concurrently with writes. Old snapshots are pruned to
//! [`BackupConfig::retention_days`].

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{Datelike, Timelike, Utc};
use nsp_core::config::BackupConfig;
use nsp_db::Pool;
use sqlx::Executor;
use tokio::task::JoinHandle;

/// Filename produced by [`snapshot_name`].
pub(crate) const NAME_PREFIX: &str = "nsp-";
pub(crate) const NAME_SUFFIX: &str = ".sqlite";

/// Spawn the backup scheduler. Returns the `JoinHandle`; callers keep it alive
/// for the process lifetime (dropping aborts the task).
pub fn spawn(pool: Pool, cfg: BackupConfig) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = tokio::fs::create_dir_all(&cfg.dir).await {
            tracing::warn!(dir = %cfg.dir.display(), %err, "backup: dir create failed");
        }
        let interval = Duration::from_secs(cfg.interval_secs.max(60));
        loop {
            if let Err(err) = run_one(&pool, &cfg).await {
                tracing::warn!(%err, "backup: snapshot failed");
            }
            if let Err(err) = prune(&cfg).await {
                tracing::debug!(%err, "backup: prune failed");
            }
            tokio::time::sleep(interval).await;
        }
    })
}

async fn run_one(pool: &Pool, cfg: &BackupConfig) -> Result<PathBuf> {
    let name = snapshot_name(Utc::now());
    let path = cfg.dir.join(&name);
    vacuum_into(pool, &path).await?;
    tracing::info!(file = %path.display(), "backup: snapshot ok");
    Ok(path)
}

/// Execute a `VACUUM INTO` against `out`. The path must not already exist;
/// SQLite refuses to overwrite.
pub async fn vacuum_into(pool: &Pool, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create backup parent dir {}", parent.display()))?;
    }
    if tokio::fs::try_exists(out).await.unwrap_or(false) {
        tokio::fs::remove_file(out)
            .await
            .with_context(|| format!("remove stale backup {}", out.display()))?;
    }

    let path_str = out
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-utf8 backup path {:?}", out))?;
    // SQLite has no bind-param support for VACUUM INTO. The path comes from
    // operator-controlled config and is escaped with single-quote doubling
    // per SQLite literal rules.
    let escaped = path_str.replace('\'', "''");
    let sql = format!("VACUUM INTO '{escaped}'");
    pool.execute(sqlx::query(&sql))
        .await
        .with_context(|| format!("vacuum into {}", out.display()))?;
    Ok(())
}

/// Delete files older than `cfg.retention_days` inside `cfg.dir`.
async fn prune(cfg: &BackupConfig) -> Result<()> {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(Duration::from_secs(u64::from(cfg.retention_days) * 86_400))
        .ok_or_else(|| anyhow::anyhow!("retention clamped"))?;

    let mut entries = tokio::fs::read_dir(&cfg.dir)
        .await
        .with_context(|| format!("read backup dir {}", cfg.dir.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with(NAME_PREFIX) || !name_str.ends_with(NAME_SUFFIX) {
            continue;
        }
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        if mtime < cutoff {
            let path = entry.path();
            if let Err(err) = tokio::fs::remove_file(&path).await {
                tracing::debug!(file = %path.display(), %err, "backup: prune remove failed");
            } else {
                tracing::info!(file = %path.display(), "backup: pruned");
            }
        }
    }
    Ok(())
}

/// Format: `nsp-YYYYMMDD-HH.sqlite` (local UTC). Hourly cadence means
/// the hour component is sufficient to avoid collisions within one run.
#[must_use]
pub fn snapshot_name(ts: chrono::DateTime<Utc>) -> String {
    format!(
        "{NAME_PREFIX}{:04}{:02}{:02}-{:02}{NAME_SUFFIX}",
        ts.year(),
        ts.month(),
        ts.day(),
        ts.hour()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn name_formats_iso_compact() {
        let t = Utc.with_ymd_and_hms(2026, 4, 20, 7, 0, 0).unwrap();
        assert_eq!(snapshot_name(t), "nsp-20260420-07.sqlite");
    }

    #[tokio::test]
    async fn vacuum_into_writes_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.db");
        let pool = nsp_db::open(&src).await.expect("open src");

        let out = dir.path().join("snap.sqlite");
        vacuum_into(&pool, &out).await.expect("vacuum into");
        assert!(out.exists(), "snapshot file created");
        assert!(
            out.metadata().unwrap().len() > 0,
            "snapshot file is non-empty"
        );
    }

    #[tokio::test]
    async fn prune_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = BackupConfig {
            enabled: true,
            interval_secs: 3600,
            dir: dir.path().to_path_buf(),
            retention_days: 7,
        };

        let old = dir.path().join("nsp-20200101-00.sqlite");
        tokio::fs::write(&old, b"stale").await.unwrap();
        // Backdate mtime so retention sees it as old (30 days ago).
        let past = std::time::SystemTime::now() - Duration::from_hours(24 * 30);
        filetime::set_file_mtime(&old, filetime::FileTime::from_system_time(past)).unwrap();

        let recent = dir.path().join("nsp-99999999-00.sqlite");
        tokio::fs::write(&recent, b"fresh").await.unwrap();

        let unrelated = dir.path().join("notes.txt");
        tokio::fs::write(&unrelated, b"keep me").await.unwrap();

        prune(&cfg).await.unwrap();
        assert!(!old.exists(), "old snapshot removed");
        assert!(recent.exists(), "recent snapshot preserved");
        assert!(unrelated.exists(), "unrelated file preserved");
    }
}
