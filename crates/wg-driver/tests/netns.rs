//! Linux network-namespace smoke test for the nsplane-backed driver.
//!
//! Runs only with `--features netns` on Linux AND when the calling process
//! has `CAP_NET_ADMIN`. The test is `#[ignore]`d by default and run in CI via
//! `cargo test --features netns -p nsp-wg-driver -- --ignored`.

#![cfg(all(feature = "netns", target_os = "linux"))]

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;

use ipnetwork::Ipv4Network;
use nsp_core::crypto::MasterKey;
use nsp_wg_driver::{BackendKind, PeerCreate, WgConfig, WgDriver};
use tempfile::TempDir;

fn has_cap_net_admin() -> bool {
    // Crude detection: either we're euid 0, or CAP_NET_ADMIN is visible in
    // the effective caps. Avoid panicking when `capsh` is absent.
    if nix_style_is_root() {
        return true;
    }
    Command::new("capsh")
        .arg("--has-p=cap_net_admin")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn nix_style_is_root() -> bool {
    // Avoid pulling `nix` as a dep; `id -u` is always present on Linux.
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

async fn build_driver(port: u16, subnet: &str) -> (WgDriver, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("t.db");
    let pool = nsp_db::open(&db_path).await.expect("open db");
    let master_key = Arc::new(MasterKey::generate());
    let subnet: Ipv4Network = subnet.parse().expect("parse subnet");
    let cfg = WgConfig {
        interface: format!("wgtest{}", port),
        listen_port: port,
        subnet: Some(subnet),
        endpoint_host: Some("127.0.0.1".into()),
        wan_interface: None,
        backend: BackendKind::Userspace,
        netstack: Default::default(),
    };
    (WgDriver::new(cfg, pool, master_key), dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn spawn_real_and_add_peer() {
    if !has_cap_net_admin() {
        eprintln!("skipping netns test: missing CAP_NET_ADMIN");
        return;
    }

    let (driver, _guard) = build_driver(51830, "10.77.77.0/24").await;
    driver
        .spawn_real()
        .await
        .expect("bring up nsplane engine on TUN");

    let req = PeerCreate {
        public_key: None,
        name: Some("ci-smoke".into()),
        ip: None,
        endpoint: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 61000))),
        keepalive: Some(25),
        preshared: false,
    };
    let (view, _secrets) = driver.add_peer(req).await.expect("add peer");
    assert_eq!(view.allowed_ip.octets()[0..3], [10, 77, 77]);

    let peers = driver.list_peers().await.expect("list");
    assert_eq!(peers.len(), 1);

    driver.remove_peer(&view.id).await.expect("remove");
    assert!(driver.list_peers().await.expect("list").is_empty());
}
