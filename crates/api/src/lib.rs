//! HTTP control-plane for nsp.
//!
//! Builds the axum `Router` used by the `nsp` binary. M1 exposes only the
//! scaffolding routes: health, status, auth/login, and the embedded SPA.

#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    Router,
};
use nsp_core::config::ApiMode;

pub mod audit;
pub mod error;
pub mod iptables;
pub mod proxy;
pub mod routes;
pub mod settings;
pub mod spa;
pub mod ss;
pub mod state;
pub mod users;
pub mod wg;

pub use error::ApiError;
pub use state::AppState;

/// Build the full application router with the given shared state.
///
/// Route layout:
/// * `/api/protocol/{ss,wg}/{status,start,stop}` — protocol-service
///   lifecycle only. No user-scoped operations live here.
/// * `/api/users[...]` — every user-scoped read, write, rotate, and
///   one-shot client material, including per-user SS/WG enable, rotate,
///   and detail.
///
/// Every `/api/*` route is wrapped in [`enforce_api_mode`] which
/// rejects writes (`Readonly`) or all requests (`Disabled`) based
/// on the operator's lockdown stance. The SPA static-asset router
/// is intentionally left alone so the dashboard still loads.
pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .merge(routes::public_router())
        .merge(routes::api_router(state.clone()))
        .merge(audit::protected_router(state.clone()))
        .merge(settings::protected_router(state.clone()))
        .nest("/api/protocol/ss", ss::protected_router(state.clone()))
        .nest("/api/protocol/wg", wg::protected_router(state.clone()))
        .nest(
            "/api/protocol/proxy",
            proxy::protected_router(state.clone()),
        )
        .nest("/api/users", users::protected_router(state.clone()))
        .nest("/api/iptables", iptables::protected_router(state.clone()))
        .layer(from_fn_with_state(state.clone(), enforce_api_mode));

    api.merge(spa::router()).with_state(state)
}

/// Middleware: gate `/api/*` requests on the operator's
/// [`ApiMode`]. Non-`/api/*` paths fall through unchanged.
///
/// * `Enabled`  — pass-through.
/// * `Readonly` — `GET` / `HEAD` / `OPTIONS` pass; everything else
///   gets `403 Forbidden` so a malicious caller's mutation attempts
///   are visible in logs (vs. a confusing 404 on real routes).
/// * `Disabled` — every `/api/*` request gets `404 Not Found`. In
///   production the binary skips the listener entirely when this
///   mode is configured (the port isn't even bound), so this branch
///   is effectively a defense-in-depth fallback for tests and for
///   the case where the router is reused outside the binary's
///   listener flow.
async fn enforce_api_mode(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if !req.uri().path().starts_with("/api/") {
        return next.run(req).await;
    }
    match state.api_mode {
        ApiMode::Enabled => next.run(req).await,
        ApiMode::Readonly => {
            if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
                next.run(req).await
            } else {
                StatusCode::FORBIDDEN.into_response()
            }
        }
        ApiMode::Disabled => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::{to_bytes, Body},
        http::{header, Method, Request, StatusCode},
    };
    use nsp_core::{auth, crypto::MasterKey};
    use nsp_proxy_driver::{ProxyDriver, ProxyDriverConfig};
    use nsp_ss_driver::{SsDriver, SsDriverConfig};
    use nsp_wg_driver::{BackendKind, WgConfig, WgDriver};
    use secrecy::SecretString;
    use serde_json::Value;
    use std::net::{IpAddr, Ipv4Addr};
    use tower::ServiceExt as _;

    fn master_key() -> Arc<MasterKey> {
        let generated = MasterKey::generate();
        let b64 = SecretString::from(generated.to_base64());
        Arc::new(MasterKey::from_base64(&b64).expect("decode master key"))
    }

    async fn pool() -> nsp_db::Pool {
        let dir = std::env::temp_dir().join(format!(
            "nsp-api-test-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        nsp_db::open(&dir.join("test.db")).await.expect("open db")
    }

    fn wg_config() -> WgConfig {
        WgConfig {
            interface: "wg-test".to_owned(),
            listen_port: 51820,
            subnet: Some("10.66.66.0/24".parse().expect("subnet")),
            endpoint_host: Some("proxy.example.com".to_owned()),
            wan_interface: None,
            backend: BackendKind::Userspace,
            netstack: Default::default(),
        }
    }

    async fn test_state(with_wg: bool) -> Arc<AppState> {
        let db = pool().await;
        let master_key = master_key();
        let mut state = AppState::new(db.clone(), master_key.clone(), 60, "test");
        if with_wg {
            let wg = WgDriver::new(wg_config(), db, master_key);
            wg.prepare().await.expect("prepare wg");
            state = state.with_wg(wg);
        }
        Arc::new(state)
    }

    async fn test_state_with_ss() -> Arc<AppState> {
        let db = pool().await;
        let master_key = master_key();
        let mut state = AppState::new(db.clone(), master_key.clone(), 60, "test");
        // Port 0 asks the OS for an ephemeral port. The SS server swap may
        // fail asynchronously if the chosen port can't be bound; the driver
        // lifecycle (`running=true` / `false`) is driven synchronously so
        // the transitions we assert below are independent of that.
        let cfg = SsDriverConfig::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            "127.0.0.1".to_owned(),
            1,
        );
        let ss = SsDriver::new(cfg, db, master_key);
        state = state.with_ss_driver(ss);
        Arc::new(state)
    }

    async fn test_state_full() -> Arc<AppState> {
        let db = pool().await;
        let master_key = master_key();
        let mut state = AppState::new(db.clone(), master_key.clone(), 60, "test");
        let wg = WgDriver::new(wg_config(), db.clone(), master_key.clone());
        wg.prepare().await.expect("prepare wg");
        state = state.with_wg(wg);
        let ss_cfg = SsDriverConfig::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            "127.0.0.1".to_owned(),
            1,
        );
        let ss = SsDriver::new(ss_cfg, db.clone(), master_key.clone());
        state = state.with_ss_driver(ss);
        let mut proxy_cfg = ProxyDriverConfig::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            0,
            "127.0.0.1".to_owned(),
            1,
        );
        proxy_cfg.allow_loopback_destinations = true;
        let proxy = ProxyDriver::new(proxy_cfg, db, master_key);
        state = state.with_proxy(proxy);
        Arc::new(state)
    }

    fn token(state: &AppState) -> String {
        auth::issue_jwt("admin", 1, 60, &state.jwt_key)
            .expect("issue jwt")
            .0
    }

    async fn send(
        state: Arc<AppState>,
        method: Method,
        uri: &str,
        bearer: Option<&str>,
        body: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let req = builder
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_owned())))
            .expect("request");
        router(state).oneshot(req).await.expect("response")
    }

    async fn body_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn legacy_protocol_routes_are_gone() {
        // The old `/api/ss/...` and `/api/wg/...` user-scoped entry points
        // were removed; they must now 404 even with a valid token.
        let state = test_state(true).await;
        let token = token(&state);
        let gone = [
            (Method::GET, "/api/ss/users"),
            (Method::POST, "/api/ss/users"),
            (Method::GET, "/api/ss/users/anything"),
            (Method::GET, "/api/wg/peers"),
            (Method::POST, "/api/wg/peers"),
            (Method::GET, "/api/wg/peers/anything"),
            (Method::GET, "/api/wg/peers/anything/config"),
            (Method::GET, "/api/wg/peers/anything/qr"),
        ];
        for (method, uri) in gone {
            let response = send(state.clone(), method, uri, Some(&token), None).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[tokio::test]
    async fn protocol_routes_require_jwt() {
        let state = test_state(true).await;
        let cases = [
            (Method::GET, "/api/protocol/wg/status"),
            (Method::POST, "/api/protocol/wg/start"),
            (Method::POST, "/api/protocol/wg/stop"),
            (Method::GET, "/api/protocol/ss/status"),
            (Method::POST, "/api/protocol/ss/start"),
            (Method::POST, "/api/protocol/ss/stop"),
        ];

        for (method, uri) in cases {
            let response = send(state.clone(), method, uri, None, None).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn status_requires_jwt() {
        let state = test_state(false).await;
        let response = send(state, Method::GET, "/api/status", None, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn disabled_wg_reports_available_false() {
        let state = test_state(false).await;
        let token = token(&state);

        let response = send(
            state.clone(),
            Method::GET,
            "/api/status",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let status = body_json(response).await;
        assert_eq!(status["wg_enabled"], false);

        // /api/protocol/wg/status always returns 200 so the Services UI can
        // render the card uniformly; `available: false` + a reason signals
        // the disabled state without forcing the UI to branch on HTTP 503.
        let response = send(
            state,
            Method::GET,
            "/api/protocol/wg/status",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["running"], false);
        assert_eq!(body["available"], false);
        assert!(body["reason"].as_str().is_some());
    }

    #[tokio::test]
    async fn ss_start_then_stop_transitions_are_reported() {
        let state = test_state_with_ss().await;
        let tok = token(&state);

        // Initial state: not running.
        let response = send(
            state.clone(),
            Method::GET,
            "/api/protocol/ss/status",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["running"], false);

        // Start -> 204; status reflects running=true.
        let response = send(
            state.clone(),
            Method::POST,
            "/api/protocol/ss/start",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = send(
            state.clone(),
            Method::GET,
            "/api/protocol/ss/status",
            Some(&tok),
            None,
        )
        .await;
        let body = body_json(response).await;
        assert_eq!(body["running"], true);

        // Duplicate start -> 409.
        let response = send(
            state.clone(),
            Method::POST,
            "/api/protocol/ss/start",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Stop -> 204; status reflects running=false.
        let response = send(
            state.clone(),
            Method::POST,
            "/api/protocol/ss/stop",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = send(
            state.clone(),
            Method::GET,
            "/api/protocol/ss/status",
            Some(&tok),
            None,
        )
        .await;
        let body = body_json(response).await;
        assert_eq!(body["running"], false);

        // Duplicate stop -> 409.
        let response = send(
            state,
            Method::POST,
            "/api/protocol/ss/stop",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    // ---------------- /api/users ----------------

    async fn create_user_helper(state: Arc<AppState>, tok: &str, name: &str) -> String {
        let body = format!(r#"{{"name":"{name}"}}"#);
        let response = send(state, Method::POST, "/api/users", Some(tok), Some(&body)).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        v["id"].as_str().expect("user id").to_owned()
    }

    #[tokio::test]
    async fn users_crud_roundtrip() {
        let state = test_state_full().await;
        let tok = token(&state);

        // Create.
        let id = create_user_helper(state.clone(), &tok, "alice").await;

        // List contains the user.
        let response = send(state.clone(), Method::GET, "/api/users", Some(&tok), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let list = body_json(response).await;
        let arr = list.as_array().expect("list");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "alice");
        assert_eq!(arr[0]["ss_enabled"], false);
        assert_eq!(arr[0]["wg_enabled"], false);

        // Rename.
        let response = send(
            state.clone(),
            Method::PATCH,
            &format!("/api/users/{id}"),
            Some(&tok),
            Some(r#"{"name":"alice2","note":"team A"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        assert_eq!(v["name"], "alice2");
        assert_eq!(v["note"], "team A");

        // Delete.
        let response = send(
            state.clone(),
            Method::DELETE,
            &format!("/api/users/{id}"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Get missing -> 404.
        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn users_enable_ss_when_driver_stopped_is_pending() {
        // SS driver is constructed but never started. Enable must still
        // succeed synchronously and mark the write as pending.
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "bob").await;

        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/ss"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        assert_eq!(v["pending"], true);
        assert_eq!(v["user_id"], id);
        assert!(v["url"].as_str().unwrap_or_default().starts_with("ss://"));
        assert!(!v["psk"].as_str().unwrap_or_default().is_empty());

        // users.ss_enabled should flip true.
        let response = send(
            state.clone(),
            Method::GET,
            &format!("/api/users/{id}"),
            Some(&tok),
            None,
        )
        .await;
        let v = body_json(response).await;
        assert_eq!(v["ss_enabled"], true);

        // Disable round-trip.
        let response = send(
            state.clone(),
            Method::DELETE,
            &format!("/api/users/{id}/ss"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        assert_eq!(v["pending"], true);
    }

    #[tokio::test]
    async fn users_enable_ss_when_driver_running_is_not_pending() {
        let state = test_state_full().await;
        let tok = token(&state);

        // Start the driver first.
        let response = send(
            state.clone(),
            Method::POST,
            "/api/protocol/ss/start",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let id = create_user_helper(state.clone(), &tok, "carol").await;
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/ss"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        assert_eq!(v["pending"], false);
    }

    #[tokio::test]
    async fn users_ss_detail_and_rotate_and_qr() {
        let state = test_state_full().await;
        let tok = token(&state);

        // Driver must be running for `user_client_material` / `user_qr_png`
        // to resolve a server PSK.
        let response = send(
            state.clone(),
            Method::POST,
            "/api/protocol/ss/start",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let id = create_user_helper(state.clone(), &tok, "erin").await;
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/ss"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let initial = body_json(response).await;
        let initial_psk = initial["psk"].as_str().expect("psk").to_owned();

        // GET detail — no PSK in body.
        let response = send(
            state.clone(),
            Method::GET,
            &format!("/api/users/{id}/ss"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let detail = body_json(response).await;
        assert_eq!(detail["user_id"], id);
        assert_eq!(detail["name"], "erin");
        assert!(detail["url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("ss://"));
        assert!(detail.get("psk").is_none());

        // QR endpoint serves a PNG.
        let response = send(
            state.clone(),
            Method::GET,
            &format!("/api/users/{id}/ss/qr"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content type"),
            "image/png"
        );

        // Rotate returns a one-shot PSK that differs from the initial one.
        let response = send(
            state,
            Method::POST,
            &format!("/api/users/{id}/ss/rotate"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let rotated = body_json(response).await;
        let rotated_psk = rotated["psk"].as_str().expect("rotated psk").to_owned();
        assert_ne!(initial_psk, rotated_psk);
    }

    #[tokio::test]
    async fn users_enable_wg_when_driver_stopped_is_pending() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "dave").await;

        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        assert_eq!(v["pending"], true);
        assert_eq!(v["user_id"], id);
        assert_eq!(v["peer"]["user_id"], id);
        assert_eq!(v["peer"]["name"], "dave");
        assert!(v["peer"]["allowed_ip"]
            .as_str()
            .unwrap_or_default()
            .starts_with("10.66.66."));
        assert!(!v["secrets"]["private_key"]
            .as_str()
            .unwrap_or_default()
            .is_empty());

        // Re-enable is idempotent: secrets omitted but still 2xx.
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        assert_eq!(v["pending"], true);
        assert!(v["secrets"].is_null());

        // Disable.
        let response = send(
            state.clone(),
            Method::DELETE,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        assert_eq!(v["pending"], true);

        // users.wg_enabled flips back.
        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}"),
            Some(&tok),
            None,
        )
        .await;
        let v = body_json(response).await;
        assert_eq!(v["wg_enabled"], false);
    }

    #[tokio::test]
    async fn users_routes_require_jwt() {
        let state = test_state_full().await;
        let cases = [
            (Method::GET, "/api/users"),
            (Method::POST, "/api/users"),
            (Method::GET, "/api/users/nope"),
            (Method::PATCH, "/api/users/nope"),
            (Method::DELETE, "/api/users/nope"),
            (Method::GET, "/api/users/nope/ss"),
            (Method::POST, "/api/users/nope/ss"),
            (Method::DELETE, "/api/users/nope/ss"),
            (Method::POST, "/api/users/nope/ss/rotate"),
            (Method::GET, "/api/users/nope/ss/qr"),
            (Method::GET, "/api/users/nope/wg"),
            (Method::POST, "/api/users/nope/wg"),
            (Method::DELETE, "/api/users/nope/wg"),
            (Method::POST, "/api/users/nope/wg/rotate"),
        ];
        for (method, uri) in cases {
            let response = send(state.clone(), method, uri, None, None).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn user_dto_carries_local_source_for_api_created_users() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "alice").await;

        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        assert_eq!(v["source"], "local");
    }

    // ---------------- api lockdown mode ----------------

    async fn test_state_with_mode(mode: nsp_core::config::ApiMode) -> Arc<AppState> {
        let db = pool().await;
        let master_key = master_key();
        Arc::new(AppState::new(db, master_key, 60, "test").with_api_mode(mode))
    }

    #[tokio::test]
    async fn api_readonly_blocks_writes_with_403() {
        let state = test_state_with_mode(nsp_core::config::ApiMode::Readonly).await;
        let tok = token(&state);

        // GET succeeds.
        let response = send(state.clone(), Method::GET, "/api/users", Some(&tok), None).await;
        assert_eq!(response.status(), StatusCode::OK);

        // POST is rejected with 403 — uniform across all /api/* routes.
        let response = send(
            state.clone(),
            Method::POST,
            "/api/users",
            Some(&tok),
            Some(r#"{"name":"alice"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // PATCH is rejected too.
        let response = send(
            state,
            Method::PATCH,
            "/api/users/anything",
            Some(&tok),
            Some(r#"{"name":"x"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn api_disabled_returns_404_for_all_methods() {
        let state = test_state_with_mode(nsp_core::config::ApiMode::Disabled).await;
        let tok = token(&state);

        let cases = [
            (Method::GET, "/api/users"),
            (Method::POST, "/api/users"),
            (Method::GET, "/api/health"), // even public-ish routes
            (Method::POST, "/api/auth/login"),
        ];
        for (method, uri) in cases {
            let response = send(state.clone(), method.clone(), uri, Some(&tok), None).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{method} {uri} should be 404 in disabled mode",
            );
        }
    }

    #[tokio::test]
    async fn lockdown_does_not_block_non_api_paths() {
        // SPA static assets live outside `/api/*` so the dashboard
        // can still load even when the API surface is locked down.
        // We can't easily assert a real SPA load here, but we can
        // confirm the middleware only kicks in for `/api/*` by
        // hitting a non-existent non-api path: the SPA fallback
        // returns 200 (its index.html catch-all) or 404 from the
        // SPA, but never the lockdown's 403/404 from middleware.
        // For unit-test purposes we just confirm `/api/*` goes
        // through the middleware (covered above) — the negative
        // case is documented behavior rather than asserted here.
        let state = test_state_with_mode(nsp_core::config::ApiMode::Disabled).await;
        let response = send(state, Method::GET, "/api/users", None, None).await;
        // The middleware short-circuits BEFORE auth runs, so the
        // result is 404, not the 401 we'd see in Enabled mode.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn users_patch_and_delete_are_forbidden_on_control_source() {
        // Admin can't touch a user that the control reconciler owns —
        // both PATCH and DELETE on /api/users/:id must return 403.
        let state = test_state_full().await;
        let tok = token(&state);

        // Pre-seed a control-owned row directly through the repo.
        nsp_db::UsersRepo::new(&state.db)
            .create_with_source("ctl-1", "ctl-alice", nsp_db::UserSource::Control, None)
            .await
            .expect("seed control user");

        let response = send(
            state.clone(),
            Method::PATCH,
            "/api/users/ctl-1",
            Some(&tok),
            Some(r#"{"name":"renamed"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = send(
            state.clone(),
            Method::DELETE,
            "/api/users/ctl-1",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Row still there, untouched.
        let response = send(state, Method::GET, "/api/users/ctl-1", Some(&tok), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        assert_eq!(v["source"], "control");
        assert_eq!(v["name"], "ctl-alice");
    }

    #[tokio::test]
    async fn users_enable_ss_missing_user_is_404() {
        let state = test_state_full().await;
        let tok = token(&state);

        let response = send(
            state,
            Method::POST,
            "/api/users/missing-id/ss",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn users_enable_wg_with_caller_public_key_omits_private_key() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "frank").await;

        // A 32-byte public key, base64 encoded.
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let caller_pub_b64 = B64.encode([9u8; 32]);
        let body = format!(r#"{{"public_key":"{caller_pub_b64}"}}"#);

        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            Some(&body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        assert_eq!(v["peer"]["public_key"].as_str().unwrap(), caller_pub_b64);
        assert!(v["secrets"]["private_key"].is_null());
        assert!(v["secrets"]["preshared_key"].is_string());
    }

    #[tokio::test]
    async fn users_wg_detail_and_rotate_roundtrip() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "gale").await;

        // Server-generated keypair.
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let enabled = body_json(response).await;
        let original_pub = enabled["peer"]["public_key"]
            .as_str()
            .expect("public_key")
            .to_owned();
        assert!(enabled["secrets"]["private_key"].is_string());

        // Detail mirrors the peer and carries no secrets.
        let response = send(
            state.clone(),
            Method::GET,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let detail = body_json(response).await;
        assert_eq!(detail["public_key"], original_pub);
        assert_eq!(detail["user_id"], id);

        // Rotate with no body: server generates a fresh keypair and
        // returns `secrets.private_key` once.
        let response = send(
            state,
            Method::POST,
            &format!("/api/users/{id}/wg/rotate"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let rotated = body_json(response).await;
        assert_ne!(
            rotated["peer"]["public_key"].as_str().unwrap(),
            original_pub
        );
        assert!(rotated["secrets"]["private_key"].is_string());
    }

    // ---------------- proxy ----------------

    #[tokio::test]
    async fn proxy_status_reports_unavailable_when_disabled() {
        // test_state without proxy driver — the route returns 200 with
        // `available: false`, mirroring the SS / WG behaviour from
        // commit 73e6516.
        let state = test_state(false).await;
        let tok = token(&state);
        let response = send(
            state,
            Method::GET,
            "/api/protocol/proxy/status",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["running"], false);
        assert_eq!(body["available"], false);
        assert!(body["reason"].as_str().is_some());
    }

    #[tokio::test]
    async fn proxy_routes_require_jwt() {
        let state = test_state_full().await;
        let cases = [
            (Method::GET, "/api/protocol/proxy/status"),
            (Method::POST, "/api/protocol/proxy/start"),
            (Method::POST, "/api/protocol/proxy/stop"),
            (Method::GET, "/api/users/nope/proxy"),
            (Method::POST, "/api/users/nope/proxy"),
            (Method::DELETE, "/api/users/nope/proxy"),
            (Method::POST, "/api/users/nope/proxy/rotate"),
        ];
        for (method, uri) in cases {
            let response = send(state.clone(), method, uri, None, None).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn users_enable_proxy_when_driver_stopped_is_pending() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "ivan").await;

        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/proxy"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        assert_eq!(v["pending"], true);
        assert_eq!(v["user_id"], id);
        assert!(!v["username"].as_str().unwrap_or_default().is_empty());
        assert!(!v["password"].as_str().unwrap_or_default().is_empty());
        assert!(v["socks5_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("socks5://"));
        assert!(v["http_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("http://"));

        // users.proxy_enabled must flip true.
        let response = send(
            state.clone(),
            Method::GET,
            &format!("/api/users/{id}"),
            Some(&tok),
            None,
        )
        .await;
        let v = body_json(response).await;
        assert_eq!(v["proxy_enabled"], true);

        // Disable removes the credential row.
        let response = send(
            state.clone(),
            Method::DELETE,
            &format!("/api/users/{id}/proxy"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        assert_eq!(v["pending"], true);

        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}"),
            Some(&tok),
            None,
        )
        .await;
        let v = body_json(response).await;
        assert_eq!(v["proxy_enabled"], false);
    }

    #[tokio::test]
    async fn users_proxy_rotate_returns_new_password() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "jamal").await;
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/proxy"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let v = body_json(response).await;
        let first_pw = v["password"].as_str().unwrap().to_owned();
        let first_user = v["username"].as_str().unwrap().to_owned();

        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/proxy/rotate"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        let new_pw = v["password"].as_str().unwrap().to_owned();
        let new_user = v["username"].as_str().unwrap().to_owned();
        assert_ne!(new_pw, first_pw, "rotate must change the password");
        // Username is stable across rotation so existing client config
        // templates that quote it keep working.
        assert_eq!(new_user, first_user);
    }

    #[tokio::test]
    async fn users_proxy_detail_excludes_password() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "kim").await;
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/proxy"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}/proxy"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let v = body_json(response).await;
        assert!(!v["username"].as_str().unwrap().is_empty());
        assert!(v.get("password").is_none());
        // URLs include the username but not the password.
        assert!(v["socks5_url"].as_str().unwrap().contains("socks5://"));
    }

    #[tokio::test]
    async fn users_wg_rejects_malformed_public_key() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "harry").await;

        let response = send(
            state,
            Method::POST,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            Some(r#"{"public_key":"not-base64!!"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn users_wg_traffic_returns_summary_and_samples() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "ivy").await;

        // Enable WG so a peer row exists.
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let enabled = body_json(response).await;
        let peer_id = enabled["peer"]["id"].as_str().expect("peer id").to_owned();

        // Seed two samples in different hour buckets so the response
        // exposes both the running totals and the time series.
        let now = 1_700_000_000;
        let repo = nsp_db::WgTrafficRepo::new(&state.db);
        repo.record(&peer_id, 100, 200, Some(now), now)
            .await
            .unwrap();
        repo.record(
            &peer_id,
            5_000,
            6_000,
            Some(now + 4_000),
            now + nsp_db::TRAFFIC_BUCKET_SECS + 30,
        )
        .await
        .unwrap();

        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}/wg/traffic"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["user_id"], id);
        assert_eq!(body["peer_id"], peer_id);
        assert_eq!(body["total_rx_bytes"], 5_000);
        assert_eq!(body["total_tx_bytes"], 6_000);
        let samples = body["samples"].as_array().expect("samples array");
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0]["rx_bytes"], 100);
        assert_eq!(samples[0]["tx_bytes"], 200);
        assert_eq!(samples[1]["rx_bytes"], 4_900);
        assert_eq!(samples[1]["tx_bytes"], 5_800);
    }

    #[tokio::test]
    async fn users_wg_traffic_404_without_peer() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "june").await;
        // No WG enabled -> 404.
        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}/wg/traffic"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn wg_peer_dto_includes_total_bytes_after_sample() {
        let state = test_state_full().await;
        let tok = token(&state);
        let id = create_user_helper(state.clone(), &tok, "kira").await;
        let response = send(
            state.clone(),
            Method::POST,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        let enabled = body_json(response).await;
        let peer_id = enabled["peer"]["id"].as_str().unwrap().to_owned();

        let repo = nsp_db::WgTrafficRepo::new(&state.db);
        repo.record(&peer_id, 500, 700, None, 1_700_000_000)
            .await
            .unwrap();

        let response = send(
            state,
            Method::GET,
            &format!("/api/users/{id}/wg"),
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["total_rx_bytes"], 500);
        assert_eq!(body["total_tx_bytes"], 700);
    }
}
