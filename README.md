# nsp

A small, single-binary control plane that manages WireGuard, Shadowsocks,
and SOCKS5 / HTTP CONNECT proxy users behind a signed API. State is a single
SQLite file; secrets can be sealed at rest with a master key; metrics and
hourly backups are built in.

* **HTTP/S control plane** — JWT-auth'd REST API + embedded admin SPA.
* **WireGuard driver** — IPAM, peer lifecycle, native netlink apply
  loop. Pluggable data plane: in-kernel `wireguard` module via
  netlink (default) or in-process userspace (nsplane + TUN) fallback.
* **Shadowsocks driver** — in-process task, debounced key reloads.
* **Proxy driver** — SOCKS5 (RFC 1928 + 1929) and HTTP CONNECT (RFC 7231 + 7235)
  on independent ports, sharing one credential set per user.
* **Optional TLS** — Let's Encrypt via `rustls-acme` (TLS-ALPN-01), static
  certs, self-signed fallback, or plaintext HTTP for local/reverse-proxy use.
* **Observability** — Prometheus `/metrics`, bearer- or JWT-gated.
* **Backups** — hourly SQLite `VACUUM INTO` snapshots with 7-day retention.

---

## Deploy with Docker

### 1. Generate a master key (one time)

The master key encrypts all secrets at rest. Keep it out of git. If unset or
empty, data-at-rest encryption is disabled.

```shell
docker run --rm ghcr.io/nsiod/nsp:latest generate-key
# e.g. 7M1vPqSg0b4WklHKkzXTUdGd8mnEz82M+U3zSIxwrFk=
```

Or, if you already have a local build:

```shell
nsp generate-key
```

### 2. Create an env file

```shell
cp .env.example .env
```

Minimal values to edit:

```dotenv
NSP_DOMAIN=proxy.example.com
NSP_ADMIN_PASSWORD=<one-time bootstrap password>
NSP_MASTER_KEY=<base64 value from step 1>
```

For local development only, leaving `NSP_MASTER_KEY=` empty also requires
`NSP_ALLOW_INSECURE_NO_MASTER_KEY=true`. Do not use that override for public
deployments because it uses a fixed development JWT signing key.

### 3. Run with docker-compose

```shell
docker compose up -d
```

The API listens on the configured listener. First login uses the bootstrap password;
remove `NSP_ADMIN_PASSWORD` from `.env` once a persistent admin
has been set.

Data is persisted under `./work`:

```
./work/
├── data/         # SQLite file (proxy.db)
├── acme/         # ACME account + cert cache (when enabled)
└── backups/      # Hourly VACUUM INTO snapshots
```

### 4. Enable ACME for real certificates

`NSP_DOMAIN` is the externally visible domain used in generated
client configuration, ACME domain fallback, and self-signed development
certificates. Point it at a DNS name that resolves to the box, then set:

```
NSP_TLS=true
NSP_ACME=true
NSP_ACME_EMAIL=ops@example.com
NSP_ACME_PRODUCTION=true
```

ACME uses the TLS-ALPN-01 challenge, so only `:443` needs to be reachable
from the internet — no separate `:80` handler is required.

---

## Configuration

Layered, in order of priority (later overrides earlier):

1. Built-in defaults
2. `--config path/to/nsp.toml`
3. Environment: flat `NSP_*` names (e.g. `NSP_LISTEN=8443`)
4. CLI flags (e.g. `--listen`, `--storage-db-path`)

Actual read path in code:

1. `ProxyConfig::default()` creates the baseline config.
2. `nsp` reads `--config` / `NSP_CONFIG` to choose the TOML path.
3. If that file exists, it is merged on top of defaults.
4. Every other CLI flag is declared with a matching `env = "NSP_*"` binding
   in clap.
5. Parsed env / CLI values are applied field-by-field on top of the merged TOML.

Important details:

- Missing config files are ignored.
- Environment variables and CLI flags share the same override path in code.
- CLI wins over env because clap resolves explicit arguments over env-backed
  defaults.
- `--listen` / `NSP_LISTEN` accept either `8443` or `0.0.0.0:8443`.
- `NSP_ACME_DOMAINS` is comma-separated in env, but a TOML array in config.

Example files:

- [.env.example](./.env.example)
- [nsp.example.toml](./nsp.example.toml)

Key sections:

| Section       | Purpose                                  |
| ------------- | ---------------------------------------- |
| `http`        | Listener address, `domain`               |
| `tls`         | Enable flag, static cert/key, `[tls.acme]` |
| `security`    | Master key, first-run admin password     |
| `storage`     | SQLite path, work dir                    |
| `wireguard`   | WG subnet, listen port, peer limits      |
| `shadowsocks` | SS bind, port, apply debounce            |
| `proxy`       | SOCKS5 + HTTP CONNECT ports, bind, debounce |
| `metrics`     | Enable `/metrics`, optional bearer token |
| `backup`      | Dir, interval, retention                 |
| `control`     | Reverse-API control-center poller        |

Common settings use the same config path across TOML, environment variables,
and CLI flags:

| Config key               | Environment variable           | CLI flag                    |
| ------------------------ | ------------------------------ | --------------------------- |
| `http.listen`            | `NSP_LISTEN`                | `--listen`                  |
| `http.domain`            | `NSP_DOMAIN`                | `--domain`                  |
| `tls.enabled`            | `NSP_TLS`                   | `--tls-enabled`             |
| `tls.cert_path`          | `NSP_TLS_CERT`              | `--tls-cert-path`           |
| `tls.key_path`           | `NSP_TLS_KEY`               | `--tls-key-path`            |
| `tls.acme.enabled`       | `NSP_ACME`                  | `--tls-acme-enabled`        |
| `tls.acme.email`         | `NSP_ACME_EMAIL`            | `--tls-acme-email`          |
| `tls.acme.domains`       | `NSP_ACME_DOMAINS`          | `--tls-acme-domains`        |
| `tls.acme.production`    | `NSP_ACME_PRODUCTION`       | `--tls-acme-production`     |
| `tls.acme.cache_dir`     | `NSP_ACME_CACHE`            | `--tls-acme-cache-dir`      |
| `storage.db_path`        | `NSP_DB`                    | `--storage-db-path`         |
| `storage.work_dir`       | `NSP_WORK_DIR`              | `--storage-work-dir`        |
| `security.master_key`    | `NSP_MASTER_KEY`            | `--security-master-key`     |
| `security.allow_insecure_no_master_key` | `NSP_ALLOW_INSECURE_NO_MASTER_KEY` | `--allow-insecure-no-master-key` |
| `security.admin_password` | `NSP_ADMIN_PASSWORD`        | `--security-admin-password` |
| `security.jwt_ttl_secs`  | `NSP_JWT_TTL`               | `--security-jwt-ttl-secs`   |
| `security.api`           | `NSP_API`                   | `--security-api`            |
| `wireguard.enabled`      | `NSP_WG`                    | `--wireguard-enabled`       |
| `wireguard.port`         | `NSP_WG_PORT`               | `--wireguard-port`          |
| `wireguard.subnet`       | `NSP_WG_SUBNET`             | `--wireguard-subnet`        |
| `wireguard.interface`    | `NSP_WG_INTERFACE`          | `--wireguard-interface`     |
| `wireguard.backend`      | `NSP_WG_BACKEND`            | `--wireguard-backend`       |
| `shadowsocks.enabled`    | `NSP_SS`                    | `--shadowsocks-enabled`     |
| `shadowsocks.bind`       | `NSP_SS_BIND`               | `--shadowsocks-bind`        |
| `shadowsocks.port`       | `NSP_SS_PORT`               | `--shadowsocks-port`        |
| `shadowsocks.apply_debounce_ms` | `NSP_SS_DEBOUNCE_MS` | `--shadowsocks-apply-debounce-ms` |
| `proxy.enabled`          | `NSP_PROXY`                 | `--proxy-enabled`           |
| `proxy.bind`             | `NSP_PROXY_BIND`            | `--proxy-bind`              |
| `proxy.socks5_port`      | `NSP_PROXY_SOCKS5_PORT`     | `--proxy-socks5-port`       |
| `proxy.http_port`        | `NSP_PROXY_HTTP_PORT`       | `--proxy-http-port`         |
| `proxy.apply_debounce_ms` | `NSP_PROXY_DEBOUNCE_MS`    | `--proxy-apply-debounce-ms` |
| `proxy.block_private_destinations` | `NSP_PROXY_BLOCK_PRIVATE` | `--proxy-block-private-destinations` |
| `proxy.max_inflight`     | `NSP_PROXY_MAX_INFLIGHT`    | `--proxy-max-inflight`      |
| `logging.level`          | `NSP_LOG`                   | `--logging-level`           |
| `logging.json`           | `NSP_JSON_LOGS`             | `--logging-json`            |
| `metrics.enabled`        | `NSP_METRICS`               | `--metrics-enabled`         |
| `metrics.bearer_token`   | `NSP_METRICS_TOKEN`         | `--metrics-bearer-token`    |
| `metrics.refresh_ms`     | `NSP_METRICS_REFRESH_MS`    | `--metrics-refresh-ms`      |
| `backup.enabled`         | `NSP_BACKUP`                | `--backup-enabled`          |
| `backup.interval_secs`   | `NSP_BACKUP_INTERVAL_SECS`  | `--backup-interval-secs`    |
| `backup.dir`             | `NSP_BACKUP_DIR`            | `--backup-dir`              |
| `backup.retention_days`  | `NSP_BACKUP_RETENTION_DAYS` | `--backup-retention-days`   |
| `control.enabled`        | `NSP_CONTROL`               | `--control-enabled`         |
| `control.url`            | `NSP_CONTROL_URL`           | `--control-url`             |
| `control.token`          | `NSP_CONTROL_TOKEN`         | `--control-token`           |
| `control.node_id`        | `NSP_CONTROL_NODE_ID`       | `--control-node-id`         |
| `control.interval_secs`  | `NSP_CONTROL_INTERVAL_SECS` | `--control-interval-secs`   |
| `control.timeout_secs`   | `NSP_CONTROL_TIMEOUT_SECS`  | `--control-timeout-secs`    |
| `control.status_interval_secs` | `NSP_CONTROL_STATUS_INTERVAL_SECS` | `--control-status-interval-secs` |
| `control.conflict_policy`| `NSP_CONTROL_CONFLICT_POLICY` | `--control-conflict-policy` |

---

## WireGuard backend

The driver ships three data-plane implementations, selected by
`wireguard.backend` (or `NSP_WG_BACKEND`):

* `kernel` *(default)* — drives the in-kernel `wireguard` module
  **directly via netlink** (genetlink for WireGuard config + rtnetlink
  for interface lifecycle). No `wg`, no `ip`, no shelling out: every
  apply is one netlink round trip. Requires the `wireguard` kernel
  module loaded (Linux ≥ 5.6 ships it in-tree) and `CAP_NET_ADMIN`.
  Lowest CPU overhead — crypto runs in-kernel without copying packets
  to userspace.
* `userspace` — runs the `dotns/nsplane` engine in-process and exposes a
  `tun` device. Self-contained fallback when the kernel module is
  unavailable. Requires `/dev/net/tun` and `CAP_NET_ADMIN`.
* `netstack` — runs the nsplane engine on a user-space TCP/IP stack
  instead of a TUN device. Needs no `/dev/net/tun`, no `CAP_NET_ADMIN`
  and no iptables (the iptables manager is not started). The stack
  owns the subnet's first host address and answers pings on it; this
  host reaches the tunnel peers through
  * a SOCKS5 listener (`wireguard.netstack.socks5` / `NSP_WG_SOCKS5`):
    CONNECT and UDP ASSOCIATE to tunnel IPs. Setting
    `socks5_username` + `socks5_password` (`NSP_WG_SOCKS5_USERNAME`,
    `NSP_WG_SOCKS5_PASSWORD`) requires RFC 1929 credentials; without
    them anyone can connect, so keep it on loopback or a trusted
    network;
  * TCP and UDP port forwards (`wireguard.netstack.forwards` /
    `NSP_WG_FORWARDS`, `wireguard.netstack.udp_forwards` /
    `NSP_WG_UDP_FORWARDS`), `listen=target`. Ports are lists and
    ranges: `127.0.0.1:8080=10.255.0.2:80` maps one port,
    `127.0.0.2:22,80,8000-8100=10.255.0.2` maps each listed port to the
    same port of the target (so `127.0.0.2` stands in for the peer on
    those ports), `127.0.0.2:8000-8009=10.255.0.2:9000-9009` maps the
    lists in order. Every port is its own socket: large ranges need a
    matching `ulimit -n`. All ports of an address, or ICMP to it, need
    a TUN device (`userspace`).

  There is no
  forwarding between peers or out to the internet, so client configs
  exported by the UI route only the tunnel subnet. A subnet is
  required (no hybrid mode).
* `auto` — pick `kernel` when its preconditions are met, otherwise
  fall back to `userspace`. Useful when the same image runs across
  hosts with mixed kernel module availability.

`/api/wg/status` reports the effective backend in the `backend`
field, and the startup log emits one line distinguishing the
requested vs effective kind.

For Docker deployments the container needs `--cap-add NET_ADMIN`
(except with `netstack`).
The kernel backend additionally needs the host's `wireguard` module
loaded (`modprobe wireguard` on the host) — no extra host binaries
required because the netlink path bypasses `wireguard-tools` entirely.

---

## Proxy exposure

The SOCKS5 + HTTP CONNECT proxy is **disabled by default**. An open
authenticated proxy on the public internet is a high-value target — bots
scan well-known proxy ports (1080, 8080, 3128, …) continuously and will
treat a single weak password as a free relay for spam, fraud, scraping,
and DDoS reflection.

Before flipping `proxy.enabled = true`:

1. **Leave the docker-compose port mappings commented out.** The defaults
   in `docker-compose.yml` ship `1080:1080/tcp` and `8080:8080/tcp`
   commented out for this reason — never uncomment them on a host that
   accepts traffic from the open internet without taking step 2 or 3.

2. **Bind on a private interface.** Set `proxy.bind` to a WireGuard
   internal address (the IP nsp listens on inside the `wg0` subnet) so
   only clients already on the tunnel can reach the proxy. This is the
   cleanest exposure pattern: a SOCKS5 user must first complete the
   WG handshake.

3. **Or restrict source IPs with iptables.** Use the firewall page (or
   the `/api/iptables` endpoint) to allow only the source addresses you
   trust:

   ```
   -A INPUT -p tcp -m multiport --dports 1080,8080 -s 198.51.100.0/24 -j ACCEPT
   -A INPUT -p tcp -m multiport --dports 1080,8080 -j DROP
   ```

Password handling notes:

* Per-user passwords are 24-char alphanumeric (`A-Za-z0-9`) — ~143 bits of
  entropy. They are stored encrypted with the master data-key (XChaCha20-
  Poly1305); plaintext is shown to the operator exactly once on enable /
  rotate and is then discarded.
* Argon2 is intentionally not used on the runtime auth path: the
  credential rides on every new TCP connection, so a deliberately slow
  hash would amortise badly across thousands of short-lived flows. The
  in-memory compare uses `subtle::ConstantTimeEq`.
* `POST /api/users/:id/proxy/rotate` regenerates the password and pushes
  the new value through the apply loop; existing clients stop working
  within one debounce window (default 500 ms).

Built-in safety rails (always on, no config knob):

* **Destination filter**: every CONNECT target is resolved through DNS,
  then any address in `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/8`, `::1`,
  `::`, or `fe80::/10` is refused (`SOCKS5 REP=0x01` / `HTTP 403`). This
  blocks pivoting to the colocated admin API, cloud metadata endpoints
  (IMDS at `169.254.169.254`), and DNS-rebinding attacks. RFC1918 / ULA
  ranges are NOT blocked because pointing users at LAN / WireGuard-
  internal hosts is a common deployment.
* **Connection ceiling**: each listener caps the global in-flight count
  at 4096 sockets. Beyond that, new TCP accepts are closed immediately,
  bounding slowloris-style memory / FD exhaustion.

---

## Observability

`/metrics` serves Prometheus text format. Wire your scraper with either:

* **Bearer token** — set `NSP_METRICS_TOKEN=<secret>` and add
  `Authorization: Bearer <secret>` to the scrape config. Recommended.
* **Admin JWT** — leave `bearer_token` unset and the route falls through to
  the same JWT middleware as the rest of the API.

Metrics exported:

```
nsp_http_requests_total{method,status,route}
nsp_ss_reload_total
nsp_ss_active_users
nsp_wg_peers
nsp_wg_rx_bytes_total{peer,name}
nsp_wg_tx_bytes_total{peer,name}
nsp_wg_last_handshake_age_seconds{peer,name}
nsp_db_pool_size
nsp_db_pool_idle
nsp_config_reload_total{source}
```

---

## Backups

`backup.enabled = true` by default. Each tick (1 h) the binary runs
`VACUUM INTO /work/backups/nsp-YYYYMMDD-HH.sqlite`; snapshots older than
`backup.retention_days` (7 by default) are pruned. `VACUUM INTO` runs at the
same snapshot the pool sees, so it is safe concurrent with writes.

Restore:

```shell
# Stop nsp, then:
cp /work/backups/nsp-20260420-07.sqlite /work/data/proxy.db
```

---

## Reverse API (control center)

Set `NSP_CONTROL=true` together with `NSP_CONTROL_URL`,
`NSP_CONTROL_NODE_ID`, and `NSP_CONTROL_TOKEN` to have nsp run as a
node managed by a remote control plane. Each tick the node POSTs a
self-report (cursor + content hashes for settings/users/iptables +
service running state) and applies the reconcile directives in the
response — no separate heartbeat needed.

The control center can drive **all** node configuration this way:
the singleton settings row, the user list (full or delta), and the
control-source iptables rules.

The full protocol — request/response shape, sync modes (`merge` vs
`replace`), reset signal, hashing rules, and a server-side decision
tree — is in [`docs/control-center.md`](./docs/control-center.md).

---

## Build from source

Requires the Rust toolchain pinned in `rust-toolchain.toml` (currently 1.90).

```shell
# Debug
cargo build -p nsp

# Release (static musl, matches the release image)
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-musl -p nsp
```

Quality gates (enforced in CI):

```shell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Release image build:

```shell
docker build -f Dockerfile.release -t nsp:release .
docker image inspect nsp:release --format '{{.Size}}'   # < 36 MB
```

## Local development

`just dev` starts the backend and the Vite dev server behind a single
origin so the SPA's `/api` calls land on the same host as the UI
(no CORS, HMR works out of the box).

It depends on [`nsiod/nsl`](https://github.com/nsiod/nsl) being
installed and running — the one-time setup:

```shell
nsl start   # starts the nsl reverse proxy daemon
just dev    # http://nsp.localhost:<port>/ui/
```

WireGuard / Shadowsocks / backups stay disabled in this flow, so no
root or CAP_NET_ADMIN is needed. Protocol-level behavior still requires
the full Docker flow.

---

## License

MPL-2.0. See `LICENSE`.
