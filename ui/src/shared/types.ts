// Shared API DTO shapes mirroring crates/api/src/{routes,ss,wg,users}.rs.
// All user-scoped material lives under /api/users; protocol namespaces
// only carry service-level status/start/stop.

export interface LoginRequest {
  password: string;
}

export interface LoginResponse {
  token: string;
  expires_at: number;
}

export interface MeResponse {
  sub: string;
}

export interface StatusResponse {
  version: string;
  ss_enabled: boolean;
  wg_enabled: boolean;
  proxy_enabled: boolean;
}

// ---- Users ----

export interface UserEntry {
  id: string;
  name: string;
  created_at: number;
  ss_enabled: boolean;
  wg_enabled: boolean;
  proxy_enabled: boolean;
  note?: string | null;
}

export interface UserCreateRequest {
  name: string;
  note?: string | null;
}

export interface UserUpdateRequest {
  name?: string;
  note?: string | null;
}

export interface UserProtocolAck {
  pending: boolean;
}

export interface UserSsEnabled {
  user_id: string;
  name: string;
  /** Hex of the per-user iPSK. */
  psk: string;
  /** Hex of the shared server uPSK. */
  server_psk: string;
  url: string;
  pending: boolean;
}

/** `GET /api/users/:id/ss` — public SS detail; no PSK. */
export interface UserSsDetail {
  user_id: string;
  name: string;
  created_at: number;
  url: string;
}

/** `POST /api/users/:id/proxy[/rotate]` response. */
export interface UserProxyEnabled {
  user_id: string;
  name: string;
  username: string;
  /** One-shot password; the server never returns plaintext again. */
  password: string;
  socks5_url: string;
  http_url: string;
  pending: boolean;
}

/** `GET /api/users/:id/proxy` — no password. */
export interface UserProxyDetail {
  user_id: string;
  name: string;
  username: string;
  socks5_url: string;
  http_url: string;
  created_at: number;
  updated_at: number;
}

// ---- Proxy (protocol status only) ----

export interface ProxyStatus {
  running: boolean;
  socks5_port: number;
  http_port: number;
  public_host: string;
  users: number;
  reload_count: number;
  last_swap_ms: number;
  available: boolean;
  reason?: string | null;
}

// ---- Shadowsocks (protocol status only) ----

export interface SsStatus {
  running: boolean;
  listen_port: number;
  public_host: string;
  method: string;
  users: number;
  reload_count: number;
  last_swap_ms: number;
  available: boolean;
  reason?: string | null;
}

// ---- WireGuard (protocol status only) ----

export interface WgStatus {
  running: boolean;
  interface: string;
  listen_port: number;
  subnet: string;
  server_public_key: string;
  total_peers: number;
  endpoint_host?: string | null;
  available: boolean;
  reason?: string | null;
  /** Effective data-plane backend: `kernel`, `userspace` or `netstack`. */
  backend: string;
}

/** Peer public fields exposed under `/api/users/:id/wg`. */
export interface WgPeer {
  id: string;
  user_id?: string | null;
  name?: string | null;
  public_key: string; // base64
  allowed_ip: string;
  endpoint?: string | null;
  keepalive?: number | null;
  has_psk: boolean;
  created_at: number;
  updated_at: number;
  rx_bytes: number;
  tx_bytes: number;
  last_handshake_secs?: number | null;
}

/**
 * One-shot secrets from WG enable/rotate. `private_key` is present only
 * when the server generated the keypair because the caller did not
 * supply their own public key.
 */
export interface WgPeerSecrets {
  private_key?: string | null;
  preshared_key?: string | null;
}

export interface UserWgEnabled {
  user_id: string;
  peer: WgPeer;
  secrets?: WgPeerSecrets | null;
  pending: boolean;
}

/** Optional request body for WG enable / rotate. */
export interface UserWgEnableRequest {
  public_key?: string;
}

// ---- Settings ----

export interface ServerSettings {
  domain: string | null;
  wg_subnet: string | null;
  ss_listen_port: number;
  wg_listen_port: number;
  token_generation: number;
  updated_at: number;
}

/** Tri-state PATCH body: omit to leave untouched, null to clear, value to set. */
export interface ServerSettingsPatch {
  domain?: string | null;
  wg_subnet?: string | null;
  ss_listen_port?: number;
  wg_listen_port?: number;
  new_password?: string;
}

export interface WgSubnetConflictBody {
  code: 'wg-subnet-conflict';
  conflicts: string[];
}

// ---- Iptables ----

export type IptablesSource = 'user' | 'wg-driver';

export interface IptablesRule {
  id: string;
  source: IptablesSource;
  priority: number;
  table: string;
  chain: string;
  spec: string;
  comment?: string | null;
  comment_tag: string;
  created_at: number;
  updated_at: number;
}

export interface IptablesCreateRequest {
  table: string;
  chain: string;
  spec: string;
  comment?: string | null;
  priority?: number;
  force?: boolean;
}

export interface IptablesVerifyRequest {
  table: string;
  chain: string;
  spec: string;
  force?: boolean;
}

export interface IptablesReconcileReport {
  reinserted: number;
  pruned: number;
  kept: number;
}

export interface IptablesSshGuardBody {
  code: 'ssh-guard';
  warn: string;
}

// ---- Audit log ----

export interface AuditEntry {
  id: number;
  ts: number;
  actor: string;
  action: string;
  target?: string | null;
  detail?: string | null;
}
