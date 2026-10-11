// Phase 1 — WireGuard control plane.
//
// Self-contained: only inspects /api/protocol/wg/status. The
// `total_peers` value is read but not pinned to 0 — by the time this
// phase runs the test fixture may already have other peers in flight
// (parallel re-runs, phases left behind), so the assertion is
// limited to what's structurally invariant: the requested backend, correct
// interface/subnet/port, server pubkey populated.

import { beforeAll, describe, expect, test } from "bun:test";

import type { Client } from "./lib/client.ts";
import { bootstrapClient } from "./lib/setup.ts";
import type { WgStatus } from "./lib/types.ts";

let client: Client;

beforeAll(async () => {
  client = await bootstrapClient();
});

describe("phase 1 — WireGuard control plane", () => {
  test("backend running with seeded subnet", async () => {
    const wg = await client.ok<WgStatus>("GET", "/api/protocol/wg/status");
    expect(wg.running).toBe(true);
    expect(wg.backend).toBe(process.env["NSP_WG_BACKEND"] ?? "kernel");
    expect(wg.available).toBe(true);
    expect(wg.interface).toBe("wg0");
    expect(wg.subnet).toBe("10.99.99.0/24");
    expect(wg.listen_port).toBe(51820);
    expect(wg.server_public_key).toBeTruthy();
    expect(typeof wg.total_peers).toBe("number");
    expect(wg.total_peers).toBeGreaterThanOrEqual(0);
  });
});
