// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64u } from "@/lib/e2ee/crypto";
import { runEnclaveOp } from "@/lib/crypto-enclave/enclave-core";
import {
  badgeMessage,
  claimsMatchShown,
  maskMinorLegalName,
  monthKey,
  parseBadgeClaims,
  type BadgeClaims,
} from "./badge-attestation";
import { badgePublicKey, signBadgeClaims } from "./badge-attestation.server";

const CLAIMS: BadgeClaims = { v: 1, handle: "jdelplanche", method: "team", name: "Jona Delplanche", country: "BE", month: "2026-10", iat: 1_800_000_000 };
const SHOWN = { handle: "JDelplanche", method: "team" as const, name: "Jona Delplanche", country: "be", verifiedAt: "2026-10-10T08:16:00Z" };

beforeEach(() => {
  vi.stubEnv("ROUT_SUBJECT_MASTER_KEY", "test-master-key-that-is-at-least-32-bytes-long");
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("minor firewall on the card name", () => {
  it("keeps the first name and the initial of the last name", () => {
    expect(maskMinorLegalName("Jona Delplanche")).toBe("Jona D.");
    expect(maskMinorLegalName("  Anna  Marie  Peeters ")).toBe("Anna P.");
    expect(maskMinorLegalName("Jona")).toBe("Jona");
  });
});

describe("signed blue-mark card", () => {
  it("signs with Ed25519 and the published key verifies it", async () => {
    const att = (await signBadgeClaims(CLAIMS))!;
    const key = (await badgePublicKey())!;
    expect(att.kid).toBe(key.kid);
    expect(ed25519.verify(b64u.decode(att.sig), badgeMessage(att.payload), b64u.decode(key.publicKey))).toBe(true);
  });

  it("gives no attestation and no key without the master key", async () => {
    vi.stubEnv("ROUT_SUBJECT_MASTER_KEY", "");
    expect(await signBadgeClaims(CLAIMS)).toBeNull();
    expect(await badgePublicKey()).toBeNull();
  });

  it("a changed payload no longer verifies in the crypto worker", async () => {
    const att = (await signBadgeClaims(CLAIMS))!;
    const pk = b64u.decode((await badgePublicKey())!.publicKey);
    const ok = await runEnclaveOp("badge.verify", { message: badgeMessage(att.payload), signature: b64u.decode(att.sig), publicKey: pk });
    expect(ok).toMatchObject({ ok: true, result: { valid: true } });
    const forged = att.payload.replace("Jona Delplanche", "Jona Delplanchf");
    const bad = await runEnclaveOp("badge.verify", { message: badgeMessage(forged), signature: b64u.decode(att.sig), publicKey: pk });
    expect(bad).toMatchObject({ ok: true, result: { valid: false } });
  });

  it("the worker refuses malformed keys and signatures", async () => {
    const r = await runEnclaveOp("badge.verify", { message: new Uint8Array([1]), signature: new Uint8Array(10), publicKey: new Uint8Array(32) });
    expect(r).toMatchObject({ ok: false, code: "invalid_input" });
  });

  it("claims must match exactly what the card shows", () => {
    expect(claimsMatchShown(CLAIMS, SHOWN)).toBe(true);
    expect(claimsMatchShown(CLAIMS, { ...SHOWN, name: "Jona D." })).toBe(false);
    expect(claimsMatchShown(CLAIMS, { ...SHOWN, country: "NL" })).toBe(false);
    expect(claimsMatchShown(CLAIMS, { ...SHOWN, verifiedAt: "2026-11-01T00:00:00Z" })).toBe(false);
    expect(claimsMatchShown(CLAIMS, { ...SHOWN, method: "didit" })).toBe(false);
  });

  it("only the canonical payload encoding is accepted", () => {
    const canonical = JSON.stringify(CLAIMS);
    expect(parseBadgeClaims(canonical)).toEqual(CLAIMS);
    expect(parseBadgeClaims(JSON.stringify({ ...CLAIMS, extra: 1 }))).toBeNull();
    expect(parseBadgeClaims(canonical.replace(",", ", "))).toBeNull();
    expect(monthKey("2026-10-31T23:30:00Z")).toBe("2026-10");
  });

  it("the browser check reports valid, then invalid for a different key", async () => {
    const att = (await signBadgeClaims(CLAIMS))!;
    const key = (await badgePublicKey())!;
    vi.doMock("@/lib/crypto-enclave/client", () => ({
      enclave: { badge: { verify: async (m: Uint8Array, s: Uint8Array, k: Uint8Array) => (await runEnclaveOp("badge.verify", { message: m, signature: s, publicKey: k }) as { result: { valid: boolean } }).result } },
    }));
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ alg: "Ed25519", ...key }), { status: 200 })));
    const { verifyBadgeAttestation, resetBadgeKey } = await import("./badge-verify");
    resetBadgeKey();
    expect(await verifyBadgeAttestation(att, SHOWN)).toBe("valid");
    expect(await verifyBadgeAttestation(att, { ...SHOWN, name: "Iemand Anders" })).toBe("invalid");

    const other = ed25519.getPublicKey(new Uint8Array(32).fill(7));
    resetBadgeKey();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ alg: "Ed25519", kid: att.kid, publicKey: b64u.encode(other) }), { status: 200 })));
    expect(await verifyBadgeAttestation(att, SHOWN)).toBe("invalid");

    resetBadgeKey();
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 503 })));
    expect(await verifyBadgeAttestation(att, SHOWN)).toBe("unavailable");
  });
});
