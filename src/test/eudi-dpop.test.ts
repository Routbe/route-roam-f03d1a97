// @vitest-environment node
/**
 * Owner rule (2026-11-19): OID4VCI token and credential endpoints require RFC 9449 DPoP;
 * zero plain Bearer tokens, a 60 s jti replay window, and ES256 + Ed25519 advertised.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { b64uEncode } from "@/lib/support/hybrid-signature";
import { jsonB64u, p256Jwk, type PublicJwk } from "@/lib/eudi/jose";
import { accessTokenHash, checkDpopProof, DualLayerReplayGuard, JtiReplayCache, jtiReplayHash, jwkThumbprint } from "@/lib/eudi/dpop";

const sqlCalls: unknown[][] = [];
// Shared layer 2 of the replay guard (db/0295), as seen from this server instance.
const shared = { store: new Set<string>(), claims: [] as unknown[][], down: false };
vi.mock("@/lib/eudi/keys.server", () => ({
  checkDpopNonce: async (n: unknown) => n === "srv-nonce",
  newDpopNonce: async () => "srv-nonce",
  checkCNonce: async () => true,
}));
vi.mock("@/lib/schema-features.server", () => ({ hasSchemaFeature: async () => true }));
vi.mock("@/lib/neon", () => ({
  sql: async (_s: TemplateStringsArray, ...values: unknown[]) => {
    if (_s.join("?").includes("rout_dpop_jti_claim")) {
      shared.claims.push(values);
      if (shared.down) throw new Error("connection refused");
      const fresh = !shared.store.has(values[0] as string);
      shared.store.add(values[0] as string);
      return [{ ok: fresh }];
    }
    sqlCalls.push(values);
    return [{ r: "ok" }];
  },
}));

const ISS = "https://rout.example";
const enc = new TextEncoder();
const edSk = ed25519.utils.randomSecretKey();
const edJwk: PublicJwk = { kty: "OKP", crv: "Ed25519", x: b64uEncode(ed25519.getPublicKey(edSk)) };
const ecSk = p256.utils.randomSecretKey();
const ecJwk = p256Jwk(p256.getPublicKey(ecSk, false));
let n = 0;

function dpop(over: { header?: Record<string, unknown>; payload?: Record<string, unknown>; ec?: boolean; signer?: Uint8Array } = {}) {
  const ec = over.ec === true;
  const header = { typ: "dpop+jwt", alg: ec ? "ES256" : "Ed25519", jwk: ec ? ecJwk : edJwk, ...over.header };
  const payload = { jti: `jti-${Date.now()}-${n++}-abcdef`, htm: "POST", htu: `${ISS}/api/public/oid4vci/token`, iat: Math.floor(Date.now() / 1000), nonce: "srv-nonce", ...over.payload };
  const input = enc.encode(`${jsonB64u(header)}.${jsonB64u(payload)}`);
  const sig = ec ? p256.sign(input, over.signer ?? ecSk) : ed25519.sign(input, over.signer ?? edSk);
  return `${jsonB64u(header)}.${jsonB64u(payload)}.${b64uEncode(sig)}`;
}
const opts = (over: Partial<Parameters<typeof checkDpopProof>[1]> = {}) => ({
  method: "POST",
  htu: `${ISS}/api/public/oid4vci/token`,
  now: Date.now(),
  checkNonce: async (x: unknown) => x === "srv-nonce",
  replay: new JtiReplayCache(),
  ...over,
});

describe("DPoP proof (RFC 9449)", () => {
  it("accepts ES256 and Ed25519 proofs and returns the key thumbprint", async () => {
    expect(await checkDpopProof(dpop(), opts())).toMatchObject({ ok: true, jkt: jwkThumbprint(edJwk) });
    expect(await checkDpopProof(dpop({ ec: true }), opts())).toMatchObject({ ok: true, jkt: jwkThumbprint(ecJwk) });
  });
  it("refuses a replayed proof within the 60 s window", async () => {
    const o = opts();
    const p = dpop();
    expect((await checkDpopProof(p, o)).ok).toBe(true);
    expect(await checkDpopProof(p, o)).toEqual({ ok: false, error: "invalid_dpop_proof" });
  });
  it("refuses iat older than 60 s", async () => {
    expect((await checkDpopProof(dpop({ payload: { iat: Math.floor(Date.now() / 1000) - 61 } }), opts())).ok).toBe(false);
  });
  it.each([
    ["missing header", null],
    ["two headers", `${"x"}, ${"y"}`],
  ])("refuses %s", async (_l, h) => {
    expect(await checkDpopProof(h, opts())).toEqual({ ok: false, error: "invalid_dpop_proof" });
  });
  it.each([
    ["wrong typ", { header: { typ: "JWT" } }],
    ["alg none", { header: { alg: "none" } }],
    ["alg EdDSA (not advertised)", { header: { alg: "EdDSA" } }],
    ["private key in jwk", { header: { jwk: { ...edJwk, d: "AA" } } }],
    ["kid header", { header: { kid: "k" } }],
    ["wrong method", { payload: { htm: "GET" } }],
    ["wrong URI", { payload: { htu: `${ISS}/api/public/oid4vci/credential` } }],
    ["wrong host", { payload: { htu: "https://evil.example/api/public/oid4vci/token" } }],
    ["short jti", { payload: { jti: "x" } }],
    ["foreign signer", { signer: ed25519.utils.randomSecretKey() }],
    ["unexpected ath", { payload: { ath: "x" } }],
  ])("refuses %s", async (_l, over) => {
    expect(await checkDpopProof(dpop(over as never), opts())).toEqual({ ok: false, error: "invalid_dpop_proof" });
  });
  it("asks for the server nonce when it is missing or stale", async () => {
    expect(await checkDpopProof(dpop({ payload: { nonce: "old" } }), opts())).toEqual({ ok: false, error: "use_dpop_nonce" });
  });
  it("binds to the access token through ath", async () => {
    const at = "A".repeat(43);
    const htu = `${ISS}/api/public/oid4vci/credential`;
    expect((await checkDpopProof(dpop({ payload: { htu, ath: accessTokenHash(at) } }), opts({ htu, accessToken: at }))).ok).toBe(true);
    expect((await checkDpopProof(dpop({ payload: { htu, ath: accessTokenHash("B".repeat(43)) } }), opts({ htu, accessToken: at }))).ok).toBe(false);
    expect((await checkDpopProof(dpop({ payload: { htu } }), opts({ htu, accessToken: at }))).ok).toBe(false);
  });
  it("a full replay cache fails closed", async () => {
    const c = new JtiReplayCache(1);
    expect(c.claim("k", "a", 0)).toBe(true);
    expect(c.claim("k", "b", 1)).toBe(false);
    expect(c.claim("k", "b", 200_000)).toBe(true);
  });
});

describe("dual-layer jti replay guard (per-instance cache + shared ledger)", () => {
  const ledger = () => {
    const seen = new Set<string>();
    const calls: string[] = [];
    return { calls, claim: async (h: string) => (calls.push(h), seen.has(h) ? false : (seen.add(h), true)) };
  };
  it("a proof accepted on one instance is refused on every other instance", async () => {
    const l = ledger();
    const a = new DualLayerReplayGuard(new JtiReplayCache(), l.claim);
    const b = new DualLayerReplayGuard(new JtiReplayCache(), l.claim);
    const p = dpop();
    expect((await checkDpopProof(p, opts({ replay: a }))).ok).toBe(true);
    expect(await checkDpopProof(p, opts({ replay: b }))).toEqual({ ok: false, error: "invalid_dpop_proof" });
  });
  it("a repeat on the same instance is refused by layer 1 without asking the ledger", async () => {
    const l = ledger();
    const g = new DualLayerReplayGuard(new JtiReplayCache(), l.claim);
    expect(await g.claim("k", "jti-0000000000000001", 0)).toBe(true);
    expect(await g.claim("k", "jti-0000000000000001", 1)).toBe(false);
    expect(l.calls).toHaveLength(1);
  });
  it("the ledger sees only a 64-hex hash of (thumbprint, jti), held for twice the 60 s window", async () => {
    const seen: [string, number][] = [];
    const g = new DualLayerReplayGuard(new JtiReplayCache(), async (h, s) => (seen.push([h, s]), true));
    await g.claim("thumb", "jti-0000000000000002", 0);
    expect(seen).toEqual([[jtiReplayHash("thumb", "jti-0000000000000002"), 120]]);
    expect(seen[0]![0]).toMatch(/^[0-9a-f]{64}$/);
    expect(jtiReplayHash("thumb", "jti-0000000000000002")).not.toBe(jtiReplayHash("thumb2", "jti-0000000000000002"));
  });
  it("an unreachable ledger fails closed, and the proof stays burnt on this instance", async () => {
    let down = true;
    const g = new DualLayerReplayGuard(new JtiReplayCache(), async () => {
      if (down) throw new Error("timeout");
      return true;
    });
    const p = dpop();
    expect(await checkDpopProof(p, opts({ replay: g }))).toEqual({ ok: false, error: "replay_store_unavailable" });
    down = false;
    expect(await checkDpopProof(p, opts({ replay: g }))).toEqual({ ok: false, error: "invalid_dpop_proof" });
  });
  it("a nonce retry (use_dpop_nonce) does not consume the jti", async () => {
    const l = ledger();
    const g = new DualLayerReplayGuard(new JtiReplayCache(), l.claim);
    expect(await checkDpopProof(dpop({ payload: { nonce: "stale" } }), opts({ replay: g }))).toEqual({ ok: false, error: "use_dpop_nonce" });
    expect(l.calls).toHaveLength(0);
  });
});

describe("OID4VCI endpoints require DPoP", () => {
  beforeEach(() => {
    sqlCalls.length = 0;
    shared.claims.length = 0;
    shared.down = false;
  });
  const form = () => new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": "c".repeat(43), tx_code: "123456" });

  it("token endpoint: no DPoP header = 401 invalid_dpop_proof, nothing reaches the database", async () => {
    const { redeemPreAuthorizedCode } = await import("@/lib/eudi/oid4vci.server");
    expect(await redeemPreAuthorizedCode(form(), { header: null, method: "POST", iss: ISS })).toMatchObject({ ok: false, status: 401, error: "invalid_dpop_proof" });
    expect(sqlCalls).toHaveLength(0);
  });
  it("token endpoint: valid proof issues a DPoP token stored as hash(token.jkt)", async () => {
    const { redeemPreAuthorizedCode } = await import("@/lib/eudi/oid4vci.server");
    const r = await redeemPreAuthorizedCode(form(), { header: dpop(), method: "POST", iss: ISS });
    expect(r).toMatchObject({ ok: true, body: { token_type: "DPoP" } });
    const token = (r as { body: { access_token: string } }).body.access_token;
    const { createHash } = await import("node:crypto");
    expect(sqlCalls[0]![2]).toBe(createHash("sha256").update(`${token}.${jwkThumbprint(edJwk)}`).digest("hex"));
    expect(sqlCalls[0]![2]).not.toBe(createHash("sha256").update(token).digest("hex"));
  });
  it("token endpoint: a proof already claimed by another instance is refused with 401", async () => {
    const { redeemPreAuthorizedCode } = await import("@/lib/eudi/oid4vci.server");
    const jti = `jti-other-instance-${n++}-abcdef`;
    shared.store.add(jtiReplayHash(jwkThumbprint(edJwk), jti));
    const r = await redeemPreAuthorizedCode(form(), { header: dpop({ payload: { jti } }), method: "POST", iss: ISS });
    expect(r).toMatchObject({ ok: false, status: 401, error: "invalid_dpop_proof" });
    expect(sqlCalls).toHaveLength(0);
  });
  it("token endpoint: an unreachable replay ledger answers 503 and redeems nothing", async () => {
    shared.down = true;
    const { redeemPreAuthorizedCode } = await import("@/lib/eudi/oid4vci.server");
    const r = await redeemPreAuthorizedCode(form(), { header: dpop(), method: "POST", iss: ISS });
    expect(r).toMatchObject({ ok: false, status: 503, error: "temporarily_unavailable" });
    expect(shared.claims).toHaveLength(1);
    expect(sqlCalls).toHaveLength(0);
  });
  it("credential endpoint: a Bearer token is refused with 401 invalid_dpop_proof", async () => {
    const { issueCredential } = await import("@/lib/eudi/oid4vci.server");
    const r = await issueCredential(`Bearer ${"t".repeat(43)}`, {}, ISS, { header: dpop(), method: "POST" });
    expect(r).toMatchObject({ ok: false, status: 401, error: "invalid_dpop_proof" });
  });
  it("credential endpoint: DPoP token without a proof is refused with 401", async () => {
    const { issueCredential } = await import("@/lib/eudi/oid4vci.server");
    expect(await issueCredential(`DPoP ${"t".repeat(43)}`, {}, ISS, { header: null, method: "POST" })).toMatchObject({ ok: false, status: 401, error: "invalid_dpop_proof" });
  });
  it("metadata advertises exactly ES256 and Ed25519 for DPoP", async () => {
    const { issuerMetadata, authorizationServerMetadata } = await import("@/lib/eudi/oid4vci.server");
    expect(issuerMetadata(ISS).dpop_signing_alg_values_supported).toEqual(["ES256", "Ed25519"]);
    expect(authorizationServerMetadata(ISS).dpop_signing_alg_values_supported).toEqual(["ES256", "Ed25519"]);
  });
});
