// @vitest-environment node
/**
 * Part 3 (EUDI wallet / post-quantum): hybrid signatures against official vectors
 * (NIST ACVP ML-DSA-65, RFC 8032 Ed25519), OID4VCI key proofs, OID4VP presentation checks,
 * Token Status List bits and signing, and worker buffer zeroization.
 */
import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import acvp from "./fixtures/ml-dsa-65-acvp.json";
import { b64uEncode, verifyHybridBytes } from "@/lib/support/hybrid-signature";
import { jsonB64u, p256Jwk, parseJws, verifyJws, type PublicJwk } from "@/lib/eudi/jose";
import { addKeyBinding, issueSdJwtVc, selectDisclosures, VERIFIED_HUMAN_VCT } from "@/lib/eudi/sd-jwt-vc";
import { decodeStatusList, encodeStatusList, statusAt, statusBits, STATUS_LIST_SIZE } from "@/lib/eudi/status-list";

vi.mock("@/lib/eudi/keys.server", () => ({ checkCNonce: async (n: unknown) => n === "fresh-nonce" }));

const hex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const enc = new TextEncoder();

// RFC 8032 section 7.1, TEST 1 and TEST 2.
const RFC8032 = [
  { sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", msg: "", sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
  { sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", msg: "72", sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
];

describe("official vectors", () => {
  it("fixture is the pinned NIST ACVP subset", () => {
    expect(acvp.commit).toBe("975de31eb83d87039ec88934fdc47d8c312b892d");
    expect(acvp.sigVer).toHaveLength(15);
    expect(acvp.keyGen).toHaveLength(5);
  });
  it.each(acvp.keyGen)("ML-DSA-65 keyGen tcId $tcId", (t) => {
    const k = ml_dsa65.keygen(hex(t.seed));
    expect(Buffer.from(k.publicKey).toString("hex").toUpperCase()).toBe(t.pk);
    expect(Buffer.from(k.secretKey).toString("hex").toUpperCase()).toBe(t.sk);
  });
  it.each(acvp.sigVer)("ML-DSA-65 sigVer tcId $tcId (expected $testPassed)", (t) => {
    const ok = ml_dsa65.verify(hex(t.signature), hex(t.message), hex(t.pk), { context: hex(t.context) });
    expect(ok).toBe(t.testPassed);
  });
  it.each(RFC8032)("Ed25519 RFC 8032 vector %#", (v) => {
    expect(Buffer.from(ed25519.getPublicKey(hex(v.sk))).toString("hex")).toBe(v.pk);
    expect(Buffer.from(ed25519.sign(hex(v.msg), hex(v.sk))).toString("hex")).toBe(v.sig);
    expect(ed25519.verify(hex(v.sig), hex(v.msg), hex(v.pk))).toBe(true);
  });
});

function hybridFixture() {
  const edSk = hex(RFC8032[0]!.sk);
  const pq = ml_dsa65.keygen(hex(acvp.keyGen[0]!.seed));
  const message = enc.encode("rout.test.hybrid.v1\nline");
  return {
    message,
    sig: { ed25519: ed25519.sign(message, edSk), mldsa65: ml_dsa65.sign(message, pq.secretKey) },
    pk: { ed25519: ed25519.getPublicKey(edSk), mldsa65: pq.publicKey },
  };
}

describe("hybrid Ed25519 + ML-DSA-65", () => {
  it("accepts when both halves are valid", () => {
    const f = hybridFixture();
    expect(verifyHybridBytes(f.message, f.sig, f.pk, { requirePq: true })).toEqual({ valid: true, pq: true });
  });
  it("rejects a broken Ed25519 half", () => {
    const f = hybridFixture();
    f.sig.ed25519[0]! ^= 1;
    expect(verifyHybridBytes(f.message, f.sig, f.pk).valid).toBe(false);
  });
  it("rejects a broken ML-DSA-65 half", () => {
    const f = hybridFixture();
    f.sig.mldsa65[10]! ^= 1;
    expect(verifyHybridBytes(f.message, f.sig, f.pk).valid).toBe(false);
  });
  it("rejects a missing PQ half when PQ is required", () => {
    const f = hybridFixture();
    expect(verifyHybridBytes(f.message, { ed25519: f.sig.ed25519, mldsa65: null }, f.pk, { requirePq: true }).valid).toBe(false);
  });
  it("rejects a changed message", () => {
    const f = hybridFixture();
    expect(verifyHybridBytes(enc.encode("other"), f.sig, f.pk).valid).toBe(false);
  });
});

describe("crypto worker zeroization", () => {
  it("support.verify_hybrid leaves every request byte at 0x00", async () => {
    const { runEnclaveOp } = await import("@/lib/crypto-enclave/enclave-core");
    const f = hybridFixture();
    const args = { message: f.message, ed25519: f.sig.ed25519, mldsa65: f.sig.mldsa65, edPublicKey: f.pk.ed25519, pqPublicKey: f.pk.mldsa65, requirePq: true };
    const r = await runEnclaveOp("support.verify_hybrid", args);
    expect(r).toEqual({ ok: true, result: { valid: true, pq: true } });
    for (const b of [args.message, args.ed25519, args.mldsa65, args.edPublicKey, args.pqPublicKey]) {
      expect(b.byteLength).toBeGreaterThan(0);
      expect(b.every((x) => x === 0)).toBe(true);
    }
  });
  it("wipes the request even when the operation fails", async () => {
    const { runEnclaveOp } = await import("@/lib/crypto-enclave/enclave-core");
    const junk = new Uint8Array(64).fill(0xab);
    const r = await runEnclaveOp("support.verify_hybrid", { message: new Uint8Array(0), ed25519: junk, mldsa65: null, edPublicKey: new Uint8Array(32).fill(7), pqPublicKey: null });
    expect(r.ok).toBe(false);
    expect(junk.every((x) => x === 0)).toBe(true);
  });
});

// ------------------------------------------------------------------ OID4VCI key proof

const ISS = "https://rout.example";
const holderSk = hex(RFC8032[1]!.sk);
const holderJwk: PublicJwk = { kty: "OKP", crv: "Ed25519", x: b64uEncode(ed25519.getPublicKey(holderSk)) };
function proof(over: { header?: Record<string, unknown>; payload?: Record<string, unknown>; sk?: Uint8Array } = {}) {
  const header = { alg: "EdDSA", typ: "openid4vci-proof+jwt", jwk: holderJwk, ...over.header };
  const payload = { aud: ISS, iat: Math.floor(Date.now() / 1000), nonce: "fresh-nonce", ...over.payload };
  const input = `${jsonB64u(header)}.${jsonB64u(payload)}`;
  return `${input}.${b64uEncode(ed25519.sign(enc.encode(input), over.sk ?? holderSk))}`;
}

describe("OID4VCI key proof", () => {
  it("accepts a fresh holder proof and returns the holder key", async () => {
    const { checkProof } = await import("@/lib/eudi/oid4vci.server");
    expect(await checkProof(proof(), ISS)).toEqual({ ok: true, jwk: holderJwk });
  });
  it.each([
    ["wrong signer", { sk: hex(RFC8032[0]!.sk) }, "invalid_proof"],
    ["wrong typ", { header: { typ: "JWT" } }, "invalid_proof"],
    ["kid instead of embedded key", { header: { kid: "k1" } }, "invalid_proof"],
    ["private key in header", { header: { jwk: { ...holderJwk, d: "AA" } } }, "invalid_proof"],
    ["wrong audience", { payload: { aud: "https://evil.example" } }, "invalid_proof"],
    ["stale iat", { payload: { iat: Math.floor(Date.now() / 1000) - 3600 } }, "invalid_proof"],
    ["unknown nonce", { payload: { nonce: "replayed" } }, "invalid_nonce"],
  ] as const)("rejects %s", async (_n, over, error) => {
    const { checkProof } = await import("@/lib/eudi/oid4vci.server");
    expect(await checkProof(proof(over as never), ISS)).toEqual({ ok: false, error });
  });
  it("rejects a non-string or malformed proof", async () => {
    const { checkProof } = await import("@/lib/eudi/oid4vci.server");
    expect((await checkProof(undefined, ISS)).ok).toBe(false);
    expect((await checkProof("a.b", ISS)).ok).toBe(false);
  });
});

// ------------------------------------------------------------------ SD-JWT VC + OID4VP

const issuerSk = p256.utils.randomSecretKey();
const issuerJwk = p256Jwk(p256.getPublicKey(issuerSk, false));
const NOW = Date.now();

async function credential(idx = 7) {
  const { statusListUri } = await import("@/lib/eudi/status-list.server");
  return issueSdJwtVc({
    issuer: ISS,
    vct: VERIFIED_HUMAN_VCT,
    claims: { verified_human: true, age_over_18: true, age_over_21: false },
    cnf: holderJwk,
    status: { idx, uri: statusListUri(ISS) },
    iat: Math.floor(NOW / 1000),
    exp: Math.floor(NOW / 1000) + 3600,
    kid: "iss1",
    sign: async (i) => p256.sign(i, issuerSk),
    signPq: async () => ({ kid: "pq1", ed25519: "x", mldsa65: "y" }),
  });
}
async function present(vc: string, keep: string[], aud: string, nonce: string, sk = holderSk) {
  return addKeyBinding(selectDisclosures(vc, keep), { alg: "EdDSA", aud, nonce, iat: Math.floor(NOW / 1000), sign: (i) => ed25519.sign(i, sk) });
}
const ctx = (over: Record<string, unknown> = {}) => ({
  iss: ISS,
  clientId: "redirect_uri:https://rout.example/vp/1",
  nonce: "n-123",
  requested: ["age_over_18"],
  issuerKey: (kid: string) => (kid === "iss1" ? issuerJwk : null),
  isActive: async (i: number) => i === 7,
  verifyPq: async () => true,
  now: NOW,
  ...over,
});

describe("OID4VP presentation check", () => {
  it("dcqlFor asks only for the requested claims of the ROUT credential", async () => {
    const { dcqlFor } = await import("@/lib/eudi/oid4vp.server");
    expect(dcqlFor(["age_over_18"])).toEqual({
      credentials: [{ id: "rout", format: "dc+sd-jwt", meta: { vct_values: [VERIFIED_HUMAN_VCT] }, claims: [{ path: ["age_over_18"] }] }],
    });
  });
  it("accepts a bound presentation and discloses only what was kept", async () => {
    const { checkPresentation } = await import("@/lib/eudi/oid4vp.server");
    const r = await checkPresentation(await present(await credential(), ["age_over_18"], ctx().clientId, "n-123"), ctx());
    expect(r.valid).toBe(true);
    expect(r.claims).toEqual({ age_over_18: true });
    expect(r.holderBinding).toBe(true);
    expect(r.status).toBe("valid");
  });
  it.each([
    ["wrong nonce", { nonce: "other" }, "kb_audience"],
    ["wrong audience", { clientId: "redirect_uri:https://evil" }, "kb_audience"],
    ["unknown issuer key", { issuerKey: () => null }, "signature"],
    ["failing PQ signature", { verifyPq: async () => false }, "pq"],
    ["revoked status", { isActive: async () => false }, "status_revoked"],
    ["missing claim", { requested: ["age_over_18", "verified_human"] }, "claims_missing"],
  ])("rejects %s", async (_n, over, reason) => {
    const { checkPresentation } = await import("@/lib/eudi/oid4vp.server");
    const vp = await present(await credential(), ["age_over_18"], ctx().clientId, "n-123");
    const r = await checkPresentation(vp, ctx(over));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe(reason);
  });
  it("rejects a key binding by someone other than the holder", async () => {
    const { checkPresentation } = await import("@/lib/eudi/oid4vp.server");
    const vp = await present(await credential(), ["age_over_18"], ctx().clientId, "n-123", hex(RFC8032[0]!.sk));
    expect((await checkPresentation(vp, ctx())).reason).toBe("kb_signature");
  });
  it("rejects an expired presentation key binding", async () => {
    const { checkPresentation } = await import("@/lib/eudi/oid4vp.server");
    const vp = await present(await credential(), ["age_over_18"], ctx().clientId, "n-123");
    expect((await checkPresentation(vp, ctx({ now: NOW + 3_000_000 }))).valid).toBe(false);
  });
});

// ------------------------------------------------------------------ Token Status List

describe("Token Status List", () => {
  it("bit i is LSB-first in byte i/8; only active indices are VALID", () => {
    const bits = statusBits([0, 9, 131071], 131072);
    expect(bits[0]).toBe(0xfe);
    expect(bits[1]).toBe(0xfd);
    expect(statusAt(bits, 0)).toBe(0);
    expect(statusAt(bits, 9)).toBe(0);
    expect(statusAt(bits, 131071)).toBe(0);
    expect(statusAt(bits, 1)).toBe(1);
  });
  it("out-of-range or bad indices count as revoked and are never set", () => {
    const bits = statusBits([-1, 1.5, STATUS_LIST_SIZE]);
    expect(bits.every((b) => b === 0xff)).toBe(true);
    expect(statusAt(bits, -1)).toBe(1);
    expect(statusAt(bits, STATUS_LIST_SIZE)).toBe(1);
  });
  it("revoking a credential flips only its bit after compress/decompress", async () => {
    const before = await decodeStatusList(await encodeStatusList(statusBits([5, 6])));
    const after = await decodeStatusList(await encodeStatusList(statusBits([6])));
    expect(statusAt(before, 5)).toBe(0);
    expect(statusAt(after, 5)).toBe(1);
    expect(statusAt(after, 6)).toBe(0);
  });
  it("refuses a list larger than the cap (decompression bomb)", async () => {
    const big = await encodeStatusList(new Uint8Array(STATUS_LIST_SIZE / 8 + 1));
    await expect(decodeStatusList(big)).rejects.toThrow("status_list_size");
  });
  it("the status-list JWT is signed by the issuer key whose kid is published", async () => {
    vi.resetModules();
    vi.doMock("@/lib/eudi/keys.server", () => ({
      issuerKey: async () => ({ kid: "iss1", jwk: issuerJwk }),
      signEs256: async (i: Uint8Array) => p256.sign(i, issuerSk),
    }));
    vi.doMock("@/lib/schema-features.server", () => ({ hasSchemaFeature: async () => false }));
    const { statusListToken, resetStatusListCache } = await import("@/lib/eudi/status-list.server");
    resetStatusListCache();
    const jwt = (await statusListToken(ISS))!;
    const j = parseJws(jwt);
    expect(j.header).toEqual({ alg: "ES256", typ: "statuslist+jwt", kid: "iss1" });
    expect(verifyJws("ES256", issuerJwk, j.signingInput, j.signature)).toBe(true);
    const other = p256Jwk(p256.getPublicKey(p256.utils.randomSecretKey(), false));
    expect(verifyJws("ES256", other, j.signingInput, j.signature)).toBe(false);
    const bits = await decodeStatusList((j.payload["status_list"] as { lst: string }).lst);
    expect(statusAt(bits, 7)).toBe(1);
    vi.doUnmock("@/lib/eudi/keys.server");
    vi.doUnmock("@/lib/schema-features.server");
  });
});
