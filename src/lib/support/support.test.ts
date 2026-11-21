// @vitest-environment node
/**
 * Support treasury rules: Belgian structured communication, Merkle tree, hybrid signatures,
 * supporter SD-JWT VC, signed receipts, bunq callbacks, coverage bar, DNSSEC parsing and the
 * crypto-worker ops that gate the crown and proof checks.
 */
import { describe, expect, it } from "vitest";
import { generateKeyPairSync, createSign } from "crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { formatOgm, generateOgm, isValidOgm, ogmCheck, parseOgm } from "./ogm";
import { checkInclusionProof, emptyRoot, INCLUSION_PROOF_VERSION, leafCommitment, MemoryTree, pathFor, siblingsFor, toHex, verifyInclusion, type LeafOpening } from "./treasury-tree";
import { b64uEncode, treasuryRootMessage, verifyHybrid, verifyHybridBytes } from "./hybrid-signature";
import { issueSupporterVc, presentSupporterVc, verifySupporterVc } from "./supporter-vc";
import { receiptMessage, transactionHash, type SupportReceipt } from "./receipt";
import { buildPdf, receiptLines } from "./receipt-pdf";
import { parseBunqPayment, verifyBunqSignature } from "./bunq-notification";
import { coverage, MONTHLY_COSTS } from "./coverage";
import { dnsQuery, dnssecFromWire } from "./dnssec.server";
import { PARTNERS } from "./partners";
import { resolveSupportAmount } from "./support.server";
import { runEnclaveOp } from "@/lib/crypto-enclave/enclave-core";

const opening = (over: Partial<LeafOpening> = {}): LeafOpening => ({ level: 2, attested: false, amountCents: 1000, month: "2026-11", nonce: "ab".repeat(31), ...over });

function keys() {
  const edSeed = new Uint8Array(32).fill(7);
  const pq = ml_dsa65.keygen(new Uint8Array(32).fill(9));
  return { edSeed, edPk: ed25519.getPublicKey(edSeed), pqSk: pq.secretKey, pqPk: pq.publicKey, kid: "0011223344556677" };
}
const K = keys();
const signBoth = (m: Uint8Array) => ({ kid: K.kid, ed25519: b64uEncode(ed25519.sign(m, K.edSeed)), mldsa65: b64uEncode(ml_dsa65.sign(m, K.pqSk)) });
const PK = { kid: K.kid, ed25519: b64uEncode(K.edPk), mldsa65: b64uEncode(K.pqPk) };

describe("Belgian structured communication", () => {
  it("uses mod 97 with 97 for a zero remainder", () => {
    expect(ogmCheck("0000000097")).toBe("97");
    expect(ogmCheck("1000000001")).toBe(String(Number(1000000001n % 97n)).padStart(2, "0"));
    expect(isValidOgm("100000000135")).toBe(true);
    expect(isValidOgm("100000000136")).toBe(false);
  });
  it("formats as +++XXX/XXXX/XXXXX+++ and reads it back from a bank description", () => {
    expect(formatOgm("100000000135")).toBe("+++100/0000/00135+++");
    expect(parseOgm("Gift ROUT +++100/0000/00135+++ bedankt")).toBe("100000000135");
    expect(parseOgm("***100/0000/00135***")).toBe("100000000135");
    expect(parseOgm("+++100/0000/00136+++")).toBeNull();
  });
  it("generates valid communications", () => {
    for (let i = 0; i < 50; i++) expect(isValidOgm(generateOgm())).toBe(true);
  });
});

describe("treasury Merkle tree", () => {
  it("appends leaves; every proof verifies against the latest root and fails for another leaf", () => {
    const t = new MemoryTree();
    expect(t.root()).toBe(emptyRoot());
    const leaves = [1, 2, 3, 4, 5].map((n) => leafCommitment(opening({ amountCents: n * 100 })));
    for (const l of leaves) t.append(l);
    for (let i = 0; i < leaves.length; i++) {
      const s = t.proof(BigInt(i));
      expect(verifyInclusion(t.root(), BigInt(i), leaves[i]!, s)).toBe(true);
      expect(verifyInclusion(t.root(), BigInt(i), leaves[(i + 1) % leaves.length]!, s)).toBe(false);
    }
  });
  it("pathFor reproduces the in-memory root from stored siblings", () => {
    const t = new MemoryTree();
    t.append(leafCommitment(opening()));
    const next = leafCommitment(opening({ amountCents: 2500 }));
    const { root } = pathFor(1n, next, siblingsFor(1n, t));
    t.append(next);
    expect(root).toBe(t.root());
  });
  it("binds level, attestation, amount and month into the leaf", () => {
    const base = leafCommitment(opening());
    expect(leafCommitment(opening({ level: 3 }))).not.toBe(base);
    expect(leafCommitment(opening({ attested: true }))).not.toBe(base);
    expect(leafCommitment(opening({ amountCents: 1001 }))).not.toBe(base);
    expect(leafCommitment(opening({ month: "2026-12" }))).not.toBe(base);
    expect(() => leafCommitment(opening({ month: "2026-13" }))).toThrow();
  });
  it("checkInclusionProof rejects a changed opening or sibling", () => {
    const t = new MemoryTree();
    const o = opening();
    const leaf = leafCommitment(o);
    t.append(leaf);
    const proof = {
      v: INCLUSION_PROOF_VERSION, index: "0", leaf: toHex(leaf), siblings: t.proof(0n).map(toHex),
      signedRoot: { size: "1", root: toHex(t.root()), ...signBoth(treasuryRootMessage("1", toHex(t.root()))) }, opening: o,
    };
    expect(checkInclusionProof(proof).ok).toBe(true);
    expect(checkInclusionProof({ ...proof, opening: { ...o, amountCents: 999 } })).toEqual({ ok: false, reason: "opening_mismatch" });
    const bad = [...proof.siblings];
    bad[0] = toHex(1n);
    expect(checkInclusionProof({ ...proof, siblings: bad })).toEqual({ ok: false, reason: "merkle_mismatch" });
    expect(checkInclusionProof({ ...proof, index: "1" })).toEqual({ ok: false, reason: "index_beyond_size" });
  });
});

describe("hybrid Ed25519 ‖ ML-DSA-65 signatures", () => {
  const m = treasuryRootMessage("3", "ab".repeat(32));
  it("accepts both signatures and reports pq", () => {
    expect(verifyHybrid(m, signBoth(m), PK)).toEqual({ valid: true, pq: true });
  });
  it("rejects a forged ML-DSA part even when Ed25519 is valid", () => {
    const s = signBoth(m);
    const other = signBoth(treasuryRootMessage("4", "ab".repeat(32)));
    expect(verifyHybrid(m, { ...s, mldsa65: other.mldsa65 }, PK).valid).toBe(false);
  });
  it("Ed25519-only is accepted unless pq is required", () => {
    const s = { ...signBoth(m), mldsa65: null };
    expect(verifyHybrid(m, s, PK)).toEqual({ valid: true, pq: false });
    expect(verifyHybrid(m, s, PK, { requirePq: true }).valid).toBe(false);
  });
  it("domain-separates roots from receipts", () => {
    const s = signBoth(m);
    expect(verifyHybridBytes(new TextEncoder().encode("rout.support.receipt.v1\n3\n" + "ab".repeat(32)), { ed25519: ed25519.sign(m, K.edSeed), mldsa65: null }, { ed25519: K.edPk, mldsa65: null }).valid).toBe(false);
    expect(verifyHybrid(m, { ...s, kid: "ffffffffffffffff" }, PK).valid).toBe(false);
  });
});

describe("supporter SD-JWT VC", () => {
  const signer = { kid: K.kid, sign: async (input: Uint8Array) => ed25519.sign(input, K.edSeed) };
  const verify = (i: Uint8Array, s: Uint8Array, kid: string) => kid === K.kid && ed25519.verify(s, i, K.edPk);
  const jti = "a".repeat(22);

  it("issues a verifiable credential; a presentation hides undisclosed claims", async () => {
    const { sdJwt } = await issueSupporterVc({ level: "public", handle: "@jona", supporter_index: 4, since: "2026-11", verified_human: true }, signer, { jti });
    const full = await verifySupporterVc(sdJwt, verify);
    expect(full).toMatchObject({ valid: true, claims: { level: "public", handle: "@jona", supporter_index: 4, verified_human: true } });
    const shown = await verifySupporterVc(presentSupporterVc(sdJwt, ["level", "handle"]), verify);
    expect(shown.valid && shown.claims).toEqual({ level: "public", handle: "@jona" });
  });
  it("pseudonymous credentials never carry a handle", async () => {
    await expect(issueSupporterVc({ level: "pseudonymous", handle: "@x", supporter_index: 1, since: "2026-11" }, signer, { jti })).rejects.toThrow("handle_forbidden");
  });
  it("rejects a tampered disclosure, a foreign key and an expired credential", async () => {
    const { sdJwt } = await issueSupporterVc({ level: "public", handle: "@jona", supporter_index: 4, since: "2026-11" }, signer, { jti, now: Date.UTC(2026, 0, 1) });
    const fake = b64uEncode(new TextEncoder().encode(JSON.stringify(["salt", "handle", "@mallory"])));
    expect(await verifySupporterVc(`${sdJwt}${fake}~`, verify, Date.UTC(2026, 1, 1))).toEqual({ valid: false, reason: "disclosure_not_signed" });
    const otherSeed = new Uint8Array(32).fill(1);
    expect((await verifySupporterVc(sdJwt, (i, s) => ed25519.verify(s, i, ed25519.getPublicKey(otherSeed)), Date.UTC(2026, 1, 1))).valid).toBe(false);
    expect(await verifySupporterVc(sdJwt, verify, Date.UTC(2027, 1, 1))).toEqual({ valid: false, reason: "expired" });
  });
});

describe("crypto worker ops", () => {
  it("support.verify_vc accepts only the issuer's key and kid", async () => {
    const signer = { kid: K.kid, sign: async (input: Uint8Array) => ed25519.sign(input, K.edSeed) };
    const { sdJwt } = await issueSupporterVc({ level: "public", handle: "@jona", supporter_index: 0, since: "2026-11" }, signer, { jti: "b".repeat(22) });
    const ok = await runEnclaveOp("support.verify_vc", { compact: sdJwt, edPublicKey: K.edPk.slice(), kid: K.kid, now: Date.now() });
    expect(ok).toMatchObject({ ok: true, result: { valid: true, claims: { handle: "@jona" } } });
    const wrongKid = await runEnclaveOp("support.verify_vc", { compact: sdJwt, edPublicKey: K.edPk.slice(), kid: "ffffffffffffffff", now: Date.now() });
    expect(wrongKid).toMatchObject({ ok: true, result: { valid: false } });
    const tampered = sdJwt.replace(/\.([A-Za-z0-9_-])/, (_m, c: string) => `.${c === "A" ? "B" : "A"}`);
    expect(await runEnclaveOp("support.verify_vc", { compact: tampered, edPublicKey: K.edPk.slice(), kid: K.kid, now: Date.now() })).toMatchObject({ ok: true, result: { valid: false } });
  });
  it("support.verify_inclusion checks Merkle path and the hybrid root signature", async () => {
    const t = new MemoryTree();
    const o = opening();
    const leaf = leafCommitment(o);
    t.append(leaf);
    t.append(leafCommitment(opening({ amountCents: 500 })));
    const root = toHex(t.root());
    const proof = { v: INCLUSION_PROOF_VERSION, index: "0", leaf: toHex(leaf), siblings: t.proof(0n).map(toHex), signedRoot: { size: "2", root, ...signBoth(treasuryRootMessage("2", root)) }, opening: o };
    const args = (p: unknown) => ({ proof: JSON.stringify(p), edPublicKey: K.edPk.slice(), pqPublicKey: K.pqPk.slice(), kid: K.kid });
    expect(await runEnclaveOp("support.verify_inclusion", args(proof))).toEqual({ ok: true, result: { valid: true, pq: true, reason: null } });
    const resigned = { ...proof, signedRoot: { ...proof.signedRoot, size: "3" } };
    expect(await runEnclaveOp("support.verify_inclusion", args(resigned))).toMatchObject({ ok: true, result: { valid: false, reason: "signature" } });
    expect(await runEnclaveOp("support.verify_inclusion", args({ ...proof, opening: { ...o, level: 1 } }))).toMatchObject({ ok: true, result: { valid: false, reason: "opening_mismatch" } });
  });
  it("support.verify_hybrid refuses non-transferable input", async () => {
    expect(await runEnclaveOp("support.verify_hybrid", { message: "x", ed25519: new Uint8Array(64), mldsa65: null, edPublicKey: K.edPk.slice(), pqPublicKey: null, requirePq: false })).toEqual({ ok: false, code: "invalid_input" });
  });
});

describe("signed receipt", () => {
  const r: SupportReceipt = {
    v: "rout.support.receipt.v1", id: "00000000-0000-4000-8000-000000000001", rail: "sepa", confirmedVia: "bunq", amountCents: 2500, currency: "EUR",
    paidAt: "2026-11-18T10:00:00.000Z", level: 2, supporterIndex: "7", txHash: transactionHash("bunq", "123", 2500, "2026-11-18T10:00:00.000Z"), treeSize: "8", treeRoot: "ab".repeat(32),
  };
  it("a changed amount breaks the signature", () => {
    const s = signBoth(receiptMessage(r));
    expect(verifyHybrid(receiptMessage(r), s, PK).valid).toBe(true);
    expect(verifyHybrid(receiptMessage({ ...r, amountCents: 25000 }), s, PK).valid).toBe(false);
  });
  it("the hashed transaction id is not the raw bunq id", () => {
    expect(r.txHash).toMatch(/^[0-9a-f]{64}$/);
    expect(r.txHash).not.toContain("123");
  });
  it("draws a PDF that carries the canonical record", () => {
    const labels = { title: "T", amount: "A", date: "D", method: "M", level: "L", index: "I", tx: "X", root: "R", notTax: "N", verify: "V", levelNames: { 1: "1", 2: "2", 3: "3" } as const };
    const pdf = new TextDecoder().decode(buildPdf(receiptLines({ receipt: r, signature: signBoth(receiptMessage(r)) }, labels)));
    expect(pdf.startsWith("%PDF-1.4")).toBe(true);
    expect(pdf).toContain("EUR 25.00");
    expect(pdf.trimEnd().endsWith("%%EOF")).toBe(true);
  });
});

describe("bunq callback", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const body = JSON.stringify({ NotificationUrl: { category: "PAYMENT", object: { Payment: { id: 991, amount: { value: "25.00", currency: "EUR" }, description: "+++100/0000/00135+++", counterparty_alias: { iban: "BE00", display_name: "X" } } } } });
  const sig = createSign("RSA-SHA256").update(body).sign(privateKey).toString("base64");

  it("accepts only bunq's server signature over the raw body", () => {
    expect(verifyBunqSignature(body, sig, pem)).toBe(true);
    expect(verifyBunqSignature(body.replace("25.00", "2500.00"), sig, pem)).toBe(false);
    expect(verifyBunqSignature(body, null, pem)).toBe(false);
  });
  it("extracts amount and structured communication, never the payer", () => {
    expect(parseBunqPayment(JSON.parse(body))).toEqual({ paymentId: "991", amountCents: 2500, ogm: "100000000135" });
  });
  it("ignores outgoing payments and other currencies", () => {
    const out = JSON.parse(body.replace('"25.00"', '"-25.00"'));
    expect(parseBunqPayment(out)).toBeNull();
    expect(parseBunqPayment(JSON.parse(body.replace('"EUR"', '"USD"')))).toBeNull();
  });
});

describe("coverage, amounts, partners, DNSSEC", () => {
  it("shows no percentage without real costs, and floors it otherwise", () => {
    expect(coverage(5000, [])).toEqual({ state: "unknown", collectedCents: 5000 });
    expect(coverage(3333, [{ provider: "x", cents: 10000 }])).toEqual({ state: "known", collectedCents: 3333, costCents: 10000, percent: 33, shortfallCents: 6667 });
  });
  it("uses the owner's baseline of €150.90 a month", () => {
    expect(Object.fromEntries(MONTHLY_COSTS.map((c) => [c.provider, c.cents]))).toEqual({
      "Infomaniak Cloud & Mail": 4850,
      "Scaleway S3 Multi-Region Vault": 2840,
      "Neon Serverless Postgres": 2900,
      "Didit NFC API & Liveness": 4500,
    });
    expect(coverage(0)).toMatchObject({ state: "known", costCents: 15090, percent: 0, shortfallCents: 15090 });
    expect(coverage(7545)).toMatchObject({ percent: 50, shortfallCents: 7545 });
    expect(coverage(15090)).toMatchObject({ percent: 100, shortfallCents: 0 });
  });
  it("accepts whole cents between €1 and €5,000", () => {
    expect(resolveSupportAmount(100)).toBe(100);
    expect(resolveSupportAmount(500_000)).toBe(500_000);
    expect(resolveSupportAmount(99)).toBeNull();
    expect(resolveSupportAmount(500_001)).toBeNull();
    expect(resolveSupportAmount(10.5)).toBeNull();
  });
  it("lists suppliers as suppliers, never as partners", () => {
    for (const p of PARTNERS.filter((x) => x.group === "infrastructure")) expect(p.relationship).toBe("supplier");
  });
  it("reads the resolver's AD flag and RCODE from the wire answer", () => {
    const head = (b2: number, b3: number) => new Uint8Array([0, 0, b2, b3, 0, 1, 0, 1, 0, 0, 0, 1]);
    expect(dnssecFromWire(head(0x81, 0xa0))).toBe("valid");
    expect(dnssecFromWire(head(0x81, 0x80))).toBe("unsigned");
    expect(dnssecFromWire(head(0x81, 0x82))).toBe("unknown"); // SERVFAIL (bogus chain)
    expect(dnssecFromWire(head(0x01, 0xa0))).toBe("unknown"); // not a response
    const q = dnsQuery("rout.be");
    expect(Array.from(q.slice(12, 20))).toEqual([4, 114, 111, 117, 116, 2, 98, 101]);
    expect(q[q.length - 4]).toBe(0x80); // DO bit
  });
});
