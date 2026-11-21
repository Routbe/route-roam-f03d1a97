import { Buffer } from "node:buffer";
import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/* ---- in-memory stand-ins for Neon, the identity store and the Didit API ---- */
type Call = { query: string; params: unknown[]; userId: string | null };
const db = vi.hoisted(() => ({
  calls: [] as Call[],
  sessions: new Map<string, { user_id: string }>(),
  attestCode: "ok",
  insertError: null as null | { code: string },
  bump: true,
  verified: false,
  ctx: null as string | null,
}));
const didit = vi.hoisted(() => ({ decision: null as unknown, fail: false }));
/** Canonical anchors handed out by canonical-id, and whether they were wiped when Neon was first written. */
const cap = vi.hoisted(() => ({ anchors: [] as { bytes: Uint8Array }[], wipedAtAttest: null as boolean | null }));

vi.mock("@/lib/neon", () => {
  const run = async (query: string, params: unknown[]) => {
    db.calls.push({ query, params, userId: db.ctx });
    if (/select user_id from public.identity_verification_sessions/.test(query)) {
      const s = db.sessions.get(params[0] as string);
      return s ? [s] : [];
    }
    if (/rout_didit_usage_bump/.test(query)) return [{ ok: db.bump }];
    if (/rout_kyc_attest/.test(query)) {
      cap.wipedAtAttest = cap.anchors.length > 0 && cap.anchors.every((a) => a.bytes.every((b) => b === 0));
      return [{ code: db.attestCode }];
    }
    if (/insert into public.identity_verifications/.test(query)) {
      if (db.insertError) throw Object.assign(new Error("temporary"), db.insertError);
      db.verified = true;
      return [];
    }
    if (/delete from public.identity_verification_sessions where state/.test(query)) {
      db.sessions.delete(params[0] as string);
      return [];
    }
    return [];
  };
  const sql = (strings: TemplateStringsArray, ...values: unknown[]) => {
    const query = strings.reduce((q, s, i) => q + s + (i < values.length ? `$${i + 1}` : ""), "");
    const p = run(query, values);
    return Object.assign(p, { catch: p.catch.bind(p) });
  };
  return {
    sql,
    withDbContext: async (ctx: { userId: string }, fn: () => Promise<unknown>) => {
      const prev = db.ctx;
      db.ctx = ctx.userId;
      try {
        return await fn();
      } finally {
        db.ctx = prev;
      }
    },
  };
});
vi.mock("@/lib/identity/identity.server", () => ({
  providerConfigured: () => true,
  diditSuccessCount: async () => 0,
  getIdentityStatus: async () => ({ tier1RealHuman: db.verified, tier2LegalIdentity: db.verified, provider: db.verified ? "didit" : null }),
  createSession: async (userId: string) => {
    const state = "cd".repeat(24);
    db.sessions.set(state, { user_id: userId });
    return state;
  },
  consumeSession: async (state: string) => {
    const s = db.sessions.get(state) ?? null;
    db.sessions.delete(state);
    return s;
  },
}));
vi.mock("@/lib/schema-features.server", () => ({ hasSchemaFeature: async () => true }));
/** Sealed-name writes: the buffers handed over, the member context, and an optional failure. */
const vault = vi.hoisted(() => ({ calls: [] as { userId: string; ctx: string | null; first: Uint8Array; last: Uint8Array; plain: string }[], fail: false }));
vi.mock("./legal-name-vault.server", () => ({
  storeSealedLegalName: async (userId: string, name: { first: Uint8Array; last: Uint8Array }) => {
    if (vault.fail) throw new Error("temporary");
    const dec = new TextDecoder();
    vault.calls.push({ userId, ctx: db.ctx, first: name.first, last: name.last, plain: `${dec.decode(name.first)} ${dec.decode(name.last)}` });
    return true;
  },
}));
vi.mock("./canonical-id", async (importOriginal) => {
  const real = await importOriginal<typeof import("./canonical-id")>();
  return {
    ...real,
    canonicalAnchors: (claims: Parameters<typeof real.canonicalAnchors>[0]) => {
      const out = real.canonicalAnchors(claims);
      cap.anchors.push(...out);
      return out;
    },
  };
});
vi.mock("./didit-client.server", () => {
  class DiditError extends Error {
    constructor(readonly code: string, readonly status: number) { super(code); }
  }
  return {
    DiditError,
    createDiditSession: async () => ({ sessionId: "s1", sessionToken: "tok", url: "https://verify.didit.me/session/tok" }),
    fetchDiditDecision: async () => {
      if (didit.fail) throw new DiditError("provider_unreachable", 0);
      return didit.decision;
    },
  };
});

import { handleDiditWebhook } from "./kyc-engine.server";
import { sealVendorRef } from "./vendor-ref";

const SECRET = "whsec_" + "w".repeat(40);
const PEPPER = "pepper-".repeat(8);
const USER = "0b1c2d3e-4f50-4617-8899-aabbccddeeff";
const STATE = "ab".repeat(24);
const SESSION = "11111111-2222-3333-4444-555555555555";
const PII = ["Carmen", "Española", "CAA000000", "99999999R", "1980-01-01"];

function decisionFor(vendorData: string) {
  return {
    session_id: SESSION, vendor_data: vendorData, status: "Approved",
    id_verifications: [{ status: "Approved", document_type: "Identity Card", document_number: "CAA000000", personal_number: "99999999R", issuing_state: "ESP", nationality: "ESP", first_name: "Carmen", last_name: "Española", date_of_birth: "1980-01-01" }],
    liveness_checks: [{ status: "Approved" }],
    face_matches: [{ status: "Approved" }],
  };
}

function signed(body: unknown, opts: { secret?: string; ts?: number; sig?: string } = {}) {
  const raw = JSON.stringify(body);
  const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
  const sig = opts.sig ?? createHmac("sha256", opts.secret ?? SECRET).update(raw).digest("hex");
  return new Request("https://rout.be/api/v1/kyc/didit/webhook", { method: "POST", body: raw, headers: { "x-signature": sig, "x-timestamp": ts, "content-type": "application/json" } });
}

let logs: string[] = [];
beforeEach(() => {
  process.env["DIDIT_WEBHOOK_SECRET"] = SECRET;
  process.env["IDENTITY_HASH_PEPPER"] = PEPPER;
  delete process.env["PEPPER_SECRET"];
  cap.anchors = [];
  cap.wipedAtAttest = null;
  db.calls = [];
  db.sessions = new Map([[STATE, { user_id: USER }]]);
  db.attestCode = "ok";
  db.insertError = null;
  db.bump = true;
  db.verified = false;
  didit.fail = false;
  vault.calls = [];
  vault.fail = false;
  logs = [];
  for (const m of ["log", "info", "warn", "error"] as const) vi.spyOn(console, m).mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(" ")); });
});
afterEach(() => vi.restoreAllMocks());

const event = (vendorData: string, status = "Approved", extra: Record<string, unknown> = {}) => ({
  event_id: "e1", session_id: SESSION, status, webhook_type: "status.updated", timestamp: Math.floor(Date.now() / 1000), vendor_data: vendorData, ...extra,
});

describe("Didit webhook", () => {
  it("answers 401 to a missing, wrong or stale signature and writes nothing", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    for (const req of [
      signed(event(ref), { sig: "0".repeat(64) }),
      signed(event(ref), { secret: "other-secret" }),
      signed(event(ref), { ts: Math.floor(Date.now() / 1000) - 301 }),
      new Request("https://rout.be/x", { method: "POST", body: "{}" }),
    ]) {
      expect((await handleDiditWebhook(req)).status).toBe(401);
    }
    expect(db.calls).toEqual([]);
  });

  it("re-fetches the decision, stores only nullifiers and never leaks PII", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    // A forged decision inside the body must be ignored.
    const res = await handleDiditWebhook(signed(event(ref, "Approved", { decision: { id_verifications: [{ document_number: "FORGED999" }] } })));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body).toEqual({ ok: true, result: "verified" });

    const attest = db.calls.find((c) => /rout_kyc_attest/.test(c.query))!;
    const nullifiers = attest.params[0] as string[];
    expect(nullifiers).toHaveLength(2);
    for (const n of nullifiers) expect(n).toMatch(/^[0-9a-f]{64}$/);
    expect(attest.params[1]).toEqual(["personal_number", "document"]);
    expect(attest.params.slice(2)).toEqual([true, "ESP", 21]);
    expect(attest.userId).toBe(USER);

    const flat = JSON.stringify(db.calls) + JSON.stringify(body) + logs.join("\n");
    for (const v of [...PII, "FORGED999"]) expect(flat).not.toContain(v);
    expect(db.verified).toBe(true);
    expect(db.sessions.has(STATE)).toBe(false);
  });

  it("refuses a cross-provider duplicate with the exact code and releases the usage slot", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    db.attestCode = "identity_already_attested_across_providers";
    const res = await handleDiditWebhook(signed(event(ref)));
    expect(await res.json()).toEqual({ ok: true, result: "identity_already_attested_across_providers" });
    expect(db.calls.some((c) => /rout_didit_usage_release/.test(c.query))).toBe(true);
    expect(db.verified).toBe(false);
  });

  it("answers 503 on a transient failure and keeps the session for Didit's retry", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    db.insertError = { code: "08006" };
    expect((await handleDiditWebhook(signed(event(ref)))).status).toBe(503);
    expect(db.sessions.has(STATE)).toBe(true);
    db.insertError = null;
    expect(await (await handleDiditWebhook(signed(event(ref)))).json()).toEqual({ ok: true, result: "verified" });

    didit.fail = true;
    db.sessions.set(STATE, { user_id: USER });
    db.verified = false;
    expect((await handleDiditWebhook(signed(event(ref)))).status).toBe(503);
    expect(logs.join("\n")).toContain("provider_unreachable");
  });

  it("closes the session on a decline and ignores unknown references and other events", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    expect(await (await handleDiditWebhook(signed(event(ref, "Declined")))).json()).toEqual({ ok: true, result: "closed" });
    expect(db.sessions.has(STATE)).toBe(false);
    expect(await (await handleDiditWebhook(signed(event("someone-else")))).json()).toEqual({ ok: true, ignored: "reference" });
    expect(await (await handleDiditWebhook(signed({ ...event(ref), webhook_type: "data.updated" }))).json()).toEqual({ ok: true, ignored: "event" });
  });

  it("refuses a decision whose vendor reference does not match the webhook", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor("rk1.other");
    expect(await (await handleDiditWebhook(signed(event(ref)))).json()).toEqual({ ok: true, result: "no_document" });
    expect(db.verified).toBe(false);
  });

  it("hashes Node.js Buffer anchors and zero-fills them with fill(0) before the first database write", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    expect(await (await handleDiditWebhook(signed(event(ref)))).json()).toEqual({ ok: true, result: "verified" });
    expect(cap.anchors).toHaveLength(2);
    for (const a of cap.anchors) expect(Buffer.isBuffer(a.bytes)).toBe(true);
    expect(cap.wipedAtAttest).toBe(true);
  });

  it("reads the webhook body into a Buffer and zero-fills it, also when the signature fails", async () => {
    const seen: Buffer[] = [];
    const from = Buffer.from.bind(Buffer);
    vi.spyOn(Buffer, "from").mockImplementation(((...args: Parameters<typeof Buffer.from>) => {
      const b = (from as (...a: unknown[]) => Buffer)(...args);
      if (args[0] instanceof ArrayBuffer) seen.push(b);
      return b;
    }) as typeof Buffer.from);
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    await handleDiditWebhook(signed(event(ref)));
    await handleDiditWebhook(signed(event(ref), { sig: "0".repeat(64) }));
    expect(seen.length).toBeGreaterThanOrEqual(2);
    for (const b of seen) {
      expect(b.length).toBeGreaterThan(0);
      expect(b.every((x) => x === 0)).toBe(true);
    }
  });

  it("accepts PEPPER_SECRET instead of IDENTITY_HASH_PEPPER and derives the same nullifiers", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    await handleDiditWebhook(signed(event(ref)));
    const first = db.calls.find((c) => /rout_kyc_attest/.test(c.query))!.params[0];

    delete process.env["IDENTITY_HASH_PEPPER"];
    process.env["PEPPER_SECRET"] = PEPPER;
    db.calls = [];
    db.verified = false;
    db.sessions.set(STATE, { user_id: USER });
    expect(await (await handleDiditWebhook(signed(event(ref)))).json()).toEqual({ ok: true, result: "verified" });
    expect(db.calls.find((c) => /rout_kyc_attest/.test(c.query))!.params[0]).toEqual(first);
  });

  it("refuses to run with two different peppers", async () => {
    process.env["PEPPER_SECRET"] = `${PEPPER}-other`;
    const ref = sealVendorRef(USER, STATE, PEPPER);
    expect((await handleDiditWebhook(signed(event(ref)))).status).toBe(503);
    expect(db.calls).toEqual([]);
  });

  it("is not configured without the webhook secret", async () => {
    delete process.env["DIDIT_WEBHOOK_SECRET"];
    expect((await handleDiditWebhook(signed(event("x")))).status).toBe(503);
  });

  it("seals the document name for the member right after attestation and zero-fills the name buffers", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    expect(await (await handleDiditWebhook(signed(event(ref)))).json()).toEqual({ ok: true, result: "verified" });
    expect(vault.calls).toHaveLength(1);
    const c = vault.calls[0]!;
    expect(c.userId).toBe(USER);
    expect(c.ctx).toBe(USER);
    expect(c.plain).toBe("Carmen Española");
    for (const b of [c.first, c.last]) {
      expect(Buffer.isBuffer(b)).toBe(true);
      expect(b.every((x) => x === 0)).toBe(true);
    }
    expect(JSON.stringify(db.calls)).not.toContain("Carmen");
  });

  it("reads the ICAO given_names / family_name of a chip read", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    const d = decisionFor(ref);
    const { first_name: _f, last_name: _l, ...doc } = d.id_verifications[0]!;
    didit.decision = { ...d, id_verifications: [], nfc_verifications: [{ ...doc, given_names: "Jona", family_name: "Delplanche" }] };
    expect(await (await handleDiditWebhook(signed(event(ref)))).json()).toEqual({ ok: true, result: "verified" });
    expect(vault.calls[0]?.plain).toBe("Jona Delplanche");
  });

  it("a failed seal answers 503 and the redelivery stores the name before closing the session", async () => {
    const ref = sealVendorRef(USER, STATE, PEPPER);
    didit.decision = decisionFor(ref);
    vault.fail = true;
    expect((await handleDiditWebhook(signed(event(ref)))).status).toBe(503);
    expect(db.sessions.has(STATE)).toBe(true);
    vault.fail = false;
    const retry = (await (await handleDiditWebhook(signed(event(ref)))).json()) as { ok: boolean; result: string };
    expect(retry.ok).toBe(true);
    expect(["verified", "already_verified"]).toContain(retry.result);
    expect(vault.calls).toHaveLength(1);
    expect(db.sessions.has(STATE)).toBe(false);
  });
});
