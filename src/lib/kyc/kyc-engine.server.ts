/**
 * Didit KYC engine (server-only), zero plaintext PII.
 *
 *   start    signed-in member -> identity_verification_sessions row (own RLS context) -> Didit v3
 *            session with an opaque sealed vendor_data -> { session_url, session_token }
 *   webhook  raw bytes -> HMAC-SHA256 + 300 s window -> status.updated -> the member named by the
 *            sealed vendor_data -> Approved: decision re-fetched from Didit (the webhook body is
 *            never trusted for identity data) -> canonical ICAO/eIDAS anchors -> universal
 *            nullifiers -> Neon -> anchors zero-filled
 *   status   none | pending | verified, from Neon only
 *
 * Stored: the nullifier (identity_verifications.unique_human_id, and with db/0288 one row
 * per anchor in verified_identity_nullifiers), provider, is_real_human, jurisdiction, and from
 * db/0290 the age floor (whole years, capped at 21), and the document name only as ciphertext
 * (profiles.legal_*_sealed, legal-name-vault.server.ts; owner directive 2026-11-18). Never stored
 * in plaintext or logged: names, document or personal numbers, the date of birth, images, the
 * decision body.
 * Raw webhook bytes, decision bytes, canonical anchors and the pepper copy are Node.js Buffers
 * (secure-buffer.ts) and are zero-filled with fill(0) right after use; the anchors immediately
 * after the nullifiers are computed. JavaScript strings parsed from the provider response cannot be
 * overwritten; they are dropped right after reading.
 * Pepper: IDENTITY_HASH_PEPPER or PEPPER_SECRET (pepper.server.ts).
 */
import { Buffer } from "node:buffer";
import { ageFloorFromVector } from "./age-vector";
import { canonicalAnchors, wipeAnchors, type CanonicalAnchor } from "./canonical-id";
import { readDiditDecision, type KycState } from "./didit-decision";
import { verifyDiditSignature } from "./didit-signature";
import { universalNullifier } from "./nullifier";
import { identityPepper, readPepper } from "./pepper.server";
import { isWiped, secretBuffer, wipe } from "./secure-buffer";
import { openVendorRef, sealVendorRef } from "./vendor-ref";

export type StartResult =
  | { ok: true; session_url: string; session_token: string }
  | { ok: false; reason: "not_configured" | "already_verified" | "limit_reached" | "provider_error" };

export type AttestResult =
  | "verified"
  | "already_verified"
  | "duplicate_human"
  | "identity_already_attested_across_providers"
  | "limit_reached"
  | "no_document"
  | "session_unknown";

const MAX_BODY = 256 * 1024;
const PENDING_REVIEW_HOURS = 72;

const pepper = () => identityPepper();

async function inMemberContext<T>(userId: string, fn: () => Promise<T>): Promise<T> {
  const { withDbContext } = await import("@/lib/neon");
  return withDbContext({ userId, workspaceId: null }, fn);
}

export async function startDiditKyc(userId: string, originInput: string | null): Promise<StartResult> {
  const id = await import("@/lib/identity/identity.server");
  if (!id.providerConfigured("didit") || !readPepper().ok) return { ok: false, reason: "not_configured" };
  const { verificationDecision } = await import("@/lib/identity/identity-tiers");
  const { diditAvailable } = await import("@/lib/identity/identity-rules");
  const { trustedOrigin } = await import("@/lib/safe-redirect");
  const origin = trustedOrigin(originInput ?? "", { allowDev: process.env["VERCEL_ENV"] !== "production" }) ?? "https://rout.be";
  return inMemberContext(userId, async () => {
    if (verificationDecision(await id.getIdentityStatus(userId), "didit") === "reject") return { ok: false, reason: "already_verified" };
    if (!diditAvailable(await id.diditSuccessCount())) return { ok: false, reason: "limit_reached" };
    // One open Didit session per member, so the status endpoint can see a decline; a hosted Didit
    // flow can take longer than the generic 30-minute session window.
    const { sql } = await import("@/lib/neon");
    await sql`delete from public.identity_verification_sessions where user_id = ${userId} and provider = 'didit'`;
    const state = await id.createSession(userId, "didit", null);
    await sql`update public.identity_verification_sessions set expires_at = now() + interval '24 hours'
      where state = ${state} and provider = 'didit'`;
    const { createDiditSession, DiditError } = await import("./didit-client.server");
    try {
      const s = await createDiditSession({ vendorData: sealVendorRef(userId, state, pepper()), callback: `${origin}/verify/handle-select` });
      return { ok: true, session_url: s.url, session_token: s.sessionToken };
    } catch (e) {
      await sql`delete from public.identity_verification_sessions where state = ${state}`.catch(() => undefined);
      if (e instanceof DiditError && e.code === "not_configured") return { ok: false, reason: "not_configured" };
      return { ok: false, reason: "provider_error" };
    }
  });
}

/**
 * realHuman mirrors the green "Real Human" shield (zero-knowledge proofs only, never KYC); the KYC
 * result itself is legalIdentity, the blue "KYC Attested" shield.
 */
export async function kycStatus(userId: string): Promise<{ state: KycState; realHuman: boolean; legalIdentity: boolean }> {
  const id = await import("@/lib/identity/identity.server");
  const { readPublicIdentity } = await import("@/lib/identity/public-identity.server");
  const realHuman = (await readPublicIdentity(userId).catch(() => ({ realHuman: false }))).realHuman;
  return inMemberContext(userId, async () => {
    const s = await id.getIdentityStatus(userId);
    if (s.tier2LegalIdentity) return { state: "verified", realHuman, legalIdentity: true };
    const { sql } = await import("@/lib/neon");
    const rows = (await sql`select 1 as x from public.identity_verification_sessions
      where user_id = ${userId} and provider = 'didit' and expires_at > now() limit 1`.catch(() => [])) as unknown[];
    return { state: rows.length ? "pending" : "none", realHuman, legalIdentity: false };
  });
}

/**
 * Registers the nullifiers for the member in the active context. Exported for tests; the webhook
 * is its only production caller.
 */
export async function attestDidit(input: {
  userId: string;
  state: string;
  nullifiers: readonly string[];
  kinds: readonly CanonicalAnchor["kind"][];
  isRealHuman: boolean;
  jurisdiction: string;
  /** Capped age in whole years (derived from the age vector, kyc/age-vector.ts), recorded only from db/0290 on. */
  ageFloor?: number | null;
  /**
   * Runs after the identity rows are written and before the session is consumed (also when a
   * redelivery finds the member already verified), so a failure answers 503 and Didit retries.
   */
  afterAttest?: () => Promise<void>;
}): Promise<AttestResult> {
  const { sql } = await import("@/lib/neon");
  const id = await import("@/lib/identity/identity.server");
  const { DIDIT_MONTHLY_LIMIT } = await import("@/lib/identity/identity-rules");
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");

  // Every step below is idempotent, and the session row is consumed only at the very end: a
  // transient failure answers 503, Didit redelivers, and the retry finds the session again.
  const open = (await sql`select user_id from public.identity_verification_sessions
      where state = ${input.state} and provider = 'didit' and expires_at > now() limit 1`) as { user_id: string }[];
  if (open[0]?.user_id !== input.userId) {
    const s = await id.getIdentityStatus(input.userId);
    return s.tier2LegalIdentity ? "already_verified" : "session_unknown";
  }
  const { verificationDecision } = await import("@/lib/identity/identity-tiers");
  if (verificationDecision(await id.getIdentityStatus(input.userId), "didit") === "reject") {
    // A redelivery after a failed afterAttest lands here: finish that step first.
    await input.afterAttest?.();
    await id.consumeSession(input.state, "didit");
    return "already_verified";
  }

  const [bumped] = (await sql`select public.rout_didit_usage_bump(${DIDIT_MONTHLY_LIMIT}::int) as ok`) as { ok: boolean }[];
  if (bumped?.ok !== true) {
    await id.consumeSession(input.state, "didit");
    return "limit_reached";
  }
  const release = () => sql`select public.rout_didit_usage_release()`.catch(() => undefined);

  try {
    if (await hasSchemaFeature("0288")) {
      const age = await hasSchemaFeature("0290");
      const [r] = (age
        ? await sql`select public.rout_kyc_attest('didit', ${[...input.nullifiers]}::text[], ${[...input.kinds]}::text[],
            ${input.isRealHuman}, true, ${input.jurisdiction}, ${input.ageFloor ?? null}::smallint) as code`
        : await sql`select public.rout_kyc_attest('didit', ${[...input.nullifiers]}::text[], ${[...input.kinds]}::text[],
            ${input.isRealHuman}, true, ${input.jurisdiction}) as code`) as { code: string }[];
      if (r?.code === "identity_already_attested_across_providers" || r?.code === "duplicate_human") {
        await release();
        await id.consumeSession(input.state, "didit");
        return r.code;
      }
      if (r?.code !== "ok") throw new Error(`kyc_attest_${r?.code ?? "failed"}`);
    }
    try {
      await sql`insert into public.identity_verifications
          (user_id, is_verified, verified_real_name, verification_provider, unique_human_id, verified_at, updated_at)
        values (${input.userId}, true, null, 'didit', ${input.nullifiers[0]!}, now(), now())
        on conflict (user_id) do update set is_verified = true, verified_real_name = null,
          verification_provider = 'didit', unique_human_id = excluded.unique_human_id, verified_at = now(), updated_at = now()
        where identity_verifications.is_verified = false`;
    } catch (error) {
      const code = (error as { code?: unknown })?.code;
      if (code === "23505") {
        await release();
        await id.consumeSession(input.state, "didit");
        return "duplicate_human";
      }
      throw error;
    }
    await input.afterAttest?.();
  } catch (error) {
    await release();
    throw error;
  }
  await id.consumeSession(input.state, "didit");
  return "verified";
}

function json(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

/** POST handler for /api/v1/kyc/didit/webhook (and the legacy /api/public/identity/didit-webhook). */
export async function handleDiditWebhook(request: Request): Promise<Response> {
  const secret = process.env["DIDIT_WEBHOOK_SECRET"];
  if (!secret) return json({ error: "not_configured" }, 503);
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > MAX_BODY) return json({ error: "too_large" }, 413);
  // Buffer.from(ArrayBuffer) shares the request's memory, so fill(0) below wipes the only copy.
  const raw = Buffer.from(await request.arrayBuffer());
  if (raw.length > MAX_BODY) {
    raw.fill(0);
    return json({ error: "too_large" }, 413);
  }
  const check = verifyDiditSignature({
    raw,
    secret,
    signature: request.headers.get("x-signature"),
    previousSignature: request.headers.get("x-signature-previous"),
    timestamp: request.headers.get("x-timestamp"),
  });
  if (!check.ok) {
    raw.fill(0);
    return json({ error: "unauthorized" }, 401);
  }

  let event: Record<string, unknown>;
  try {
    event = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)) as Record<string, unknown>;
  } catch {
    return json({ error: "bad_request" }, 400);
  } finally {
    raw.fill(0);
  }
  const type = event["webhook_type"];
  const status = typeof event["status"] === "string" ? event["status"] : "";
  const sessionId = typeof event["session_id"] === "string" ? event["session_id"] : "";
  const vendorData = typeof event["vendor_data"] === "string" ? event["vendor_data"] : "";
  // The decision in the body is dropped unread: only the re-fetched decision counts.
  delete event["decision"];
  if (type !== undefined && type !== "status.updated") return json({ ok: true, ignored: "event" });
  if (!sessionId || !status) return json({ ok: true, ignored: "shape" });

  let ref: { userId: string; state: string } | null;
  try {
    ref = openVendorRef(vendorData, pepper());
  } catch {
    return json({ error: "not_configured" }, 503);
  }
  if (!ref) return json({ ok: true, ignored: "reference" });
  const member = ref;

  try {
    return await inMemberContext(member.userId, async () => {
      const { sql } = await import("@/lib/neon");
      if (status === "Declined" || status === "Abandoned" || status === "Expired" || status === "Kyc Expired") {
        await sql`delete from public.identity_verification_sessions where state = ${member.state} and provider = 'didit'`;
        return json({ ok: true, result: "closed" });
      }
      if (status === "In Review" || status === "Resubmitted") {
        await sql`update public.identity_verification_sessions
          set expires_at = greatest(expires_at, now() + make_interval(hours => ${PENDING_REVIEW_HOURS}::int))
          where state = ${member.state} and provider = 'didit'`;
        return json({ ok: true, result: "pending" });
      }
      if (status !== "Approved") return json({ ok: true, ignored: "status" });
      return json({ ok: true, result: await approve(member, sessionId, vendorData) });
    });
  } catch (e) {
    const { DiditError } = await import("./didit-client.server");
    const code = e instanceof DiditError ? e.code : "internal";
    console.error(`[kyc] webhook failed: ${code}`);
    // 503 makes Didit retry (twice, after ~1 and ~4 minutes); nothing was written for this event.
    return json({ error: "retry" }, 503);
  }
}

async function approve(member: { userId: string; state: string }, sessionId: string, vendorData: string): Promise<AttestResult> {
  const { fetchDiditDecision } = await import("./didit-client.server");
  let decision: unknown = await fetchDiditDecision(sessionId);
  const reading = readDiditDecision(decision, { sessionId, vendorData });
  decision = null;
  if (!reading.ok) {
    if (reading.reason === "not_approved") return "session_unknown";
    return "no_document";
  }
  const anchors = canonicalAnchors(reading.claims);
  reading.claims = {};
  // The document name moves into unpooled Buffers at once; the parsed strings are dropped here
  // (V8 strings cannot be overwritten) and the Buffers are zero-filled in finally.
  const nameBytes = reading.legalName ? { first: secretBuffer(reading.legalName.first), last: secretBuffer(reading.legalName.last) } : null;
  reading.legalName = null;
  try {
    if (!anchors.length) return "no_document";
    const p = pepper();
    const nullifiers = anchors.map((a) => universalNullifier(a.bytes, p));
    // Destroy the canonical identifiers the moment the nullifiers exist, before any database call.
    const kinds = anchors.map((a) => a.kind);
    for (const a of anchors) a.bytes.fill(0);
    if (!anchors.every((a) => isWiped(a.bytes))) throw new Error("kyc_wipe_failed");
    return await attestDidit({
      userId: member.userId,
      state: member.state,
      nullifiers,
      kinds,
      isRealHuman: reading.isRealHuman,
      jurisdiction: reading.jurisdiction,
      ageFloor: ageFloorFromVector(reading.ageVector),
      afterAttest: nameBytes
        ? async () => {
            const { storeSealedLegalName } = await import("./legal-name-vault.server");
            await storeSealedLegalName(member.userId, nameBytes);
          }
        : undefined,
    });
  } finally {
    wipeAnchors(anchors);
    wipe(...anchors.map((a) => a.bytes), nameBytes?.first, nameBytes?.last);
  }
}
