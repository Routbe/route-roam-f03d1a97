/**
 * OpenID for Verifiable Presentations 1.0 verifier (server-only), cross-device: a member starts a
 * request in the Developer Console, the wallet scans `openid4vp://…` and posts its vp_token to the
 * response endpoint (response_mode direct_post), and the console reads the checked result.
 *
 * Client identifier prefix `redirect_uri:` (unsigned request, passed by value). Production EUDI
 * wallets additionally require a registered relying-party access certificate (x509_san_dns),
 * which only the owner can obtain; until then this works with wallets in test mode.
 * Only credentials issued by ROUT itself are trusted: issuer key, holder binding (KB-JWT with this
 * request's nonce and client_id), status list and the rout_pq hybrid signature are all checked.
 */
import { b64uEncode } from "@/lib/support/hybrid-signature";
import { STATUS_LIST_ID } from "./status-list";
import { VERIFIED_HUMAN_CLAIMS, VERIFIED_HUMAN_VCT, verifySdJwtVc, type VerifiedHumanClaim } from "./sd-jwt-vc";
import { statusListUri } from "./status-list.server";

export const DCQL_CREDENTIAL_ID = "rout";
const token32 = () => b64uEncode(crypto.getRandomValues(new Uint8Array(32)));
const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : v == null ? null : String(v));

async function ready(): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  return hasSchemaFeature("0294");
}

export const responseUriOf = (iss: string, id: string) => `${iss}/api/public/oauth/vp/response/${id}`;
export const clientIdOf = (iss: string, id: string) => `redirect_uri:${responseUriOf(iss, id)}`;

export function dcqlFor(claims: readonly VerifiedHumanClaim[]) {
  return {
    credentials: [
      {
        id: DCQL_CREDENTIAL_ID,
        format: "dc+sd-jwt",
        meta: { vct_values: [VERIFIED_HUMAN_VCT] },
        claims: claims.map((c) => ({ path: [c] })),
      },
    ],
  };
}

export type VpStartResult = { ok: true; id: string; url: string; expiresAt: string } | { ok: false; reason: "not_ready" | "unavailable" };

export async function createVpRequest(userId: string, iss: string, input: { label: string; claims: VerifiedHumanClaim[] }): Promise<VpStartResult> {
  if (!(await ready())) return { ok: false, reason: "not_ready" };
  const claims = [...new Set(input.claims)].filter((c) => (VERIFIED_HUMAN_CLAIMS as readonly string[]).includes(c));
  if (claims.length === 0) return { ok: false, reason: "unavailable" };
  const nonce = token32();
  const state = token32();
  const dcql = dcqlFor(claims);
  const { sql, withDbContext } = await import("@/lib/neon");
  const id = await withDbContext({ userId, workspaceId: null }, async () => {
    const rows = (await sql`select public.rout_vp_request_create(${input.label}, ${nonce}, ${state}, ${JSON.stringify(dcql)}::jsonb) as id`) as { id: string | null }[];
    return rows[0]?.id ?? null;
  });
  if (!id) return { ok: false, reason: "unavailable" };
  const responseUri = responseUriOf(iss, id);
  const params = new URLSearchParams({
    client_id: clientIdOf(iss, id),
    response_type: "vp_token",
    response_mode: "direct_post",
    response_uri: responseUri,
    nonce,
    state,
    dcql_query: JSON.stringify(dcql),
  });
  return { ok: true, id, url: `openid4vp://?${params.toString()}`, expiresAt: new Date(Date.now() + 10 * 60_000).toISOString() };
}

export type ClaimValue = string | number | boolean | null;
export type VpCheck = {
  valid: boolean;
  reason: string | null;
  claims: Record<string, ClaimValue>;
  missing: string[];
  holderBinding: boolean;
  status: "valid" | "revoked" | "unknown";
  pq: boolean;
  issuer: string;
  vct: string;
  checkedAt: string;
};

/** Checks one presentation against a request; pure apart from the injected lookups. */
export async function checkPresentation(
  presentation: unknown,
  ctx: {
    iss: string;
    clientId: string;
    nonce: string;
    requested: readonly string[];
    issuerKey: (kid: string) => import("./jose").PublicJwk | null;
    isActive: (idx: number) => Promise<boolean>;
    verifyPq: (line: string, sig: import("@/lib/support/hybrid-signature").HybridSignature) => Promise<boolean>;
    now?: number;
  },
): Promise<VpCheck> {
  const now = ctx.now ?? Date.now();
  const base = { claims: {}, missing: [...ctx.requested], holderBinding: false, status: "unknown" as const, pq: false, issuer: ctx.iss, vct: VERIFIED_HUMAN_VCT, checkedAt: new Date(now).toISOString() };
  if (typeof presentation !== "string") return { ...base, valid: false, reason: "malformed" };
  const r = await verifySdJwtVc(presentation, {
    issuer: ctx.iss,
    vct: VERIFIED_HUMAN_VCT,
    issuerKey: ctx.issuerKey,
    now,
    keyBinding: { aud: ctx.clientId, nonce: ctx.nonce },
    verifyPq: ctx.verifyPq,
  });
  if (!r.valid) return { ...base, valid: false, reason: r.reason };
  const missing = ctx.requested.filter((c) => !Object.hasOwn(r.claims, c));
  const status = r.status && r.status.uri === statusListUri(ctx.iss) ? ((await ctx.isActive(r.status.idx)) ? "valid" : "revoked") : "unknown";
  const valid = missing.length === 0 && status === "valid" && r.pq;
  return {
    valid,
    reason: valid ? null : missing.length ? "claims_missing" : status !== "valid" ? `status_${status}` : "pq_missing",
    claims: Object.fromEntries(
      Object.entries(r.claims).map(([k, v]): [string, ClaimValue] => [k, v === null || ["string", "number", "boolean"].includes(typeof v) ? (v as ClaimValue) : JSON.stringify(v)]),
    ),
    missing,
    holderBinding: r.kb,
    status,
    pq: r.pq,
    issuer: ctx.iss,
    vct: VERIFIED_HUMAN_VCT,
    checkedAt: new Date(now).toISOString(),
  };
}

/** direct_post handler body: vp_token (JSON object keyed by DCQL id) + state, or a wallet error. */
export async function handleVpResponse(id: string, form: URLSearchParams, iss: string): Promise<{ status: number; body: Record<string, unknown> }> {
  if (!(await ready())) return { status: 503, body: { error: "temporarily_unavailable" } };
  const { sql } = await import("@/lib/neon");
  const req = ((await sql`select * from public.rout_vp_request_for_wallet(${id}::uuid)`) as Record<string, unknown>[])[0];
  const state = form.get("state") ?? "";
  if (!req || req["status"] !== "pending" || new Date(String(iso(req["expires_at"]))).getTime() <= Date.now() || state !== req["state"]) {
    return { status: 400, body: { error: "invalid_request" } };
  }
  const complete = async (status: "verified" | "rejected", result: Record<string, unknown>) =>
    ((await sql`select public.rout_vp_request_complete(${id}::uuid, ${state}, ${status}, ${JSON.stringify(result)}::jsonb) as ok`) as { ok: boolean }[])[0]?.ok === true;

  const walletError = form.get("error");
  if (walletError) {
    await complete("rejected", { valid: false, reason: `wallet_${walletError.slice(0, 40).replace(/[^a-z_]/gi, "")}` });
    return { status: 200, body: {} };
  }
  let presentation: unknown = null;
  try {
    const token = JSON.parse(form.get("vp_token") ?? "") as Record<string, unknown>;
    const list = token?.[DCQL_CREDENTIAL_ID];
    presentation = Array.isArray(list) ? list[0] : list;
  } catch {
    presentation = null;
  }
  const dcql = req["dcql"] as { credentials?: { claims?: { path?: unknown[] }[] }[] };
  const requested = (dcql?.credentials?.[0]?.claims ?? []).map((c) => String(c.path?.[0] ?? "")).filter(Boolean);

  const { issuerKey } = await import("./keys.server");
  const key = await issuerKey();
  const { pqPublicKey } = await import("@/lib/crypto/hybrid-signer.server");
  const pqKey = await pqPublicKey("identity");
  const { pqMessage } = await import("@/lib/crypto/pq-purposes");
  const { verifyHybrid } = await import("@/lib/support/hybrid-signature");
  const { activeStatusIndices } = await import("./status-list.server");
  let active: Set<number> | null = null;

  const check = await checkPresentation(presentation, {
    iss,
    clientId: clientIdOf(iss, id),
    nonce: String(req["nonce"]),
    requested,
    issuerKey: (kid) => (key && key.kid === kid ? key.jwk : null),
    isActive: async (idx) => (active ??= new Set(await activeStatusIndices())).has(idx),
    verifyPq: async (line, sig) => !!pqKey && verifyHybrid(pqMessage("identity", [line]), sig, pqKey, { requirePq: true }).valid,
  });
  await complete(check.valid ? "verified" : "rejected", check as unknown as Record<string, unknown>);
  return { status: 200, body: {} };
}

export type VpRequestView = { label: string; status: "pending" | "verified" | "rejected"; result: VpCheck | null; createdAt: string; expiresAt: string; completedAt: string | null };

export async function readMyVpRequest(userId: string, id: string): Promise<VpRequestView | null> {
  if (!(await ready())) return null;
  const { sql, withDbContext } = await import("@/lib/neon");
  const row = await withDbContext({ userId, workspaceId: null }, async () => ((await sql`select * from public.rout_vp_request_mine(${id}::uuid)`) as Record<string, unknown>[])[0]);
  if (!row) return null;
  return {
    label: String(row["label"]),
    status: row["status"] as VpRequestView["status"],
    result: (row["result"] as VpCheck | null) ?? null,
    createdAt: iso(row["created_at"]) ?? "",
    expiresAt: iso(row["expires_at"]) ?? "",
    completedAt: iso(row["completed_at"]),
  };
}

export const STATUS_LIST_PATH = `/api/public/status/${STATUS_LIST_ID}`;
