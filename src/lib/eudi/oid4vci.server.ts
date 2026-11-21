/**
 * OpenID for Verifiable Credential Issuance 1.0 (server-only), pre-authorized code flow:
 *   member creates an offer (Developer Console) -> wallet redeems code + tx_code at the token
 *   endpoint -> fetches a c_nonce -> sends a key proof to the credential endpoint -> receives one
 *   SD-JWT VC bound to its key, with a Token Status List index and a rout_pq hybrid signature.
 * Only SHA-256 hashes of codes and tokens reach the database (db/0294).
 * Both endpoints require RFC 9449 DPoP (no Bearer fallback): the access token is bound to the
 * wallet's DPoP key by storing only SHA-256(token "." jkt), so a token presented with any other
 * key is simply unknown to the database.
 */
import { b64uEncode } from "@/lib/support/hybrid-signature";
import { isPublicJwk, parseJws, verifyJws, type PublicJwk } from "./jose";
import { issueSdJwtVc, VERIFIED_HUMAN_CONFIG, VERIFIED_HUMAN_VCT, verifiedHumanClaims } from "./sd-jwt-vc";
import { statusListUri } from "./status-list.server";
import { checkDpopProof, DPOP_ALGS, DualLayerReplayGuard, JtiReplayCache, ReplayStoreUnavailable } from "./dpop";

export const PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
export const PROOF_TYP = "openid4vci-proof+jwt";
export const ACCESS_TOKEN_TTL_S = 300;
export const CREDENTIAL_DAYS = 365;

const enc = new TextEncoder();
async function sha256Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}
/**
 * Shared layer of the DPoP replay guard: one row per (thumbprint, jti) hash in
 * public.dpop_jti_replays (db/0295), claimed atomically on the database clock, so a proof used on
 * one instance is refused on every other. Without 0295 the endpoints refuse (fail closed).
 */
async function claimSharedJti(jtiHash: string, holdSeconds: number): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (!(await hasSchemaFeature("0295"))) throw new ReplayStoreUnavailable("0295 missing");
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select public.rout_dpop_jti_claim(${jtiHash}, ${holdSeconds}) as ok`) as { ok: boolean }[];
  return rows[0]?.ok === true;
}
/** DPoP jti replay guard: per-instance cache (layer 1) + shared database ledger (layer 2). */
const dpopReplay = new DualLayerReplayGuard(new JtiReplayCache(), claimSharedJti);
const replayDown = { ok: false, status: 503, error: "temporarily_unavailable", description: "Proof checking is not available right now." } as const;
export const TOKEN_PATH = "/api/public/oid4vci/token";
export const CREDENTIAL_PATH = "/api/public/oid4vci/credential";
const boundTokenHash = (token: string, jkt: string) => sha256Hex(`${token}.${jkt}`);

export type DpopRequest = { header: string | null; method: string; iss: string; now?: number };
async function dpopGate(req: DpopRequest, path: string, accessToken?: string) {
  const { checkDpopNonce } = await import("./keys.server");
  const now = req.now ?? Date.now();
  return checkDpopProof(req.header, { method: req.method, htu: `${req.iss}${path}`, now, checkNonce: (n) => checkDpopNonce(n, now), replay: dpopReplay, accessToken });
}
/** A fresh server nonce for the DPoP-Nonce response header (null = issuance off). */
export async function freshDpopNonce(): Promise<string | null> {
  const { newDpopNonce } = await import("./keys.server");
  return newDpopNonce();
}

const token32 = () => b64uEncode(crypto.getRandomValues(new Uint8Array(32)));

/** Six uniformly random digits (rejection sampling, no modulo bias). */
export function newTxCode(): string {
  let out = "";
  while (out.length < 6) {
    const b = crypto.getRandomValues(new Uint8Array(8));
    for (const x of b) if (x < 250 && out.length < 6) out += String(x % 10);
  }
  return out;
}

async function ready(): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  return hasSchemaFeature("0294");
}

export function issuerMetadata(iss: string) {
  return {
    credential_issuer: iss,
    authorization_servers: [`${iss}/oid4vci`],
    credential_endpoint: `${iss}${CREDENTIAL_PATH}`,
    nonce_endpoint: `${iss}/api/public/oid4vci/nonce`,
    dpop_signing_alg_values_supported: [...DPOP_ALGS],
    display: [{ name: "ROUT", locale: "nl-BE" }, { name: "ROUT", locale: "en" }],
    credential_configurations_supported: {
      [VERIFIED_HUMAN_CONFIG]: {
        format: "dc+sd-jwt",
        vct: VERIFIED_HUMAN_VCT,
        scope: VERIFIED_HUMAN_CONFIG,
        cryptographic_binding_methods_supported: ["jwk"],
        credential_signing_alg_values_supported: ["ES256"],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ["ES256", "EdDSA"] } },
        credential_metadata: {
          display: [
            { name: "ROUT geverifieerd mens", locale: "nl-BE" },
            { name: "ROUT verified human", locale: "en" },
          ],
          claims: [
            { path: ["verified_human"], display: [{ name: "Geverifieerd mens", locale: "nl-BE" }, { name: "Verified human", locale: "en" }] },
            { path: ["age_over_16"], display: [{ name: "16 of ouder", locale: "nl-BE" }, { name: "Age 16 or over", locale: "en" }] },
            { path: ["age_over_18"], display: [{ name: "18 of ouder", locale: "nl-BE" }, { name: "Age 18 or over", locale: "en" }] },
            { path: ["age_over_21"], display: [{ name: "21 of ouder", locale: "nl-BE" }, { name: "Age 21 or over", locale: "en" }] },
          ],
        },
      },
    },
  };
}

export function authorizationServerMetadata(iss: string) {
  return {
    issuer: `${iss}/oid4vci`,
    token_endpoint: `${iss}${TOKEN_PATH}`,
    dpop_signing_alg_values_supported: [...DPOP_ALGS],
    grant_types_supported: [PRE_AUTH_GRANT],
    "pre-authorized_grant_anonymous_access_supported": true,
    response_types_supported: [],
    token_endpoint_auth_methods_supported: ["none"],
  };
}

// ---------------------------------------------------------------- offer (signed-in member)

export type OfferResult =
  | { ok: true; uri: string; offer: Record<string, unknown>; txCode: string; expiresAt: string }
  | { ok: false; reason: "not_ready" | "unavailable" };

export async function createOffer(userId: string, iss: string): Promise<OfferResult> {
  if (!(await ready())) return { ok: false, reason: "not_ready" };
  const { issuerKey } = await import("./keys.server");
  if (!(await issuerKey())) return { ok: false, reason: "not_ready" };
  const code = token32();
  const txCode = newTxCode();
  const { sql, withDbContext } = await import("@/lib/neon");
  const id = await withDbContext({ userId, workspaceId: null }, async () => {
    const rows = (await sql`select public.rout_vci_offer_create(${VERIFIED_HUMAN_CONFIG}, ${await sha256Hex(code)}, ${await sha256Hex(txCode)}) as id`) as { id: string | null }[];
    return rows[0]?.id ?? null;
  });
  if (!id) return { ok: false, reason: "unavailable" };
  const offer = {
    credential_issuer: iss,
    credential_configuration_ids: [VERIFIED_HUMAN_CONFIG],
    grants: {
      [PRE_AUTH_GRANT]: {
        "pre-authorized_code": code,
        tx_code: { input_mode: "numeric", length: 6, description: "De code die ROUT naast de QR-code toont." },
      },
    },
  };
  return {
    ok: true,
    uri: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`,
    offer,
    txCode,
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  };
}

// ---------------------------------------------------------------- token endpoint

export type TokenResult =
  | { ok: true; body: { access_token: string; token_type: "DPoP"; expires_in: number } }
  | { ok: false; status: number; error: string; description: string };

export async function redeemPreAuthorizedCode(form: URLSearchParams, dpop: DpopRequest): Promise<TokenResult> {
  const proof = await dpopGate(dpop, TOKEN_PATH);
  if (!proof.ok) {
    if (proof.error === "replay_store_unavailable") return replayDown;
    return proof.error === "use_dpop_nonce"
      ? { ok: false, status: 400, error: "use_dpop_nonce", description: "Retry with the server nonce from the DPoP-Nonce header." }
      : { ok: false, status: 401, error: "invalid_dpop_proof", description: "A valid DPoP proof is required." };
  }
  if (form.get("grant_type") !== PRE_AUTH_GRANT) return { ok: false, status: 400, error: "unsupported_grant_type", description: "Only the pre-authorized code grant is supported." };
  const code = form.get("pre-authorized_code") ?? "";
  const tx = form.get("tx_code") ?? "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(code) || !/^[0-9]{6}$/.test(tx)) return { ok: false, status: 400, error: "invalid_grant", description: "Unknown code or transaction code." };
  if (!(await ready())) return { ok: false, status: 503, error: "temporarily_unavailable", description: "Issuance is not available yet." };
  const accessToken = token32();
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select public.rout_vci_redeem(${await sha256Hex(code)}, ${await sha256Hex(tx)}, ${await boundTokenHash(accessToken, proof.jkt)}) as r`) as { r: string }[];
  const r = rows[0]?.r ?? "invalid";
  if (r !== "ok") return { ok: false, status: 400, error: "invalid_grant", description: r === "expired" ? "The offer has expired." : r === "locked" ? "Too many wrong transaction codes." : r === "used" ? "The offer was already used." : "Unknown code or transaction code." };
  return { ok: true, body: { access_token: accessToken, token_type: "DPoP", expires_in: ACCESS_TOKEN_TTL_S } };
}

// ---------------------------------------------------------------- credential endpoint

export type CredentialResult =
  | { ok: true; body: { credentials: { credential: string }[] } }
  | { ok: false; status: number; error: string; description: string };

/** The holder's key from an OID4VCI proof JWT (typ, alg, embedded public jwk, aud, nonce, iat). */
export async function checkProof(proofJwt: unknown, iss: string, now = Date.now()): Promise<{ ok: true; jwk: PublicJwk } | { ok: false; error: string }> {
  if (typeof proofJwt !== "string") return { ok: false, error: "invalid_proof" };
  let jws;
  try {
    jws = parseJws(proofJwt, 4096);
  } catch {
    return { ok: false, error: "invalid_proof" };
  }
  const { header, payload } = jws;
  const jwk = header["jwk"];
  if (header["typ"] !== PROOF_TYP || (header["alg"] !== "ES256" && header["alg"] !== "EdDSA") || !isPublicJwk(jwk)) return { ok: false, error: "invalid_proof" };
  if ("kid" in header || "x5c" in header) return { ok: false, error: "invalid_proof" };
  if (!verifyJws(header["alg"], jwk, jws.signingInput, jws.signature)) return { ok: false, error: "invalid_proof" };
  if (payload["aud"] !== iss || typeof payload["iat"] !== "number" || Math.abs(now / 1000 - payload["iat"]) > 300) return { ok: false, error: "invalid_proof" };
  const { checkCNonce } = await import("./keys.server");
  if (!(await checkCNonce(payload["nonce"], now))) return { ok: false, error: "invalid_nonce" };
  return { ok: true, jwk };
}

export async function issueCredential(authorization: string | null, body: unknown, iss: string, dpop: Omit<DpopRequest, "iss">): Promise<CredentialResult> {
  // DPoP scheme only: a plain Bearer token (no key binding) is refused outright.
  const token = /^DPoP ([A-Za-z0-9_-]{43})$/.exec(authorization ?? "")?.[1];
  if (!token) return { ok: false, status: 401, error: "invalid_dpop_proof", description: "A DPoP-bound access token is required." };
  const proofOfPossession = await dpopGate({ ...dpop, iss }, CREDENTIAL_PATH, token);
  if (!proofOfPossession.ok) {
    if (proofOfPossession.error === "replay_store_unavailable") return replayDown;
    return proofOfPossession.error === "use_dpop_nonce"
      ? { ok: false, status: 401, error: "use_dpop_nonce", description: "Retry with the server nonce from the DPoP-Nonce header." }
      : { ok: false, status: 401, error: "invalid_dpop_proof", description: "A valid DPoP proof is required." };
  }
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const configId = b["credential_configuration_id"] ?? (b["format"] === "dc+sd-jwt" && b["vct"] === VERIFIED_HUMAN_VCT ? VERIFIED_HUMAN_CONFIG : undefined);
  if (configId !== VERIFIED_HUMAN_CONFIG) return { ok: false, status: 400, error: "unknown_credential_configuration", description: "Unknown credential configuration." };
  const proofs = (b["proofs"] as { jwt?: unknown } | undefined)?.jwt;
  const legacy = b["proof"] as { proof_type?: unknown; jwt?: unknown } | undefined;
  const proofJwt = Array.isArray(proofs) ? (proofs.length === 1 ? proofs[0] : null) : legacy?.proof_type === "jwt" ? legacy.jwt : null;
  const proof = await checkProof(proofJwt, iss);
  if (!proof.ok) return { ok: false, status: 400, error: proof.error, description: proof.error === "invalid_nonce" ? "Fetch a fresh c_nonce." : "The key proof is not valid." };
  if (!(await ready())) return { ok: false, status: 503, error: "temporarily_unavailable", description: "Issuance is not available yet." };

  const { issuerKey, signEs256 } = await import("./keys.server");
  const key = await issuerKey();
  if (!key) return { ok: false, status: 503, error: "temporarily_unavailable", description: "Issuance is not available yet." };
  const jti = token32();
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select * from public.rout_vci_issue(${await boundTokenHash(token, proofOfPossession.jkt)}, ${await sha256Hex(jti)}, ${CREDENTIAL_DAYS})`) as Record<string, unknown>[];
  const row = rows[0];
  if (!row) return { ok: false, status: 401, error: "invalid_token", description: "The access token is unknown, used or expired." };
  const { signPq } = await import("@/lib/crypto/hybrid-signer.server");
  const iat = Math.floor(Date.now() / 1000);
  const exp = Math.floor(new Date(String(row["expires_at"])).getTime() / 1000);
  const credential = await issueSdJwtVc({
    issuer: iss,
    vct: VERIFIED_HUMAN_VCT,
    claims: verifiedHumanClaims((row["claims"] ?? {}) as Record<string, unknown>),
    cnf: proof.jwk,
    status: { idx: Number(row["status_idx"]), uri: statusListUri(iss) },
    iat,
    exp: Number.isFinite(exp) ? exp : iat + CREDENTIAL_DAYS * 86400,
    kid: key.kid,
    sign: async (input) => {
      const sig = await signEs256(input);
      if (!sig) throw new Error("issuer_key_unavailable");
      return sig;
    },
    signPq: (line) => signPq("identity", [line]),
  });
  return { ok: true, body: { credentials: [{ credential }] } };
}

// ---------------------------------------------------------------- member's own credentials

export type WalletCredentialRow = { statusIdx: number; config: string; issuedAt: string; expiresAt: string; revokedAt: string | null };
const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : v == null ? null : String(v));

export async function listMyWalletCredentials(userId: string): Promise<WalletCredentialRow[]> {
  if (!(await ready())) return [];
  const { sql, withDbContext } = await import("@/lib/neon");
  const rows = await withDbContext({ userId, workspaceId: null }, async () => (await sql`select * from public.rout_vci_mine()`) as Record<string, unknown>[]);
  return rows.map((r) => ({ statusIdx: Number(r["status_idx"]), config: String(r["config"]), issuedAt: iso(r["issued_at"]) ?? "", expiresAt: iso(r["expires_at"]) ?? "", revokedAt: iso(r["revoked_at"]) }));
}

export async function revokeMyWalletCredential(userId: string, statusIdx: number): Promise<boolean> {
  if (!(await ready())) return false;
  const { sql, withDbContext } = await import("@/lib/neon");
  const ok = await withDbContext({ userId, workspaceId: null }, async () => ((await sql`select public.rout_vci_revoke(${statusIdx}) as ok`) as { ok: boolean }[])[0]?.ok === true);
  if (ok) {
    const { resetStatusListCache } = await import("./status-list.server");
    resetStatusListCache();
  }
  return ok;
}
