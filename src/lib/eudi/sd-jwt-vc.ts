/**
 * SD-JWT VC (RFC 9901 SD-JWT, draft-ietf-oauth-sd-jwt-vc) for EUDI wallets: issuer JWT signed ES256
 * (what wallets accept today), holder binding through cnf.jwk, status through a Token Status List
 * reference, and every claim selectively disclosable. ROUT adds `rout_pq`: a hybrid Ed25519 +
 * ML-DSA-65 signature (purpose "identity") over the JSON of the payload without `rout_pq`; wallets
 * ignore it, ROUT verifiers check it. Browser-safe: signers and key lookups are passed in.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { b64uDecode, b64uEncode, type HybridSignature } from "@/lib/support/hybrid-signature";
import { isPublicJwk, jsonB64u, parseJws, publicJwkOf, verifyJws, type PublicJwk } from "./jose";

export const SD_JWT_VC_TYP = "dc+sd-jwt";
export const KB_JWT_TYP = "kb+jwt";
export const VERIFIED_HUMAN_VCT = "https://rout.be/credentials/verified-human/v1";
export const VERIFIED_HUMAN_CONFIG = "rout_verified_human";
export const VERIFIED_HUMAN_CLAIMS = ["verified_human", "age_over_16", "age_over_18", "age_over_21"] as const;
export type VerifiedHumanClaim = (typeof VERIFIED_HUMAN_CLAIMS)[number];

const enc = new TextEncoder();
const dec = new TextDecoder();
const digestOf = (disclosure: string) => b64uEncode(sha256(enc.encode(disclosure)));

/** Claims of the "verified human" credential from what the database attested (no nationality, no name). */
export function verifiedHumanClaims(row: { verified_human?: unknown; age_floor?: unknown }): Partial<Record<VerifiedHumanClaim, boolean>> {
  const out: Partial<Record<VerifiedHumanClaim, boolean>> = { verified_human: row.verified_human === true };
  const age = typeof row.age_floor === "number" && Number.isInteger(row.age_floor) ? row.age_floor : null;
  if (age !== null) {
    out.age_over_16 = age >= 16;
    out.age_over_18 = age >= 18;
    out.age_over_21 = age >= 21;
  }
  return out;
}

/** The exact line the `rout_pq` signature covers. */
export const pqLineOf = (payloadWithoutPq: Record<string, unknown>) => JSON.stringify(payloadWithoutPq);

export type IssueInput = {
  issuer: string;
  vct: string;
  claims: Record<string, unknown>;
  cnf: PublicJwk;
  status: { idx: number; uri: string };
  iat: number;
  exp: number;
  kid: string;
  sign: (signingInput: Uint8Array) => Promise<Uint8Array>;
  /** Hybrid signature over pqLineOf(payload); null leaves rout_pq out. */
  signPq?: (line: string) => Promise<HybridSignature | null>;
  salt?: () => string;
};

export async function issueSdJwtVc(input: IssueInput): Promise<string> {
  const salt = input.salt ?? (() => b64uEncode(crypto.getRandomValues(new Uint8Array(16))));
  const disclosures = Object.entries(input.claims).map(([name, value]) => jsonB64u([salt(), name, value]));
  const header = { alg: "ES256", typ: SD_JWT_VC_TYP, kid: input.kid };
  const payload: Record<string, unknown> = {
    iss: input.issuer,
    iat: input.iat,
    exp: input.exp,
    vct: input.vct,
    cnf: { jwk: publicJwkOf(input.cnf) },
    status: { status_list: { idx: input.status.idx, uri: input.status.uri } },
    _sd_alg: "sha-256",
    _sd: disclosures.map(digestOf).sort(),
  };
  const pq = input.signPq ? await input.signPq(pqLineOf(payload)) : null;
  if (pq) payload["rout_pq"] = pq;
  const signingInput = `${jsonB64u(header)}.${jsonB64u(payload)}`;
  const sig = await input.sign(enc.encode(signingInput));
  return `${signingInput}.${b64uEncode(sig)}~${disclosures.map((d) => `${d}~`).join("")}`;
}

/** Keep only the named disclosures (issuer signature stays valid). */
export function selectDisclosures(compact: string, keep: readonly string[]): string {
  const parts = compact.split("~");
  const jwt = parts[0]!;
  const kept = parts.slice(1, -1).filter((raw) => {
    try {
      const arr = JSON.parse(dec.decode(b64uDecode(raw))) as unknown[];
      return Array.isArray(arr) && typeof arr[1] === "string" && keep.includes(arr[1]);
    } catch {
      return false;
    }
  });
  return `${jwt}~${kept.map((d) => `${d}~`).join("")}`;
}

/** Holder side (wallets, tests): append a KB-JWT over the presentation. */
export async function addKeyBinding(
  presentation: string,
  opts: { alg: "ES256" | "EdDSA"; aud: string; nonce: string; iat: number; sign: (input: Uint8Array) => Promise<Uint8Array> | Uint8Array },
): Promise<string> {
  if (!presentation.endsWith("~")) throw new RangeError("format");
  const header = { alg: opts.alg, typ: KB_JWT_TYP };
  const payload = { iat: opts.iat, aud: opts.aud, nonce: opts.nonce, sd_hash: digestOf(presentation) };
  const input = `${jsonB64u(header)}.${jsonB64u(payload)}`;
  const sig = await opts.sign(enc.encode(input));
  return `${presentation}${input}.${b64uEncode(sig)}`;
}

export type VerifyOptions = {
  issuer: string;
  vct: string;
  /** The issuer's ES256 key for the header kid (null = unknown kid). */
  issuerKey: (kid: string) => PublicJwk | null;
  now: number;
  /** When set, a KB-JWT with this audience and nonce is required. */
  keyBinding?: { aud: string; nonce: string; maxAgeSeconds?: number };
  /** Hybrid check of rout_pq; returns true when valid. Absent = rout_pq not checked. */
  verifyPq?: (line: string, sig: HybridSignature) => Promise<boolean>;
};

export type VerifyResult =
  | { valid: true; claims: Record<string, unknown>; status: { idx: number; uri: string } | null; pq: boolean; kb: boolean; exp: number }
  | { valid: false; reason: string };

export async function verifySdJwtVc(compact: string, opts: VerifyOptions): Promise<VerifyResult> {
  if (typeof compact !== "string" || compact.length > 32768) return { valid: false, reason: "malformed" };
  const parts = compact.split("~");
  if (parts.length < 2) return { valid: false, reason: "malformed" };
  const kbRaw = parts[parts.length - 1]!;
  const presentation = `${parts.slice(0, -1).join("~")}~`;
  let jws;
  try {
    jws = parseJws(parts[0]!, 16384);
  } catch {
    return { valid: false, reason: "malformed" };
  }
  const { header, payload } = jws;
  if (header["alg"] !== "ES256" || header["typ"] !== SD_JWT_VC_TYP || typeof header["kid"] !== "string") return { valid: false, reason: "header" };
  if (payload["iss"] !== opts.issuer || payload["vct"] !== opts.vct || payload["_sd_alg"] !== "sha-256") return { valid: false, reason: "type" };
  const exp = payload["exp"];
  if (typeof exp !== "number" || exp * 1000 <= opts.now) return { valid: false, reason: "expired" };
  const key = opts.issuerKey(header["kid"]);
  if (!key || !verifyJws("ES256", key, jws.signingInput, jws.signature)) return { valid: false, reason: "signature" };

  const sd = payload["_sd"];
  if (!Array.isArray(sd)) return { valid: false, reason: "sd" };
  const claims: Record<string, unknown> = {};
  for (const raw of parts.slice(1, -1)) {
    let arr: unknown;
    try {
      arr = JSON.parse(dec.decode(b64uDecode(raw)));
    } catch {
      return { valid: false, reason: "disclosure" };
    }
    if (!Array.isArray(arr) || arr.length !== 3 || typeof arr[0] !== "string" || typeof arr[1] !== "string") return { valid: false, reason: "disclosure" };
    if (!sd.includes(digestOf(raw))) return { valid: false, reason: "disclosure_not_signed" };
    if (Object.hasOwn(claims, arr[1]) || ["iss", "exp", "iat", "vct", "cnf", "status", "_sd", "_sd_alg", "rout_pq"].includes(arr[1])) {
      return { valid: false, reason: "disclosure_name" };
    }
    claims[arr[1]] = arr[2];
  }

  let kb = false;
  if (opts.keyBinding) {
    const cnf = (payload["cnf"] as { jwk?: unknown } | undefined)?.jwk;
    if (!isPublicJwk(cnf)) return { valid: false, reason: "cnf" };
    let kbJws;
    try {
      kbJws = parseJws(kbRaw, 4096);
    } catch {
      return { valid: false, reason: "kb_missing" };
    }
    if (kbJws.header["typ"] !== KB_JWT_TYP) return { valid: false, reason: "kb_header" };
    if (!verifyJws(kbJws.header["alg"], cnf, kbJws.signingInput, kbJws.signature)) return { valid: false, reason: "kb_signature" };
    const p = kbJws.payload;
    const maxAge = opts.keyBinding.maxAgeSeconds ?? 300;
    if (p["aud"] !== opts.keyBinding.aud || p["nonce"] !== opts.keyBinding.nonce) return { valid: false, reason: "kb_audience" };
    if (typeof p["iat"] !== "number" || Math.abs(opts.now / 1000 - p["iat"]) > maxAge) return { valid: false, reason: "kb_time" };
    if (p["sd_hash"] !== digestOf(presentation)) return { valid: false, reason: "kb_sd_hash" };
    kb = true;
  } else if (kbRaw !== "") {
    return { valid: false, reason: "malformed" };
  }

  let pq = false;
  if (opts.verifyPq && payload["rout_pq"] !== undefined) {
    const { rout_pq: sig, ...rest } = payload;
    const s = sig as HybridSignature;
    if (!s || typeof s !== "object" || typeof s.kid !== "string" || typeof s.ed25519 !== "string" || typeof s.mldsa65 !== "string") {
      return { valid: false, reason: "pq" };
    }
    if (!(await opts.verifyPq(pqLineOf(rest), s))) return { valid: false, reason: "pq" };
    pq = true;
  }

  const st = (payload["status"] as { status_list?: { idx?: unknown; uri?: unknown } } | undefined)?.status_list;
  const status = st && typeof st.idx === "number" && typeof st.uri === "string" ? { idx: st.idx, uri: st.uri } : null;
  return { valid: true, claims, status, pq, kb, exp };
}
