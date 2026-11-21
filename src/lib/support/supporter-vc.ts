/**
 * ROUT Supporter credential as an SD-JWT VC (IETF draft-ietf-oauth-sd-jwt-vc, RFC 9901 SD-JWT):
 * issuer-signed JWT (EdDSA / Ed25519, typ "dc+sd-jwt") with salted, selectively disclosable
 * claims. The holder decides which disclosures to show (a profile shows level + handle only).
 * EdDSA keeps it readable by EUDI wallets; the treasury roots carry the post-quantum signature.
 *
 * Issue and verify take the signer/verifier as functions: the server signs with its HKDF key,
 * the browser verifies inside the crypto worker (support.verify_vc).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { b64uDecode, b64uEncode } from "./hybrid-signature";

export const SUPPORTER_VCT = "https://rout.be/credentials/supporter/v1";
export const SUPPORTER_ISSUER = "https://rout.be";
export const SD_JWT_TYP = "dc+sd-jwt";
const ONE_YEAR_S = 365 * 24 * 3600;
const enc = new TextEncoder();
const dec = new TextDecoder();

export type SupporterClaims = {
  level: "public" | "pseudonymous";
  /** Level 1 only. */
  handle?: string;
  supporter_index: number;
  since: string;
  verified_human?: boolean;
};
type ClaimName = keyof SupporterClaims;
const CLAIM_NAMES: readonly ClaimName[] = ["level", "handle", "supporter_index", "since", "verified_human"];

const jsonB64u = (v: unknown) => b64uEncode(enc.encode(JSON.stringify(v)));
const digestOf = (disclosure: string) => b64uEncode(sha256(enc.encode(disclosure)));

export async function issueSupporterVc(
  claims: SupporterClaims,
  signer: { kid: string; sign: (signingInput: Uint8Array) => Promise<Uint8Array> },
  opts: { now?: number; jti: string; salt?: () => string } = { jti: "" },
): Promise<{ sdJwt: string; exp: number }> {
  if (claims.level === "public" && !claims.handle) throw new RangeError("handle_required");
  if (claims.level === "pseudonymous" && claims.handle) throw new RangeError("handle_forbidden");
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(opts.jti)) throw new RangeError("jti_invalid");
  const salt = opts.salt ?? (() => b64uEncode(crypto.getRandomValues(new Uint8Array(16))));
  const disclosures: string[] = [];
  for (const name of CLAIM_NAMES) {
    const value = claims[name];
    if (value === undefined) continue;
    disclosures.push(jsonB64u([salt(), name, value]));
  }
  const iat = Math.floor((opts.now ?? Date.now()) / 1000);
  const exp = iat + ONE_YEAR_S;
  const header = { alg: "EdDSA", typ: SD_JWT_TYP, kid: signer.kid };
  const payload = {
    iss: SUPPORTER_ISSUER,
    iat,
    exp,
    jti: opts.jti,
    vct: SUPPORTER_VCT,
    _sd_alg: "sha-256",
    _sd: disclosures.map(digestOf).sort(),
  };
  const signingInput = `${jsonB64u(header)}.${jsonB64u(payload)}`;
  const sig = await signer.sign(enc.encode(signingInput));
  return { sdJwt: `${signingInput}.${b64uEncode(sig)}~${disclosures.join("~")}~`, exp };
}

export type ParsedSdJwt = {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
  disclosures: { raw: string; name: string; value: unknown }[];
};

export function parseSdJwt(compact: string): ParsedSdJwt {
  if (typeof compact !== "string" || compact.length > 8192 || !compact.endsWith("~")) throw new RangeError("format");
  const parts = compact.split("~");
  const jwt = parts[0]!;
  const raws = parts.slice(1, -1);
  const [h, p, s, extra] = jwt.split(".");
  if (!h || !p || !s || extra !== undefined) throw new RangeError("jwt_format");
  const disclosures = raws.map((raw) => {
    const arr = JSON.parse(dec.decode(b64uDecode(raw))) as unknown;
    if (!Array.isArray(arr) || arr.length !== 3 || typeof arr[0] !== "string" || typeof arr[1] !== "string") throw new RangeError("disclosure");
    return { raw, name: arr[1] as string, value: arr[2] as unknown };
  });
  return {
    header: JSON.parse(dec.decode(b64uDecode(h))) as Record<string, unknown>,
    payload: JSON.parse(dec.decode(b64uDecode(p))) as Record<string, unknown>,
    signingInput: enc.encode(`${h}.${p}`),
    signature: b64uDecode(s),
    disclosures,
  };
}

/** A presentation with only the named disclosures (the issuer signature stays valid). */
export function presentSupporterVc(compact: string, keep: readonly ClaimName[]): string {
  const parsed = parseSdJwt(compact);
  const kept = parsed.disclosures.filter((d) => (keep as readonly string[]).includes(d.name)).map((d) => d.raw);
  return `${compact.split("~")[0]}~${kept.map((r) => `${r}~`).join("")}`;
}

export type SupporterVerification =
  | { valid: true; claims: Partial<SupporterClaims>; exp: number; kid: string }
  | { valid: false; reason: string };

export async function verifySupporterVc(
  compact: string,
  verifyEd25519: (signingInput: Uint8Array, signature: Uint8Array, kid: string) => Promise<boolean> | boolean,
  now: number = Date.now(),
): Promise<SupporterVerification> {
  let parsed: ParsedSdJwt;
  try {
    parsed = parseSdJwt(compact);
  } catch {
    return { valid: false, reason: "malformed" };
  }
  const { header, payload } = parsed;
  if (header["alg"] !== "EdDSA" || header["typ"] !== SD_JWT_TYP || typeof header["kid"] !== "string") return { valid: false, reason: "header" };
  if (payload["vct"] !== SUPPORTER_VCT || payload["iss"] !== SUPPORTER_ISSUER || payload["_sd_alg"] !== "sha-256") return { valid: false, reason: "type" };
  const exp = payload["exp"];
  if (typeof exp !== "number" || exp * 1000 <= now) return { valid: false, reason: "expired" };
  const sd = payload["_sd"];
  if (!Array.isArray(sd)) return { valid: false, reason: "sd" };
  const seen = new Set<string>();
  const claims: Record<string, unknown> = {};
  for (const d of parsed.disclosures) {
    if (!sd.includes(digestOf(d.raw))) return { valid: false, reason: "disclosure_not_signed" };
    if (seen.has(d.name) || !(CLAIM_NAMES as readonly string[]).includes(d.name)) return { valid: false, reason: "disclosure_name" };
    seen.add(d.name);
    claims[d.name] = d.value;
  }
  if (parsed.signature.length !== 64) return { valid: false, reason: "signature" };
  let ok = false;
  try {
    ok = await verifyEd25519(parsed.signingInput, parsed.signature, header["kid"] as string);
  } catch {
    ok = false;
  }
  if (!ok) return { valid: false, reason: "signature" };
  return { valid: true, claims: claims as Partial<SupporterClaims>, exp, kid: header["kid"] as string };
}
