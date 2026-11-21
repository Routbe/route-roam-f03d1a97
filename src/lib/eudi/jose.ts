/**
 * Minimal JOSE for the EUDI wallet flows (browser-safe, no keys): compact JWS parsing and
 * verification for ES256 (P-256, raw r‖s) and EdDSA (Ed25519) against a public JWK.
 * Anything with a private member ("d") or another curve is refused.
 */
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { b64uDecode, b64uEncode } from "@/lib/support/hybrid-signature";

const enc = new TextEncoder();
const dec = new TextDecoder();

export type JwsAlg = "ES256" | "EdDSA";
export type PublicJwk = { kty: "EC"; crv: "P-256"; x: string; y: string } | { kty: "OKP"; crv: "Ed25519"; x: string };

export const jsonB64u = (v: unknown) => b64uEncode(enc.encode(JSON.stringify(v)));

export function isPublicJwk(v: unknown): v is PublicJwk {
  if (!v || typeof v !== "object") return false;
  const j = v as Record<string, unknown>;
  if ("d" in j) return false;
  try {
    if (j["kty"] === "EC" && j["crv"] === "P-256" && typeof j["x"] === "string" && typeof j["y"] === "string") {
      return b64uDecode(j["x"]).length === 32 && b64uDecode(j["y"]).length === 32;
    }
    if (j["kty"] === "OKP" && j["crv"] === "Ed25519" && typeof j["x"] === "string") return b64uDecode(j["x"]).length === 32;
  } catch {
    return false;
  }
  return false;
}

/** Only the public members, in a fixed order (what we embed in cnf / publish). */
export function publicJwkOf(j: PublicJwk): PublicJwk {
  return j.kty === "EC" ? { kty: "EC", crv: "P-256", x: j.x, y: j.y } : { kty: "OKP", crv: "Ed25519", x: j.x };
}

export type ParsedJws = { header: Record<string, unknown>; payload: Record<string, unknown>; signingInput: Uint8Array; signature: Uint8Array };

export function parseJws(compact: string, max = 16384): ParsedJws {
  if (typeof compact !== "string" || compact.length > max) throw new RangeError("jws_size");
  const [h, p, s, extra] = compact.split(".");
  if (!h || !p || !s || extra !== undefined) throw new RangeError("jws_format");
  const header = JSON.parse(dec.decode(b64uDecode(h))) as unknown;
  const payload = JSON.parse(dec.decode(b64uDecode(p))) as unknown;
  if (!header || typeof header !== "object" || Array.isArray(header) || !payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new RangeError("jws_json");
  }
  return { header: header as Record<string, unknown>, payload: payload as Record<string, unknown>, signingInput: enc.encode(`${h}.${p}`), signature: b64uDecode(s) };
}

export function verifyJws(alg: unknown, jwk: PublicJwk, signingInput: Uint8Array, signature: Uint8Array): boolean {
  try {
    if (alg === "ES256" && jwk.kty === "EC") {
      if (signature.length !== 64) return false;
      const pk = new Uint8Array(65);
      pk[0] = 4;
      pk.set(b64uDecode(jwk.x), 1);
      pk.set(b64uDecode(jwk.y), 33);
      return p256.verify(signature, signingInput, pk, { lowS: false });
    }
    if (alg === "EdDSA" && jwk.kty === "OKP") {
      return signature.length === 64 && ed25519.verify(signature, signingInput, b64uDecode(jwk.x));
    }
  } catch {
    return false;
  }
  return false;
}

/** ES256 public JWK from an uncompressed P-256 point. */
export function p256Jwk(uncompressed: Uint8Array): PublicJwk {
  if (uncompressed.length !== 65 || uncompressed[0] !== 4) throw new RangeError("p256_point");
  return { kty: "EC", crv: "P-256", x: b64uEncode(uncompressed.slice(1, 33)), y: b64uEncode(uncompressed.slice(33)) };
}

export async function sha256B64u(text: string): Promise<string> {
  const { sha256 } = await import("@noble/hashes/sha2.js");
  return b64uEncode(sha256(enc.encode(text)));
}
