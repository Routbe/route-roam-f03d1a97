/**
 * Signed blue-mark card (Ed25519). Browser-safe: no keys live here.
 *
 * The server signs exactly what the verification card shows (handle, method, name as shown,
 * country, verification month). The browser checks that signature in the crypto worker against
 * ROUT's published badge key (/api/badge/key) and only then shows "signature valid". A card
 * whose text differs from the signed claims counts as invalid.
 */
import { b64u } from "@/lib/e2ee/crypto";

export const BADGE_ATTESTATION_CONTEXT = "rout.badge_attestation.v1";

export type BadgeMethod = "team" | "didit";

export type BadgeClaims = {
  v: 1;
  handle: string;
  method: BadgeMethod;
  /** The name exactly as the card shows it (already masked for a minor). */
  name: string | null;
  country: string | null;
  /** Verification month as YYYY-MM (UTC). */
  month: string | null;
  /** Issued at, seconds since the epoch. */
  iat: number;
};

export type BadgeAttestation = {
  kid: string;
  payload: string;
  sig: string;
  /** Didit cards: hybrid Ed25519 + ML-DSA-65 attestation over the same payload (purpose "didit"). */
  pq?: import("@/lib/crypto/pq-purposes").PqAttestation | null;
};

/** Fixed key order, so the signed bytes are reproducible. */
export function canonicalBadgePayload(c: BadgeClaims): string {
  return JSON.stringify({ v: 1, handle: c.handle, method: c.method, name: c.name, country: c.country, month: c.month, iat: c.iat });
}

/** The exact bytes that are signed: domain-separated context, NUL, payload. */
export function badgeMessage(payload: string): Uint8Array {
  return new TextEncoder().encode(`${BADGE_ATTESTATION_CONTEXT}\u0000${payload}`);
}

export function monthKey(value: string | null | undefined): string | null {
  if (!value) return null;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

const optStr = (v: unknown, max: number): v is string | null => v === null || (typeof v === "string" && v.length <= max);

export function parseBadgeClaims(payload: string): BadgeClaims | null {
  if (typeof payload !== "string" || payload.length > 1024) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(payload);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  if (c["v"] !== 1 || typeof c["handle"] !== "string" || !/^[a-z0-9._-]{1,64}$/.test(c["handle"])) return null;
  if (c["method"] !== "team" && c["method"] !== "didit") return null;
  if (!optStr(c["name"], 200) || !optStr(c["country"], 3) || !optStr(c["month"], 7)) return null;
  if (typeof c["iat"] !== "number" || !Number.isInteger(c["iat"])) return null;
  const claims: BadgeClaims = { v: 1, handle: c["handle"], method: c["method"], name: c["name"], country: c["country"], month: c["month"], iat: c["iat"] };
  // Reject anything that is not the canonical encoding (extra keys, other order, whitespace).
  return canonicalBadgePayload(claims) === payload ? claims : null;
}

export function isBadgeAttestation(v: unknown): v is BadgeAttestation {
  if (!v || typeof v !== "object") return false;
  const a = v as Record<string, unknown>;
  return typeof a["kid"] === "string" && /^[0-9a-f]{16}$/.test(a["kid"])
    && typeof a["payload"] === "string" && a["payload"].length <= 1024
    && typeof a["sig"] === "string" && /^[A-Za-z0-9_-]{86}$/.test(a["sig"]);
}

export function decodeSignature(sig: string): Uint8Array | null {
  try {
    const out = b64u.decode(sig);
    return out.length === 64 ? out : null;
  } catch {
    return null;
  }
}

/** True when the signed claims say exactly what the card shows. */
export function claimsMatchShown(
  claims: BadgeClaims,
  shown: { handle: string | null | undefined; method: BadgeMethod | null | undefined; name: string | null | undefined; country: string | null | undefined; verifiedAt: string | null | undefined },
): boolean {
  const name = (shown.name ?? "").trim() || null;
  const country = (shown.country ?? "").trim().toUpperCase() || null;
  return claims.handle === (shown.handle ?? "").trim().toLowerCase()
    && claims.method === shown.method
    && claims.name === name
    && claims.country === country
    && claims.month === monthKey(shown.verifiedAt);
}

/**
 * Minor firewall for the card: first given name plus the initial of the last name
 * ("Jona Delplanche" -> "Jona D."). A single name stays as it is.
 */
export function maskMinorLegalName(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length < 2) return parts[0] ?? "";
  const last = parts[parts.length - 1]!;
  return `${parts[0]} ${last.charAt(0).toLocaleUpperCase()}.`;
}
