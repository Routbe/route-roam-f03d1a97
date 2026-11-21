/**
 * Deterministic canonical identity anchors (ICAO Doc 9303 / eIDAS), pure and client-safe.
 *
 *   <ISO 3166-1 alpha-3 issuer>:<class>:<value>
 *     class  PN = national personal number (BSN, rijksregisternummer, DNI, ...): one per person
 *            P / I / R / DL / X = document number of a passport, identity card, residence permit,
 *            driving licence or another document: one per document
 *     value  NFKD, diacritics removed, upper case, only A-Z and 0-9 (MRZ filler "<", spaces,
 *            hyphens and dots dropped)
 *
 * The personal-number anchor comes first when present: it is the same for a passport and an ID
 * card of one person, and for every provider (itsme and Didit both read the Belgian national number).
 * Anchors are returned as unpooled Node.js Buffers so the caller can zero-fill them after hashing.
 */

import type { Buffer } from "node:buffer";
import { secretBuffer } from "./secure-buffer";

export type AnchorKind = "personal_number" | "document";
export type CanonicalAnchor = { kind: AnchorKind; bytes: Buffer };

export type DocumentClaims = {
  issuingState?: string | null;
  nationality?: string | null;
  documentType?: string | null;
  documentNumber?: string | null;
  personalNumber?: string | null;
};

/** ICAO Doc 9303 Part 3 codes that differ from ISO 3166-1 alpha-3. */
const ICAO_TO_ISO3: Record<string, string> = { D: "DEU" };

/** ICAO codes that name no issuing state; they never anchor a national personal number. */
const NON_STATE = new Set(["XXA", "XXB", "XXC", "XXX", "UNO", "UNA", "UNK", "XOM", "XPO", "XCC", "XES", "XMP", "EUE", "XBA", "XIM", "XDC", "XEC"]);

/** ISO 3166-1 alpha-2 to alpha-3 for eIDAS (EU/EEA) issuers and the most common other issuers. */
const ISO2_TO_ISO3: Record<string, string> = {
  AT: "AUT", BE: "BEL", BG: "BGR", HR: "HRV", CY: "CYP", CZ: "CZE", DK: "DNK", EE: "EST", FI: "FIN", FR: "FRA",
  DE: "DEU", GR: "GRC", EL: "GRC", HU: "HUN", IE: "IRL", IT: "ITA", LV: "LVA", LT: "LTU", LU: "LUX", MT: "MLT",
  NL: "NLD", PL: "POL", PT: "PRT", RO: "ROU", SK: "SVK", SI: "SVN", ES: "ESP", SE: "SWE", IS: "ISL", LI: "LIE",
  NO: "NOR", CH: "CHE", GB: "GBR", UK: "GBR", US: "USA", CA: "CAN", AU: "AUS", NZ: "NZL", JP: "JPN", KR: "KOR",
  BR: "BRA", MX: "MEX", AR: "ARG", IN: "IND", CN: "CHN", TR: "TUR", UA: "UKR", MA: "MAR", ZA: "ZAF", RS: "SRB",
  AL: "ALB", BA: "BIH", ME: "MNE", MK: "MKD", MD: "MDA", GE: "GEO", AM: "ARM", IL: "ISR", AE: "ARE", SG: "SGP",
};

/** Issuer as ISO 3166-1 alpha-3, or null when it cannot be determined unambiguously. */
export function canonicalCountry(input: string | null | undefined): string | null {
  const v = (input ?? "").normalize("NFKD").toUpperCase().replace(/[^A-Z]/g, "");
  if (!v) return null;
  if (ICAO_TO_ISO3[v]) return ICAO_TO_ISO3[v]!;
  if (v.length === 2) return ISO2_TO_ISO3[v] ?? null;
  return v.length === 3 ? v : null;
}

/** Identifier value: NFKD without combining marks, upper case, A-Z and 0-9 only. */
export function canonicalValue(input: string | null | undefined): string {
  return (input ?? "")
    .normalize("NFKD")
    .replace(/\p{M}+/gu, "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
}

/** Document class from a provider label ("Passport", "Identity Card") or an MRZ type ("P", "ID", "I<"). */
export function documentClass(input: string | null | undefined): "P" | "I" | "R" | "DL" | "X" {
  const v = (input ?? "").normalize("NFKD").toUpperCase().replace(/[^A-Z]/g, "");
  if (!v) return "X";
  if (v.startsWith("PASS") || v === "P" || /^P[A-Z]$/.test(v)) return "P";
  if (v.includes("DRIV") || v === "DL") return "DL";
  if (v.includes("RESIDEN") || v === "R" || v === "RP") return "R";
  if (v.includes("IDENT") || v === "ID" || v === "I" || v === "IC" || /^I[A-Z]$/.test(v) || v.includes("NATIONALID")) return "I";
  return "X";
}

const MIN_LEN = 5;
const MAX_LEN = 32;

/** Canonical anchors, personal number first; [] when the claims cannot anchor an identity. */
export function canonicalAnchors(claims: DocumentClaims): CanonicalAnchor[] {
  const issuer = canonicalCountry(claims.issuingState) ?? canonicalCountry(claims.nationality);
  if (!issuer) return [];
  const out: CanonicalAnchor[] = [];
  const pn = canonicalValue(claims.personalNumber);
  if (!NON_STATE.has(issuer) && pn.length >= MIN_LEN + 1 && pn.length <= MAX_LEN) {
    out.push({ kind: "personal_number", bytes: secretBuffer(`${issuer}:PN:${pn}`) });
  }
  const doc = canonicalValue(claims.documentNumber);
  if (doc.length >= MIN_LEN && doc.length <= MAX_LEN) {
    const cls = documentClass(claims.documentType);
    // A personal number repeated as document number (some ID cards) is one anchor, not two.
    if (!(out.length && doc === pn)) out.push({ kind: "document", bytes: secretBuffer(`${issuer}:${cls}:${doc}`) });
  }
  return out;
}

/** Zero-fill every anchor buffer (call in finally). */
export function wipeAnchors(anchors: readonly CanonicalAnchor[]) {
  for (const a of anchors) a.bytes.fill(0);
}
