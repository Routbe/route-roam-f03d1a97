/**
 * Pure reading of a Didit v3 decision (GET /v3/session/{id}/decision/). Only the fields needed for a
 * canonical anchor, the zero-knowledge claims and the legal name are touched; addresses, images
 * and MRZ text are never copied out of the decision object. The date of birth is reduced on the
 * spot to the age-threshold vector (age-vector.ts) and never copied. The legal name is handed to
 * the engine only to be sealed at once into the member's RPF1 vault fields (owner directive
 * 2026-11-17); it is never stored, logged or returned in plaintext.
 */
import { ageVectorFromBirthDate } from "./age-vector";
import type { DocumentClaims } from "./canonical-id";
import { canonicalCountry } from "./canonical-id";

export type DiditStatus =
  | "Approved" | "Declined" | "In Review" | "In Progress" | "Not Started" | "Abandoned" | "Expired" | "Kyc Expired" | "Resubmitted" | "Awaiting User";

export type DecisionReading =
  | { ok: true; claims: DocumentClaims; jurisdiction: string; isRealHuman: boolean; ageVector: number | null; legalName: { first: string; last: string } | null }
  | { ok: false; reason: "not_approved" | "no_document" | "vendor_mismatch" | "session_mismatch" };

type Doc = { status?: unknown; document_type?: unknown; document_number?: unknown; personal_number?: unknown; issuing_state?: unknown; nationality?: unknown; date_of_birth?: unknown; first_name?: unknown; last_name?: unknown; given_names?: unknown; family_name?: unknown };
type Check = { status?: unknown };

const str = (v: unknown): string | null => (typeof v === "string" && v.length <= 128 ? v : null);
const approved = (x: { status?: unknown } | null | undefined) => x?.status === "Approved";

function first<T extends { status?: unknown }>(list: unknown): T | null {
  if (!Array.isArray(list)) return null;
  return (list.find((x) => x && typeof x === "object" && approved(x as T)) as T | undefined) ?? null;
}

const NAME = /^[\p{L}\p{M}' .-]{1,70}$/u;
const cleanName = (v: unknown) => {
  const s = str(v)?.normalize("NFC").replace(/\s+/g, " ").trim() ?? "";
  return NAME.test(s) ? s : null;
};
/** First and last name as printed on the document (chip first), or null when either is unusable. */
function legalNameOf(doc: Doc): { first: string; last: string } | null {
  // OCR uses first_name/last_name; chip (NFC) reads may carry the ICAO given_names/family_name.
  const first = cleanName(doc.first_name) ?? cleanName(doc.given_names);
  const last = cleanName(doc.last_name) ?? cleanName(doc.family_name);
  return first && last ? { first, last } : null;
}

export function readDiditDecision(decision: unknown, expect: { sessionId: string; vendorData: string }, now: Date = new Date()): DecisionReading {
  const d = (decision && typeof decision === "object" ? decision : {}) as Record<string, unknown>;
  if (d["session_id"] !== expect.sessionId) return { ok: false, reason: "session_mismatch" };
  if (d["vendor_data"] !== expect.vendorData) return { ok: false, reason: "vendor_mismatch" };
  if (d["status"] !== "Approved") return { ok: false, reason: "not_approved" };
  // A chip read (NFC) is preferred over OCR: it is signed by the issuing state.
  const chip = first<Doc>(d["nfc_verifications"]);
  const ocr = first<Doc>(d["id_verifications"]);
  const doc = chip && str(chip.document_number) ? { ...ocr, ...chip } : ocr;
  if (!doc || !str(doc.document_number)) return { ok: false, reason: "no_document" };
  const jurisdiction = canonicalCountry(str(doc.issuing_state)) ?? canonicalCountry(str(doc.nationality));
  if (!jurisdiction) return { ok: false, reason: "no_document" };
  const live = first<Check>(d["liveness_checks"]);
  const faces = Array.isArray(d["face_matches"]) ? (d["face_matches"] as Check[]) : [];
  return {
    ok: true,
    claims: {
      issuingState: str(doc.issuing_state),
      nationality: str(doc.nationality),
      documentType: str(doc.document_type),
      documentNumber: str(doc.document_number),
      personalNumber: str(doc.personal_number),
    },
    jurisdiction,
    // A real human means a passed liveness check, and no failed face match against the document.
    isRealHuman: Boolean(live) && faces.every((f) => f?.status === undefined || approved(f)),
    // The chip's date of birth is state-signed; OCR is the fallback.
    ageVector: ageVectorFromBirthDate(chip?.date_of_birth, now) ?? ageVectorFromBirthDate(ocr?.date_of_birth, now),
    legalName: legalNameOf(doc),
  };
}

/** The coarse states the status endpoint reports. */
export type KycState = "none" | "pending" | "in_review" | "verified";
