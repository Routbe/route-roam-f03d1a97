import { describe, expect, it } from "vitest";
import { readDiditDecision } from "./didit-decision";

const base = {
  session_id: "11111111-2222-3333-4444-555555555555",
  vendor_data: "rk1.ref",
  status: "Approved",
  id_verifications: [{
    status: "Approved", document_type: "Identity Card", document_number: "CAA000000", personal_number: "99999999R",
    issuing_state: "ESP", nationality: "ESP", first_name: "Carmen", last_name: "Española", date_of_birth: "1980-01-01",
    portrait_image: "https://example.invalid/p.jpg",
  }],
  liveness_checks: [{ status: "Approved" }],
  face_matches: [{ status: "Approved" }],
};
const expectIds = { sessionId: base.session_id, vendorData: base.vendor_data };

describe("readDiditDecision", () => {
  it("extracts only the anchor fields, the age vector and the legal name, never dates or images", () => {
    const r = readDiditDecision(base, expectIds);
    expect(r).toEqual({
      ok: true,
      jurisdiction: "ESP",
      isRealHuman: true,
      ageVector: 511,
      legalName: { first: "Carmen", last: "Española" },
      claims: { issuingState: "ESP", nationality: "ESP", documentType: "Identity Card", documentNumber: "CAA000000", personalNumber: "99999999R" },
    });
    const flat = JSON.stringify(r);
    for (const pii of ["1980", "01-01", "jpg"]) expect(flat).not.toContain(pii);
  });

  it("drops a legal name that is missing or not a plausible name", () => {
    const doc = base.id_verifications[0]!;
    const r = readDiditDecision({ ...base, id_verifications: [{ ...doc, last_name: "<script>" }] }, expectIds);
    expect(r.ok && r.legalName).toBeNull();
  });

  it("prefers the state-signed NFC chip read over OCR", () => {
    const r = readDiditDecision({ ...base, nfc_verifications: [{ status: "Approved", document_number: "CHIP12345", issuing_state: "ESP" }] }, expectIds);
    expect(r.ok && r.claims.documentNumber).toBe("CHIP12345");
    expect(r.ok && r.claims.personalNumber).toBe("99999999R");
  });

  it("binds the decision to the webhook's session and vendor reference", () => {
    expect(readDiditDecision({ ...base, session_id: "other" }, expectIds)).toEqual({ ok: false, reason: "session_mismatch" });
    expect(readDiditDecision({ ...base, vendor_data: "rk1.other" }, expectIds)).toEqual({ ok: false, reason: "vendor_mismatch" });
  });

  it("refuses anything that is not approved or has no usable document", () => {
    expect(readDiditDecision({ ...base, status: "Declined" }, expectIds)).toEqual({ ok: false, reason: "not_approved" });
    expect(readDiditDecision({ ...base, id_verifications: [{ ...base.id_verifications[0], status: "Declined" }] }, expectIds)).toEqual({ ok: false, reason: "no_document" });
    expect(readDiditDecision({ ...base, id_verifications: [{ ...base.id_verifications[0], issuing_state: "", nationality: "" }] }, expectIds)).toEqual({ ok: false, reason: "no_document" });
    expect(readDiditDecision(null, expectIds)).toEqual({ ok: false, reason: "session_mismatch" });
  });

  it("is a real human only with a passed liveness check and no failed face match", () => {
    expect((readDiditDecision({ ...base, liveness_checks: [] }, expectIds) as { isRealHuman: boolean }).isRealHuman).toBe(false);
    expect((readDiditDecision({ ...base, face_matches: [{ status: "Declined" }] }, expectIds) as { isRealHuman: boolean }).isRealHuman).toBe(false);
  });
});
