import { describe, expect, it } from "vitest";
import {
  legalHandleTiers,
  verifiedHandleCandidates,
  validateChosenVerifiedHandle,
  isSafeVerifiedHandleShape,
} from "@/lib/verified-handle-builder";
import { isReservedSlug, isProtectedPublicSlug } from "@/lib/reserved-slugs";

const reserved = (h: string) => isReservedSlug(h) || isProtectedPublicSlug(h);
const all = (n: Parameters<typeof legalHandleTiers>[0]) => {
  const t = legalHandleTiers(n);
  if (!t) throw new Error("no tiers");
  return [...t.tier1, ...t.tier2, ...t.tier3, ...t.tier4];
};

describe("verified-handle-builder", () => {
  it("normale naam: voornaam en achternaam eerst, met elk scheidingsteken", () => {
    const t = legalHandleTiers({ first: "Jan", last: "Peeters" })!;
    for (const h of ["jan.peeters", "peeters.jan", "jan-peeters", "jan_peeters", "janpeeters", "peetersjan"]) {
      expect(t.tier1).toContain(h);
    }
  });

  it("accenten worden ASCII", () => {
    const hs = all({ first: "José", last: "Ménière" });
    expect(hs).toContain("jose.meniere");
    expect(hs.every((h) => /^[a-z0-9._-]+$/.test(h))).toBe(true);
  });

  it("dubbele achternaam en tussenvoegsels", () => {
    expect(all({ first: "Jan", last: "Van den Broeck" })).toContain("jan.vandenbroeck");
    expect(all({ first: "Marie", last: "Dupont-Lambert" })).toContain("marie.dupontlambert");
  });

  it("tussennamen leveren varianten, primaire naam blijft herleidbaar", () => {
    const hs = all({ first: "Jona Zeno", last: "Delplanche" });
    expect(hs).toContain("jona.delplanche");
    expect(hs.some((h) => h.includes("zeno"))).toBe(true);
  });

  it("nooit '..' in eender welke variant", () => {
    for (const n of [{ first: "Jan", last: "Peeters" }, { first: "A. B.", last: "De Smet" }, { first: "Jona Zeno", last: "d'Haene" }]) {
      expect(all(n).some((h) => h.includes(".."))).toBe(false);
    }
    expect(isSafeVerifiedHandleShape("jan..peeters", true)).toBe(false);
  });

  it("valt pas terug op -- en __ als alles bezet is", () => {
    const name = { first: "Jan", last: "Peeters" };
    expect(verifiedHandleCandidates(name).every((c) => c.tier < 4)).toBe(true);
    const t = legalHandleTiers(name)!;
    const normal = new Set([...t.tier1, ...t.tier2, ...t.tier3]);
    const out = verifiedHandleCandidates(name, { isTaken: (h) => normal.has(h) });
    expect(out.length).toBeGreaterThan(0);
    expect(out.every((c) => c.tier === 4)).toBe(true);
    expect(out.map((c) => c.handle)).toContain("jan--peeters");
    expect(out.map((c) => c.handle)).toContain("jan__peeters");
  });

  it("weigert een fallback zolang een normale variant vrij is", () => {
    const r = validateChosenVerifiedHandle({ first: "Jan", last: "Peeters" }, "jan--peeters", { isTaken: () => false, isReserved: reserved });
    expect(r).toEqual({ ok: false, code: "HANDLE_FALLBACK_NOT_ALLOWED" });
  });

  it("weigert gemanipuleerde handles die niet bij de Didit-naam horen", () => {
    const r = validateChosenVerifiedHandle({ first: "Jan", last: "Peeters" }, "piet.janssens", { isTaken: () => false, isReserved: reserved });
    expect(r).toEqual({ ok: false, code: "HANDLE_NOT_LEGALLY_TRACEABLE" });
  });

  it("weigert een bezette handle", () => {
    const r = validateChosenVerifiedHandle({ first: "Jan", last: "Peeters" }, "jan.peeters", { isTaken: (h) => h === "jan.peeters", isReserved: reserved });
    expect(r).toEqual({ ok: false, code: "HANDLE_TAKEN" });
  });

  it("aanvaardt een geldige vrije handle", () => {
    const r = validateChosenVerifiedHandle({ first: "Jan", last: "Peeters" }, "@Jan.Peeters", { isTaken: () => false, isReserved: reserved });
    expect(r).toEqual({ ok: true, tier: 1 });
  });

  it("gereserveerde namen zijn nooit claimbaar, ook niet als ze uit de naam volgen", () => {
    const r = validateChosenVerifiedHandle({ first: "Rout", last: "Admin" }, "admin", { isTaken: () => false, isReserved: reserved });
    expect(r.ok).toBe(false);
    for (const s of ["u", "api", "auth", "login", "register", "admin", "dashboard", "settings", "about", "verify", "badge", "badges", "workspace", "workspaces", "org", "support", "privacy", "terms", "legal", "security", "status", "rout", "delplanche"]) {
      expect(isReservedSlug(s)).toBe(true);
    }
    for (const s of ["monarchie", "koninklijkpaleis", "palaisroyal", "belgie", "belgique", "belgien", "belgium", "brussels", "bruxelles", "brussel", "vlaanderen", "wallonie", "vrt", "rtbf", "federaal", "overheid", "gouvernement", "politie", "police"]) {
      expect(isProtectedPublicSlug(s)).toBe(true);
    }
    const out = verifiedHandleCandidates({ first: "Jan", last: "Peeters" }, { isReserved: (h) => h === "jan.peeters" });
    expect(out.map((c) => c.handle)).not.toContain("jan.peeters");
  });
});
