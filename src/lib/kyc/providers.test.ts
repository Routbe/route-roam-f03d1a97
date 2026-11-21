import { describe, expect, it } from "vitest";
import { discoverProviders, IDENTITY_PROVIDERS, recommendedProviders, regionFromLocale } from "./providers";
import { readFileSync } from "node:fs";

const ids = (l: { id: string }[]) => l.map((p) => p.id);

describe("provider discovery", () => {
  it("lists the providers named by the owner", () => {
    for (const id of ["itsme", "digid", "eid", "france_identite", "mitid", "cie", "didit", "idnow", "shufti_pro", "trulioo", "world_id"]) {
      expect(ids([...IDENTITY_PROVIDERS])).toContain(id);
    }
  });

  it("uses only provider ids the 0288 provider CHECK allows", () => {
    const sql = readFileSync("db/0288_universal_identity_nullifiers.sql", "utf8");
    for (const p of IDENTITY_PROVIDERS) expect(sql).toContain(`'${p.id}'`);
  });

  it("only Didit and W Identity have an engine", () => {
    expect(IDENTITY_PROVIDERS.filter((p) => p.engine).map((p) => p.id).sort()).toEqual(["didit", "w_identity"]);
  });

  it("searches names, countries, documents and national numbers", () => {
    expect(ids(discoverProviders({ query: "itsme" }))).toEqual(["itsme"]);
    expect(ids(discoverProviders({ query: "DigiD" }))).toEqual(["digid"]);
    expect(ids(discoverProviders({ query: "idnow" }))).toEqual(["idnow"]);
    expect(ids(discoverProviders({ query: "bsn" }))).toEqual(["digid"]);
    expect(ids(discoverProviders({ query: "rijksregisternummer" }))).toEqual(["itsme"]);
    expect(ids(discoverProviders({ query: "identite" }))).toContain("france_identite");
    expect(ids(discoverProviders({ query: "paspoort", docLabels: { passport: "Paspoort" } }))).toContain("didit");
    expect(discoverProviders({ query: "zzzz" })).toEqual([]);
  });

  it("filters by category chip", () => {
    expect(discoverProviders({ filter: "national_eid" }).every((p) => p.categories.includes("national_eid"))).toBe(true);
    expect(ids(discoverProviders({ filter: "zero_knowledge" })).sort()).toEqual(["w_identity", "world_id"]);
  });

  it("orders active engines first, then the member's region", () => {
    const list = discoverProviders({ region: "BE", active: new Set(["didit"]) });
    expect(list[0]!.id).toBe("didit");
    expect(list[1]!.id).toBe("itsme");
    const nl = discoverProviders({ region: "NL" });
    expect(ids(nl).indexOf("digid")).toBeLessThan(ids(nl).indexOf("mitid"));
  });

  it("recommends regional providers plus the active ones", () => {
    const r = ids(recommendedProviders("DK", new Set(["didit"])));
    expect(r).toContain("mitid");
    expect(r).toContain("didit");
    expect(r).not.toContain("digid");
  });

  it("reads the region from a language tag", () => {
    expect(regionFromLocale("nl-BE")).toBe("BE");
    expect(regionFromLocale("fr_fr")).toBe("FR");
    expect(regionFromLocale("de")).toBeNull();
    expect(regionFromLocale(undefined)).toBeNull();
  });
});
