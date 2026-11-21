import { describe, expect, it } from "vitest";
import { HUB_COPY, hubCopy } from "./hub-copy";
import { nextPollDelay, POLL_DEADLINE_MS } from "./modal-flow";

function keys(o: unknown, prefix = ""): string[] {
  return Object.entries(o as Record<string, unknown>).flatMap(([k, v]) => (v && typeof v === "object" ? keys(v, `${prefix}${k}.`) : [`${prefix}${k}`]));
}

describe("hub copy", () => {
  it("has the same non-empty keys in nl, en, fr and de", () => {
    const ref = keys(HUB_COPY.nl).sort();
    for (const l of ["en", "fr", "de"] as const) expect(keys(HUB_COPY[l]).sort()).toEqual(ref);
    for (const l of Object.values(HUB_COPY)) for (const k of keys(l)) expect(k.split(".").reduce<any>((o, p) => o[p], l)).not.toBe("");
  });

  it("uses the owner's exact Dutch search text and chips", () => {
    expect(HUB_COPY.nl.search).toBe("Zoek provider, land of documenttype (bijv. itsme, DigiD, IDnow)...");
    expect(Object.values(HUB_COPY.nl.filters)).toEqual(["Alle", "⚡ Nationale eID", "🛂 ID-kaart, paspoort & NFC", "🛡️ Zero-Knowledge"]);
  });

  it("falls back to Dutch", () => {
    expect(hubCopy("es")).toBe(HUB_COPY.nl);
    expect(hubCopy("fr-BE")).toBe(HUB_COPY.fr);
  });
});

describe("modal polling schedule", () => {
  it("polls every 3 s, then 10 s, then 30 s, and stops after 20 minutes", () => {
    expect(nextPollDelay(0)).toBe(3_000);
    expect(nextPollDelay(3 * 60_000)).toBe(10_000);
    expect(nextPollDelay(11 * 60_000)).toBe(30_000);
    expect(POLL_DEADLINE_MS).toBe(20 * 60_000);
  });
});
