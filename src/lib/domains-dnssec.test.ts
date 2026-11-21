import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/neon", () => ({ sql: vi.fn() }));
import { checkDomainDns, queryWithDnssec } from "./domains.server";

function doh(answers: Record<string, { AD: boolean; data: string[] }>) {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    const u = new URL(url);
    expect(u.searchParams.get("do")).toBe("1");
    const a = answers[`${u.searchParams.get("name")}|${u.searchParams.get("type")}`];
    return new Response(JSON.stringify({ Status: 0, AD: a?.AD ?? false, Answer: (a?.data ?? []).map((d) => ({ name: "x", type: 16, data: `"${d}"` })) }));
  }));
}
afterEach(() => vi.unstubAllGlobals());

describe("DNSSEC-required domain verification", () => {
  it("reports the AD bit of the resolver", async () => {
    doh({ "_rout.signed.be|TXT": { AD: true, data: ["tok"] } });
    expect(await queryWithDnssec("_rout.signed.be", "TXT")).toEqual({ records: ["tok"], dnssec: true });
  });

  it("verifies only a DNSSEC-validated ownership record", async () => {
    doh({ "_rout.signed.be|TXT": { AD: true, data: ["rout-verify=tok"] }, "signed.be|CNAME": { AD: true, data: ["edge.rout.be."] } });
    const ok = await checkDomainDns("signed.be", "tok", "edge.rout.be", "1.2.3.4");
    expect(ok).toMatchObject({ txtFound: true, dnssecMissing: false, cnameFound: true });
  });

  it("refuses the same record from an unsigned zone and says why", async () => {
    doh({ "_rout.plain.be|TXT": { AD: false, data: ["rout-verify=tok"] }, "plain.be|CNAME": { AD: false, data: ["edge.rout.be."] } });
    const r = await checkDomainDns("plain.be", "tok", "edge.rout.be", "1.2.3.4");
    expect(r).toMatchObject({ txtFound: false, dnssecMissing: true });
  });
});
