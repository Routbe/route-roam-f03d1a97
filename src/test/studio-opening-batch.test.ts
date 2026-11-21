import { beforeEach, describe, expect, it, vi } from "vitest";

type Lazy = { query: string; params: unknown[] };
const batches: Lazy[][] = [];
const single: Lazy[] = [];
let batchFails = false;
let draftRow: Record<string, unknown> | null = null;
const USER = "11111111-1111-4111-8111-111111111111";
const PROFILE = { username: "jan", display_name: "Jan", theme: "noir", card_style: "bordered", blocks: [], display_prefs: {} };

function answer(q: Lazy): Record<string, unknown>[] {
  if (q.query.includes("from public.profiles")) return [{ ...PROFILE }];
  if (q.query.includes("alias_profiles")) return [{ handle: "jan-alias" }];
  if (q.query.includes("rout_public_identity_badges")) return [{ user_id: USER, didit_legal_identity: true }];
  if (q.query.includes("from public.profile_drafts")) return draftRow ? [draftRow] : [];
  return [];
}

vi.mock("@/lib/neon", () => {
  const make = (strings: TemplateStringsArray, ...values: unknown[]) => {
    const lazy: Lazy = { query: strings.join("$"), params: values };
    return Object.assign(lazy, {
      then: (ok: (rows: unknown) => unknown, bad?: (e: unknown) => unknown) => {
        single.push(lazy);
        return Promise.resolve(answer(lazy)).then(ok, bad);
      },
    });
  };
  const sql = Object.assign(make, {
    transaction: async (queries: Lazy[]) => {
      batches.push(queries);
      if (batchFails) throw Object.assign(new Error("relation missing"), { code: "42P01" });
      return queries.map(answer);
    },
  });
  return { sql };
});

describe("opening the profile studio", () => {
  beforeEach(() => { batches.length = 0; single.length = 0; batchFails = false; draftRow = null; });

  it("reads profile, alias, blue mark and draft in one database round trip", async () => {
    draftRow = { payload: { username: "jan", displayName: "Draft" }, revision: 3, published_revision: 2 };
    const { readStudioOpening } = await import("@/lib/studio-profile.server");
    const opened = await readStudioOpening(USER, "verified");
    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(4);
    expect(single).toHaveLength(0);
    expect(opened?.live.aliasHandle).toBe("jan-alias");
    expect(opened?.live.diditVerified).toBe(true);
    expect(opened?.draft?.["revision"]).toBe(3);
  });

  it("binds the badge lookup to a scalar id so the batch needs no type lookup first", async () => {
    const { readStudioOpening } = await import("@/lib/studio-profile.server");
    await readStudioOpening(USER, "verified");
    const badge = batches[0]?.find((q) => q.query.includes("rout_public_identity_badges"));
    expect(badge?.params).toEqual([USER]);
  });

  it("reports a missing draft so only the first opening creates one", async () => {
    const { readStudioOpening } = await import("@/lib/studio-profile.server");
    const opened = await readStudioOpening(USER, "verified");
    expect(opened?.draft).toBeNull();
  });

  it("never gives the blue mark when the badge function answers for nobody", async () => {
    const { readStudioOpening } = await import("@/lib/studio-profile.server");
    const opened = await readStudioOpening("22222222-2222-4222-8222-222222222222", null);
    expect(opened?.live.diditVerified).toBe(false);
  });

  it("falls back to separate tolerant reads when the batch fails", async () => {
    batchFails = true;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { readStudioOpening } = await import("@/lib/studio-profile.server");
    const opened = await readStudioOpening(USER, "verified");
    expect(opened?.live.username).toBe("jan");
    expect(opened?.draft).toBeUndefined();
    expect(single.some((q) => q.query.includes("from public.profiles"))).toBe(true);
  });
});
