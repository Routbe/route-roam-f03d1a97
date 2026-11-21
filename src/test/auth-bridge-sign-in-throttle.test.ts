import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];
let member: Record<string, unknown> = {};

vi.mock("@/lib/neon", () => ({
  sql: (strings: TemplateStringsArray) => {
    const query = strings.join("?");
    calls.push(query);
    if (query.includes("rout_resolve_account")) return Promise.resolve([]);
    if (query.includes("from public.users")) return Promise.resolve([{ ...member }]);
    return Promise.resolve([]);
  },
  withDbContext: async (_ctx: unknown, fn: () => Promise<unknown>) => fn(),
}));

const AUTH_ID = "11111111-1111-4111-8111-111111111111";
const identity = { id: AUTH_ID, email: "a@b.be", name: null, image: null, emailVerified: true };
const updates = () => calls.filter((q) => q.includes("update public.users"));

describe("last sign-in time is written at most once per hour", () => {
  beforeEach(() => {
    calls.length = 0;
    member = { id: AUTH_ID, email: "a@b.be", user_metadata: { neon_auth_id: AUTH_ID }, is_disabled: false };
  });

  it("asks the database clock whether the last write is an hour old", async () => {
    member.sign_in_stale = false;
    const { bridgeIdentity } = await import("@/lib/auth/bridge.server");
    await bridgeIdentity(identity);
    const read = calls.find((q) => q.includes("from public.users")) ?? "";
    expect(read).toContain("last_sign_in_at <= now() - interval '1 hour'");
  });

  it("skips the write when the member signed in less than an hour ago", async () => {
    member.sign_in_stale = false;
    const { bridgeIdentity } = await import("@/lib/auth/bridge.server");
    const user = await bridgeIdentity(identity);
    expect(user?.id).toBe(AUTH_ID);
    expect(updates()).toHaveLength(0);
  });

  it("writes once the hour has passed, guarded against a second concurrent write", async () => {
    member.sign_in_stale = true;
    const { bridgeIdentity } = await import("@/lib/auth/bridge.server");
    await bridgeIdentity(identity);
    expect(updates()).toHaveLength(1);
    expect(updates()[0]).toContain("last_sign_in_at <= now() - interval '1 hour'");
  });

  it("still records the first link of a new sign-in identity right away", async () => {
    member.sign_in_stale = false;
    member.user_metadata = {};
    member.auth_user_id = null;
    const { bridgeIdentity } = await import("@/lib/auth/bridge.server");
    await bridgeIdentity({ ...identity, id: AUTH_ID });
    expect(updates().some((q) => q.includes("last_sign_in_at = now()"))).toBe(true);
  });
});
