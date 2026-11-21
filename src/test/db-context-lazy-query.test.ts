import { afterEach, describe, expect, it, vi } from "vitest";
const { postgresMock } = vi.hoisted(() => ({ postgresMock: vi.fn() }));
vi.mock("postgres", () => ({ default: postgresMock }));
import { sql, withDbContext } from "@/lib/neon";

const USER = "3ee53fa5-3c3c-49c4-a197-87d2461a1ae1";

describe("database context on deferred queries", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("keeps the signed-in account when a query is awaited after withDbContext returns", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://u:p@ep-lazy.neon.tech/db");
    const calls: { query: string; params: unknown[] }[] = [];
    const unsafe = async (query: string, params: unknown[]) => { calls.push({ query, params }); return Object.assign([], { count: 0, command: "SELECT" }); };
    postgresMock.mockReturnValue({
      begin: async (fn: (tx: unknown) => unknown) => fn({ unsafe }), unsafe, end: vi.fn(),
      batch: async (parts: Promise<unknown>[]) => Promise.all(parts), typed: (value: unknown) => value,
    });

    // The same shape the sign-in bridge uses: the callback returns the unexecuted query.
    await withDbContext({ userId: USER, workspaceId: null }, () => sql`select 1`);

    const contextStatement = calls.find((q) => q.query.includes("rout.current_user_id"));
    expect(contextStatement?.params[0]).toBe(USER);
  });
});
