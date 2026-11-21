// @vitest-environment node
import { afterEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ postgres: vi.fn(), begin: vi.fn(), unsafe: vi.fn(), batch: vi.fn() }));
vi.mock("postgres", () => ({ default: mocks.postgres }));
import { databaseTransport, runBatch, withDbContext } from "@/lib/neon";
afterEach(() => { vi.unstubAllEnvs(); vi.clearAllMocks(); });

function fakeDriver() {
  mocks.unsafe.mockImplementation(async (query: string) => Object.assign(query === "select true as ok" ? [{ ok: true }] : [], { count: 1, command: "SELECT" }));
  mocks.begin.mockImplementation(async (a: unknown, b?: unknown) => (typeof a === "function" ? a : b as (tx: unknown) => unknown)({ unsafe: mocks.unsafe, batch: mocks.batch, typed: (value: unknown) => value }));
  mocks.postgres.mockReturnValue({
    begin: mocks.begin, unsafe: mocks.unsafe, end: vi.fn(),
    batch: mocks.batch.mockImplementation(async (parts: Promise<unknown>[]) => Promise.all(parts)),
    typed: (value: unknown) => value,
  });
}

it("reads DATABASE_URL after import, enforces TLS and preserves the atomic security prefix", async () => {
  vi.stubEnv("DATABASE_URL", "postgresql://runtime:secret@ep-test.neon.tech/db");
  fakeDriver();
  expect(databaseTransport()).toBe("direct");
  const result = await withDbContext({ userId: "11111111-1111-4111-8111-111111111111", workspaceId: null }, () => runBatch([{ query: "select true as ok", params: [] }]));
  expect(mocks.postgres).toHaveBeenCalledWith("postgresql://runtime:secret@ep-test.neon.tech/db", expect.objectContaining({ ssl: "require" }));
  // One pipelined batch (one Sync), no BEGIN/COMMIT round trips.
  expect(mocks.begin).not.toHaveBeenCalled();
  expect(mocks.batch).toHaveBeenCalledTimes(1);
  expect(mocks.unsafe.mock.calls[0]?.[0]).toBe("set local role rout_app");
  expect(mocks.unsafe.mock.calls[1]?.[0]).toContain("set_config");
  expect(mocks.unsafe.mock.calls[2]?.[0]).toContain("runtime_role_unsafe");
  expect(result[0]?.rows).toEqual([{ ok: true }]);
});

it("ignores Lovable connector keys: without DATABASE_URL there is no database", () => {
  vi.stubEnv("DATABASE_URL", "");
  vi.stubEnv("NEON_API_KEY", "test"); vi.stubEnv("LOVABLE_API_KEY", "test");
  expect(databaseTransport()).toBe("none");
});

it("runs serializable batches with the isolation level on BEGIN", async () => {
  vi.stubEnv("DATABASE_URL", "postgresql://runtime:secret@ep-test2.neon.tech/db");
  fakeDriver();
  await runBatch([{ query: "select true as ok", params: [] }], { isolation: "Serializable" });
  expect(mocks.begin.mock.calls[0]?.[0]).toBe("isolation level serializable");
  expect(mocks.batch).toHaveBeenCalledTimes(1);
});
