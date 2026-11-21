// @vitest-environment node
import { PGlite } from "@electric-sql/pglite";
import { afterEach, expect, it, vi } from "vitest";
import { GatewayPool, bindParam, jsonText, runBatch, withDbContext } from "@/lib/neon";
import { contextStatements } from "@/lib/db-context";
const { postgresMock } = vi.hoisted(() => ({ postgresMock: vi.fn() }));
vi.mock("postgres", () => ({ default: postgresMock }));

afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });
it("refuses fake interactive transactions before any network request", async () => {
  const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
  const pool = new GatewayPool();
  await expect(pool.query("BEGIN")).rejects.toThrow("interactive_transactions_unsupported");
  await expect(pool.query("ROLLBACK")).rejects.toThrow("interactive_transactions_unsupported");
  await expect(pool.connect()).rejects.toThrow("interactive_transactions_unsupported");
  expect(fetch).not.toHaveBeenCalled();
});
it("steps down to rout_app, then sends context and role guard in the same atomic batch", async () => {
  vi.stubEnv("DATABASE_URL", "postgresql://u:p@ep-steps.neon.tech/db");
  const userId="11111111-1111-4111-8111-111111111111";
  const unsafe=vi.fn(async (query: string) => Object.assign(query === "select true as ok" ? [{ok:true}] : [], { count: 1, command: "SELECT" }));
  const begin=vi.fn(async (fn: (tx: unknown) => unknown) => fn({ unsafe }));
  const batch=vi.fn(async (parts: Promise<unknown>[]) => Promise.all(parts));
  const typed=(value: unknown, oid: number) => ({ value, oid });
  postgresMock.mockReturnValue({ begin, unsafe, batch, typed, end: vi.fn() });
  const results=await withDbContext({userId,workspaceId:null},()=>runBatch([{query:"select true as ok",params:[]}]));
  expect(unsafe.mock.calls[0]?.[0]).toBe("set local role rout_app");
  expect(unsafe.mock.calls[1]?.[0]).toContain("set_config('rout.current_user_id', $1, true)");
  expect((unsafe.mock.calls[1] as unknown[])?.[1]).toEqual(expect.arrayContaining([{ value: userId, oid: 705 }]));
  expect(unsafe.mock.calls[2]?.[0]).toContain("runtime_role_unsafe");
  // Every statement stays on the extended protocol inside one Sync.
  expect(unsafe.mock.calls.every((c) => (c as unknown[])[2] && ((c as unknown[])[2] as { simple?: boolean }).simple === false)).toBe(true);
  expect(results[0]?.rows).toEqual([{ok:true}]);
  expect(batch).toHaveBeenCalledTimes(1);
  expect(batch.mock.calls[0]?.[0]).toHaveLength(4);
  expect(begin).not.toHaveBeenCalled();
});

it("binds scalars as untyped text and leaves booleans, bytes and arrays to the driver", () => {
  const typed=(value: unknown, oid: number) => ({ value, oid });
  expect(bindParam({ typed } as never, "abc")).toEqual({ value: "abc", oid: 705 });
  expect(bindParam({ typed } as never, 42)).toEqual({ value: "42", oid: 705 });
  expect(bindParam({ typed } as never, null)).toEqual({ value: null, oid: 705 });
  expect(bindParam({ typed } as never, true)).toBe(true);
  const bytes=new Uint8Array([1]);
  expect(bindParam({ typed } as never, bytes)).toBe(bytes);
  const list=["a","b"];
  expect(bindParam({ typed } as never, list)).toBe(list);
});

it("sends JSON text to json(b) parameters as the JSON it is", () => {
  expect(jsonText('{"a":1}')).toBe('{"a":1}');
  expect(jsonText(["a","b"])).toBe('["a","b"]');
  expect(jsonText({ a: 1 })).toBe('{"a":1}');
});
it("PostgreSQL rolls back a late failure and clears transaction-local current_user_id", async () => {
  const db=new PGlite(); const userId="11111111-1111-4111-8111-111111111111";
  try {
    await db.exec("create table tx_probe(id int primary key)");
    await db.exec("BEGIN");
    const statement=contextStatements({userId,workspaceId:null})[0];
    if (!statement) throw new Error("Missing context statement");
    await db.query(statement.query,statement.params);
    expect((await db.query<{uid:string}>("select current_setting('rout.current_user_id',true) as uid")).rows[0]?.uid).toBe(userId);
    await db.exec("insert into tx_probe values(1)");
    await expect(db.exec("insert into tx_probe values(1)")).rejects.toThrow();
    await db.exec("ROLLBACK");
    expect((await db.query("select * from tx_probe")).rows).toEqual([]);
    expect((await db.query<{uid:string|null}>("select nullif(current_setting('rout.current_user_id',true),'') as uid")).rows[0]?.uid).toBeNull();
  } finally { await db.close(); }
}, 30000);