// @vitest-environment node
/**
 * The manager inbox's own statements (src/lib/workspace-inbox-sql.ts) on an offline replay of
 * db/. Proves the key setup is all-or-nothing: an owner or admin ends with a live epoch they
 * hold; anyone else, or a refused envelope, leaves no epoch behind at all, so the ask page can
 * never open on a key nobody can read. Also checks the role lookup the inbox gates on.
 * Neon is not touched.
 */
import { randomBytes, randomUUID } from "node:crypto";
import type { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { replayDb } from "../../scripts/formal-rls/replay";
import { b64uEncode } from "@/lib/booking-engine/sealed-booking";
import { ASK_KEY, ASK_SAVE, KEY_INIT, QUESTIONS, ROLE, STATE } from "@/lib/workspace-inbox-sql";

const OWNER = "00000000-0000-4000-8000-0000000000b1";
const ADMIN = "00000000-0000-4000-8000-0000000000b2";
const DEVELOPER = "00000000-0000-4000-8000-0000000000b3";
const OUTSIDER = "00000000-0000-4000-8000-0000000000b4";
const WS = "00000000-0000-4000-8000-0000000000e1";
const WS_ADMIN = "00000000-0000-4000-8000-0000000000e2";

const publicKey = () => b64uEncode(new Uint8Array(randomBytes(1600)));
const kid = () => b64uEncode(new Uint8Array(randomBytes(16)));
/** A wsk-shaped RVE1 envelope in the smallest padded bucket. */
const wsk = () => {
  const b = new Uint8Array(randomBytes(2687));
  b.set([0x52, 0x56, 0x45, 0x31, 0x01, 10], 0);
  return b64uEncode(b);
};

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
  await db.exec(`
    insert into public.users (id, email) values
      ('${OWNER}', 'i1@example.test'), ('${ADMIN}', 'i2@example.test'), ('${DEVELOPER}', 'i3@example.test'), ('${OUTSIDER}', 'i4@example.test');
    insert into public.workspaces (id, name, slug) values ('${WS}', 'Inbox Club', 'inbox-club'), ('${WS_ADMIN}', 'Admin Club', 'admin-club');
    insert into public.workspace_members (workspace_id, user_id, role) values
      ('${WS}', '${OWNER}', 'owner'), ('${WS}', '${DEVELOPER}', 'developer'),
      ('${WS_ADMIN}', '${OWNER}', 'owner'), ('${WS_ADMIN}', '${ADMIN}', 'admin');
  `);
}, 300_000);
afterAll(async () => { await db?.close(); });

/** One app batch as rout_app with the member context, exactly like runBatch: all or nothing. */
async function batch(userId: string, statements: { query: string; params: unknown[] }[]) {
  await db.exec("begin; set local role rout_app;");
  try {
    await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    const out: Record<string, unknown>[][] = [];
    for (const s of statements) out.push((await db.query<Record<string, unknown>>(s.query, s.params)).rows);
    await db.exec("commit;");
    return out;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}
const keyInit = (userId: string, ws: string, epoch: number, envelope = wsk(), member = userId) => {
  const k = kid();
  return batch(userId, [
    { query: KEY_INIT[0]!, params: [ws, epoch, publicKey(), k] },
    { query: KEY_INIT[1]!, params: [ws, epoch, member, randomUUID(), k, envelope] },
    { query: KEY_INIT[2]!, params: [ws, epoch] },
  ]);
};
const epochs = async (ws: string) =>
  ((await batch(OWNER, [{ query: STATE, params: [ws] }]))[0]![0]!["r"] as { epochs: { epoch: number; status: string; heldBy: number }[] }).epochs;

describe("workspace inbox key setup", () => {
  it("the role lookup answers owner, admin and developer, and nothing for an outsider", async () => {
    const role = async (u: string, ws: string) => (await batch(u, [{ query: ROLE, params: [ws] }]))[0]![0]!["r"];
    expect(await role(OWNER, WS)).toBe("owner");
    expect(await role(ADMIN, WS_ADMIN)).toBe("admin");
    expect(await role(DEVELOPER, WS)).toBe("developer");
    expect(await role(OUTSIDER, WS)).toBeNull();
  });

  it("a developer's attempt publishes nothing", async () => {
    await expect(keyInit(DEVELOPER, WS, 1)).rejects.toThrow(/division by zero/);
    expect(await epochs(WS)).toEqual([]);
  });

  it("an envelope of the wrong shape rolls the publish back too", async () => {
    await expect(keyInit(OWNER, WS, 1, "not-an-envelope")).rejects.toThrow(/division by zero/);
    expect(await epochs(WS)).toEqual([]);
  });

  it("storing the key for someone else (here a developer) also rolls back", async () => {
    await expect(keyInit(OWNER, WS, 1, wsk(), DEVELOPER)).rejects.toThrow(/division by zero/);
    expect(await epochs(WS)).toEqual([]);
  });

  it("the owner ends with a live epoch 1 that they hold", async () => {
    const [pub, store] = await keyInit(OWNER, WS, 1);
    expect(pub![0]!["r"]).toMatchObject({ ok: true, epoch: 1 });
    expect(store![0]!["r"]).toMatchObject({ ok: true });
    expect(await epochs(WS)).toMatchObject([{ epoch: 1, status: "active", heldBy: 1 }]);
  });

  it("an admin sets up their own workspace the same way", async () => {
    await keyInit(ADMIN, WS_ADMIN, 1);
    expect(await epochs(WS_ADMIN)).toMatchObject([{ epoch: 1, status: "active", heldBy: 1 }]);
  });

  it("a rotation retires epoch 1 and leaves epoch 2 live and held", async () => {
    await keyInit(OWNER, WS, 2);
    expect(await epochs(WS)).toMatchObject([{ epoch: 2, status: "active", heldBy: 1 }, { epoch: 1, status: "retired" }]);
  });

  it("only a manager switches the page on, and the public key answers only then", async () => {
    expect((await batch(DEVELOPER, [{ query: ASK_SAVE, params: [WS, true] }]))[0]![0]!["r"]).toBe("forbidden");
    expect((await batch(OUTSIDER, [{ query: ASK_KEY, params: ["inbox-club"] }]))[0]![0]!["r"]).toBeNull();
    expect((await batch(OWNER, [{ query: ASK_SAVE, params: [WS, true] }]))[0]![0]!["r"]).toBe("ok");
    expect((await batch(OUTSIDER, [{ query: ASK_KEY, params: ["inbox-club"] }]))[0]![0]!["r"]).toMatchObject({ workspaceId: WS, epoch: 2 });
  });

  it("a developer sees no questions and no key history", async () => {
    const [list, state] = await batch(DEVELOPER, [{ query: QUESTIONS, params: [WS] }, { query: STATE, params: [WS] }]);
    expect(list).toEqual([]);
    expect(state![0]!["r"]).toEqual({ epochs: [] });
  });
});
