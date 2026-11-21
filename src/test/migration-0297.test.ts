// @vitest-environment node
/**
 * db/0297 on an offline replay of db/: free workspaces get a 4-character Crockford base32
 * suffix from the same alphabet as src/lib/workspace-slug-suffix.ts, existing suffixes are kept,
 * the trigger is a pinned definer nobody can call directly, and the rollback restores exactly
 * what Neon held before 0297. Neon is not touched.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { PGlite } from "@electric-sql/pglite";
import { ROOT, applyPending, applyReleased, replayDb } from "../../scripts/formal-rls/replay";
import { CROCKFORD_SUFFIX_ALPHABET, SUFFIXED_WORKSPACE_SLUG } from "@/lib/workspace-slug-suffix";

let db: PGlite;
beforeAll(async () => {
  db = await replayDb();
}, 300_000);
afterAll(async () => {
  await db?.close();
});

async function insertFree(slug: string): Promise<string> {
  const r = await db.query<{ slug: string }>(
    "insert into public.workspaces (id, name, slug, plan, created_at) values (gen_random_uuid(), 'Test', $1, 'free', now()) returning slug",
    [slug],
  );
  return r.rows[0]!.slug;
}

type FnState = { secdef: boolean; cfg: string[] | null; app: boolean; pub: boolean };
const fnState = async () =>
  (await db.query<FnState>(`select p.prosecdef as secdef, p.proconfig as cfg,
    has_function_privilege('rout_app', p.oid, 'execute') as app,
    exists (select 1 from aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a where a.grantee = 0 and a.privilege_type = 'EXECUTE') as pub
    from pg_proc p where p.oid = 'public.enforce_workspace_slug_suffix()'::regprocedure`)).rows[0]!;

describe("db/0297 Crockford suffix for free workspaces", () => {
  it("uses exactly the alphabet the app uses", () => {
    const sql = readFileSync(join(ROOT, "db", "0297_workspace_slug_crockford_suffix.sql"), "utf8");
    expect(/v_alphabet constant text := '([^']+)'/.exec(sql)?.[1]).toBe(CROCKFORD_SUFFIX_ALPHABET);
    expect(CROCKFORD_SUFFIX_ALPHABET).toHaveLength(32);
    expect(CROCKFORD_SUFFIX_ALPHABET).not.toMatch(/[ilou]/);
  });

  it("appends a Crockford suffix to a free slug without one", async () => {
    expect(await insertFree("acmestudio")).toMatch(/^acmestudio-[0-9a-hjkmnp-tv-z]{4}$/);
  });

  it("keeps a slug that already carries a 4-character suffix", async () => {
    expect(await insertFree("bakery-x7k2")).toBe("bakery-x7k2");
  });

  it("cuts a long base to 35 characters without a dangling hyphen and stays within 40", async () => {
    const slug = await insertFree(`${"a".repeat(34)}-bcdefg`);
    expect(slug).toMatch(new RegExp(`^${"a".repeat(34)}-[0-9a-hjkmnp-tv-z]{4}$`));
    expect(slug.length).toBeLessThanOrEqual(40);
  });

  it("300 free workspaces with the same base all get distinct valid suffixes", async () => {
    const slugs = new Set<string>();
    for (let i = 0; i < 300; i++) slugs.add(await insertFree("samebase"));
    expect(slugs.size).toBe(300);
    for (const s of slugs) expect(s).toMatch(SUFFIXED_WORKSPACE_SLUG);
  });

  it("the trigger is a definer on pg_catalog, pg_temp that neither PUBLIC nor rout_app can call", async () => {
    const s = await fnState();
    expect(s.secdef).toBe(true);
    expect(s.cfg).toContain("search_path=pg_catalog, pg_temp");
    expect(s.app).toBe(false);
    expect(s.pub).toBe(false);
  });

  it("rollback restores Neon's pre-0297 state and 0297 re-applies cleanly", async () => {
    await applyPending(db, "0297_workspace_slug_crockford_suffix_rollback.sql");
    const before = await fnState();
    expect(before).toEqual({ secdef: false, cfg: ["search_path=public"], app: true, pub: true });
    expect(await insertFree("rolledback")).toMatch(/^rolledback-[0-9a-f]{4}$/);
    await applyReleased(db, "0297_workspace_slug_crockford_suffix.sql");
    const after = await fnState();
    expect(after.secdef).toBe(true);
    expect(after.app).toBe(false);
    expect(after.pub).toBe(false);
  });
});
