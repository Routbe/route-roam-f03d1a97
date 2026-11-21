// @vitest-environment node
/**
 * db/0287 (A1 EXPAND, live on Neon since 2026-11-17) on an offline replay of db/ up to 0286, applied with the definer guard in the
 * same transaction. Proves without touching Neon:
 *   - rout_app and PUBLIC hold no right on vault_enclave.profile_field_keys; rout_app executes
 *     exactly the three entry points and the shape check, and never the guard trigger;
 *   - only a first, well-formed key version can be registered by the app role, every attempt is on
 *     the hash-chained vault audit log, and stored versions are append-only (retire once);
 *   - writes as rout_app through sealProfilePatch leave the plaintext column NULL, the ciphertext
 *     opens in the app with the ring the definer hands back, and blind-index lookups find the row;
 *   - the database refuses malformed ciphertext, an index without its ciphertext, and a second
 *     profile with the same Stripe account (bidx uniqueness);
 *   - rout_profile_referred_mine answers only for the caller;
 *   - fast-check: arbitrary values round-trip through the real table as rout_app;
 *   - the rollback refuses while a key exists.
 */
import { PGlite } from "@electric-sql/pglite";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { applyReleased, replayDb } from "../../scripts/formal-rls/replay";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { deriveFieldKek, generateFieldKey, openFieldKeyring, type FieldKeyring, type StoredFieldKey } from "@/lib/profile-private/field-keys";
import { PRIVATE_PROFILE_FIELDS } from "@/lib/profile-private/field-seal";
import { backfillSelect, backfillStatements, BACKFILL_FIELDS } from "@/lib/profile-private/backfill-plan";
import { bidxColumn, indexCandidates, openProfileRow, sealedColumn, SEALED_COLUMNS, sealProfilePatch } from "@/lib/profile-private/sealed-profile";

const A = "00000000-0000-4000-8000-0000000002a1";
const B = "00000000-0000-4000-8000-0000000002a2";
const C = "00000000-0000-4000-8000-0000000002a3";
const KEK_SECRET = "K".repeat(64);
const FILE = "0287_profile_field_encryption.sql";
const ENTRY_POINTS = ["rout_profile_field_keys()", "rout_profile_field_key_register(bytea, bytea, bytea)", "rout_profile_referred_mine()", "rout_rpf1_shape_ok(bytea)"];

let db: PGlite;

beforeAll(async () => {
  db = await replayDb((f) => f < "0287");
  await applyReleased(db, FILE);
  await db.exec(`
    insert into public.users (id, email) values ('${A}', 'a@example.test'), ('${B}', 'b@example.test'), ('${C}', 'c@example.test');
    insert into public.profiles (id, username) values ('${A}', 'a-one'), ('${B}', 'b-two'), ('${C}', 'c-three')
      on conflict (id) do update set username = excluded.username;
    update public.profiles set referred_by = '${A}' where id = '${B}';
  `);
}, 600_000);
afterAll(async () => { await db?.close(); });

async function asApp<T>(userId: string | null, query: string, params: unknown[] = [], commit = false): Promise<T[]> {
  await db.exec("begin; set local role rout_app;");
  try {
    if (userId) await db.query("select set_config('rout.current_user_id', $1, true)", [userId]);
    const rows = (await db.query<T>(query, params)).rows;
    await db.exec(commit ? "commit;" : "rollback;");
    return rows;
  } catch (e) {
    await db.exec("rollback;");
    throw e;
  }
}

type KeyRow = { version: number; kid: Uint8Array; wrapped_key: Uint8Array; kek_id: Uint8Array; active: boolean };
async function loadRing(): Promise<FieldKeyring> {
  const rows = await asApp<KeyRow>(null, "select * from public.rout_profile_field_keys()");
  const stored: StoredFieldKey[] = rows.map((r) => ({ version: r.version, kid: r.kid, wrapped: r.wrapped_key, kekId: r.kek_id, active: r.active }));
  return openFieldKeyring(deriveFieldKek(KEK_SECRET), stored);
}

/** One UPDATE of public.profiles as rout_app with the given column values. */
async function writeAs(userId: string | null, profileId: string, patch: Record<string, unknown>) {
  const cols = Object.keys(patch);
  const set = cols.map((c, i) => `"${c}" = $${i + 2}`).join(", ");
  await asApp(userId, `update public.profiles set ${set} where id = $1`, [profileId, ...cols.map((c) => patch[c])], true);
}

describe("rights", () => {
  it("no table right on the key ring for rout_app or PUBLIC", async () => {
    for (const role of ["rout_app", "public"]) {
      for (const priv of ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]) {
        const [r] = (await db.query<{ ok: boolean }>(`select has_table_privilege($1, 'vault_enclave.profile_field_keys', $2) as ok`, [role, priv])).rows;
        expect(r!.ok, `${role} ${priv}`).toBe(false);
      }
    }
    await expect(asApp(null, "select * from vault_enclave.profile_field_keys")).rejects.toThrow();
  });

  it("rout_app executes exactly the entry points; PUBLIC none; the guard trigger nobody", async () => {
    for (const f of ENTRY_POINTS) {
      const [r] = (await db.query<{ app: boolean; pub: boolean }>(
        `select has_function_privilege('rout_app', $1, 'EXECUTE') as app, has_function_privilege('public', $1, 'EXECUTE') as pub`, [`public.${f}`])).rows;
      expect(r, f).toEqual({ app: true, pub: false });
    }
    const [g] = (await db.query<{ app: boolean; pub: boolean }>(
      `select has_function_privilege('rout_app', 'vault_enclave.profile_field_keys_guard()', 'EXECUTE') as app,
              has_function_privilege('public', 'vault_enclave.profile_field_keys_guard()', 'EXECUTE') as pub`)).rows;
    expect(g).toEqual({ app: false, pub: false });
  });

  it("rout_app reads the sealed and index columns, which hold no plaintext", async () => {
    for (const c of SEALED_COLUMNS) {
      const [r] = (await db.query<{ ok: boolean }>(`select has_column_privilege('rout_app', 'public.profiles', $1, 'SELECT') as ok`, [c])).rows;
      expect(r!.ok, c).toBe(true);
    }
  });
});

describe("key ring registration", () => {
  it("accepts one first version, refuses a second and malformed ones, and audits every attempt", async () => {
    const kek = deriveFieldKek(KEK_SECRET);
    const bad = generateFieldKey(kek, 1).stored;
    const magic = bad.wrapped.slice();
    magic[0] = 0;
    const [m] = await asApp<{ ok: boolean }>(A, "select public.rout_profile_field_key_register($1, $2, $3) as ok", [bad.kid, magic, bad.kekId], true);
    expect(m!.ok).toBe(false);
    const otherKek = new Uint8Array(16).fill(5);
    const [k] = await asApp<{ ok: boolean }>(A, "select public.rout_profile_field_key_register($1, $2, $3) as ok", [bad.kid, bad.wrapped, otherKek], true);
    expect(k!.ok).toBe(false);

    const good = generateFieldKey(kek, 1).stored;
    const [first] = await asApp<{ ok: boolean }>(A, "select public.rout_profile_field_key_register($1, $2, $3) as ok", [good.kid, good.wrapped, good.kekId], true);
    expect(first!.ok).toBe(true);
    const again = generateFieldKey(kek, 1).stored;
    const [second] = await asApp<{ ok: boolean }>(B, "select public.rout_profile_field_key_register($1, $2, $3) as ok", [again.kid, again.wrapped, again.kekId], true);
    expect(second!.ok).toBe(false);

    const audit = (await db.query<{ outcome: string; reason: string }>(
      `select outcome, reason from vault_enclave.audit_logs where action = 'profile_field_key_register' order by seq`)).rows;
    expect(audit).toEqual([
      { outcome: "denied", reason: "malformed" },
      { outcome: "denied", reason: "malformed" },
      { outcome: "granted", reason: "ok" },
      { outcome: "denied", reason: "ring_exists" },
    ]);
    expect((await db.query<{ ok: boolean }>("select vault_enclave.verify_audit_chain() as ok")).rows[0]!.ok).toBe(true);
    const ring = await loadRing();
    expect(ring.activeVersion).toBe(1);
    ring.dispose();
  });

  it("stored versions are append-only: no delete, no change, retire once", async () => {
    await expect(db.exec("delete from vault_enclave.profile_field_keys")).rejects.toThrow(/append-only/);
    await expect(db.exec("update vault_enclave.profile_field_keys set kid = kid")).rejects.toThrow(/retired once/);
    await expect(db.exec("truncate vault_enclave.profile_field_keys")).rejects.toThrow();
  });
});

describe("sealed writes and reads as rout_app", () => {
  it("a moderation write leaves no plaintext and opens back in the app", async () => {
    const ring = await loadRing();
    try {
      const patch = sealProfilePatch(ring, C, { moderation_reason: "Spam reports from 4 members", moderated_by: A, payment_method: "manual_admin" });
      // Row security lets a member write only their own row; the app's admin path runs in the owner's context.
      await writeAs(C, C, { ...patch, moderated_at: new Date().toISOString() });
      const cols = ["moderation_reason", "moderated_by", "payment_method"] as const;
      const [raw] = await asApp<Record<string, unknown>>(C, `select id, ${cols.map((c) => `${c}, ${sealedColumn(c)}`).join(", ")} from public.profiles where id = $1`, [C]);
      for (const c of cols) expect(raw![c]).toBeNull();
      expect(Buffer.from(raw!["moderation_reason_sealed"] as Uint8Array).includes(Buffer.from("Spam reports"))).toBe(false);
      const open = openProfileRow(ring, raw!, cols);
      expect(open).toMatchObject({ moderation_reason: "Spam reports from 4 members", moderated_by: A, payment_method: "manual_admin" });
    } finally {
      ring.dispose();
    }
  });

  it("finds a profile by blind index (Stripe account, VAT) and keeps Stripe accounts unique", async () => {
    const ring = await loadRing();
    try {
      await writeAs(A, A, sealProfilePatch(ring, A, { stripe_account_id: "acct_1QzXy", business_vat: "BE 0123.456.789" }));
      const find = async (field: "stripe_account_id" | "business_vat", value: string) =>
        (await asApp<{ id: string }>(null, `select id from public.profiles where ${bidxColumn(field)} = any($1::bytea[])`, [indexCandidates(ring, field, value)])).map((r) => r.id);
      expect(await find("stripe_account_id", "acct_1QzXy")).toEqual([A]);
      expect(await find("stripe_account_id", "acct_1qzxy")).toEqual([]);
      expect(await find("business_vat", "be0123456789")).toEqual([A]);
      await expect(writeAs(B, B, sealProfilePatch(ring, B, { stripe_account_id: "acct_1QzXy" }))).rejects.toThrow(/stripe_account_id_bidx_key|duplicate/);
    } finally {
      ring.dispose();
    }
  });

  it("refuses malformed ciphertext and an index without ciphertext", async () => {
    await expect(writeAs(A, A, { business_vat_sealed: new Uint8Array(200) })).rejects.toThrow(/sealed_shape/);
    await expect(writeAs(B, B, { email_bidx: new Uint8Array(32), email_sealed: null })).rejects.toThrow(/bidx_pair/);
    await expect(writeAs(B, B, { forwarding_email_token_bidx: new Uint8Array(31) })).rejects.toThrow(/bidx_len/);
  });

  it("arbitrary values round-trip through the table (fast-check)", async () => {
    const ring = await loadRing();
    try {
      await fc.assert(fc.asyncProperty(
        fc.constantFrom(...PRIVATE_PROFILE_FIELDS.filter((f) => f !== "stripe_account_id")),
        fc.string({ unit: "grapheme", minLength: 1, maxLength: 300 }),
        async (f, v) => {
          await writeAs(B, B, sealProfilePatch(ring, B, { [f]: v }));
          // The app role reads only the ciphertext (several plaintext columns are withheld since 0277).
          const [raw] = await asApp<Record<string, unknown>>(B, `select id, ${sealedColumn(f)} from public.profiles where id = $1`, [B]);
          const [plain] = (await db.query<Record<string, unknown>>(`select ${f} from public.profiles where id = $1`, [B])).rows;
          expect(plain![f]).toBeNull();
          expect(openProfileRow(ring, raw!, [f])[f]).toBe(v);
        }), { numRuns: 40 });
    } finally {
      ring.dispose();
    }
  }, 120_000);
});

describe("backfill", () => {
  it("seals every legacy value, nulls the plaintext and skips a row changed in between", async () => {
    const D = "00000000-0000-4000-8000-0000000002a4";
    await db.exec(`insert into public.users (id, email) values ('${D}', 'd@example.test');
      update public.profiles set business_vat = 'NL123456789B01', payment_method = 'stripe', moderation_reason = 'legacy note',
        moderated_by = '${A}', stripe_account_id = 'acct_legacyD' where id = '${D}';`);
    const ring = await loadRing();
    try {
      const sel = backfillSelect(500);
      const rows = (await db.query<Record<string, unknown>>(sel.query, sel.params)).rows;
      expect(rows.map((r) => r["id"])).toContain(D);
      const stmts = backfillStatements(ring, rows.filter((r) => r["id"] === D));
      expect(stmts).toHaveLength(BACKFILL_FIELDS.length);
      // A concurrent write between read and update: that field is left for the next batch.
      await db.exec(`update public.profiles set payment_method = 'bank_transfer_automatic' where id = '${D}'`);
      await db.exec("begin");
      let changed = 0;
      for (const st of stmts) changed += (await db.query(st.query, st.params)).affectedRows ?? 0;
      await db.exec("commit");
      expect(changed).toBe(BACKFILL_FIELDS.length - 1);
      const [raw] = (await db.query<Record<string, unknown>>(`select * from public.profiles where id = $1`, [D])).rows;
      for (const f of BACKFILL_FIELDS.filter((f) => f !== "payment_method")) expect(raw![f], f).toBeNull();
      expect(raw!["payment_method"]).toBe("bank_transfer_automatic");
      expect(openProfileRow(ring, raw!, BACKFILL_FIELDS.filter((f) => f !== "payment_method"))).toMatchObject({
        business_vat: "NL123456789B01", moderation_reason: "legacy note", moderated_by: A, stripe_account_id: "acct_legacyD",
      });
      const found = (await db.query<{ id: string }>(`select id from public.profiles where stripe_account_id_bidx = any($1::bytea[])`, [indexCandidates(ring, "stripe_account_id", "acct_legacyD")])).rows;
      expect(found.map((r) => r.id)).toEqual([D]);
    } finally {
      ring.dispose();
    }
  });
});

describe("referred_by behind a definer", () => {
  it("answers only for the caller", async () => {
    const q = "select public.rout_profile_referred_mine() as r";
    expect((await asApp<{ r: boolean }>(B, q))[0]!.r).toBe(true);
    expect((await asApp<{ r: boolean }>(A, q))[0]!.r).toBe(false);
    expect((await asApp<{ r: boolean }>(null, q))[0]!.r).toBe(false);
  });
});

describe("rollback", () => {
  it("refuses while a key version exists", async () => {
    const body = readFileSync(join(__dirname, "..", "..", "db-pending", "0287_profile_field_encryption_rollback.sql"), "utf8");
    await expect(db.exec(`begin;\n${body}\n;commit;`)).rejects.toThrow(/rollback refused/);
    await db.exec("rollback;").catch(() => undefined);
  });
});
