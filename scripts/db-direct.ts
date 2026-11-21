/**
 * Direct PostgreSQL access for admin scripts: MIGRATION_URL (owner login),
 * else DATABASE_URL, over TLS. Same request/response shape the scripts used
 * before ({ query, params } -> { rows, rowCount, command }; { queries } ->
 * { results } in ONE transaction, all or nothing). No vendor proxy involved.
 */
import postgres from "postgres";

type Statement = { query: string; params?: unknown[] };
type Result = { rows: Record<string, unknown>[]; rowCount: number | null; command: string };
const TEXT_TYPES = [1082, 1083, 1114, 1184, 1266];

let client: postgres.Sql | null = null;
export function directUrl(): string {
  const url = process.env["MIGRATION_URL"]?.trim() || process.env["DATABASE_URL"]?.trim();
  if (!url) throw new Error("Geen databaseverbinding: zet MIGRATION_URL (of DATABASE_URL).");
  return url;
}
function db(): postgres.Sql {
  client ??= postgres(directUrl(), {
    ssl: "require",
    max: 1,
    prepare: false,
    onnotice: () => {},
    types: Object.fromEntries(TEXT_TYPES.map((oid) => [`t${oid}`, { to: oid, from: [oid], serialize: String, parse: (v: string) => v }])),
  });
  return client;
}
const norm = (params: unknown[] = []) => params.map((p) =>
  p === undefined ? null : p instanceof Date ? p.toISOString()
  : p !== null && typeof p === "object" && !(p instanceof Uint8Array) && (!Array.isArray(p) || p.some((v) => v !== null && typeof v === "object")) ? JSON.stringify(p) : p);
async function run(tx: postgres.TransactionSql | postgres.Sql, s: Statement): Promise<Result> {
  const r = await tx.unsafe(s.query, norm(s.params) as never[]);
  return { rows: [...r] as Record<string, unknown>[], rowCount: r.count ?? null, command: String(r.command ?? "") };
}

export async function sqlRequest(body: Statement): Promise<Result>;
export async function sqlRequest(body: { queries: Statement[] }, opts?: { readOnly?: boolean }): Promise<{ results: Result[] }>;
export async function sqlRequest(body: Statement | { queries: Statement[] }, opts: { readOnly?: boolean } = {}): Promise<any> {
  if ("queries" in body) {
    const results = await db().begin(opts.readOnly ? "read only" : "", async (tx) => {
      const out: Result[] = [];
      for (const s of body.queries) out.push(await run(tx, s));
      return out;
    });
    return { results };
  }
  return run(db(), body);
}
export async function closeDirect(): Promise<void> {
  await client?.end({ timeout: 5 });
  client = null;
}
