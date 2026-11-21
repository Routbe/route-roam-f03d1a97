/**
 * Server-only Postgres access over the runtime DATABASE_URL only, through the
 * standard PostgreSQL wire protocol with TLS enforced. No vendor proxy.
 *
 * `sql` mimics the @neondatabase/serverless HTTP client surface used across the
 * app: tagged templates, `sql.query(text, params)`, `sql.unsafe(raw)` and
 * `sql.transaction([...])`. One call = one pipelined batch, one network round trip
 * (no session state).
 */

import { AsyncLocalStorage } from "node:async_hooks";
import postgres from "postgres";
import { contextStatements, type DbContext } from "@/lib/db-context";
import { GENERIC_TEMPORARY_ERROR } from "@/lib/security/safe-errors";

/**
 * Request-scoped RLS context. Auth middleware runs handlers inside
 * `withDbContext`, and every query then runs in a transaction that first sets
 * `rout.current_user_id` / `rout.workspace_id` with `set_config(..., true)` (= SET LOCAL).
 * Without a context (anonymous, cron) nothing is set, so both read as null.
 */
const dbContext = new AsyncLocalStorage<DbContext>();
export function withDbContext<T>(ctx: DbContext, fn: () => T): T {
  return dbContext.run(ctx, fn);
}
/** User id of the active request context, if any. */
export function currentDbUserId(): string | null {
  return dbContext.getStore()?.userId ?? null;
}
function activeContext(): Statement[] {
  const ctx = dbContext.getStore();
  return ctx ? contextStatements(ctx) : [];
}

type Row = Record<string, unknown>;
type Statement = { query: string; params: unknown[] };
type GatewayResult = { rows: Row[]; rowCount: number | null; command: string };

/** Resolve credentials on every request, never while bundling the application. */
export function hasDatabase(): boolean {
  return databaseTransport() !== "none";
}
export function databaseTransport(): "direct" | "none" {
  return process.env["DATABASE_URL"]?.trim() ? "direct" : "none";
}

/** Transaction-scoped switch to the least-privilege role (no-op when already rout_app). */
export const RUNTIME_ROLE_SWITCH = "set local role rout_app";

export const RUNTIME_ROLE_GUARD = `do $guard$
begin
  if current_user <> 'rout_app' or exists (
    select 1 from pg_roles where rolname = current_user and (rolbypassrls or rolsuper)
  ) or exists (
    select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace
    where n.nspname in ('public','neon_auth','vault_enclave') and c.relkind in ('r','p')
      and pg_has_role(current_user, c.relowner, 'USAGE')
  ) then
    raise exception 'runtime_role_unsafe' using errcode = '42501';
  end if;
end $guard$`;

/** Dates and timestamps stay strings, as the app has always received them. */
const TEXT_TYPES = [1082, 1083, 1114, 1184, 1266];
let pool: { url: string; client: postgres.Sql } | null = null;
export const jsonText = (v: unknown): string => (typeof v === "string" ? v : JSON.stringify(v));
function client(connectionString: string): postgres.Sql {
  if (pool?.url === connectionString) return pool.client;
  void pool?.client.end({ timeout: 5 });
  const types: Record<string, unknown> = Object.fromEntries(TEXT_TYPES.map((oid) => [`t${oid}`, {
    to: oid, from: [oid], serialize: (v: unknown) => String(v), parse: (v: string) => v,
  }]));
  // A string bound to a json(b) parameter already is JSON text (normaliseParams
  // and every caller use JSON.stringify); the driver's default would encode it a
  // second time into a JSON string. Same result as an untyped (unknown) parameter.
  types.json = { to: 3802, from: [114, 3802], serialize: jsonText, parse: (v: string) => JSON.parse(v) };
  const created = postgres(connectionString, {
    ssl: "require", // TLS is mandatory whatever the URL says
    max: Number(process.env["DATABASE_POOL_MAX"] ?? 10),
    idle_timeout: 30,
    connect_timeout: 15,
    prepare: false, // safe behind PgBouncer / Neon's pooler
    onnotice: () => {},
    types: types as never,
  });
  pool = { url: connectionString, client: created };
  return created;
}

/** Normalise params: objects/arrays of objects go as JSON text for json(b) columns. */
function normaliseParams(params: unknown[]): unknown[] {
  return params.map((p) => {
    if (p instanceof Date) return p.toISOString();
    if (p === undefined) return null;
    if (p instanceof Uint8Array) return p;
    // Objects (and arrays holding objects) travel as JSON text for json(b) columns.
    if (p !== null && typeof p === "object" && (!Array.isArray(p) || p.some((v) => v !== null && typeof v === "object"))) return JSON.stringify(p);
    return p;
  });
}

export async function runQuery(query: string, params: unknown[] = []): Promise<GatewayResult> {
  const [result] = await runBatch([{ query, params }]);
  if (!result) throw new Error("Neon returned no statement result");
  return result;
}

/**
 * PostgreSQL's "unknown" type. A parameter sent as unknown is typed by the server
 * exactly like one sent without a type (oid 0), but the driver no longer has to
 * ask the server for the parameter types first, which costs a round trip.
 */
export const UNKNOWN_PARAM_OID = 705;

/**
 * Scalars travel as untyped text and the server infers their type; JSON text
 * reaches json(b) columns as the JSON it is. Booleans, bytes, bigints and arrays
 * keep the driver's own typing (arrays still need the server's description).
 */
export function bindParam(db: Pick<postgres.Sql, "typed">, value: unknown): unknown {
  if (value === null || typeof value === "string") return db.typed(value as never, UNKNOWN_PARAM_OID);
  if (typeof value === "number") return db.typed(String(value) as never, UNKNOWN_PARAM_OID);
  return value;
}

/**
 * One request is one PostgreSQL transaction, never an interactive callback.
 *
 * The role switch, the RLS context, the role guard and the statements go out as
 * one pipelined batch with a single Sync: PostgreSQL runs them as one implicit
 * transaction, so a failing statement (the guard included) stops every later one
 * and nothing commits. That is one network round trip instead of one per statement
 * plus BEGIN and COMMIT. Serializable batches keep an explicit BEGIN/COMMIT around
 * the same pipelined batch, so a serialization failure surfaces on COMMIT.
 */
export async function runBatch(
  input: Statement[],
  opts: { withContext?: boolean; isolation?: "Serializable" } = {},
): Promise<GatewayResult[]> {
  for (const statement of input) {
    if (TRANSACTION_CONTROL.test(statement.query)) throw new Error("interactive_transactions_unsupported: use one atomic PostgreSQL batch");
  }
  const prefix = [
    // The linked login may be the database owner; every batch steps down to
    // rout_app so RLS applies. The guard below still fails closed otherwise.
    { query: RUNTIME_ROLE_SWITCH, params: [] },
    ...(opts.withContext === false ? [] : activeContext()),
    { query: RUNTIME_ROLE_GUARD, params: [] },
  ];
  const queries = [...prefix, ...input].map(s => ({ query: s.query, params: normaliseParams(s.params) }));
  const connectionString = process.env["DATABASE_URL"]?.trim();
  if (!connectionString) throw new Error("DATABASE_URL ontbreekt: geen runtime databaseverbinding ingesteld.");
  let json: { results: GatewayResult[] };
  try {
    // The atomic role/context/guard prefix runs first; an owner URL never queries as the owner.
    const db = client(connectionString);
    const pipelined = async (conn: postgres.Sql | postgres.TransactionSql) => {
      // simple: false keeps every statement on the extended protocol: a simple-protocol
      // query would end the implicit transaction in the middle of the batch.
      const parts = queries.map((s) => conn.unsafe(s.query, s.params.map((v) => bindParam(conn, v)) as never[], { simple: false }));
      const settled = (await conn.batch(parts)) as unknown as postgres.RowList<Row[]>[];
      return settled.map((r) => ({ rows: [...r] as Row[], rowCount: r.count ?? null, command: String(r.command ?? "") }));
    };
    const results = opts.isolation
      ? await db.begin("isolation level serializable", (tx) => pipelined(tx))
      : await pipelined(db);
    json = { results: results as GatewayResult[] };
  } catch (cause) {
    const code = (cause as { code?: unknown })?.code;
    const safeCode = typeof code === "string" && /^[A-Z0-9]{5}$/.test(code) ? code : undefined;
    console.error("[database] request failed", { code: safeCode });
    throw Object.assign(new Error(GENERIC_TEMPORARY_ERROR), { code: safeCode });
  }
  if (!Array.isArray(json.results) || json.results.length !== prefix.length + input.length) {
    throw new Error("Invalid Neon transaction response");
  }
  return json.results.slice(prefix.length);
}

export const withPostgresTransaction = runBatch;

/**
 * One statement in a SERIALIZABLE transaction, re-run with exponential backoff
 * only on 40001/40P01 (PostgreSQL rolled it back, so a retry cannot double-apply).
 */
export async function runSerializable(query: string, params: unknown[] = []): Promise<GatewayResult> {
  const { withSerializableRetry } = await import("@/lib/db-retry");
  return withSerializableRetry(async () => {
    const [result] = await runBatch([{ query, params }], { isolation: "Serializable" });
    if (!result) throw new Error("Neon returned no statement result");
    return result;
  });
}
const TRANSACTION_CONTROL = /^\s*(?:begin|commit|rollback|start\s+transaction|end|savepoint|release\s+savepoint)\b/i;

/** Lazy query: executes when awaited, or as part of `sql.transaction([...])`. */
class LazyQuery implements PromiseLike<Row[]> {
  /**
   * The RLS context is captured when the query is built, not when it is awaited:
   * `withDbContext(ctx, () => sql\`...\`)` returns the unexecuted query and the
   * caller awaits it after the context has already ended.
   */
  private readonly ctx: DbContext | undefined = dbContext.getStore();
  constructor(readonly statement: Statement) {}
  private exec?: Promise<Row[]>;
  run(): Promise<Row[]> {
    const execute = () => runQuery(this.statement.query, this.statement.params).then((r) => r.rows);
    this.exec ??= this.ctx ? dbContext.run(this.ctx, execute) : execute();
    return this.exec;
  }
  then<A = Row[], B = never>(
    onfulfilled?: ((value: Row[]) => A | PromiseLike<A>) | null,
    onrejected?: ((reason: unknown) => B | PromiseLike<B>) | null,
  ): Promise<A | B> {
    return this.run().then(onfulfilled, onrejected);
  }
  /** Promise compatibility: `sql\`...\`.catch()` must work like a real promise. */
  catch<B = never>(onrejected?: ((reason: unknown) => B | PromiseLike<B>) | null): Promise<Row[] | B> {
    return this.run().catch(onrejected);
  }
  finally(onfinally?: (() => void) | null): Promise<Row[]> {
    return this.run().finally(onfinally);
  }
}

class RawSql {
  constructor(readonly text: string) {}
}

function buildTemplate(strings: TemplateStringsArray, values: unknown[]): Statement {
  let query = "";
  const params: unknown[] = [];
  strings.forEach((chunk, i) => {
    query += chunk;
    if (i < values.length) {
      const v = values[i];
      if (v instanceof RawSql) query += v.text;
      else {
        params.push(v);
        query += `$${params.length}`;
      }
    }
  });
  return { query, params };
}

type SqlTag = {
  (strings: TemplateStringsArray, ...values: unknown[]): LazyQuery & Promise<any[]>;
  query(text: string, params?: unknown[]): LazyQuery & Promise<any[]>;
  unsafe(text: string): any;
  transaction(queries: PromiseLike<unknown>[]): Promise<any[][]>;
};

function makeSql(): SqlTag {
  const tag = ((strings: TemplateStringsArray, ...values: unknown[]) =>
    new LazyQuery(buildTemplate(strings, values))) as unknown as SqlTag;
  tag.query = (text: string, params: unknown[] = []) => new LazyQuery({ query: text, params }) as never;
  tag.unsafe = (text: string) => new RawSql(text);
  tag.transaction = async (queries) => {
    const statements = queries.map((q) => {
      if (!(q instanceof LazyQuery)) throw new Error("sql.transaction expects queries created by sql`` or sql.query()");
      return q.statement;
    });
    const results = await runBatch(statements);
    return results.map((r) => r.rows);
  };
  return tag;
}

export const sql: SqlTag = makeSql();

/** Drop-in for `neon(url)` from @neondatabase/serverless: the URL is ignored, the active transport is used. */
export function neon(_connectionString?: string): SqlTag {
  return sql;
}

/** Better Auth must never receive a successful fake BEGIN/COMMIT. */
export class GatewayPool {
  async query(text: string | { text: string; values?: unknown[] }, values?: unknown[]) {
    const q = typeof text === "string" ? text : text.text;
    const p = typeof text === "string" ? (values ?? []) : (text.values ?? values ?? []);
    if (TRANSACTION_CONTROL.test(q)) {
      throw new Error("interactive_transactions_unsupported: use a reviewed PostgreSQL function or atomic batch");
    }
    const r = await runQuery(q, p);
    return { ...r, fields: [] };
  }
  async connect(): Promise<never> {
    throw new Error("interactive_transactions_unsupported: Better Auth requires a reviewed gateway-compatible adapter");
  }
  async end() {}
  on() { return this; }
}
