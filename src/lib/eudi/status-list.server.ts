/** The signed Token Status List served at /api/public/status/rout-1 (cached 60 s per worker). */
import { jsonB64u } from "./jose";
import { encodeStatusList, statusBits, STATUS_LIST_ID, STATUS_LIST_TYP } from "./status-list";

export const statusListUri = (issuer: string) => `${issuer}/api/public/status/${STATUS_LIST_ID}`;

export async function activeStatusIndices(): Promise<number[]> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (!(await hasSchemaFeature("0294"))) return [];
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select status_idx from public.rout_public_status_active()`) as { status_idx: unknown }[];
  return rows.map((r) => Number(r.status_idx));
}

let cache: { at: number; token: string } | null = null;
const TTL_S = 300;

export async function statusListToken(issuer: string, now = Date.now()): Promise<string | null> {
  if (cache && now - cache.at < 60_000) return cache.token;
  const { issuerKey, signEs256 } = await import("./keys.server");
  const key = await issuerKey();
  if (!key) return null;
  const iat = Math.floor(now / 1000);
  const header = { alg: "ES256", typ: STATUS_LIST_TYP, kid: key.kid };
  const payload = {
    sub: statusListUri(issuer),
    iat,
    exp: iat + 3600,
    ttl: TTL_S,
    status_list: { bits: 1, lst: await encodeStatusList(statusBits(await activeStatusIndices())) },
  };
  const input = `${jsonB64u(header)}.${jsonB64u(payload)}`;
  const sig = await signEs256(new TextEncoder().encode(input));
  if (!sig) return null;
  const { b64uEncode } = await import("@/lib/support/hybrid-signature");
  const token = `${input}.${b64uEncode(sig)}`;
  cache = { at: now, token };
  return token;
}

/** Test hook. */
export function resetStatusListCache() {
  cache = null;
}
