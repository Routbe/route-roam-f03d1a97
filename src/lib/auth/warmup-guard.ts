/**
 * Server-side deadline for the session lookup in requireAuth.
 *
 * The browser gives a Studio load 8 s and a session check 5 s. When the
 * session lookup alone outlives this guard (a cold function instance, a new
 * TLS connection to Neon), the server fails fast with `warming_up` instead
 * of letting the browser run into its own timeout; the client then retries
 * once against the now-warm instance. The lookup itself is not cancelled.
 */
export const AUTH_WARMUP_GUARD_MS = 6_000;
export const WARMING_UP = "warming_up" as const;

export type WarmingUpError = Error & { statusCode: 503; code: typeof WARMING_UP };

export function isWarmingUp(error: unknown): boolean {
  return error instanceof Error && error.message === WARMING_UP;
}

export function withWarmupGuard<T>(work: Promise<T>, timeoutMs: number = AUTH_WARMUP_GUARD_MS): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      console.warn(`[auth:warming_up] session lookup exceeded ${timeoutMs}ms`);
      reject(Object.assign(new Error(WARMING_UP), { statusCode: 503 as const, code: WARMING_UP }) as WarmingUpError);
    }, timeoutMs);
  });
  // A late rejection of the abandoned lookup must not surface as unhandled.
  work.catch(() => {});
  return Promise.race([work, deadline]).finally(() => clearTimeout(timer));
}
