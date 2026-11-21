import { AsyncLocalStorage } from "node:async_hooks";
import type { CapturedSocialProfile } from "./social-onboarding";

/**
 * Request-scoped note of the profile a social provider returned during one OAuth callback.
 * The auth handler opens the scope around `/callback/*` only and reads it only when Better
 * Auth refused the sign-in with `signup_disabled`; nothing leaves the request.
 */
const scope = new AsyncLocalStorage<{ profile: CapturedSocialProfile | null }>();

export function runSocialCallback<T>(fn: () => Promise<T>): Promise<{ result: T; profile: CapturedSocialProfile | null }> {
  const store = { profile: null as CapturedSocialProfile | null };
  return scope.run(store, async () => ({ result: await fn(), profile: store.profile }));
}

export function noteSocialProfile(provider: string, info: unknown): void {
  const store = scope.getStore();
  const user = (info as { user?: CapturedSocialProfile["user"] } | null)?.user;
  if (store && user) store.profile = { provider, user };
}

/** Provider options whose userinfo result is noted for the onboarding hand-off; behaviour is unchanged. */
export function capturingProvider<O extends Record<string, unknown>>(
  factory: (o: O) => { id: string; getUserInfo: (token: never) => Promise<unknown> },
  options: O,
): O {
  const base = factory(options);
  return {
    ...options,
    getUserInfo: async (token: never) => {
      const info = await base.getUserInfo(token);
      noteSocialProfile(base.id, info);
      return info;
    },
  };
}
