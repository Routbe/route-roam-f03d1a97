/** Pure release validation. Reports names and reasons, never configured values. */
export const RELEASE_REQUIRED = [
  "DATABASE_URL", "PUBLIC_ORIGIN",
] as const;

export function validateReleaseEnvironment(env: Record<string, string | undefined>) {
  const issues: { key: string; reason: string }[] = [];
  for (const key of RELEASE_REQUIRED) {
    if (!env[key]?.trim()) issues.push({ key, reason: "Missing required setting" });
  }
  return issues;
}

/** Canonical public origin used when PUBLIC_ORIGIN is missing or not a credential-free HTTPS URL. */
export const DEFAULT_PUBLIC_ORIGIN = "https://rout.be";

function isSafePublicOrigin(value: string | undefined): boolean {
  if (!value?.trim()) return false;
  try {
    const url = new URL(value.trim());
    return url.protocol === "https:" && !url.username && !url.password;
  } catch { return false; }
}

/** Returns a copy of env whose PUBLIC_ORIGIN falls back to DEFAULT_PUBLIC_ORIGIN. */
export function withReleaseDefaults(env: Record<string, string | undefined>) {
  return isSafePublicOrigin(env.PUBLIC_ORIGIN) ? { ...env } : { ...env, PUBLIC_ORIGIN: DEFAULT_PUBLIC_ORIGIN };
}

/** Invalid optional URL formatting warns without blocking the release. */
export function releaseEnvironmentWarnings(env: Record<string, string | undefined>): string[] {
  // Never include configured values in diagnostics.
  if (!env.PUBLIC_ORIGIN?.trim() || isSafePublicOrigin(env.PUBLIC_ORIGIN)) return [];
  return ["PUBLIC_ORIGIN should be a valid HTTPS URL without credentials; authentication will use its safe fallback."];
}