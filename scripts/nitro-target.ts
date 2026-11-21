// Pure Nitro target selection, shared by vite.config.ts and its test.
// Own server (default): self-contained dist/. Vercel: Nitro writes the Build
// Output API v3 tree to .vercel/output, which Vercel deploys as-is.
/** Vercel region of the Neon database (eu-central-1, Frankfurt). */
export const VERCEL_FUNCTION_REGION = "fra1";

export function nitroTarget(env: Record<string, string | undefined>) {
  const preset = env["NITRO_PRESET"]?.trim() || (env["VERCEL"] ? "vercel" : "node-server");
  const base = { preset, noExternals: true } as const;
  if (preset !== "vercel") return { ...base, output: { dir: "dist" } };
  // No output override: the preset's .vercel/output is the only place Vercel looks.
  // Node runtime is pinned so a Bun-driven build never switches functions to Bun.
  // Crons stay only in vercel.json: Vercel merges them into the deployment itself,
  // so a second copy in .vercel/output/config.json fails the build as a duplicate.
  // Functions run in Frankfurt (fra1), next to Neon (eu-central-1): every app query is one
  // transaction of about six round trips, so Vercel's default iad1 made one Studio load ~70
  // transatlantic round trips and ran into the browser's 8 s timeout.
  return { ...base, vercel: { functions: { runtime: "nodejs22.x", regions: [VERCEL_FUNCTION_REGION] }, config: { version: 3 as const } } };
}
