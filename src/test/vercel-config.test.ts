// @vitest-environment node
import { existsSync, readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { nitroTarget } from "../../scripts/nitro-target";

const vercelJson = JSON.parse(readFileSync("vercel.json", "utf8"));

it("builds the Vercel preset into .vercel/output when Vercel runs the build", () => {
  const target = nitroTarget({ VERCEL: "1" });
  expect(target.preset).toBe("vercel");
  expect("output" in target).toBe(false);
});
it("pins Vercel functions to Node 22, even when Bun drives the build", () => {
  const target = nitroTarget({ NITRO_PRESET: "vercel" });
  expect("vercel" in target && target.vercel.functions.runtime).toBe("nodejs22.x");
});
it("runs Vercel functions only in fra1, the region of the Neon database", () => {
  const target = nitroTarget({ VERCEL: "1" });
  expect("vercel" in target && target.vercel.functions.regions).toEqual(["fra1"]);
});
it("keeps the self-contained dist/ build for own servers", () => {
  expect(nitroTarget({})).toEqual({ preset: "node-server", noExternals: true, output: { dir: "dist" } });
});
it("lets NITRO_PRESET override the Vercel default", () => {
  expect(nitroTarget({ VERCEL: "1", NITRO_PRESET: "node-server" }).preset).toBe("node-server");
});
it("uses the vercel build script and leaves the output directory to the Build Output API", () => {
  expect(vercelJson.buildCommand).toBe("bun run build:vercel");
  expect(vercelJson.framework).toBeNull();
  expect(vercelJson.outputDirectory).toBeUndefined();
});
it("declares no routing or headers in vercel.json, because .vercel/output/config.json owns them", () => {
  for (const key of ["rewrites", "routes", "redirects", "headers", "cleanUrls", "trailingSlash"]) {
    expect(vercelJson[key], key).toBeUndefined();
  }
});
it("declares the cleanup cron exactly once, only in vercel.json, backed by a route file", () => {
  const cleanup = vercelJson.crons.filter((c: { path: string }) => c.path === "/api/public/cron/cleanup-assets");
  expect(cleanup).toEqual([{ path: "/api/public/cron/cleanup-assets", schedule: "0 3 * * *" }]);
  const keys = vercelJson.crons.map((c: { path: string; schedule: string }) => `${c.schedule} ${c.path}`);
  expect(new Set(keys).size).toBe(keys.length);
  for (const { path } of vercelJson.crons as { path: string }[]) {
    const file = `src/routes/${path.slice(1).replace("api/public/", "api_.public.").replaceAll("/", ".")}.ts`;
    expect(existsSync(file), file).toBe(true);
  }
});
it("never copies crons into the generated Build Output config, because Vercel merges vercel.json crons itself", () => {
  const target = nitroTarget({ VERCEL: "1" });
  expect("vercel" in target && "crons" in target.vercel.config).toBe(false);
});
