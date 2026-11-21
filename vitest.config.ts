import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { readdirSync, readFileSync, realpathSync } from "node:fs";
import mdx from "@mdx-js/rollup";
import remarkFrontmatter from "remark-frontmatter";
import remarkMdxFrontmatter from "remark-mdx-frontmatter";

export default defineConfig({
  plugins: [{
    name: "rout-docs-test-catalog",
    resolveId(id) { if (id === "virtual:rout-docs") return "\0virtual:rout-docs"; },
    load(id) {
      if (id !== "\0virtual:rout-docs") return;
      const sources: Record<string, string> = {};
      const visit = (dir: string) => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
          const file = `${dir}/${entry.name}`;
          if (entry.isDirectory()) visit(file);
          else if (file.endsWith(".mdx")) sources[`/${file}`] = readFileSync(file, "utf8");
        }
      };
      visit("src/content");
      return `export default ${JSON.stringify(sources)}`;
    },
  }, mdx({ include: /\.mdx$/, providerImportSource: "@mdx-js/react", remarkPlugins: [remarkFrontmatter, remarkMdxFrontmatter] }), react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    // The full run replays db/ in PGlite in many files at once and runs a Z3 proof; with one worker
    // per core those CPU-bound files starved each other past the 5 s default (10 timeouts on 16 cores).
    // Half the cores and a 30 s per-test budget keep every test deterministic; an assertion still fails at once.
    maxWorkers: "50%",
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  // `?url` imports (fonts in __root.tsx) are served through Vite's fs guard; when
  // node_modules is a symlink outside the project, its real path must be allowed.
  server: { fs: { allow: [__dirname, realpathSync(path.resolve(__dirname, "node_modules"))] } },
});
