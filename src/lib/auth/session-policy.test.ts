import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { SESSION_MAX_AGE_SEC, SESSION_REFRESH_AFTER_SEC } from "./session-policy";

describe("session policy", () => {
  it("keeps a session 90 days", () => expect(SESSION_MAX_AGE_SEC).toBe(7_776_000));
  it("slides the end forward once the session is older than 24 hours", () => expect(SESSION_REFRESH_AFTER_SEC).toBe(86_400));
  it("is the policy Better Auth is configured with", () => {
    const src = readFileSync(join(__dirname, "..", "better-auth.server.ts"), "utf8");
    expect(src).toMatch(/expiresIn: SESSION_MAX_AGE_SEC,\s*updateAge: SESSION_REFRESH_AFTER_SEC/);
  });
});
