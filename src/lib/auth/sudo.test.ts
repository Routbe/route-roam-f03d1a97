import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/better-auth.server", () => ({
  resolveAuthSecret: () => ({ secret: "test-secret-test-secret-test-secret" }),
}));
vi.mock("@/lib/audit-log.server", () => ({ recordSecurityEvent: vi.fn() }));

import { hmacSha256Hex } from "@/lib/audit-chain";
import { stepUpPayload, type StepUpAction, type StepUpMethod } from "./step-up-rules";
import { SUDO_COOKIE, SUDO_TTL_SEC, readCookieHeader, sudoSetCookie } from "./sudo-rules";
import {
  SudoRequiredError,
  ensureSudo,
  mintSudoToken,
  sessionBinding,
  verifySudoToken,
} from "./sudo.server";

const USER = "6f1c2b9e-1d2a-4c3b-9a8f-0e1d2c3b4a59";
const OTHER = "0a7d4c1e-2b3f-4e5a-8b9c-1d2e3f4a5b6c";
const SESSION = "sessiontoken-aaaaaaaaaaaaaaaa";
const T0 = 1_800_000_000;

async function stepUpCookie(
  userId: string,
  method: StepUpMethod,
  verifiedAt: number,
  scope: StepUpAction | "*" = "*",
) {
  const p = stepUpPayload(userId, method, verifiedAt, scope);
  return `${p}.${await hmacSha256Hex("stepup:test-secret-test-secret-test-secret", p)}`;
}

async function mint(at = T0, now = T0) {
  const m = await mintSudoToken(USER, await stepUpCookie(USER, "passkey", at), SESSION, now);
  if (!m) throw new Error("not minted");
  return m;
}

describe("sudo mode: 300 s hard TTL", () => {
  it("is valid at 299 s and refused at 300 s after the passkey", async () => {
    const { value } = await mint();
    expect(SUDO_TTL_SEC).toBe(300);
    expect(await verifySudoToken(value, USER, SESSION, T0 + 299)).not.toBeNull();
    expect(await verifySudoToken(value, USER, SESSION, T0 + 300)).toBeNull();
  });

  it("counts the window from the passkey verification, not from the exchange", async () => {
    const { claims, value } = await mint(T0, T0 + 100);
    expect(claims.expiresAtSec).toBe(T0 + 300);
    expect(await verifySudoToken(value, USER, SESSION, T0 + 300)).toBeNull();
  });

  it("refuses a token whose window was stretched, even with a valid signature", async () => {
    const binding = await sessionBinding(SESSION);
    const forged = `s1.${USER}.${binding}.${T0}.${T0 + 3600}.AAAAAAAAAAAAAAAAAAAAAA`;
    const signed = `${forged}.${await hmacSha256Hex("sudo:test-secret-test-secret-test-secret", forged)}`;
    expect(await verifySudoToken(signed, USER, SESSION, T0 + 10)).toBeNull();
  });
});

describe("sudo mode: only a fresh passkey opens it", () => {
  it("refuses an authenticator-app, e-mail or card proof", async () => {
    for (const method of ["totp", "email", "card", "sms"] as const) {
      expect(
        await mintSudoToken(USER, await stepUpCookie(USER, method, T0), SESSION, T0),
      ).toBeNull();
    }
  });
  it("refuses a passkey proof given for one specific action", async () => {
    expect(
      await mintSudoToken(
        USER,
        await stepUpCookie(USER, "passkey", T0, "card_reveal"),
        SESSION,
        T0,
      ),
    ).toBeNull();
  });
  it("refuses a passkey proof older than 120 s", async () => {
    expect(
      await mintSudoToken(USER, await stepUpCookie(USER, "passkey", T0 - 121), SESSION, T0),
    ).toBeNull();
  });
  it("refuses another member's passkey proof and a missing session", async () => {
    expect(
      await mintSudoToken(USER, await stepUpCookie(OTHER, "passkey", T0), SESSION, T0),
    ).toBeNull();
    expect(await mintSudoToken(USER, await stepUpCookie(USER, "passkey", T0), null, T0)).toBeNull();
  });
});

describe("sudo mode: bound to member and session", () => {
  it("does not work in another sign-in session", async () => {
    const { value } = await mint();
    expect(await verifySudoToken(value, USER, "another-session-bbbbbbbbbbbb", T0 + 1)).toBeNull();
  });
  it("does not work for another member", async () => {
    const { value } = await mint();
    expect(await verifySudoToken(value, OTHER, SESSION, T0 + 1)).toBeNull();
  });
  it("does not accept a step-up cookie as a sudo token", async () => {
    expect(
      await verifySudoToken(await stepUpCookie(USER, "passkey", T0), USER, SESSION, T0 + 1),
    ).toBeNull();
  });
});

describe("requireSudo gate", () => {
  it("throws SUDO_REQUIRED without a sudo cookie", async () => {
    const read = (name: string) =>
      name === "better-auth.session_token" ? `${SESSION}.sig` : undefined;
    await expect(ensureSudo(USER, "account_merge", read)).rejects.toBeInstanceOf(SudoRequiredError);
  });
  it("lets a valid sudo session through", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0 * 1000 + 5_000);
    try {
      const { value } = await mint();
      const read = (name: string) =>
        name === SUDO_COOKIE
          ? value
          : name === "better-auth.session_token"
            ? `${SESSION}.sig`
            : undefined;
      await expect(ensureSudo(USER, "account_merge", read)).resolves.toMatchObject({
        expiresAtSec: T0 + 300,
      });
    } finally {
      vi.useRealTimers();
    }
  });
  it("sets a host-only, HttpOnly, Secure, SameSite=Strict cookie", () => {
    const c = sudoSetCookie("v", 300);
    expect(c.startsWith("__Host-sudo_session=")).toBe(true);
    for (const attr of ["Path=/", "Max-Age=300", "HttpOnly", "Secure", "SameSite=Strict"])
      expect(c).toContain(attr);
    expect(c).not.toMatch(/Domain=/i);
    expect(readCookieHeader(`a=1; ${SUDO_COOKIE}=x%2Ey; b=2`, SUDO_COOKIE)).toBe("x.y");
  });
});

describe("sensitive endpoints carry requireSudo", () => {
  const gated: [string, string, string][] = [
    ["src/lib/account-merge.functions.ts", "startAccountMerge", "account_merge"],
    ["src/lib/account-merge.functions.ts", "previewAccountMerge", "account_merge"],
    ["src/lib/account-merge.functions.ts", "redeemAccountMerge", "account_merge"],
    ["src/lib/recovery/ceremony.functions.ts", "saveRecoveryCeremony", "recovery_vault"],
    ["src/lib/recovery/ceremony.functions.ts", "deleteRecoveryCeremony", "recovery_vault"],
    [
      "src/lib/pq/hardware-publication.functions.ts",
      "publishHardwareIdentity",
      "hardware_identity",
    ],
    ["src/lib/oauth/console.functions.ts", "rotateOAuthSecret", "oauth_secret_rotate"],
    ["src/lib/custom-presence.functions.ts", "rotatePresenceApiKey", "presence_key_rotate"],
    ["src/lib/omni-ingest.functions.ts", "rotateIngestToken", "ingest_token_rotate"],
    ["src/lib/workspace-inbox.functions.ts", "initWsInboxKey", "workspace_key_rotate"],
    ["src/lib/sign/sign.functions.ts", "signSignRequest", "document_sign"],
  ];
  for (const [file, fn, label] of gated) {
    it(`${fn} requires sudo (${label})`, () => {
      const src = readFileSync(file, "utf8");
      const start = src.indexOf(`export const ${fn} = createServerFn`);
      expect(start).toBeGreaterThanOrEqual(0);
      const head = src.slice(start, src.indexOf(".handler(", start));
      expect(head).toContain(`requireSudo("${label}")`);
    });
  }
});
