/**
 * Browser side of Sudo Mode. Holds no secret: the sudo token lives only in an HttpOnly cookie.
 * The SudoModal (mounted once in __root) registers the opener; withSudo retries an action once
 * after the member confirmed with a passkey.
 */
import { isStepUpRequiredError } from "./step-up-rules";
import { isSudoRequiredError } from "./sudo-rules";
import { i18n } from "@/lib/i18n";

export type SudoState = { active: boolean; expiresAt: string | null; secondsLeft: number };
const INACTIVE: SudoState = { active: false, expiresAt: null, secondsLeft: 0 };
const ENDPOINT = "/api/v1/auth/sudo";

type Opener = (resolve: (ok: boolean) => void) => void;
let opener: Opener | null = null;
const listeners = new Set<(s: SudoState) => void>();
let current: SudoState = INACTIVE;

function publish(s: SudoState) {
  current = s;
  for (const l of listeners) l(s);
}

export function registerSudoOpener(o: Opener | null) {
  opener = o;
}
export function subscribeSudo(l: (s: SudoState) => void): () => void {
  listeners.add(l);
  l(current);
  return () => listeners.delete(l);
}
export const sudoSnapshot = () => current;

async function call(method: "GET" | "POST" | "DELETE"): Promise<SudoState> {
  const res = await fetch(ENDPOINT, {
    method,
    credentials: "same-origin",
    headers: { accept: "application/json" },
  });
  if (!res.ok) return INACTIVE;
  const body = (await res.json().catch(() => null)) as SudoState | null;
  return body && typeof body.active === "boolean" ? body : INACTIVE;
}

export async function readSudoStatus(): Promise<SudoState> {
  const s = await call("GET").catch(() => INACTIVE);
  publish(s);
  return s;
}

/** Call right after a successful authClient.signIn.passkey(): opens the 300 s window. */
export async function activateSudo(): Promise<SudoState> {
  const s = await call("POST").catch(() => INACTIVE);
  publish(s);
  return s;
}

export async function endSudo(): Promise<void> {
  await call("DELETE").catch(() => INACTIVE);
  publish(INACTIVE);
}

/** Opens the sudo dialog; resolves true once a sudo session is active. */
export function requestSudo(): Promise<boolean> {
  return new Promise((resolve) => (opener ? opener(resolve) : resolve(false)));
}

/** The member closed the passkey prompt; the message is shown as is. */
export class SudoCancelledError extends Error {
  constructor() {
    super(i18n.t("sudo.cancelled"));
  }
}

/**
 * Runs fn; when the server answers SUDO_REQUIRED (or, for passkey-gated vault actions,
 * STEP_UP_REQUIRED) it asks for a passkey once and retries. A passkey tap refreshes both.
 */
export async function withSudo<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (!isSudoRequiredError(e) && !isStepUpRequiredError(e)) throw e;
    if (!(await requestSudo())) throw new SudoCancelledError();
    return fn();
  }
}
