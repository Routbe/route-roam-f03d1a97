/**
 * WebAuthn Conditional UI for the auth card. One `navigator.credentials.get({ mediation: "conditional" })`
 * runs under the caller's AbortController while the card is open, so the OS sheet (Face ID / Touch ID /
 * Android / Safari desktop) offers saved passkeys as soon as the e-mail field (autocomplete="username webauthn")
 * is focused. The caller aborts it on unmount and before any explicit passkey ceremony, because a browser
 * runs only one WebAuthn request at a time.
 *
 * It talks to the same Better Auth endpoints as `authClient.signIn.passkey()`; the server forces
 * userVerification "required" on the options and checks UV again when verifying.
 */
import { base64URLStringToBuffer, bufferToBase64URLString } from "@simplewebauthn/browser";

export type ConditionalPasskeyOutcome = "signed-in" | "unsupported" | "aborted" | "rejected";

type PkcLike = { isConditionalMediationAvailable?: () => Promise<boolean> };
export type ConditionalPasskeyEnv = {
  fetch: typeof fetch;
  credentials: Pick<CredentialsContainer, "get"> | undefined;
  pkc: PkcLike | undefined;
  basePath?: string;
};

type AuthOptionsJSON = {
  challenge?: unknown;
  rpId?: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
};

function browserEnv(): ConditionalPasskeyEnv {
  const w = typeof window === "undefined" ? undefined : window;
  return {
    fetch: (input, init) => fetch(input, init),
    credentials: w?.navigator?.credentials,
    pkc: w?.PublicKeyCredential as PkcLike | undefined,
  };
}

const isAbort = (err: unknown) => err instanceof Error && err.name === "AbortError";

export async function runConditionalPasskey(signal: AbortSignal, env: ConditionalPasskeyEnv = browserEnv()): Promise<ConditionalPasskeyOutcome> {
  const base = env.basePath ?? "/api/auth";
  if (!env.credentials || typeof env.pkc?.isConditionalMediationAvailable !== "function") return "unsupported";
  try {
    if (!(await env.pkc.isConditionalMediationAvailable())) return "unsupported";
    if (signal.aborted) return "aborted";

    const optionsRes = await env.fetch(`${base}/passkey/generate-authenticate-options`, {
      method: "GET",
      credentials: "include",
      headers: { accept: "application/json" },
      signal,
    });
    if (!optionsRes.ok) return "rejected";
    const options = (await optionsRes.json()) as AuthOptionsJSON;
    if (typeof options.challenge !== "string" || !options.challenge) return "rejected";
    if (signal.aborted) return "aborted";

    const credential = (await env.credentials.get({
      mediation: "conditional",
      signal,
      publicKey: {
        challenge: base64URLStringToBuffer(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification ?? "required",
        extensions: options.extensions,
        // Conditional UI requires an empty allow list: the OS lists every passkey for this site.
        allowCredentials: [],
      },
    })) as PublicKeyCredential | null;
    if (signal.aborted) return "aborted";
    if (!credential) return "rejected";

    const assertion = credential.response as AuthenticatorAssertionResponse;
    const response = {
      id: credential.id,
      rawId: bufferToBase64URLString(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
      response: {
        authenticatorData: bufferToBase64URLString(assertion.authenticatorData),
        clientDataJSON: bufferToBase64URLString(assertion.clientDataJSON),
        signature: bufferToBase64URLString(assertion.signature),
        userHandle: assertion.userHandle ? bufferToBase64URLString(assertion.userHandle) : undefined,
      },
    };
    const verified = await env.fetch(`${base}/passkey/verify-authentication`, {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ response }),
      signal,
    });
    if (signal.aborted) return "aborted";
    return verified.ok ? "signed-in" : "rejected";
  } catch (err) {
    return isAbort(err) || signal.aborted ? "aborted" : "rejected";
  }
}
