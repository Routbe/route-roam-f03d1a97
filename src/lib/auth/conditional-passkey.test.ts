import { describe, expect, it, vi } from "vitest";
import { runConditionalPasskey, type ConditionalPasskeyEnv } from "./conditional-passkey";

const buf = (...bytes: number[]) => new Uint8Array(bytes).buffer;
const credential = {
  id: "cred-1",
  rawId: buf(1, 2, 3),
  type: "public-key",
  authenticatorAttachment: "platform",
  response: { authenticatorData: buf(4), clientDataJSON: buf(5), signature: buf(6), userHandle: buf(7) },
};

function env(overrides: Partial<ConditionalPasskeyEnv> = {}) {
  const fetchMock = vi.fn(async (url: string) =>
    String(url).endsWith("generate-authenticate-options")
      ? new Response(JSON.stringify({ challenge: "AQID", rpId: "rout.be", userVerification: "required", allowCredentials: [{ id: "x", type: "public-key" }] }))
      : new Response("{}", { status: 200 }),
  );
  const get = vi.fn(async (_opts?: CredentialRequestOptions) => credential as unknown as Credential);
  return {
    fetchMock,
    get,
    env: { fetch: fetchMock as unknown as typeof fetch, credentials: { get }, pkc: { isConditionalMediationAvailable: async () => true }, ...overrides } satisfies ConditionalPasskeyEnv,
  };
}

describe("WebAuthn conditional mediation on the auth card", () => {
  it("starts navigator.credentials.get with mediation 'conditional', the caller's signal and an empty allow list", async () => {
    const { env: e, get } = env();
    const controller = new AbortController();
    await runConditionalPasskey(controller.signal, e);
    const call = get.mock.calls[0]?.[0] as CredentialRequestOptions;
    expect(call.mediation).toBe("conditional");
    expect(call.signal).toBe(controller.signal);
    expect(call.publicKey?.allowCredentials).toEqual([]);
    expect(call.publicKey?.userVerification).toBe("required");
  });

  it("verifies the picked passkey with the server and reports signed-in", async () => {
    const { env: e, fetchMock } = env();
    expect(await runConditionalPasskey(new AbortController().signal, e)).toBe("signed-in");
    const [url, init] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(url).toBe("/api/auth/passkey/verify-authentication");
    expect(JSON.parse(String(init.body)).response).toMatchObject({ id: "cred-1", rawId: "AQID", response: { signature: "Bg", userHandle: "Bw" } });
  });

  it("an abort stops the request without verifying anything", async () => {
    const controller = new AbortController();
    const { env: e, fetchMock } = env({
      credentials: {
        get: (opts) => new Promise((_, reject) => opts?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })))),
      },
    });
    const run = runConditionalPasskey(controller.signal, e);
    await new Promise((r) => setTimeout(r, 0));
    controller.abort();
    expect(await run).toBe("aborted");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does nothing on browsers without conditional mediation", async () => {
    const { env: e, get, fetchMock } = env({ pkc: { isConditionalMediationAvailable: async () => false } });
    expect(await runConditionalPasskey(new AbortController().signal, e)).toBe("unsupported");
    expect(get).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("a refused verification is not a sign-in", async () => {
    const { env: e } = env();
    e.fetch = (async (url: string) =>
      String(url).endsWith("generate-authenticate-options") ? new Response(JSON.stringify({ challenge: "AQID" })) : new Response("{}", { status: 401 })) as unknown as typeof fetch;
    expect(await runConditionalPasskey(new AbortController().signal, e)).toBe("rejected");
  });
});
