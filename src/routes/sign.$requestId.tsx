import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Download, FileSignature, KeyRound, ShieldCheck } from "lucide-react";
import { useI18n } from "@/lib/i18n";
import { useAuth } from "@/hooks/useAuth";
import { useSudoMode } from "@/hooks/useSudoMode";
import { Button } from "@/components/ui/button";
import { PdfViewer } from "@/components/sign/PdfViewer";
import { SanitizeReport } from "@/components/sign/SanitizeReport";
import { openSignRequestFn, signSignRequest } from "@/lib/sign/sign.functions";
import { sanitizePdf, type SanitizeResult } from "@/lib/sign/pdf-sanitizer";
import { maySign } from "@/lib/sign/sign-rules";
import { keyFromFragment } from "@/lib/sign/sign-envelope";
import { b64ToBytes, bytesToB64 } from "@/lib/sign/b64";

const title = "Document ondertekenen — ROUT Sign";
const description = "Lees het opgeschoonde document volledig en bevestig je handtekening met je passkey.";

export const Route = createFileRoute("/sign/$requestId")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex, nofollow" },
      { name: "referrer", content: "no-referrer" },
    ],
  }),
  component: SignRequestPage,
});

type Opened = NonNullable<Awaited<ReturnType<typeof openSignRequestFn>>>;
const stashKey = (id: string) => `rout.sign.k.${id}`;

function SignRequestPage() {
  const { requestId } = Route.useParams();
  const { t } = useI18n();
  const { user, loading } = useAuth();
  const sudo = useSudoMode();
  const open = useServerFn(openSignRequestFn);
  const sign = useServerFn(signSignRequest);
  const [fragment, setFragment] = useState<string | null>(null);
  const [req, setReq] = useState<Opened | null | undefined>(undefined);
  const [doc, setDoc] = useState<{ pdf: Uint8Array; report: Extract<SanitizeResult, { ok: true }> } | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [pages, setPages] = useState(0);
  const [reachedEnd, setReachedEnd] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [pqState, setPqState] = useState<"checking" | "valid" | "invalid" | "unavailable" | null>(null);

  // The key lives only in the fragment; it is kept for this tab across the sign-in detour, then the URL is cleaned.
  useEffect(() => {
    const fromHash = window.location.hash.length > 1 ? window.location.hash : null;
    if (fromHash) {
      sessionStorage.setItem(stashKey(requestId), fromHash);
      history.replaceState(null, "", window.location.pathname);
    }
    setFragment(fromHash ?? sessionStorage.getItem(stashKey(requestId)));
  }, [requestId]);

  useEffect(() => {
    if (!user) return;
    let live = true;
    open({ data: { id: requestId } })
      .then((r) => live && setReq(r ?? null))
      .catch((e) => live && setFailure(e instanceof Error ? e.message : t("sign.error.generic")));
    return () => {
      live = false;
    };
  }, [user, requestId, open, t]);

  // Hybrid server attestation over the signed record, checked in the crypto worker.
  useEffect(() => {
    if (!req || req.status !== "signed" || !req.signedEnvelope || !req.signedAt || !req.pqAttestation) return;
    let live = true;
    setPqState("checking");
    const signedAt = req.signedAt;
    const attestation = req.pqAttestation;
    void (async () => {
      // The envelope hash is computed in the crypto worker: no WebCrypto on the main thread.
      const { enclave } = await import("@/lib/crypto-enclave/client");
      const { sha256: signedSha256 } = await enclave.sign.envelopeSha256(b64ToBytes(req.signedEnvelope!));
      const { verifyPqAttestation } = await import("@/lib/crypto/pq-verify");
      return verifyPqAttestation("sign", [requestId, req.sourceSha256, signedSha256, signedAt], attestation);
    })()
      .catch(() => "unavailable" as const)
      .then((state) => live && setPqState(state));
    return () => {
      live = false;
    };
  }, [req, requestId]);

  useEffect(() => {
    if (!req || req.status !== "open" || !fragment) return;
    const key = keyFromFragment(fragment);
    if (!key) return setFailure(t("sign.error.key"));
    let live = true;
    (async () => {
      try {
        const { enclave } = await import("@/lib/crypto-enclave/client");
        const { plaintext } = await enclave.sign.open(key, b64ToBytes(req.envelope), "original");
        const res = await sanitizePdf(plaintext);
        plaintext.fill(0);
        if (!res.ok) throw new Error(t(`sign.error.${res.reason}`));
        if (live) setDoc({ pdf: res.bytes, report: res });
      } catch (e) {
        if (live) setFailure(e instanceof Error && e.message ? e.message : t("sign.error.key"));
      }
    })();
    return () => {
      live = false;
    };
  }, [req, fragment, t]);

  useEffect(() => {
    if (!doc || pages === 0) return;
    const started = Date.now();
    const id = window.setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => window.clearInterval(id);
  }, [doc, pages]);

  const onEnd = useCallback(() => setReachedEnd(true), []);
  const minRead = req?.minReadSeconds ?? 30;
  const canSign = maySign({ elapsedSeconds: elapsed, minReadSeconds: minRead, scrolledToEnd: reachedEnd, pageCount: pages });

  async function confirm() {
    if (!req || !fragment || !canSign) return;
    const key = keyFromFragment(fragment);
    if (!key) return;
    setBusy(true);
    try {
      const { enclave } = await import("@/lib/crypto-enclave/client");
      const att = await enclave.sign.attest(key, b64ToBytes(req.envelope));
      const res = await sudo.run(() =>
        sign({ data: { id: requestId, sourceSha256: att.sourceSha256, digest: att.digest, signedEnvelope: bytesToB64(att.signedEnvelope) } }),
      );
      if (res?.result === "ok") {
        setDone(true);
        sessionStorage.removeItem(stashKey(requestId));
      } else toast.error(t(`sign.result.${res?.result ?? "invalid_input"}`));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("sign.error.generic"));
    } finally {
      setBusy(false);
    }
  }

  async function downloadSigned() {
    if (!req?.signedEnvelope || !fragment) return;
    const key = keyFromFragment(fragment);
    if (!key) return toast.error(t("sign.error.key"));
    const { enclave } = await import("@/lib/crypto-enclave/client");
    const { plaintext } = await enclave.sign.open(key, b64ToBytes(req.signedEnvelope), "signed");
    const url = URL.createObjectURL(new Blob([plaintext as BlobPart], { type: "application/pdf" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `rout-sign-${requestId.slice(0, 8)}.pdf`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  return (
    <main className="mx-auto max-w-3xl space-y-6 px-4 py-10">
      <header className="space-y-2">
        <h1 className="flex items-center gap-2 text-2xl font-semibold"><FileSignature className="h-6 w-6 text-primary" aria-hidden />{t("sign.request.title")}</h1>
        <p className="rounded-xl border border-border bg-muted/40 p-3 text-xs text-muted-foreground">{t("sign.phase1")}</p>
      </header>

      {!loading && !user && (
        <section className="space-y-3 rounded-2xl border border-border p-5 text-sm">
          <p>{t("sign.request.signIn")}</p>
          <Button asChild className="min-h-11">
            <Link to="/auth/$authView" params={{ authView: "sign-in" }} search={{ redirect: `/sign/${requestId}` } as never}>{t("sign.request.signInButton")}</Link>
          </Button>
        </section>
      )}

      {failure && <p role="alert" className="rounded-2xl border border-destructive/40 p-4 text-sm text-destructive">{failure}</p>}
      {user && req === null && <p role="status" className="rounded-2xl border border-border p-4 text-sm">{t("sign.request.notFound")}</p>}
      {user && req && req.status !== "open" && (
        <section className="space-y-3 rounded-2xl border border-border p-5 text-sm">
          <p>{t(`sign.status.${req.status}`)}{req.signedAt ? ` · ${new Date(req.signedAt).toLocaleString()}` : ""}</p>
          {pqState && (
            <p className="flex items-center gap-2 text-xs text-muted-foreground" aria-live="polite" data-pq={pqState}>
              <ShieldCheck className={`h-4 w-4 ${pqState === "valid" ? "text-primary" : pqState === "invalid" ? "text-destructive" : ""}`} aria-hidden />
              {t(`sign.pq.${pqState}`)}
            </p>
          )}
          {req.signedEnvelope && fragment && (
            <Button variant="outline" className="min-h-11" onClick={() => void downloadSigned()}>
              <Download className="mr-2 h-4 w-4" aria-hidden />{t("sign.request.download")}
            </Button>
          )}
        </section>
      )}
      {user && req?.status === "open" && !fragment && <p role="alert" className="text-sm text-destructive">{t("sign.error.key")}</p>}

      {doc && !done && (
        <>
          <SanitizeReport neutralized={doc.report.neutralized} removedText={doc.report.removedText} />
          <PdfViewer pdf={doc.pdf} onPages={setPages} onReachedEnd={onEnd} />
          <section className="sticky bottom-4 space-y-2 rounded-2xl border border-border bg-card/95 p-4 shadow-lg backdrop-blur">
            <p className="text-xs text-muted-foreground" aria-live="polite">
              {!reachedEnd ? t("sign.request.scroll") : elapsed < minRead ? t("sign.request.wait", { n: minRead - elapsed }) : t("sign.request.readyToSign")}
            </p>
            <Button className="min-h-11 w-full" disabled={!canSign || busy} onClick={() => void confirm()}>
              <KeyRound className="mr-2 h-4 w-4" aria-hidden />{busy ? t("sign.request.signing") : t("sign.request.sign")}
            </Button>
          </section>
        </>
      )}
      {done && <p role="status" className="rounded-2xl border border-primary/40 bg-primary/5 p-5 text-sm">{t("sign.request.done")}</p>}
    </main>
  );
}
