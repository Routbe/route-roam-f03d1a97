import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { FileSignature, Link2, Trash2, Upload } from "lucide-react";
import { useI18n } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { SanitizeReport } from "@/components/sign/SanitizeReport";
import { createSignRequestFn, getSignReadiness, listMySignRequestsFn, revokeSignRequestFn } from "@/lib/sign/sign.functions";
import { MAX_PDF_BYTES, sanitizePdf, type SanitizeResult } from "@/lib/sign/pdf-sanitizer";
import { SIGN_DAYS, SIGN_MIN_READ } from "@/lib/sign/sign-rules";
import { keyToFragment } from "@/lib/sign/sign-envelope";
import { bytesToB64 } from "@/lib/sign/b64";

const title = "ROUT Sign — document laten ondertekenen";
const description = "Laat een PDF ondertekenen door een geverifieerde persoon. Het document blijft versleuteld; de sleutel zit alleen in de link.";

export const Route = createFileRoute("/_authenticated/sign/")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: SignHome,
});

type Clean = Extract<SanitizeResult, { ok: true }> & { name: string };

function SignHome() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const readiness = useServerFn(getSignReadiness);
  const list = useServerFn(listMySignRequestsFn);
  const create = useServerFn(createSignRequestFn);
  const revoke = useServerFn(revokeSignRequestFn);
  const ready = useQuery({ queryKey: ["sign-ready"], queryFn: () => readiness() });
  const mine = useQuery({ queryKey: ["sign-mine"], queryFn: () => list(), enabled: ready.data?.available === true });
  const [clean, setClean] = useState<Clean | null>(null);
  const [minRead, setMinRead] = useState<number>(SIGN_MIN_READ.default);
  const [days, setDays] = useState<number>(SIGN_DAYS.default);
  const [busy, setBusy] = useState(false);
  const [link, setLink] = useState<string | null>(null);

  async function pick(file: File | undefined) {
    setLink(null);
    setClean(null);
    if (!file) return;
    if (file.size > MAX_PDF_BYTES) return void toast.error(t("sign.error.too_large"));
    const res = await sanitizePdf(new Uint8Array(await file.arrayBuffer()));
    if (!res.ok) return void toast.error(t(`sign.error.${res.reason}`));
    setClean({ ...res, name: file.name });
  }

  async function submit() {
    if (!clean) return;
    setBusy(true);
    try {
      const { enclave } = await import("@/lib/crypto-enclave/client");
      const { envelope, key } = await enclave.sign.seal(clean.bytes.slice());
      const fragment = keyToFragment(key);
      key.fill(0);
      const res = await create({ data: { envelope: bytesToB64(envelope), days, minReadSeconds: minRead } });
      if (!res) throw new Error(t("sign.error.generic"));
      setLink(`${window.location.origin}/sign/${res.id}#k=${fragment}`);
      setClean(null);
      void qc.invalidateQueries({ queryKey: ["sign-mine"] });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("sign.error.generic"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-3xl space-y-6 px-4 py-10">
      <header className="space-y-2">
        <h1 className="flex items-center gap-2 text-2xl font-semibold"><FileSignature className="h-6 w-6 text-primary" aria-hidden />{t("sign.home.title")}</h1>
        <p className="text-muted-foreground">{t("sign.home.lead")}</p>
        <p className="rounded-xl border border-border bg-muted/40 p-3 text-xs text-muted-foreground">{t("sign.phase1")}</p>
      </header>

      {ready.data && !ready.data.available ? (
        <p role="status" className="rounded-2xl border border-border p-4 text-sm">{t("sign.unavailable")}</p>
      ) : (
        <section className="space-y-4 rounded-2xl border border-border bg-card p-5">
          <label className="flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-xl border border-dashed border-border p-6 text-sm hover:bg-muted/40">
            <Upload className="h-4 w-4" aria-hidden />
            {clean ? clean.name : t("sign.home.pick")}
            <input type="file" accept="application/pdf" className="sr-only" onChange={(e) => void pick(e.target.files?.[0])} />
          </label>
          {clean && <SanitizeReport neutralized={clean.neutralized} removedText={clean.removedText} />}
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="text-sm">
              <span className="text-muted-foreground">{t("sign.home.minRead")}</span>
              <select className="mt-1 block min-h-11 w-full rounded-md border border-input bg-background px-3" value={minRead} onChange={(e) => setMinRead(Number(e.target.value))}>
                {[10, 30, 60, 120, 300, 600].map((s) => <option key={s} value={s}>{t("sign.home.seconds", { n: s })}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="text-muted-foreground">{t("sign.home.days")}</span>
              <select className="mt-1 block min-h-11 w-full rounded-md border border-input bg-background px-3" value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {[1, 3, 7, 14, 30].map((d) => <option key={d} value={d}>{t("sign.home.dayCount", { n: d })}</option>)}
              </select>
            </label>
          </div>
          <Button className="min-h-11 w-full" disabled={!clean || busy} onClick={() => void submit()}>
            {busy ? t("sign.home.sealing") : t("sign.home.create")}
          </Button>
          {link && (
            <div className="space-y-2 rounded-xl border border-primary/40 bg-primary/5 p-4 text-sm">
              <p className="font-medium">{t("sign.home.linkReady")}</p>
              <p className="break-all font-mono text-xs">{link}</p>
              <Button variant="outline" className="min-h-11" onClick={() => void navigator.clipboard.writeText(link).then(() => toast.success(t("sign.home.copied")))}>
                <Link2 className="mr-2 h-4 w-4" aria-hidden />{t("sign.home.copy")}
              </Button>
              <p className="text-xs text-muted-foreground">{t("sign.home.linkNote")}</p>
            </div>
          )}
        </section>
      )}

      {mine.data && mine.data.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-base font-medium">{t("sign.home.mine")}</h2>
          <ul className="divide-y divide-border rounded-2xl border border-border">
            {mine.data.map((r) => (
              <li key={r.id} className="flex items-center gap-3 p-3 text-sm">
                <span className="flex-1">
                  <span className="font-mono text-xs">{r.id.slice(0, 8)}</span> · {t(`sign.status.${r.status}`)}
                  <span className="block text-xs text-muted-foreground">{new Date(r.createdAt).toLocaleString()}</span>
                </span>
                {r.status === "open" && (
                  <Button
                    variant="ghost"
                    className="min-h-11"
                    aria-label={t("sign.home.revoke")}
                    onClick={() => void revoke({ data: { id: r.id } }).then(() => qc.invalidateQueries({ queryKey: ["sign-mine"] }))}
                  >
                    <Trash2 className="h-4 w-4" aria-hidden />
                  </Button>
                )}
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">{t("sign.home.mineNote")}</p>
        </section>
      )}
    </main>
  );
}
