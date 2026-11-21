import { useEffect, useMemo, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { useNavigate } from "@tanstack/react-router";
import { QRCodeSVG } from "qrcode.react";
import { Check, Copy, CreditCard, Download, Landmark, Loader2, ShieldCheck, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Altcha } from "@/components/Altcha";
import { takeProof } from "@/lib/altcha-client";
import { useAuth } from "@/hooks/useAuth";
import { useI18n } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { getMySupport, getSupportDonation, getSupportOverview, startSupportDonation } from "@/lib/support/support.functions";
import { SUPPORT_PRESETS_CENTS_CLIENT } from "@/lib/support/amounts";
import type { DonationView, SupportOverview } from "@/lib/support/support.server";
import type { SignedReceipt } from "@/lib/support/receipt";
import { VerifiedSupporterCrown } from "./VerifiedSupporterCrown";
import { SupportNav } from "./SupportNav";

const K = "pages.supportfund.";
const card = "rounded-xl border border-border/60 bg-card p-5 shadow-sm";
const tokenKey = (id: string) => `rout.support.${id}`;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

function useT() {
  const { t, locale } = useI18n();
  const euro = (cents: number) => new Intl.NumberFormat(locale === "en" ? "en-IE" : `${locale}-BE`, { style: "currency", currency: "EUR" }).format(cents / 100);
  return { t: (k: string, o?: Record<string, unknown>) => t(K + k, o), euro };
}

function download(name: string, data: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function CopyRow({ label, value, display }: { label: string; value: string; display?: string }) {
  const { t } = useT();
  const [done, setDone] = useState(false);
  return (
    <div className="flex items-center justify-between gap-3 py-2.5">
      <div className="min-w-0">
        <p className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</p>
        <p className="truncate font-mono text-sm">{display ?? value}</p>
      </div>
      <Button
        type="button"
        size="sm"
        variant="ghost"
        className="min-h-11 min-w-11"
        aria-label={`${label}: ${done ? t("copied") : t("copy")}`}
        onClick={async () => {
          await navigator.clipboard.writeText(value).catch(() => null);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }}
      >
        {done ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
      </Button>
    </div>
  );
}

function CoverageBar({ overview }: { overview: SupportOverview }) {
  const { t, euro } = useT();
  const c = overview.coverage;
  return (
    <section className={card} aria-labelledby="coverage-title">
      <h2 id="coverage-title" className="text-sm font-medium text-foreground">{t("coverage.title")}</h2>
      {c.state === "unknown" ? (
        <p className="mt-2 text-sm text-muted-foreground">{t("coverage.unknown", { amount: euro(c.collectedCents) })}</p>
      ) : (
        <>
          <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.min(100, c.percent)}>
            <div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${Math.min(100, c.percent)}%` }} />
          </div>
          <p className="mt-2 flex flex-wrap justify-between gap-2 text-sm">
            <span className="font-medium">{t("coverage.known", { percent: c.percent, cost: euro(c.costCents) })}</span>
            <span className="text-muted-foreground">{c.shortfallCents > 0 ? t("coverage.short", { amount: euro(c.shortfallCents) }) : t("coverage.full")}</span>
          </p>
        </>
      )}
    </section>
  );
}

function ReceiptButton({ receipt }: { receipt: SignedReceipt }) {
  const { t } = useT();
  return (
    <Button
      type="button"
      variant="outline"
      className="min-h-11"
      onClick={async () => {
        const { buildPdf, receiptLines } = await import("@/lib/support/receipt-pdf");
        const pdf = buildPdf(
          receiptLines(receipt, {
            title: t("receipt.title"), amount: t("receipt.amount"), date: t("receipt.date"), method: t("receipt.method"), level: t("receipt.level"),
            index: t("receipt.index"), tx: t("receipt.tx"), root: t("receipt.root"), notTax: t("receipt.notTax"), verify: t("receipt.verify"),
            levelNames: { 1: t("level.1.title"), 2: t("level.2.title"), 3: t("level.3.title") },
          }),
        );
        download(`rout-receipt-${receipt.receipt.id.slice(0, 8)}.pdf`, pdf.slice().buffer as ArrayBuffer, "application/pdf");
      }}
    >
      <Download className="size-4" aria-hidden /> {t("receipt.download")}
    </Button>
  );
}

function SepaInstructions({ view, link }: { view: Pick<DonationView, "amountCents" | "ogmText" | "epc" | "account">; link: string | null }) {
  const { t, euro } = useT();
  if (!view.account || !view.ogmText) return null;
  return (
    <div className="grid gap-5 sm:grid-cols-[1fr_auto]">
      <div>
        <p className="text-sm text-muted-foreground">{t("sepa.intro")}</p>
        <div className="mt-3 divide-y divide-border/60">
          <CopyRow label={t("sepa.name")} value={view.account.name} />
          <CopyRow label={t("sepa.iban")} value={view.account.iban} display={view.account.iban.replace(/(.{4})/g, "$1 ").trim()} />
          <CopyRow label={t("sepa.amount")} value={(view.amountCents / 100).toFixed(2)} display={euro(view.amountCents)} />
          <CopyRow label={t("sepa.ogm")} value={view.ogmText} />
        </div>
        {link && (
          <div className="mt-4 rounded-lg bg-muted/60 p-3">
            <CopyRow label={t("sepa.keep")} value={link} display={link.replace(/#.*/, "#…")} />
            <p className="text-xs text-muted-foreground">{t("sepa.keepHint")}</p>
          </div>
        )}
      </div>
      {view.epc && (
        <figure className="flex flex-col items-center gap-2 justify-self-center">
          <div className="rounded-lg border border-border/60 bg-background p-3">
            <QRCodeSVG value={view.epc} size={184} level="M" marginSize={0} bgColor="transparent" fgColor="currentColor" className="text-foreground" aria-label={t("sepa.qr")} />
          </div>
          <figcaption className="text-xs text-muted-foreground">{t("sepa.qr")}</figcaption>
        </figure>
      )}
    </div>
  );
}

function DonationStatus({ id, cancelled }: { id: string; cancelled: boolean }) {
  const { t } = useT();
  const read = useServerFn(getSupportDonation);
  const [token, setToken] = useState<string | null>(null);
  const [view, setView] = useState<DonationView | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const fromHash = new URLSearchParams(window.location.hash.slice(1)).get("t");
    const stored = sessionStorage.getItem(tokenKey(id));
    const tok = fromHash && TOKEN_RE.test(fromHash) ? fromHash : stored && TOKEN_RE.test(stored) ? stored : null;
    setToken(tok);
    if (tok && !fromHash) History.prototype.replaceState.call(window.history, window.history.state, "", `${window.location.pathname}${window.location.search}#t=${tok}`);
    if (!tok) setView(null);
  }, [id]);

  const refresh = async () => {
    if (!token) return;
    setBusy(true);
    try {
      setView(await read({ data: { id, token } }));
    } catch {
      setView(null);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  if (cancelled && (!view || view.status === "pending")) return <section className={card}><p className="text-sm">{t("status.cancel")}</p></section>;
  if (view === undefined) return <section className={card}><Loader2 className="size-5 animate-spin text-muted-foreground" aria-hidden /></section>;
  if (view === null) return <section className={card}><p className="text-sm text-muted-foreground">{t("status.missing")}</p></section>;

  const link = token ? `${window.location.origin}/support/donations?d=${id}#t=${token}` : null;
  return (
    <section className={cn(card, "space-y-4")} aria-live="polite">
      <h2 className="font-serif text-xl font-semibold">{t("status.title")}</h2>
      <p className={cn("text-sm", view.status === "paid" ? "font-medium text-foreground" : "text-muted-foreground")}>{t(`status.${view.status}`)}</p>
      {view.status === "pending" && view.rail === "sepa" && <SepaInstructions view={view} link={link} />}
      {view.status === "pending" && (
        <Button type="button" variant="ghost" className="min-h-11" onClick={() => void refresh()} disabled={busy}>
          {busy && <Loader2 className="size-4 animate-spin" aria-hidden />} {t("status.refresh")}
        </Button>
      )}
      {view.status === "paid" && (
        <div className="flex flex-wrap gap-2">
          {view.receipt && <ReceiptButton receipt={view.receipt} />}
          {view.credential && (
            <Button type="button" variant="outline" className="min-h-11" onClick={() => download("rout-supporter.sd-jwt", view.credential!, "application/dc+sd-jwt")}>
              <Download className="size-4" aria-hidden /> {t("cred.download")}
            </Button>
          )}
          {view.proof && (
            <Button type="button" variant="outline" className="min-h-11" onClick={() => download("rout-inclusion-proof.json", JSON.stringify(view.proof, null, 2), "application/json")}>
              <Download className="size-4" aria-hidden /> {t("proof.download")}
            </Button>
          )}
        </div>
      )}
      {view.status === "paid" && (view.credential || view.proof) && (
        <div className="grid gap-3 text-xs text-muted-foreground sm:grid-cols-2">
          {view.credential && <p><span className="font-medium text-foreground">{t("cred.title")}.</span> {t("cred.desc")}</p>}
          {view.proof && <p><span className="font-medium text-foreground">{t("proof.title")}.</span> {t("proof.desc")}</p>}
        </div>
      )}
    </section>
  );
}

type Start = Awaited<ReturnType<typeof startSupportDonation>>;

function DonateForm({ overview }: { overview: SupportOverview }) {
  const { t, euro } = useT();
  const { user } = useAuth();
  const start = useServerFn(startSupportDonation);
  const navigate = useNavigate();
  const [preset, setPreset] = useState<number | null>(1000);
  const [custom, setCustom] = useState("");
  const [level, setLevel] = useState<1 | 2 | 3>(2);
  const [rail, setRail] = useState<"sepa" | "stripe">(overview.sepa ? "sepa" : "stripe");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sepa, setSepa] = useState<Extract<Start, { rail: "sepa" }> | null>(null);
  const [armed, setArmed] = useState(false);

  const amountCents = useMemo(() => {
    if (preset !== null) return preset;
    const n = Number(custom.replace(",", "."));
    return Number.isFinite(n) ? Math.round(n * 100) : 0;
  }, [preset, custom]);
  const railOk = rail === "sepa" ? overview.sepa : overview.stripe;
  const canSubmit = overview.ready && railOk && amountCents >= 100 && amountCents <= 500_000 && !(level === 1 && !user) && !busy;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) {
      if (amountCents < 100 || amountCents > 500_000) setError(t("error.amount"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const altcha = await takeProof();
      const r = await start({ data: { level, rail, amountCents, origin: window.location.origin, altcha } });
      if (!r.ok) {
        setError(r.reason === "rate_limited" ? t("error.rate") : r.reason === "sign_in_required" ? t("error.signin") : r.reason === "invalid_amount" ? t("error.amount") : r.reason === "not_ready" ? t("form.notReady") : t("error.generic"));
        return;
      }
      sessionStorage.setItem(tokenKey(r.id), r.token);
      if (r.rail === "stripe") {
        window.location.assign(r.url);
        return;
      }
      setSepa(r);
      void navigate({ to: "/support/donations", search: { d: r.id }, hash: `t=${r.token}`, replace: true, resetScroll: false });
    } catch {
      setError(t("error.generic"));
    } finally {
      setBusy(false);
    }
  };

  if (sepa) {
    return (
      <section className={card}>
        <h2 className="mb-3 font-serif text-xl font-semibold">{t("sepa.title")}</h2>
        <SepaInstructions view={{ amountCents: sepa.amountCents, ogmText: sepa.ogmText, epc: sepa.epc, account: sepa.account }} link={`${window.location.origin}/support/donations?d=${sepa.id}#t=${sepa.token}`} />
      </section>
    );
  }

  const option = (on: boolean) =>
    cn("flex min-h-11 w-full cursor-pointer flex-col items-start gap-0.5 rounded-lg border p-3 text-left transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring", on ? "border-foreground bg-muted/60" : "border-border/60 hover:bg-muted/40");

  return (
    <form className={cn(card, "space-y-6")} onSubmit={submit} onFocusCapture={() => setArmed(true)} noValidate>
      <h2 className="font-serif text-xl font-semibold">{t("form.title")}</h2>
      {!overview.ready && <p className="rounded-lg bg-muted/60 p-3 text-sm text-muted-foreground">{t("form.notReady")}</p>}

      <fieldset>
        <legend className="mb-2 text-sm font-medium">{t("form.amount")}</legend>
        <div className="flex flex-wrap gap-2">
          {SUPPORT_PRESETS_CENTS_CLIENT.map((c) => (
            <button key={c} type="button" aria-pressed={preset === c} onClick={() => { setPreset(c); setCustom(""); }} className={cn("min-h-11 min-w-16 rounded-full border px-4 text-sm", preset === c ? "border-foreground bg-foreground text-background" : "border-border/60 hover:bg-muted")}>
              {euro(c)}
            </button>
          ))}
          <label className="flex items-center gap-2 text-sm">
            <span className="sr-only">{t("form.custom")}</span>
            <Input inputMode="decimal" placeholder={t("form.custom")} value={custom} onChange={(e) => { setCustom(e.target.value); setPreset(null); }} className="h-11 w-40" />
          </label>
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-2 text-sm font-medium">{t("form.level")}</legend>
        <div className="grid gap-2 sm:grid-cols-3">
          {([1, 2, 3] as const).map((l) => (
            <label key={l} className={option(level === l)}>
              <input type="radio" name="level" value={l} checked={level === l} onChange={() => setLevel(l)} className="sr-only" />
              <span className="text-sm font-medium">{t(`level.${l}.title`)}</span>
              <span className="text-xs text-muted-foreground">{t(`level.${l}.desc`)}</span>
              {l === 1 && !user && <span className="text-xs text-foreground">{t("level.1.signin")}</span>}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-2 text-sm font-medium">{t("form.rail")}</legend>
        <div className="grid gap-2 sm:grid-cols-2">
          {([["sepa", Landmark, overview.sepa], ["stripe", CreditCard, overview.stripe]] as const).map(([r, Icon, available]) => (
            <label key={r} className={cn(option(rail === r), !available && "opacity-60")}>
              <input type="radio" name="rail" value={r} checked={rail === r} onChange={() => setRail(r)} className="sr-only" />
              <span className="flex items-center gap-2 text-sm font-medium"><Icon className="size-4" aria-hidden /> {t(`rail.${r}.title`)}</span>
              <span className="text-xs text-muted-foreground">{available ? t(`rail.${r}.desc`) : t("form.unavailable")}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" className="min-h-11" disabled={!canSubmit}>
          {busy && <Loader2 className="size-4 animate-spin" aria-hidden />} {busy ? t("form.working") : t("form.submit")}
        </Button>
        <Altcha active={armed} />
      </div>
    </form>
  );
}

function Ledger({ overview }: { overview: SupportOverview }) {
  const { t, euro } = useT();
  return (
    <section className={card} aria-labelledby="ledger-title">
      <h2 id="ledger-title" className="font-serif text-xl font-semibold">{t("ledger.title")}</h2>
      {overview.root && (
        <p className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
          {t("ledger.root", { size: overview.root.size, root: `${overview.root.root.slice(0, 16)}…` })} · {overview.root.mldsa65 ? t("ledger.pq") : t("ledger.edOnly")} · {t("ledger.key", { kid: overview.root.kid })}
        </p>
      )}
      {overview.ledger.length === 0 ? (
        <p className="mt-3 text-sm text-muted-foreground">{t("ledger.empty")}</p>
      ) : (
        <ul className="mt-3 divide-y divide-border/60">
          {overview.ledger.map((e, i) => (
            <li key={`${e.index ?? "a"}-${i}`} className="flex items-center justify-between gap-3 py-2.5 text-sm">
              <span className="flex min-w-0 items-center gap-1.5">
                {e.level === 1 && e.handle ? (
                  <>
                    <span className="truncate font-medium">@{e.handle}</span>
                    <VerifiedSupporterCrown handle={e.handle} className="size-3.5" />
                  </>
                ) : e.level === 2 ? (
                  <span className="font-mono">{t("ledger.pseudonym", { index: e.index })}</span>
                ) : (
                  <span className="text-muted-foreground">{t("ledger.anonymous")}</span>
                )}
                {e.attested && <span className="rounded-full border border-border/60 px-2 py-0.5 text-[11px] text-muted-foreground">{t("ledger.human")}</span>}
              </span>
              <span className="shrink-0 tabular-nums text-muted-foreground">{euro(e.amountCents)} · {e.month}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function VerifyProof({ overview }: { overview: SupportOverview }) {
  const { t } = useT();
  const [text, setText] = useState("");
  const [result, setResult] = useState<"ok" | "okPq" | "fail" | "noKey" | null>(null);
  const [busy, setBusy] = useState(false);
  const check = async () => {
    if (!overview.publicKey) return setResult("noKey");
    setBusy(true);
    try {
      const [{ enclave }, { b64uDecode }] = await Promise.all([import("@/lib/crypto-enclave/client"), import("@/lib/support/hybrid-signature")]);
      const pk = overview.publicKey;
      const r = await enclave.support.verifyInclusion(text.trim(), { ed25519: b64uDecode(pk.ed25519), mldsa65: pk.mldsa65 ? b64uDecode(pk.mldsa65) : null, kid: pk.kid });
      setResult(r.valid ? (r.pq ? "okPq" : "ok") : "fail");
    } catch {
      setResult("fail");
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className={card} aria-labelledby="verify-title">
      <h2 id="verify-title" className="font-serif text-xl font-semibold">{t("verify.title")}</h2>
      <p className="mt-1 text-sm text-muted-foreground">{t("verify.desc")}</p>
      <label className="mt-3 block text-sm font-medium" htmlFor="proof-json">{t("verify.paste")}</label>
      <Textarea id="proof-json" value={text} onChange={(e) => { setText(e.target.value); setResult(null); }} rows={4} className="mt-1 font-mono text-xs" spellCheck={false} />
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Button type="button" variant="outline" className="min-h-11" onClick={() => void check()} disabled={!text.trim() || busy}>
          {busy && <Loader2 className="size-4 animate-spin" aria-hidden />} {t("verify.button")}
        </Button>
        {result && (
          <p role="status" className={cn("flex items-center gap-1.5 text-sm", result.startsWith("ok") ? "text-foreground" : "text-destructive")}>
            {result.startsWith("ok") ? <ShieldCheck className="size-4" aria-hidden /> : <ShieldX className="size-4" aria-hidden />}
            {t(`verify.${result}`)}
          </p>
        )}
      </div>
    </section>
  );
}

function MyDonations() {
  const { t, euro } = useT();
  const { user } = useAuth();
  const mine = useServerFn(getMySupport);
  const [rows, setRows] = useState<Awaited<ReturnType<typeof getMySupport>>>([]);
  useEffect(() => {
    if (!user) return;
    mine().then(setRows).catch(() => setRows([]));
  }, [user, mine]);
  if (!user || rows.length === 0) return null;
  return (
    <section className={card} aria-labelledby="mine-title">
      <h2 id="mine-title" className="font-serif text-xl font-semibold">{t("mine.title")}</h2>
      <ul className="mt-3 divide-y divide-border/60">
        {rows.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5 text-sm">
            <span>{euro(r.amountCents)} · {new Date(r.createdAt).toLocaleDateString()} · {t(`status.${r.status}`).split(".")[0]}</span>
            <span className="flex gap-2">
              {r.receipt && <ReceiptButton receipt={r.receipt} />}
              {r.credential && (
                <Button type="button" variant="ghost" className="min-h-11" onClick={() => download("rout-supporter.sd-jwt", r.credential!, "application/dc+sd-jwt")}>
                  <Download className="size-4" aria-hidden /> {t("cred.download")}
                </Button>
              )}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function SupportDonationsPage({ initial, donationId, cancelled }: { initial: SupportOverview; donationId: string | null; cancelled: boolean }) {
  const { t } = useT();
  const load = useServerFn(getSupportOverview);
  const [overview, setOverview] = useState(initial);
  useEffect(() => {
    if (donationId) load().then(setOverview).catch(() => null);
  }, [donationId, load]);
  return (
    <main className="mx-auto w-full max-w-3xl space-y-6 px-4 py-10 sm:py-14">
      <header className="space-y-4">
        <SupportNav active="donations" />
        <h1 className="font-serif text-3xl font-semibold tracking-tight sm:text-4xl">{t("title")}</h1>
        <p className="max-w-prose text-base text-muted-foreground">{t("lead")}</p>
      </header>
      <CoverageBar overview={overview} />
      {donationId ? <DonationStatus id={donationId} cancelled={cancelled} /> : <DonateForm overview={overview} />}
      <MyDonations />
      <Ledger overview={overview} />
      <VerifyProof overview={overview} />
    </main>
  );
}
