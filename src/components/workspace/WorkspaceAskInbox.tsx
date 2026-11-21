import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { KeyRound, Loader2, Lock, MessageSquareLock, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { MasterKeyRecoveryCard } from "@/components/booking/SealedBookingDetails";
import { b64uDecode, b64uEncode } from "@/lib/booking-engine/sealed-booking";
import { useI18n } from "@/lib/i18n";
import { withSudo } from "@/lib/auth/sudo-client";
import {
  declineWsInboxQuestion, getWsInbox, initWsInboxKey, publishWsInboxQuestion, replyWsInboxQuestion, setWsAskEnabled,
} from "@/lib/workspace-inbox.functions";

type Inbox = Extract<Awaited<ReturnType<typeof getWsInbox>>, { ok: true }>;
type Question = Inbox["questions"][number];
type Device = "checking" | "ready" | "needs_master" | "error";
const card = "space-y-4 rounded-2xl border border-border bg-card p-5";
const OPEN_BATCH = 100;

/**
 * Owner/admin inbox for the anonymous question page (db/0285). Questions are opened in the
 * crypto worker with the workspace key the manager's own envelope carries; answers are sealed
 * there to the visitor's reply key. The server only ever sees ciphertext, except for a
 * question and answer a manager deliberately publishes as an FAQ item.
 */
export function WorkspaceAskInbox({ workspaceId, slug }: { workspaceId: string; slug: string }) {
  const { t } = useI18n();
  const load = useServerFn(getWsInbox);
  const initKey = useServerFn(initWsInboxKey);
  const saveAsk = useServerFn(setWsAskEnabled);
  const reply = useServerFn(replyWsInboxQuestion);
  const publish = useServerFn(publishWsInboxQuestion);
  const decline = useServerFn(declineWsInboxQuestion);
  const [inbox, setInbox] = useState<Inbox | "loading" | "forbidden" | "unavailable">("loading");
  const [device, setDevice] = useState<Device>("checking");
  const [texts, setTexts] = useState<Record<string, string | null>>({});
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    const r = await load({ data: { workspaceId, slug } }).catch(() => null);
    if (!alive.current) return;
    if (!r) return setInbox("unavailable");
    if (!r.ok) return setInbox(r.reason);
    setInbox(r);
    try {
      const { enclave } = await import("@/lib/crypto-enclave/client");
      if (!(await enclave.deviceKey.status(r.userId))) return setDevice("needs_master");
      setDevice("ready");
      const opened: Record<string, string | null> = {};
      for (const own of r.ownKeys) {
        const rows = r.questions.filter((q) => q.epoch === own.epoch);
        const ownEnv = b64uDecode(own.envelope);
        if (!ownEnv) continue;
        for (let i = 0; i < rows.length; i += OPEN_BATCH) {
          const batch = rows.slice(i, i + OPEN_BATCH);
          const items = batch.flatMap((q) => {
            const envelope = b64uDecode(q.envelope);
            return envelope ? [{ payloadId: q.payloadId, envelope, id: q.id }] : [];
          });
          const res = await enclave.workspaceInbox.open(r.userId, workspaceId, own.epoch, { envelope: ownEnv, memberRef: own.memberRef }, items)
            .catch(() => ({ texts: items.map(() => null) }));
          items.forEach((it, k) => { opened[it.id] = res.texts[k] ?? null; });
        }
      }
      if (alive.current) setTexts(opened);
    } catch {
      if (alive.current) setDevice("error");
    }
  }, [load, workspaceId, slug]);

  useEffect(() => {
    alive.current = true;
    void refresh();
    return () => { alive.current = false; setTexts({}); };
  }, [refresh]);

  const active = inbox !== "loading" && typeof inbox === "object" ? inbox.epochs.find((e) => e.status === "active") ?? null : null;
  const holdsActive = Boolean(active && typeof inbox === "object" && inbox.ownKeys.some((k) => k.epoch === active.epoch));
  const sorted = useMemo(() => (typeof inbox === "object" ? [...inbox.questions] : []), [inbox]);

  if (inbox === "loading") return <section className={card}><p className="text-sm text-muted-foreground" role="status">{t("wsInbox.loading")}</p></section>;
  if (inbox === "forbidden") return null;
  if (inbox === "unavailable") return <section className={card}><p className="text-sm text-muted-foreground" role="status">{t("wsInbox.unavailable")}</p></section>;

  async function createKey(rotate: boolean) {
    if (typeof inbox !== "object") return;
    if (rotate && !window.confirm(t("wsInbox.key.rotateConfirm"))) return;
    setBusy(true);
    try {
      const { enclave } = await import("@/lib/crypto-enclave/client");
      const me = await enclave.rve1.deviceKey(inbox.userId);
      const memberRef = crypto.randomUUID();
      const epoch = Math.max(0, ...inbox.epochs.map((e) => e.epoch)) + 1;
      const g = await enclave.workspaceInbox.generate(workspaceId, epoch, { memberRef, publicKey: me.publicKey });
      const r = await withSudo(() => initKey({ data: { workspaceId, epoch, publicKey: b64uEncode(g.publicKey), kid: b64uEncode(g.kid), memberRef, envelope: b64uEncode(g.envelope) } }));
      if (r.result === "ok") toast.success(t("wsInbox.key.created"));
      else toast.error(t(`wsInbox.result.${r.result}`));
    } catch {
      toast.error(t("wsInbox.result.failed"));
    } finally {
      setBusy(false);
      void refresh();
    }
  }

  async function toggleAsk(enabled: boolean) {
    setBusy(true);
    const r = await saveAsk({ data: { workspaceId, enabled } }).catch(() => ({ result: "unavailable" as const }));
    setBusy(false);
    if (r.result !== "ok") toast.error(t(`wsInbox.result.${r.result}`));
    void refresh();
  }

  return (
    <section className={card} aria-labelledby="ws-inbox-title">
      <div className="space-y-1">
        <h2 id="ws-inbox-title" className="flex items-center gap-2 font-medium"><MessageSquareLock className="h-4 w-4" aria-hidden />{t("wsInbox.title")}</h2>
        <p className="text-sm text-muted-foreground">{t("wsInbox.intro")}</p>
      </div>

      {device === "needs_master" && <MasterKeyRecoveryCard onRetry={() => { setDevice("checking"); void refresh(); }} />}
      {device === "error" && (
        <p className="flex items-start gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-3 text-sm" role="alert">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-hidden />{t("wsInbox.deviceError")}
        </p>
      )}

      {!active ? (
        <div className="space-y-2 rounded-xl border border-border bg-background/60 p-3">
          <p className="text-sm">{t("wsInbox.key.none")}</p>
          <Button size="sm" onClick={() => void createKey(false)} disabled={busy || device !== "ready"}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}{t("wsInbox.key.create")}
          </Button>
        </div>
      ) : (
        <div className="space-y-3 rounded-xl border border-border bg-background/60 p-3">
          <p className="flex items-center gap-2 text-sm"><Lock className="h-4 w-4 text-primary" aria-hidden />{t("wsInbox.key.active", { epoch: active.epoch })}</p>
          {!holdsActive && <p className="text-sm text-muted-foreground">{t("wsInbox.key.notHeld")}</p>}
          {active.missing.length > 0 && <p className="text-xs text-muted-foreground">{t("wsInbox.key.missing", { count: active.missing.length })}</p>}
          <div className="flex items-center justify-between gap-4">
            <label htmlFor="ws-ask-on" className="text-sm font-medium">{t("wsInbox.enable")}</label>
            <Switch id="ws-ask-on" checked={inbox.enabled} disabled={busy || !holdsActive} onCheckedChange={(v) => void toggleAsk(v)} />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button asChild size="sm" variant="outline"><a href={`/w/${slug}/ask`} target="_blank" rel="noreferrer">{t("wsInbox.openPage")}</a></Button>
            <Button size="sm" variant="ghost" onClick={() => void createKey(true)} disabled={busy || device !== "ready"}>{t("wsInbox.key.rotate")}</Button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        <h3 className="text-sm font-semibold">{t("wsInbox.list.title", { count: sorted.length })}</h3>
        {sorted.length === 0 && <p className="text-sm text-muted-foreground">{t("wsInbox.list.empty")}</p>}
        {sorted.map((q) => (
          <QuestionItem
            key={q.id}
            q={q}
            text={texts[q.id]}
            onReply={async (answer) => {
              const question = texts[q.id];
              const pk = b64uDecode(q.guestPublicKey);
              if (!question || !pk) return false;
              const { enclave } = await import("@/lib/crypto-enclave/client");
              const sealed = await enclave.workspaceInbox.sealAnswer(pk, question, answer).catch(() => null);
              if (!sealed) { toast.error(t("wsInbox.result.failed")); return false; }
              const r = await reply({ data: { questionId: q.id, envelope: b64uEncode(sealed.envelope), hash: b64uEncode(sealed.hash) } }).catch(() => ({ result: "unavailable" as const }));
              if (r.result === "ok") { toast.success(t("wsInbox.replied")); void refresh(); return true; }
              toast.error(t(`wsInbox.result.${r.result}`));
              return false;
            }}
            onPublish={async (question, answer) => {
              const r = await publish({ data: { questionId: q.id, question, answer } }).catch(() => ({ result: "unavailable" as const }));
              if (r.result === "ok") { toast.success(t("wsInbox.published")); void refresh(); return true; }
              toast.error(t(`wsInbox.result.${r.result}`));
              return false;
            }}
            onDecline={async () => {
              if (!window.confirm(t("wsInbox.declineConfirm"))) return;
              const r = await decline({ data: { questionId: q.id } }).catch(() => ({ result: "unavailable" as const }));
              if (r.result === "ok") void refresh();
              else toast.error(t(`wsInbox.result.${r.result}`));
            }}
          />
        ))}
      </div>
    </section>
  );
}

function QuestionItem({ q, text, onReply, onPublish, onDecline }: {
  q: Question;
  text: string | null | undefined;
  onReply: (answer: string) => Promise<boolean>;
  onPublish: (question: string, answer: string) => Promise<boolean>;
  onDecline: () => Promise<void>;
}) {
  const { t } = useI18n();
  const [answer, setAnswer] = useState("");
  const [faqQuestion, setFaqQuestion] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const closed = q.status === "declined" || q.status === "published";
  const date = q.createdAt ? new Date(q.createdAt).toLocaleString() : "";

  async function run(fn: () => Promise<boolean | void>) {
    setBusy(true);
    try {
      if ((await fn()) === true) { setAnswer(""); setFaqQuestion(null); }
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className="space-y-3 rounded-xl border border-border bg-background p-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <Badge variant={q.status === "open" ? "default" : "secondary"}>{t(`wsInbox.status.${q.status}`)}</Badge>
        <span>{date}</span>
        {q.hasReply && <span>· {t("wsInbox.hasReply")}</span>}
      </div>
      {text === undefined ? (
        <p className="text-sm text-muted-foreground">{t("wsInbox.locked")}</p>
      ) : text === null ? (
        <p className="text-sm text-destructive">{t("wsInbox.unreadable")}</p>
      ) : (
        <p className="whitespace-pre-wrap break-words text-sm">{text}</p>
      )}
      {typeof text === "string" && !closed && (
        <div className="space-y-2">
          <label className="sr-only" htmlFor={`ans-${q.id}`}>{t("wsInbox.answerLabel")}</label>
          <Textarea id={`ans-${q.id}`} value={answer} maxLength={4000} rows={3} placeholder={t("wsInbox.answerPlaceholder")} onChange={(e) => setAnswer(e.target.value)} />
          {faqQuestion !== null && (
            <div className="space-y-1">
              <label className="text-xs font-medium" htmlFor={`faq-${q.id}`}>{t("wsInbox.faqQuestionLabel")}</label>
              <Input id={`faq-${q.id}`} value={faqQuestion} maxLength={2000} onChange={(e) => setFaqQuestion(e.target.value)} />
              <p className="text-xs text-muted-foreground">{t("wsInbox.faqHint")}</p>
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={busy || !answer.trim()} onClick={() => void run(() => onReply(answer.trim()))}>{t("wsInbox.reply")}</Button>
            {faqQuestion === null ? (
              <Button size="sm" variant="outline" disabled={busy} onClick={() => setFaqQuestion(text)}>{t("wsInbox.publish")}</Button>
            ) : (
              <Button size="sm" variant="outline" disabled={busy || !answer.trim() || !faqQuestion.trim()} onClick={() => void run(() => onPublish(faqQuestion.trim(), answer.trim()))}>{t("wsInbox.publishConfirm")}</Button>
            )}
            <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run(onDecline)}>{t("wsInbox.decline")}</Button>
          </div>
        </div>
      )}
    </article>
  );
}
