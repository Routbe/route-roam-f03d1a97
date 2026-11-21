import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, ExternalLink, Loader2, ScanLine, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { hubCopy, type HubCopy } from "@/lib/kyc/hub-copy";
import { nextPollDelay, POLL_DEADLINE_MS, type KycPhase } from "@/lib/kyc/modal-flow";

type ErrorKey = keyof HubCopy["errors"];

/**
 * Didit verification modal: POST /api/v1/kyc/didit/session, open the hosted Didit flow in a new tab,
 * then poll /api/v1/kyc/status (no client state is stored; the session URL lives in memory only).
 */
export function DiditVerificationModal({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { i18n } = useTranslation();
  const c = hubCopy(i18n.language);
  const qc = useQueryClient();
  const [phase, setPhase] = useState<KycPhase>("idle");
  const [error, setError] = useState<ErrorKey | null>(null);
  const [sessionUrl, setSessionUrl] = useState<string | null>(null);
  const [popupBlocked, setPopupBlocked] = useState(false);
  const poll = useRef<{ timer: ReturnType<typeof setTimeout> | null; started: number; sawPending: boolean; abort: AbortController | null }>({
    timer: null, started: 0, sawPending: false, abort: null,
  });

  const stopPolling = useCallback(() => {
    if (poll.current.timer) clearTimeout(poll.current.timer);
    poll.current.abort?.abort();
    poll.current.timer = null;
    poll.current.abort = null;
  }, []);

  const tick = useCallback(async () => {
    const p = poll.current;
    const elapsed = Date.now() - p.started;
    if (elapsed > POLL_DEADLINE_MS) {
      setPhase("error");
      setError("timeout");
      return;
    }
    p.abort = new AbortController();
    try {
      const res = await fetch("/api/v1/kyc/status", { credentials: "same-origin", cache: "no-store", signal: p.abort.signal });
      if (res.status === 401) {
        setPhase("error");
        setError("unauthorized");
        return;
      }
      if (res.ok) {
        const body = (await res.json()) as { state?: string };
        if (body.state === "verified") {
          setPhase("verified");
          void qc.invalidateQueries({ queryKey: ["identity-status"] });
          return;
        }
        if (body.state === "pending") p.sawPending = true;
        else if (body.state === "none" && p.sawPending) {
          setPhase("failed");
          return;
        }
      }
    } catch (e) {
      if ((e as Error)?.name === "AbortError") return;
      // Network hiccup: keep polling until the deadline.
    }
    p.timer = setTimeout(() => void tick(), nextPollDelay(Date.now() - p.started));
  }, [qc]);

  const start = useCallback(async () => {
    stopPolling();
    setError(null);
    setPopupBlocked(false);
    setPhase("starting");
    let res: Response;
    try {
      res = await fetch("/api/v1/kyc/didit/session", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
    } catch {
      setPhase("error");
      setError("network");
      return;
    }
    const body = (await res.json().catch(() => ({}))) as { session_url?: string; session_token?: string; error?: string };
    if (!res.ok || !body.session_url) {
      const key = (res.status === 401 ? "unauthorized" : body.error) as ErrorKey | undefined;
      setPhase("error");
      setError(key && key in c.errors ? key : "provider_error");
      return;
    }
    setSessionUrl(body.session_url);
    const w = window.open(body.session_url, "_blank");
    if (w) w.opener = null;
    else setPopupBlocked(true);
    setPhase("waiting");
    poll.current.started = Date.now();
    poll.current.sawPending = false;
    poll.current.timer = setTimeout(() => void tick(), 1500);
  }, [c.errors, stopPolling, tick]);

  // Poll right away when the member comes back from the Didit tab.
  useEffect(() => {
    if (phase !== "waiting") return;
    const onVisible = () => {
      if (document.visibilityState !== "visible") return;
      stopPolling();
      void tick();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [phase, stopPolling, tick]);

  useEffect(() => {
    if (!open) {
      stopPolling();
      setPhase("idle");
      setError(null);
      setSessionUrl(null);
    }
    return stopPolling;
  }, [open, stopPolling]);

  const busy = phase === "starting";
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ScanLine className="h-5 w-5" aria-hidden /> {c.modalTitle}
          </DialogTitle>
          <DialogDescription>{c.modalIntro}</DialogDescription>
        </DialogHeader>

        <div aria-live="polite" role="status" className="min-h-12 text-sm">
          {phase === "waiting" && (
            <p className="flex items-start gap-2 text-muted-foreground">
              <Loader2 className="mt-0.5 h-4 w-4 shrink-0 animate-spin" aria-hidden /> {c.modalWaiting}
            </p>
          )}
          {phase === "waiting" && popupBlocked && <p className="mt-2 text-muted-foreground">{c.modalPopupBlocked}</p>}
          {phase === "verified" && (
            <p className="flex items-start gap-2 font-medium text-primary">
              <BadgeCheck className="mt-0.5 h-4 w-4 shrink-0" aria-hidden /> {c.modalVerified}
            </p>
          )}
          {phase === "failed" && (
            <p className="flex items-start gap-2 text-destructive">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden /> {c.modalFailed}
            </p>
          )}
          {phase === "error" && error && (
            <p className="flex items-start gap-2 text-destructive">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden /> {c.errors[error]}
            </p>
          )}
        </div>

        <DialogFooter className="gap-2 sm:gap-2">
          {(phase === "idle" || phase === "starting") && (
            <Button type="button" onClick={() => void start()} disabled={busy} className="min-h-11 gap-2">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <ScanLine className="h-4 w-4" aria-hidden />} {c.modalStart}
            </Button>
          )}
          {phase === "waiting" && sessionUrl && (
            <Button asChild variant="outline" className="min-h-11 gap-2">
              <a href={sessionUrl} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4" aria-hidden /> {c.modalOpen}
              </a>
            </Button>
          )}
          {(phase === "failed" || (phase === "error" && error !== "already_verified" && error !== "not_configured")) && (
            <Button type="button" onClick={() => void start()} className="min-h-11">{c.modalRetry}</Button>
          )}
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} className="min-h-11">{c.modalClose}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
