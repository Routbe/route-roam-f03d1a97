import { useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Fingerprint, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { isMinorDob } from "@/lib/minor-safety";
import { SIGNUP_CONSENT_VERSION } from "@/lib/signup-consent";

const ENDPOINT = "/api/auth-passkey/social";
const PROVIDER_LABEL: Record<string, string> = { google: "Google", github: "GitHub", gitlab: "GitLab" };

type Pending = { status: "pending_passkey_setup"; provider: string; email: string; name: string };

/**
 * Unified onboarding for a new Google/GitHub/GitLab member (status pending_passkey_setup):
 * step 1 asks the age (the server keeps only whole years), step 2 registers the passkey.
 * The account and session exist only after that passkey ceremony (`onEnroll`).
 */
export function SocialOnboardingDialog({ onEnroll }: { onEnroll: (ticket: string) => Promise<void> }) {
  const { t } = useTranslation();
  const [pending, setPending] = useState<Pending | null>(null);
  const [step, setStep] = useState<"age" | "passkey">("age");
  const [dob, setDob] = useState("");
  const [parentEmail, setParentEmail] = useState("");
  const [consented, setConsented] = useState(false);
  const [ticket, setTicket] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const minor = isMinorDob(dob);

  useEffect(() => {
    let live = true;
    fetch(ENDPOINT, { credentials: "include" })
      .then((r) => (r.ok ? r.json() : null))
      .then((j: Pending | { status: "none" } | null) => {
        if (live && j?.status === "pending_passkey_setup") setPending(j as Pending);
      })
      .catch(() => null);
    return () => { live = false; };
  }, []);

  if (!pending) return null;
  const provider = PROVIDER_LABEL[pending.provider] ?? pending.provider;

  async function submitAge(e: React.FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (!consented) { toast.error(t("auth.signupConsent.required")); return; }
    setBusy(true);
    const value = dob;
    setDob("");
    try {
      const res = await fetch(ENDPOINT, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ dob: value, parentEmail: minor ? parentEmail.trim().toLowerCase() : "", consent: SIGNUP_CONSENT_VERSION }),
      });
      const json = (await res.json().catch(() => ({}))) as { ticket?: string; code?: string };
      if (res.ok && typeof json.ticket === "string") {
        setTicket(json.ticket);
        setStep("passkey");
        return;
      }
      setDob(value);
      if (json.code === "onboarding_expired") { toast.error(t("auth.onboard.expired")); setPending(null); return; }
      toast.error(t(json.code === "dob_invalid" ? "auth.pk.dobInvalid" : json.code === "parent_required" || json.code === "parent_email_same" ? "auth.pk.parentInvalid" : "auth.pk.failed"));
    } catch {
      setDob(value);
      toast.error(t("auth.pk.failed"));
    } finally {
      setBusy(false);
    }
  }

  async function createPasskey() {
    if (!ticket || busy) return;
    setBusy(true);
    try {
      await onEnroll(ticket);
    } catch (err) {
      const msg = String((err as Error)?.message ?? "");
      toast.error(/account_exists/.test(msg) ? t("auth.pk.accountExists") : /signup_ticket_invalid/.test(msg) ? t("auth.onboard.expired") : t("auth.onboard.passkeyFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    await fetch(ENDPOINT, { method: "DELETE", credentials: "include" }).catch(() => null);
    setPending(null);
  }

  return (
    <AlertDialog open>
      <AlertDialogContent className="max-w-md" data-testid="social-onboarding">
        <AlertDialogHeader>
          <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-full bg-primary/10 text-primary sm:mx-0">
            {step === "age" ? <ShieldCheck className="h-5 w-5" aria-hidden /> : <Fingerprint className="h-5 w-5" aria-hidden />}
          </div>
          <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            {t("auth.onboard.step", { n: step === "age" ? 1 : 2 })}
          </p>
          <AlertDialogTitle>{step === "age" ? t("auth.onboard.title", { provider }) : t("auth.onboard.passkeyTitle")}</AlertDialogTitle>
          <AlertDialogDescription>
            {step === "age" ? t("auth.onboard.body", { email: pending.email }) : t("auth.onboard.passkeyBody")}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {step === "age" ? (
          <form onSubmit={submitAge} className="space-y-3.5">
            <div className="space-y-1.5">
              <Label htmlFor="onboard-dob" className="text-sm">{t("auth.pk.dob")}</Label>
              <input
                id="onboard-dob"
                type="date"
                required
                autoComplete="off"
                value={dob}
                max={new Date().toISOString().slice(0, 10)}
                min="1900-01-01"
                onChange={(e) => setDob(e.target.value)}
                className="h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground"
              />
            </div>
            {minor && (
              <div className="space-y-1.5 rounded-lg border border-border bg-muted/40 p-3">
                <Label htmlFor="onboard-parent" className="text-sm">{t("auth.pk.parentEmail")}</Label>
                <input
                  id="onboard-parent"
                  type="email"
                  required
                  autoComplete="off"
                  value={parentEmail}
                  onChange={(e) => setParentEmail(e.target.value)}
                  className="h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground"
                />
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  {t("auth.pk.parentNote")} <Link to="/info/parental-consent" target="_blank" className="underline">{t("auth.pk.parentHow")}</Link>
                </p>
              </div>
            )}
            <div className="flex items-start gap-2.5">
              <Checkbox id="onboard-consent" checked={consented} onCheckedChange={(v) => setConsented(v === true)} aria-required="true" className="mt-0.5" />
              <Label htmlFor="onboard-consent" className="text-xs font-normal leading-relaxed text-muted-foreground">
                {t("auth.signupConsent.before")}{" "}
                <Link to="/terms" className="font-medium text-foreground underline underline-offset-2">{t("auth.signupConsent.terms")}</Link>{" "}
                {t("auth.signupConsent.and")}{" "}
                <Link to="/privacy" className="font-medium text-foreground underline underline-offset-2">{t("auth.signupConsent.privacy")}</Link>{" "}
                {t("auth.signupConsent.after")}
              </Label>
            </div>
            <p className="text-xs leading-relaxed text-muted-foreground">{t("auth.age.privacy")}</p>
            <Button type="submit" className="h-11 w-full" disabled={busy || !dob || !consented}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : t("auth.onboard.next")}
            </Button>
            <Button type="button" variant="ghost" className="h-11 w-full" onClick={() => void cancel()} disabled={busy}>
              {t("auth.onboard.cancel")}
            </Button>
          </form>
        ) : (
          <div className="space-y-3.5">
            <Button type="button" className="h-11 w-full gap-2" onClick={() => void createPasskey()} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Fingerprint className="h-4 w-4" aria-hidden />}
              {t("auth.onboard.passkeyCta")}
            </Button>
            <p className="text-xs leading-relaxed text-muted-foreground">{t("auth.onboard.passkeyNote", { provider })}</p>
            <Button type="button" variant="ghost" className="h-11 w-full" onClick={() => void cancel()} disabled={busy}>
              {t("auth.onboard.cancel")}
            </Button>
          </div>
        )}
      </AlertDialogContent>
    </AlertDialog>
  );
}
