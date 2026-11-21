import { useEffect, useRef, useState } from "react";
import { Link } from "@/lib/router-compat";
import { toast } from "sonner";
import { ArrowLeft, ArrowRight, Fingerprint, ChevronDown, KeyRound, LifeBuoy, Loader2, Lock, Mail, MailCheck, ShieldCheck } from "lucide-react";

import { AppLayout } from "@/components/layout/AppLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/hooks/useAuth";
import { useTranslation } from "react-i18next";
import { authClient } from "@/lib/auth-client";
import { POST_AUTH_PATH, AUTH_ERROR_CODES } from "@/lib/auth/post-auth";
import { beginAuthIntent } from "@/lib/tour-draft.functions";
import { Altcha } from "@/components/Altcha";
import { isAdminMode } from "@/lib/app-mode";
import { usePortalFrame } from "@/components/layout/PortalContext";
import { prefetchProof, withAltcha } from "@/lib/altcha-client";
import { runConditionalPasskey } from "@/lib/auth/conditional-passkey";
import { authTabFromKey, syncAuthTabUrl, type AuthTab } from "@/lib/auth/auth-tab-url";
import { AUTH_UNAVAILABLE_TEXT, type AuthReadiness } from "@/lib/auth-readiness";
import type { AuthProvidersInfo } from "@/lib/auth-providers.functions";
import { useI18n } from "@/lib/i18n";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";
import { SIGNUP_CONSENT_VERSION, canSubmitSignUp } from "@/lib/signup-consent";
import { isMinorDob, signupAgeProblem } from "@/lib/minor-safety";
import { redeemLoginCodeFn } from "@/lib/login-code.functions";
import { SecondFactorStep } from "@/components/auth/SecondFactorStep";
import { PublicProviderSignIn } from "@/components/auth/PublicProviderSignIn";
import { SocialOnboardingDialog } from "@/components/auth/SocialOnboardingDialog";

/** Deliberately permissive: catches typos, never rejects a valid address. */
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

type Mode = "signin" | "signup" | "recovery" | "reset";
/** Steps inside the sign-in card. */
type SignInStep = "choose" | "methods" | "link-sent" | "second";
/** OPAQUE password pages: their own cross-origin-isolated documents (full page load only). */
const SECURE_PASSWORD_PATH = "/secure/password";
type ApiResult = { data?: Record<string, unknown>; error?: { code?: string; message?: string } };

function errorMessage(error: unknown, fallback: string) {
  if (error && typeof error === "object" && "message" in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  return fallback;
}

async function postJson(path: string, body: unknown, proof: string): Promise<ApiResult> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json", "x-altcha": proof },
    body: JSON.stringify(body),
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (res.ok) return { data: json };
  return { error: { code: typeof json["code"] === "string" ? json["code"] : `http_${res.status}`, message: typeof json["message"] === "string" ? json["message"] : undefined } };
}

/** First-passkey enrollment must run signed out, so the ticket/token decides the account. */
async function enrollPasskey(context: string, name: string) {
  await authClient.signOut().catch(() => null);
  const res = await authClient.passkey.addPasskey({ context, name, createSession: true } as never);
  const error = (res as { error?: { message?: string; code?: string } } | undefined)?.error;
  if (error) throw Object.assign(new Error(error.message || "passkey_failed"), { code: error.code });
}

/**
 * ROUT sign-in card. First step: passkey (WebAuthn/FIDO2), one-time e-mail link
 * (with a 6-digit code for another device) or e-mail + password. Members with
 * 2FA on finish with a second step (passkey, authenticator app, SMS or recovery
 * code). Sign-up creates the account together with its first passkey.
 */
export default function AuthNeon({ initialMode = "signin", initialProviders = null, smartEntry: smartEntryProp = false }: { initialMode?: Mode; initialProviders?: AuthProvidersInfo | null; smartEntry?: boolean }) {
  const { t } = useTranslation();
  const { locale } = useI18n();
  const adminPortal = Boolean(usePortalFrame()) || isAdminMode();
  const { user } = useAuth();

  const [mode, setMode] = useState<Mode>(adminPortal && initialMode === "signup" ? "signin" : initialMode);
  const [email, setEmail] = useState("");
  const [emailError, setEmailError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<SignInStep>("choose");
  const [mailCode, setMailCode] = useState("");
  const [recoveryFiled, setRecoveryFiled] = useState(false);
  const [recoveryToken, setRecoveryToken] = useState<string | null>(null);
  const [consented, setConsented] = useState(false);
  // `?onboard=social`: a new Google/GitHub/GitLab member in pending_passkey_setup (set by the address read below).
  const [socialOnboard, setSocialOnboard] = useState(false);
  const [dob, setDob] = useState("");
  const [parentEmail, setParentEmail] = useState("");
  const minor = isMinorDob(dob);
  const redirected = useRef(false);
  const [readiness, setReadiness] = useState<AuthReadiness | null>(initialProviders?.readiness ?? null);
  const [configuredProviders, setConfiguredProviders] = useState<string[]>(initialProviders?.providers ?? []);
  const unavailable = readiness?.ready === false;
  // Password sign-in exists only once OPAQUE is live (db/0270), never in the admin portal's sign-up.
  const passwordAvailable = !unavailable && initialProviders?.password === true;
  // Identifier-first card (/login): one e-mail field, then every way in plus an inline sign-up fold-out.
  // There is deliberately no "does this address exist" lookup: that would let anyone test who is a member.
  const smart = smartEntryProp && !adminPortal;
  const [embedded, setEmbedded] = useState(false);
  useEffect(() => {
    try { setEmbedded(window.self !== window.top); } catch { setEmbedded(true); }
  }, []);

  useEffect(() => {
    if (initialProviders) return;
    fetch("/api/public/auth/providers", { credentials: "omit" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((body: { providers?: string[]; readiness?: AuthReadiness }) => {
        if (body.readiness) setReadiness(body.readiness);
        setConfiguredProviders(body.providers ?? []);
      })
      .catch(() => setReadiness(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once; server data never changes on this page
  }, []);

  useEffect(() => {
    if (!user || redirected.current || recoveryToken) return;
    redirected.current = true;
    window.location.replace(POST_AUTH_PATH);
  }, [user, recoveryToken]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const code = params.get("error");
    const redirect = params.get("redirect") ?? params.get("next");
    const token = params.get("token");
    // Old e-mailed reset links land on "reset", which now only explains the passkey/link route.
    if (initialMode !== "reset" && token && /^[0-9a-f]{64}$/.test(token)) {
      setRecoveryToken(token);
      setMode("recovery");
    }
    if (params.get("onboard") === "social" && !adminPortal) {
      setMode("signup");
      setSocialOnboard(true);
    }
    if (params.get("second_factor") === "1") {
      setMode("signin");
      setStep("second");
    }
    if (code && initialMode !== "reset") {
      const known = (AUTH_ERROR_CODES as readonly string[]).includes(code) ? code : "provider_rejected";
      if (known === "signup_disabled") setMode("signup");
      toast.error(known === "method_disabled" ? t("auth.pk.methodDisabled") : known === "link_expired" ? t("auth.mf.linkExpired") : known === "signup_disabled" ? t("auth.signupDisabled") : t("auth.pk.failed"));
    }
    if (redirect) void beginAuthIntent({ data: { next: redirect } }).catch(() => null);
    if (params.toString()) window.history.replaceState({}, "", window.location.pathname);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [t]);

  const onEmailChange = (value: string) => {
    setEmail(value);
    setEmailError(value && !EMAIL_REGEX.test(value.trim()) ? t("auth.ui.email.invalid") : null);
  };
  const emailAccepted = () => {
    if (EMAIL_REGEX.test(email.trim())) return true;
    const message = t("auth.ui.email.invalid");
    setEmailError(message);
    toast.error(message);
    return false;
  };
  /** Moves focus (and the view) to the first sign-up field that still needs input. */
  const focusField = (id: string) => {
    const el = typeof document === "undefined" ? null : document.getElementById(id);
    if (!el) return;
    el.focus({ preventScroll: true });
    el.scrollIntoView({ block: "center", behavior: "smooth" });
  };

  // Silent ALTCHA pre-fetch: the proof-of-work starts on the e-mail field's first focus,
  // so the token is ready before "Verder met e-mail" / the passkey button is pressed.
  const [altchaArmed, setAltchaArmed] = useState(false);
  const armAltcha = () => {
    if (unavailable) return;
    void prefetchProof().catch(() => null);
    if (!altchaArmed) setAltchaArmed(true);
  };

  /** Session cookie is set server-side: one full load to /auth/continue, which re-checks it and 303s. */
  // `/auth/sign-up?onboard=social`: a new Google/GitHub/GitLab member waits in
  // pending_passkey_setup; read after hydration so the server frame stays the same.

  const goToPostAuth = () => {
    redirected.current = true;
    window.location.replace(POST_AUTH_PATH);
  };

  const passkeyLogin = async () => {
    if (unavailable) { toast.error(AUTH_UNAVAILABLE_TEXT[locale]); return; }
    stopConditional();
    setLoading(true);
    try {
      const res = await authClient.signIn.passkey();
      if (res?.error) {
        toast.error(res.error.message || t("auth.passkey.failed"));
        return;
      }
      // Session cookie is set: go straight to the post-auth landing instead of waiting for a client refresh.
      redirected.current = true;
      window.location.replace(POST_AUTH_PATH);
      return;
    } catch (err) {
      toast.error(errorMessage(err, t("auth.passkey.failed")));
    } finally {
      setLoading(false);
      if (!redirected.current) restartConditional();
    }
  };

  // WebAuthn Conditional UI: on mount one navigator.credentials.get({ mediation: "conditional" }) runs
  // under an AbortController, so focusing the e-mail field (autocomplete="username webauthn") offers
  // saved passkeys in the OS sheet (Face ID / Touch ID / Android / Safari desktop), on both tabs.
  // It is aborted on unmount and before every explicit passkey ceremony (one WebAuthn request at a time).
  const entryTab = mode === "signin" || mode === "signup";
  const conditionalRef = useRef<AbortController | null>(null);
  const [conditionalRun, setConditionalRun] = useState(0);
  const stopConditional = () => {
    conditionalRef.current?.abort();
    conditionalRef.current = null;
  };
  const restartConditional = () => setConditionalRun((n) => n + 1);
  useEffect(() => {
    if (!readiness?.ready || !entryTab || step === "second") return;
    const controller = new AbortController();
    conditionalRef.current = controller;
    void runConditionalPasskey(controller.signal).then((outcome) => {
      if (outcome !== "signed-in" || controller.signal.aborted) return;
      redirected.current = true;
      window.location.replace(POST_AUTH_PATH);
    });
    return () => {
      controller.abort();
      if (conditionalRef.current === controller) conditionalRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readiness?.ready, entryTab, step === "second", conditionalRun]);

  const failMessage = (error: { code?: string; message?: string; status?: number } | undefined, fallback: string) => {
    if (!error) return fallback;
    if (error.status === 429 || error.code === "rate_limited") return t("auth.ui.code.tooMany");
    if (error.code === "INVALID_EMAIL_OR_PASSWORD") return t("auth.mf.wrongPassword");
    return error.message || fallback;
  };

  /** One-time e-mail link (+ 6-digit code for another device). */
  const sendLink = async () => {
    if (unavailable) { toast.error(AUTH_UNAVAILABLE_TEXT[locale]); return; }
    if (!emailAccepted()) return;
    setLoading(true);
    const address = email.trim().toLowerCase();
    try {
      const result = await withAltcha(address, (proof) =>
        authClient.signIn.magicLink({ email: address, callbackURL: POST_AUTH_PATH, errorCallbackURL: "/auth/sign-in?error=link_expired", fetchOptions: { headers: { "x-altcha": proof } } }),
      );
      const error = (result as { error?: { code?: string; message?: string; status?: number } } | undefined)?.error;
      if (error) {
        toast.error(failMessage(error, t("auth.mail.failed")));
        return;
      }
      setMailCode("");
      setStep("link-sent");
    } catch (err) {
      toast.error(errorMessage(err, t("auth.mail.failed")));
    } finally {
      setLoading(false);
    }
  };

  const redeemMailCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await redeemLoginCodeFn({ data: { email: email.trim().toLowerCase(), code: mailCode } });
      if (!res.ok) {
        toast.error(res.reason === "rate_limited" ? t("auth.ui.code.tooMany") : t("auth.ui.code.invalid"));
        return;
      }
      window.location.assign(res.link);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Same checks and signed ticket for both sign-up kinds; `withPassword` hands the
   * ticket to the secure password page in the URL fragment (never sent to a server).
   */
  const signUp = async (e: React.FormEvent | null, withPassword = false) => {
    e?.preventDefault();
    if (unavailable) { toast.error(AUTH_UNAVAILABLE_TEXT[locale]); return; }
    if (adminPortal) return;
    // Checked in the order the fields appear, so the first gap gets focus.
    if (!emailAccepted()) { focusField("auth-email"); return; }
    const ageProblem = signupAgeProblem({ dob, parentEmail, email });
    if (ageProblem) {
      focusField(ageProblem === "dob_invalid" ? "auth-signup-dob" : "auth-signup-parent");
      toast.error(ageProblem === "dob_invalid" ? t("auth.pk.dobInvalid") : t("auth.pk.parentInvalid"));
      return;
    }
    if (!consented) { focusField("auth-signup-consent"); toast.error(t("auth.signupConsent.required")); return; }
    stopConditional();
    setLoading(true);
    const address = email.trim().toLowerCase();
    try {
      const result = await withAltcha(address, (proof) =>
        postJson("/api/auth-passkey/signup", { email: address, name: name.trim(), dob, parentEmail: minor ? parentEmail.trim().toLowerCase() : "", consent: SIGNUP_CONSENT_VERSION }, proof),
      );
      if (result.error || typeof result.data?.["ticket"] !== "string") {
        toast.error(result.error?.message || t("auth.ui.toast.failed"));
        return;
      }
      if (withPassword) {
        window.location.assign(`${SECURE_PASSWORD_PATH}/new#${new URLSearchParams({ ticket: result.data["ticket"] as string, email: address }).toString()}`);
        return;
      }
      await enrollPasskey(result.data["ticket"] as string, "ROUT");
      toast.success(minor ? t("auth.pk.welcomeMinor") : t("auth.ui.toast.welcome"));
      goToPostAuth();
    } catch (err) {
      const code = (err as { code?: string }).code;
      toast.error(code === "account_exists" || /account_exists/.test(String((err as Error).message)) ? t("auth.pk.accountExists") : errorMessage(err, t("auth.pk.failed")));
    } finally {
      setLoading(false);
      if (!redirected.current) restartConditional();
    }
  };

  const fileRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailAccepted()) return;
    setLoading(true);
    const address = email.trim().toLowerCase();
    try {
      const result = await withAltcha(address, (proof) => postJson("/api/auth-passkey/recovery", { email: address, note: note.trim() }, proof));
      if (result.error) {
        toast.error(result.error.message || t("auth.ui.toast.failed"));
        return;
      }
      setRecoveryFiled(true);
    } catch (err) {
      toast.error(errorMessage(err, t("auth.ui.toast.failed")));
    } finally {
      setLoading(false);
    }
  };

  const bindRecoveryPasskey = async () => {
    if (!recoveryToken) return;
    setLoading(true);
    try {
      await enrollPasskey(`rq.${recoveryToken}`, "ROUT");
      setRecoveryToken(null);
      toast.success(t("auth.pk.recovered"));
      goToPostAuth();
    } catch (err) {
      toast.error(/recovery_token_invalid/.test(String((err as Error).message)) ? t("auth.pk.tokenInvalid") : errorMessage(err, t("auth.pk.failed")));
    } finally {
      setLoading(false);
    }
  };

  const emailField = (
    <div className="space-y-1">
      <Label htmlFor="auth-email" className="text-sm">{t("auth.ui.email.label")}</Label>
      <Input
        id="auth-email"
        type="email"
        value={email}
        onChange={(e) => onEmailChange(e.target.value)}
        placeholder={t("auth.email.placeholder")}
        autoComplete="username webauthn"
        onFocus={armAltcha}
        aria-invalid={emailError ? true : undefined}
        aria-describedby={emailError ? "auth-email-error" : undefined}
        className={`h-10 rounded-lg ${emailError ? "border-destructive focus-visible:ring-destructive/30" : ""}`}
        required
      />
      {emailError && <p id="auth-email-error" className="text-[11px] text-destructive">{emailError}</p>}
      {!unavailable && <Altcha className="mt-1" active={altchaArmed} />}
    </div>
  );

  // Inline accordion; the password itself is typed only on the secure document,
  // which needs a full page load because it is cross-origin isolated (COOP/COEP).
  const passwordFold = (
    <details className="group w-full rounded-lg border border-border">
    <summary className="flex min-h-11 cursor-pointer list-none items-center gap-1.5 px-3 text-xs text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
      <Lock className="h-3.5 w-3.5" aria-hidden /> {t("auth.mf.usePassword")}
      <ChevronDown className="ml-auto h-3.5 w-3.5 transition-transform group-open:rotate-180" aria-hidden />
    </summary>
    <div className="space-y-2 px-3 pb-3">
      <p className="text-[11px] leading-relaxed text-muted-foreground">{t("auth.mf.passwordAccordionBody")}</p>
      <Button asChild variant="outline" className="h-11 w-full gap-2 rounded-lg">
        <a href={`${SECURE_PASSWORD_PATH}${EMAIL_REGEX.test(email.trim()) ? `#${new URLSearchParams({ email: email.trim().toLowerCase() }).toString()}` : ""}`}>
          <Lock className="h-4 w-4" aria-hidden /> {t("auth.mf.passwordAccordionCta")}
        </a>
      </Button>
    </div>
                      </details>
  );

  /** Sign-up fields after the e-mail address; shared by the sign-up tab and the /login fold-out. */
  const signupFields = (
    <>
    <div className="space-y-1">
      <Label htmlFor="auth-signup-name" className="text-sm">{t("auth.pk.name")}</Label>
      <Input id="auth-signup-name" value={name} maxLength={80} autoComplete="name" onChange={(e) => setName(e.target.value)} className="h-10 rounded-lg" />
    </div>
    <div className="space-y-1.5">
      <Label htmlFor="auth-signup-dob" className="text-sm">{t("auth.pk.dob")}</Label>
      <input
        id="auth-signup-dob"
        type="date"
        required
        value={dob}
        max={new Date().toISOString().slice(0, 10)}
        min="1900-01-01"
        onChange={(e) => setDob(e.target.value)}
        className="h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground"
      />
      <p className="text-[11px] leading-relaxed text-muted-foreground">{t("auth.age.privacy")}</p>
    </div>
    {minor && (
      <div className="space-y-1.5 rounded-lg border border-border bg-muted/40 p-3">
        <Label htmlFor="auth-signup-parent" className="text-sm">{t("auth.pk.parentEmail")}</Label>
        <input
          id="auth-signup-parent"
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
    <div className="flex items-start gap-2.5 rounded-lg border border-border p-3">
      <Checkbox id="auth-signup-consent" checked={consented} onCheckedChange={(v) => setConsented(v === true)} required aria-required="true" className="mt-0.5" />
      <label htmlFor="auth-signup-consent" className="text-xs leading-relaxed text-muted-foreground">
        {t("auth.signupConsent.before")}{" "}
        <Link to="/terms" className="font-medium text-foreground underline underline-offset-2">{t("auth.signupConsent.terms")}</Link>{" "}
        {t("auth.signupConsent.and")}{" "}
        <Link to="/privacy" className="font-medium text-foreground underline underline-offset-2">{t("auth.signupConsent.privacy")}</Link>{" "}
        {t("auth.signupConsent.after")}
      </label>
    </div>
    <p className="text-[11px] leading-relaxed text-muted-foreground">{t("auth.pk.signupNote")}</p>
    </>
  );
  /** Passkey submit of the /login fold-out; the sign-up tab uses its hero button instead. */
  const signupSubmit = (
    <Button type="submit" className="h-11 w-full gap-2 rounded-lg font-medium" disabled={!canSubmitSignUp({ consented, busy: loading, unavailable, emailError: !!emailError })}>
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-4 w-4" />} {t("auth.pk.signupCta")}
    </Button>
  );
  const signupPasswordOption = (
    <>
    {passwordAvailable && (
      <Button type="button" variant="ghost" className="h-auto min-h-11 w-full gap-2 whitespace-normal text-sm" disabled={!canSubmitSignUp({ consented, busy: loading, unavailable, emailError: !!emailError })} onClick={() => void signUp(null, true)}>
        <Lock className="h-4 w-4 shrink-0" aria-hidden /> {t("auth.pw.signupWithPassword")}
      </Button>
    )}
    </>
  );

  /** Tab switch: state only (the card never remounts) plus /login <-> /register via history.replaceState. */
  const switchTab = (tab: AuthTab) => {
    if (tab !== mode) {
      setMode(tab);
      if (syncAuthTabUrl(tab)) document.title = t(tab === "signup" ? "auth.card.registerTitle" : "auth.meta.signin");
    }
    setStep("choose");
  };
  const onTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (mode !== "signin" && mode !== "signup") return;
    const next = authTabFromKey(e.key, mode);
    if (!next) return;
    e.preventDefault();
    switchTab(next);
    document.getElementById(`auth-tab-${next}`)?.focus();
  };

  const linkButton = (target: Mode, label: string, Icon: typeof KeyRound) => (
    <button
      type="button"
      onClick={() => { setMode(target); setStep("choose"); }}
      className="inline-flex items-center gap-1.5 text-xs text-muted-foreground underline underline-offset-4 hover:text-foreground"
    >
      <Icon className="h-3.5 w-3.5" aria-hidden /> {label}
    </button>
  );

  const linkButtonStep = (target: SignInStep, label: string, Icon: typeof KeyRound) => (
    <button
      type="button"
      onClick={() => setStep(target)}
      className="inline-flex items-center gap-1.5 text-xs text-muted-foreground underline underline-offset-4 hover:text-foreground"
    >
      <Icon className="h-3.5 w-3.5" aria-hidden /> {label}
    </button>
  );

  return (
    <AppLayout>
      {socialOnboard && (
        <SocialOnboardingDialog
          onEnroll={async (ticket) => {
            await enrollPasskey(ticket, "ROUT");
            toast.success(t("auth.ui.toast.welcome"));
            goToPostAuth();
          }}
        />
      )}
      <div className="flex min-h-[calc(100vh-4rem)] w-full flex-col items-center justify-center bg-background p-4 text-foreground">
        {!adminPortal && (
          <div className="w-full max-w-md">
            <Link to="/" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
              <ArrowLeft className="h-4 w-4" /> {t("auth.ui.back")}
            </Link>
          </div>
        )}

        <div className="w-full max-w-md rounded-2xl border border-border bg-card p-5 sm:p-7" data-testid="auth-card">
          {!adminPortal && !smart && (mode === "signin" || mode === "signup") && step !== "second" && (
            <div className="mb-4 grid grid-cols-2 gap-1 rounded-xl border border-border bg-muted/40 p-1" role="tablist" aria-label={t("auth.card.modeLabel")} data-testid="auth-mode-tabs">
              {(["signin", "signup"] as const).map((tab) => {
                const selected = mode === tab;
                return (
                  <button
                    key={tab}
                    type="button"
                    role="tab"
                    id={`auth-tab-${tab}`}
                    aria-selected={selected}
                    aria-controls={selected ? `auth-panel-${tab}` : undefined}
                    tabIndex={selected ? 0 : -1}
                    onClick={() => switchTab(tab)}
                    onKeyDown={onTabKeyDown}
                    className={`h-11 rounded-lg text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${selected ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}
                  >
                    {tab === "signin" ? t("auth.card.tabSignin") : t("auth.ui.signup.cta")}
                  </button>
                );
              })}
            </div>
          )}
          <div className="mb-4">
            <h1 className="mb-1 font-display text-2xl text-foreground">
              {adminPortal ? t("auth.admin") : mode === "signup" ? t("auth.ui.signup.cta") : mode === "recovery" ? t("auth.pk.recoveryTitle") : mode === "reset" ? t("auth.mf.resetTitle") : t("auth.card.welcomeBack")}
            </h1>
            {mode !== "reset" && step !== "second" && (
              <p className="text-sm text-muted-foreground">{mode === "recovery" ? t("auth.pk.recoverySubtitle") : mode === "signup" ? t("auth.pk.signupSubtitle") : smart ? t("auth.smart.subtitle") : t("auth.pk.subtitle")}</p>
            )}
          </div>

          {embedded && (
            <Alert className="mb-4"><AlertDescription className="flex flex-col gap-2">
              <span>Inloggen en registreren met een passkey werkt niet in dit ingebedde venster. Open de pagina in een nieuw tabblad.</span>
              <a href={typeof window !== "undefined" ? window.location.href : "/auth/sign-in"} target="_blank" rel="noopener noreferrer" className="font-medium underline">Open in nieuw tabblad</a>
            </AlertDescription></Alert>
          )}
          {unavailable && <Alert variant="destructive" className="mb-4"><AlertDescription>{AUTH_UNAVAILABLE_TEXT[locale]}</AlertDescription></Alert>}

          {mode === "signin" && step === "second" && (
            <SecondFactorStep
              allowTrust={!adminPortal}
              onDone={goToPostAuth}
              onRestart={() => setStep("choose")}
            />
          )}

          {mode === "signin" && step !== "second" && (
            <div className="space-y-3">
              {smart && step === "choose" && (
                <div className="space-y-4" data-testid="auth-smart-entry">
                  <PublicProviderSignIn configured={configuredProviders} readiness={readiness} disabled={loading} />
                  <div className="flex items-center gap-3 text-[11px] uppercase tracking-wide text-muted-foreground" aria-hidden>
                    <span className="h-px flex-1 bg-border" /> {t("auth.mf.orEmail")} <span className="h-px flex-1 bg-border" />
                  </div>
                  <form onSubmit={(e) => { e.preventDefault(); if (emailAccepted()) setStep("methods"); }} className="space-y-3">
                    {emailField}
                    <Button type="submit" disabled={loading || unavailable || !!emailError} className="cta-glow h-11 w-full gap-2 rounded-lg">
                      {t("auth.smart.continue")} <ArrowRight className="h-4 w-4" aria-hidden />
                    </Button>
                  </form>
                  <p className="text-center text-[11px] text-muted-foreground">{t("auth.smart.autofillHint")}</p>
                  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
                    <button type="button" onClick={() => void passkeyLogin()} disabled={loading || unavailable} className="tap-wide inline-flex items-center gap-1.5 text-xs text-muted-foreground underline underline-offset-4 hover:text-foreground">
                      <Fingerprint className="h-3.5 w-3.5" aria-hidden /> {t("auth.passkey")}
                    </button>
                    {linkButton("recovery", t("auth.mf.recoveryLink"), LifeBuoy)}
                  </div>
                </div>
              )}

              {smart && step === "methods" && (
                <div className="space-y-3" data-testid="auth-smart-methods">
                  <div className="flex items-center justify-between gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2">
                    <span className="min-w-0 truncate text-sm text-foreground">{email.trim().toLowerCase()}</span>
                    <button type="button" onClick={() => setStep("choose")} className="tap-wide shrink-0 text-xs text-muted-foreground underline underline-offset-4 hover:text-foreground">{t("auth.smart.change")}</button>
                  </div>
                  <p className="text-sm text-muted-foreground">{t("auth.smart.methods")}</p>
                  <Button type="button" onClick={() => void passkeyLogin()} disabled={loading || unavailable} className="cta-glow h-auto min-h-12 w-full gap-2 whitespace-normal px-4 py-3 text-sm">
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-4 w-4 shrink-0" />} {t("auth.passkey")}
                  </Button>
                  <Button type="button" variant="outline" onClick={() => void sendLink()} disabled={loading || unavailable} className="h-11 w-full gap-2 rounded-lg">
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Mail className="h-4 w-4" />} {t("auth.mf.sendLink")}
                  </Button>
                  {passwordAvailable && passwordFold}
                  <details className="group rounded-lg border border-border" onToggle={(e) => { if ((e.currentTarget as HTMLDetailsElement).open) setMode("signin"); }}>
                    <summary className="flex min-h-11 cursor-pointer list-none items-center gap-1.5 px-3 text-sm font-medium text-foreground [&::-webkit-details-marker]:hidden">
                      <KeyRound className="h-4 w-4" aria-hidden /> {t("auth.smart.newTitle")}
                      <ChevronDown className="ml-auto h-4 w-4 transition-transform group-open:rotate-180" aria-hidden />
                    </summary>
                    <form onSubmit={signUp} className="space-y-3.5 px-3 pb-3">
                      <p className="text-[11px] leading-relaxed text-muted-foreground">{t("auth.smart.newBody")}</p>
                      {signupFields}
                      {signupSubmit}
                      {signupPasswordOption}
                    </form>
                  </details>
                </div>
              )}

              {!smart && step === "choose" && (
                <div className="space-y-4" data-testid="auth-signin-choose" {...(!adminPortal ? { id: "auth-panel-signin", role: "tabpanel", "aria-labelledby": "auth-tab-signin" } : {})}>
                  <Button type="button" onClick={() => void passkeyLogin()} disabled={loading || unavailable} data-testid="auth-passkey-hero" className="cta-glow h-auto min-h-12 w-full gap-2 whitespace-normal px-4 py-3 text-center text-sm leading-tight sm:text-base">
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-5 w-5 shrink-0" />} <span className="min-w-0">{adminPortal ? t("auth.passkey") : t("auth.card.passkeyHero")}</span>
                  </Button>
                  <p className="text-center text-[11px] text-muted-foreground">{t("auth.passkey.hint")}</p>
                  {!adminPortal && <>
                    <div className="flex items-center gap-3 text-[11px] uppercase tracking-wide text-muted-foreground" aria-hidden>
                      <span className="h-px flex-1 bg-border" /> {t("auth.card.orAccount")} <span className="h-px flex-1 bg-border" />
                    </div>
                    <PublicProviderSignIn compact configured={configuredProviders} readiness={readiness} disabled={loading} />
                  </>}
                  <form onSubmit={(e) => { e.preventDefault(); void sendLink(); }} className="space-y-3">
                    {emailField}
                    <Button type="submit" variant="outline" disabled={loading || unavailable || !!emailError} className="h-11 w-full gap-2 rounded-lg">
                      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Mail className="h-4 w-4" />} {adminPortal ? t("auth.mf.sendLink") : t("auth.card.continueEmail")}
                    </Button>
                  </form>
                  {passwordAvailable && passwordFold}
                  {adminPortal && <p className="text-[11px] text-muted-foreground">{t("auth.mf.adminNote")}</p>}
                  <div className="flex justify-center border-t border-border pt-3" data-testid="auth-card-footer">
                    {linkButton("recovery", adminPortal ? t("auth.mf.recoveryLink") : t("auth.card.lostEmail"), LifeBuoy)}
                  </div>
                </div>
              )}

              {step === "link-sent" && (
                <div className="space-y-3" data-testid="auth-link-sent">
                  <div className="space-y-2 rounded-2xl border border-border bg-card/60 p-4 text-center">
                    <span className="mx-auto flex h-10 w-10 items-center justify-center rounded-full border border-border bg-muted/60"><MailCheck className="h-5 w-5" aria-hidden /></span>
                    <p className="font-medium text-foreground">{t("auth.mf.linkSentTitle")}</p>
                    <p className="text-sm text-muted-foreground">{t("auth.mf.linkSentBody", { email: email.trim().toLowerCase() })}</p>
                  </div>
                  <form onSubmit={redeemMailCode} className="space-y-2">
                    <Label htmlFor="auth-mail-code" className="text-sm">{t("auth.mf.codeFromMail")}</Label>
                    <input
                      id="auth-mail-code"
                      value={mailCode}
                      onChange={(e) => setMailCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      className="h-11 w-full rounded-xl border border-input bg-background text-center font-mono tracking-[0.4em] text-foreground"
                    />
                    <Button type="submit" disabled={loading || mailCode.length !== 6} className="h-11 w-full rounded-xl">
                      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : t("auth.mf.useCode")}
                    </Button>
                  </form>
                  {linkButtonStep("choose", t("auth.mf.otherAddress"), ArrowLeft)}
                </div>
              )}

            </div>
          )}

          {mode === "reset" && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">{t("auth.pw.resetGone")}</p>
              <Button type="button" variant="outline" className="h-11 w-full" onClick={() => { setMode("signin"); setStep("choose"); }}>{t("auth.mf.backToSignIn")}</Button>
            </div>
          )}

          {mode === "signup" && !adminPortal && (
            <form onSubmit={signUp} noValidate className="mx-auto max-w-md space-y-3.5" id="auth-panel-signup" role="tabpanel" aria-labelledby="auth-tab-signup" data-testid="auth-signup-panel">
              {/* Hero: the form's only passkey submit. Missing fields get focus first; then the ticket and navigator.credentials.create run. */}
              <Button type="submit" disabled={loading || unavailable} data-testid="auth-passkey-hero" className="cta-glow h-auto min-h-12 w-full gap-2 whitespace-normal px-4 py-3 text-center text-sm leading-tight sm:text-base">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-5 w-5 shrink-0" />} <span className="min-w-0">{t("auth.card.passkeyHeroSignup")}</span>
              </Button>
              <p className="text-center text-[11px] leading-relaxed text-muted-foreground">{t("auth.card.signupHeroHint")}</p>
              <div className="flex items-center gap-3 text-[11px] uppercase tracking-wide text-muted-foreground" aria-hidden>
                <span className="h-px flex-1 bg-border" /> {t("auth.card.orAccount")} <span className="h-px flex-1 bg-border" />
              </div>
              <div className="space-y-2" data-testid="auth-signup-providers">
                <PublicProviderSignIn
                  configured={configuredProviders}
                  readiness={readiness}
                  disabled={loading}
                  errorPath="/auth/sign-up"
                  compact
                />
                <p className="text-center text-[11px] leading-relaxed text-muted-foreground">{t("auth.provider.signupHint")}</p>
              </div>
              <div className="flex items-center gap-3 text-[11px] uppercase tracking-wide text-muted-foreground" aria-hidden>
                <span className="h-px flex-1 bg-border" /> {t("auth.mf.orEmail")} <span className="h-px flex-1 bg-border" />
              </div>
              {emailField}
              {signupFields}
              {signupPasswordOption}
              <div className="flex justify-center border-t border-border pt-3" data-testid="auth-card-footer">
                {linkButton("recovery", t("auth.card.lostEmail"), LifeBuoy)}
              </div>
            </form>
          )}

          {mode === "recovery" && (
            recoveryToken ? (
              <div className="space-y-3">
                <p className="flex items-start gap-2 text-sm text-muted-foreground"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden /> {t("auth.pk.bindIntro")}</p>
                <Button type="button" onClick={() => void bindRecoveryPasskey()} disabled={loading || unavailable} className="h-11 w-full gap-2 rounded-lg">
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-4 w-4" />} {t("auth.pk.bindCta")}
                </Button>
              </div>
            ) : recoveryFiled ? (
              <div data-testid="auth-recovery-filed" className="space-y-3 rounded-2xl border border-border bg-card/60 p-4 text-center">
                <span className="mx-auto flex h-10 w-10 items-center justify-center rounded-full border border-border bg-muted/60"><MailCheck className="h-5 w-5" aria-hidden /></span>
                <p className="text-sm text-muted-foreground">{t("auth.pk.recoveryFiled")}</p>
                {linkButton("signin", t("auth.pk.haveAccount"), Fingerprint)}
              </div>
            ) : (
              <form onSubmit={fileRecovery} className="space-y-3.5">
                <Link to="/recovery" className="flex items-start gap-2 rounded-xl border border-border bg-card/60 p-3 text-sm hover:bg-muted/60">
                  <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden />
                  <span><span className="font-medium">Herstelkluis ingesteld?</span> <span className="text-muted-foreground">Log meteen in met 2 van je 3 stukken.</span></span>
                </Link>
                {emailField}
                <div className="space-y-1">
                  <Label htmlFor="auth-recovery-note" className="text-sm">{t("auth.pk.recoveryNote")}</Label>
                  <Textarea id="auth-recovery-note" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} rows={3} />
                </div>
                <Button type="submit" className="h-11 w-full rounded-lg" disabled={loading || unavailable || !!emailError}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : t("auth.pk.recoveryCta")}
                </Button>
                {linkButton("signin", t("auth.pk.haveAccount"), Fingerprint)}
              </form>
            )
          )}
        </div>
      </div>
    </AppLayout>
  );
}
