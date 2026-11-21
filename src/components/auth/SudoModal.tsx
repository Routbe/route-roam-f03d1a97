import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { Fingerprint, Loader2, ShieldCheck } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { getStepUpOptions } from "@/lib/auth/step-up.functions";
import { activateSudo, registerSudoOpener } from "@/lib/auth/sudo-client";
import { authClient } from "@/lib/auth-client";
import { useTranslation } from "@/lib/i18n";

/** Minimal passkey prompt for Sudo Mode; mounted once in __root, opened through requestSudo(). */
export function SudoModal() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [hasPasskey, setHasPasskey] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const options = useServerFn(getStepUpOptions);

  useEffect(() => {
    registerSudoOpener((resolve) => {
      resolver.current?.(false);
      resolver.current = resolve;
      setError(null);
      setBusy(false);
      setHasPasskey(null);
      setOpen(true);
      void options({ data: undefined })
        .then((r) => setHasPasskey(r.enrolled.passkey))
        .catch(() => setHasPasskey(true));
    });
    return () => registerSudoOpener(null);
  }, [options]);

  const close = useCallback((ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setOpen(false);
  }, []);

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      const r = await authClient.signIn.passkey();
      if (r?.error) throw new Error(t("sudo.passkeyFailed"));
      const s = await activateSudo();
      if (!s.active) throw new Error(t("sudo.notOpened"));
      close(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("ui.failed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && close(false)}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" aria-hidden /> {t("sudo.title")}
          </DialogTitle>
          <DialogDescription>{t("sudo.description")}</DialogDescription>
        </DialogHeader>
        {hasPasskey === false && (
          <p role="alert" className="rounded-md border border-border bg-muted p-2 text-sm">
            {t("sudo.noPasskey")}{" "}
            <Link
              to="/settings"
              className="underline underline-offset-2"
              onClick={() => close(false)}
            >
              {t("sudo.addPasskey")}
            </Link>
          </p>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => close(false)}>
            {t("ui.cancel")}
          </Button>
          <Button
            className="gap-1.5"
            disabled={busy || hasPasskey === false}
            onClick={() => void confirm()}
          >
            {busy ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Fingerprint className="h-4 w-4" aria-hidden />
            )}
            {t("sudo.usePasskey")}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
