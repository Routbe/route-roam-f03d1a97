import { ShieldCheck } from "lucide-react";
import { useI18n } from "@/lib/i18n";
import type { HiddenKind } from "@/lib/sign/pdf-sanitizer";

/** What the sanitizer removed, shown before anyone signs. */
export function SanitizeReport({ neutralized, removedText }: { neutralized: string[]; removedText: Record<HiddenKind, number> }) {
  const { t } = useI18n();
  const hidden = removedText.invisible + removedText.white + removedText.tiny;
  return (
    <div className="flex items-start gap-3 rounded-2xl border border-border bg-muted/40 p-4 text-sm">
      <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-primary" aria-hidden />
      <div className="space-y-1">
        <p className="font-medium">{t("sign.report.title")}</p>
        {neutralized.length === 0 && hidden === 0 ? (
          <p className="text-muted-foreground">{t("sign.report.clean")}</p>
        ) : (
          <ul className="list-disc space-y-0.5 pl-4 text-muted-foreground">
            {neutralized.length > 0 && <li>{t("sign.report.active", { n: neutralized.length, names: [...new Set(neutralized)].join(", ") })}</li>}
            {removedText.invisible > 0 && <li>{t("sign.report.invisible", { n: removedText.invisible })}</li>}
            {removedText.white > 0 && <li>{t("sign.report.white", { n: removedText.white })}</li>}
            {removedText.tiny > 0 && <li>{t("sign.report.tiny", { n: removedText.tiny })}</li>}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">{t("sign.report.note")}</p>
      </div>
    </div>
  );
}
