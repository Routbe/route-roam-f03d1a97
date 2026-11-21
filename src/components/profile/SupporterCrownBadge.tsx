import { Crown } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useI18n } from "@/lib/i18n";

/**
 * Discreet ROUT Supporter / Pro mark. Strictly separate from identity: it says the member
 * supports ROUT, never who they are. The blue identity mark comes only from Didit.
 * Opens a small card on click, like the blue mark.
 */
export function SupporterCrownBadge({ color, className = "size-4", cardBg, cardBorder, textColor, mutedColor }: {
  color?: string; className?: string; cardBg?: string; cardBorder?: string; textColor?: string; mutedColor?: string;
}) {
  const { t } = useI18n();
  const label = t("profile.supporter.label");
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={label}
          title={label}
          aria-haspopup="dialog"
          className="tap-badge inline-flex shrink-0 items-center justify-center rounded-full opacity-80 transition-[opacity,transform] duration-150 hover:opacity-60 active:scale-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-current focus-visible:ring-offset-2 motion-reduce:transition-none"
          style={color ? { color } : undefined}
        >
          <Crown className={className} strokeWidth={1.75} aria-hidden />
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="center"
        aria-label={label}
        className="w-72 max-w-[calc(100vw-1.5rem)] rounded-xl border p-4 text-left"
        style={cardBg ? { background: cardBg, borderColor: cardBorder, color: textColor } : undefined}
      >
        <div className="flex items-start gap-2">
          <Crown className="mt-0.5 h-6 w-6 shrink-0" strokeWidth={1.75} style={color ? { color } : undefined} aria-hidden />
          <div className="space-y-1">
            <p className="text-sm font-semibold leading-tight">{label}</p>
            <p className="text-xs leading-relaxed" style={mutedColor ? { color: mutedColor } : undefined}>{t("profile.supporter.body")}</p>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
