import { useTranslation } from "react-i18next";
import { Check, ChevronDown } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export type StudioPageOption<T extends string> = { value: T; path: string; label: string };

/**
 * Page picker next to the last Studio breadcrumb: chooses which public page of the current
 * profile (/, /tip, /ask, …) Studio edits. Switching confirms with a short toast; the caller
 * renders the progress line (StudioSwitchLine) so the change is visible on the canvas too.
 */
export function StudioPagePicker<T extends string>({
  options,
  value,
  onChange,
}: {
  options: StudioPageOption<T>[];
  value: T;
  onChange: (next: T) => void;
}) {
  const { t } = useTranslation();
  const current = options.find((o) => o.value === value) ?? options[0];
  if (!current) return null;
  return (
    <span className="flex min-w-0 items-center gap-1">
      <span aria-hidden className="text-muted-foreground">·</span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            aria-label={t("studio.pagePicker.label")}
            className="min-h-11 min-w-11 gap-1 px-2 font-mono text-xs text-foreground"
          >
            {current.path}
            <ChevronDown className="size-3.5" aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-64 max-w-[calc(100vw-24px)]">
          {options.map((o) => (
            <DropdownMenuItem
              key={o.value}
              className="min-h-11"
              onSelect={() => {
                if (o.value === value) return;
                onChange(o.value);
                toast(t("studio.pagePicker.selected", { page: o.path }));
              }}
            >
              <span className="w-14 shrink-0 font-mono text-xs text-muted-foreground">{o.path}</span>
              <span className="flex-1">{o.label}</span>
              {o.value === value ? <Check className="size-4" aria-hidden /> : null}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </span>
  );
}

/** Thin line that sweeps across the canvas once each time the edited page changes. */
export function StudioSwitchLine({ token }: { token: number }) {
  if (token === 0) return null;
  return <div key={token} aria-hidden className="studio-switch-line" />;
}
