import { Link } from "@tanstack/react-router";
import { useI18n } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const K = "pages.supportfund.";

/** Tabs between the donation page, the partner wall and the existing help centre. */
export function SupportNav({ active }: { active: "donations" | "partners" }) {
  const { t } = useI18n();
  const item = (on: boolean) =>
    cn(
      "inline-flex min-h-11 items-center rounded-full px-4 text-sm transition-colors",
      on ? "bg-foreground text-background" : "text-muted-foreground hover:bg-muted hover:text-foreground",
    );
  return (
    <nav aria-label={t(K + "title")} className="flex flex-wrap gap-1">
      <Link to="/support/donations" className={item(active === "donations")} aria-current={active === "donations" ? "page" : undefined}>
        {t(K + "nav.donations")}
      </Link>
      <Link to="/support/partners" className={item(active === "partners")} aria-current={active === "partners" ? "page" : undefined}>
        {t(K + "nav.partners")}
      </Link>
      <Link to="/support" className={item(false)}>
        {t(K + "nav.help")}
      </Link>
    </nav>
  );
}
