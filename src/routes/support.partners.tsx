import { createFileRoute } from "@tanstack/react-router";
import { getRequestLocale } from "@/lib/locale.functions";
import { supportMeta } from "@/lib/support/meta";
import { SupportPartnersPage } from "@/components/support/SupportPartnersPage";

export const Route = createFileRoute("/support/partners")({
  loader: () => getRequestLocale().catch(() => ({ locale: "en" as const })),
  head: ({ loaderData }) => ({ meta: supportMeta("partners", loaderData?.locale) }),
  component: SupportPartnersPage,
});
