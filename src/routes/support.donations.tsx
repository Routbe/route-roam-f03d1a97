import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { getRequestLocale } from "@/lib/locale.functions";
import { getSupportOverview } from "@/lib/support/support.functions";
import { supportMeta } from "@/lib/support/meta";
import { SupportDonationsPage } from "@/components/support/SupportDonationsPage";

const search = z.object({
  d: z.string().uuid().optional().catch(undefined),
  status: z.enum(["success", "cancel"]).optional().catch(undefined),
});

export const Route = createFileRoute("/support/donations")({
  validateSearch: search,
  loader: async () => {
    const [locale, overview] = await Promise.all([
      getRequestLocale().catch(() => ({ locale: "en" as const })),
      getSupportOverview(),
    ]);
    return { locale: locale.locale, overview };
  },
  head: ({ loaderData }) => ({ meta: supportMeta("donations", loaderData?.locale) }),
  component: DonationsRoute,
});

function DonationsRoute() {
  const { overview } = Route.useLoaderData();
  const { d, status } = Route.useSearch();
  return <SupportDonationsPage initial={overview} donationId={d ?? null} cancelled={status === "cancel"} />;
}
