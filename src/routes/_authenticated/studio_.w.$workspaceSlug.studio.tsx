import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useTranslation } from "react-i18next";
import { ExternalLink } from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { ProfileEditor } from "@/components/dashboard/ProfileEditor";
import { Button } from "@/components/ui/button";
import { activateScopeFromUrl, getWorkspaceContext } from "@/lib/workspaces.functions";
import { canManageTeam } from "@/lib/workspace-rules";
import { ScopeActivationState, isForbidden } from "@/components/workspace/ScopeActivationState";
import { WorkspaceAskInbox } from "@/components/workspace/WorkspaceAskInbox";
import { WorkspaceSupportCard } from "@/components/workspace/WorkspaceSupportCard";
import { StudioPagePicker, StudioSwitchLine } from "@/components/studio/StudioPagePicker";
import { WORKSPACE_STUDIO_PAGES, workspacePagePath, type WorkspaceStudioPage } from "@/lib/workspace-studio-pages";

export const Route = createFileRoute("/_authenticated/studio_/w/$workspaceSlug/studio")({
  head: () => ({
    meta: [
      { title: "Workspace Studio | ROUT" },
      { name: "description", content: "De volledige ROUT Studio voor deze workspace: inhoud, vormgeving, componenten en audio." },
      { name: "robots", content: "noindex, nofollow" },
      { property: "og:title", content: "Workspace Studio | ROUT" },
      { property: "og:description", content: "De volledige ROUT Studio voor deze workspace." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: WorkspaceStudioPage,
});

/**
 * Full Studio parity for workspaces: the same StudioCanvas (ProfileEditor)
 * as the personal Studio — same tabs, design options, blocks and the
 * universal audio block — bound to the workspace instead of the member.
 * The breadcrumb page picker switches to the workspace's other public pages
 * (/ask, /feedback, /support); the editor stays mounted so unsaved drafts survive.
 */
function WorkspaceStudioPage() {
  const { workspaceSlug } = Route.useParams();
  const { t } = useTranslation();
  const activate = useServerFn(activateScopeFromUrl);
  const ctxFn = useServerFn(getWorkspaceContext);
  const qc = useQueryClient();
  const [scope, setScope] = useState<"loading" | "ready" | "denied" | "error">("loading");
  const [attempt, setAttempt] = useState(0);
  const [page, setPage] = useState<WorkspaceStudioPage>("profile");
  const [switchToken, setSwitchToken] = useState(0);

  useEffect(() => {
    let alive = true;
    void activate({ data: { workspaceSlug } })
      .then(() => {
        if (!alive) return;
        qc.removeQueries({ queryKey: ["workspace-context"] });
        setScope("ready");
      })
      .catch((e) => alive && setScope(isForbidden(e) ? "denied" : "error"));
    return () => {
      alive = false;
    };
  }, [activate, qc, workspaceSlug, attempt]);

  const ctx = useQuery({ queryKey: ["workspace-context"], queryFn: () => ctxFn(), enabled: scope === "ready", retry: false });
  const summary = ctx.data?.available ? ctx.data.workspaces.find((w) => w.slug === workspaceSlug) ?? null : null;
  const manage = Boolean(summary && canManageTeam(summary.role));

  const crumbs = [{ label: "Studio", to: "/studio" }, { label: workspaceSlug }];
  if (scope === "denied" || scope === "error") {
    return (
      <AppLayout title="Workspace Studio" crumbs={crumbs}>
        <ScopeActivationState kind={scope} onRetry={() => { setScope("loading"); setAttempt((a) => a + 1); }} />
      </AppLayout>
    );
  }
  if (scope === "loading") {
    return (
      <AppLayout title="Workspace Studio" crumbs={crumbs}>
        <p className="text-sm text-muted-foreground">{t("studio.common.loading")}</p>
      </AppLayout>
    );
  }
  const publicPath = `/w/${encodeURIComponent(workspaceSlug)}${workspacePagePath(page) === "/" ? "" : workspacePagePath(page)}`;
  return (
    <AppLayout
      title="Workspace Studio"
      crumbs={crumbs}
      breadcrumbActions={
        <StudioPagePicker
          options={WORKSPACE_STUDIO_PAGES.map((p) => ({ value: p, path: workspacePagePath(p), label: t(`studio.pagePicker.workspace.${p}`) }))}
          value={page}
          onChange={(next) => { setPage(next); setSwitchToken((n) => n + 1); }}
        />
      }
    >
      <StudioSwitchLine token={switchToken} />
      <div hidden={page !== "profile"}>
        <ProfileEditor key={`workspace:${workspaceSlug}`} variant="workspace" workspaceSlug={workspaceSlug} />
      </div>
      {page !== "profile" ? (
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="min-w-0 space-y-4">
            {summary && manage && page === "ask" ? <WorkspaceAskInbox workspaceId={summary.id} slug={workspaceSlug} /> : null}
            {summary && manage && page === "support" ? <WorkspaceSupportCard workspaceId={summary.id} slug={workspaceSlug} /> : null}
            {!manage && page !== "feedback" ? (
              <p className="text-sm text-muted-foreground">{t("studio.pagePicker.managersOnly")}</p>
            ) : null}
            <p className="text-sm text-muted-foreground">{t("studio.pagePicker.livePreview")}</p>
            <Button asChild variant="outline" className="min-h-11">
              <a href={publicPath} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="size-4" aria-hidden />
                {t("studio.pagePicker.openPage", { page: `rout.be${publicPath}` })}
              </a>
            </Button>
          </div>
          <iframe
            key={publicPath}
            title={t("studio.pagePicker.previewTitle", { page: workspacePagePath(page) })}
            src={publicPath}
            className="h-[720px] w-full rounded-xl border border-border bg-background"
          />
        </div>
      ) : null}
    </AppLayout>
  );
}
