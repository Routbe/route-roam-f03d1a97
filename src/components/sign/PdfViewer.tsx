import { useEffect, useRef, useState } from "react";
import { useI18n } from "@/lib/i18n";

/**
 * Read-only PDF viewer for ROUT Sign: pages are drawn to canvases only (no text, link or form
 * layer, scripting off), so nothing in the document can act. Reports the page count and when the
 * last page has been scrolled into view. pdf.js is loaded only in the browser.
 */
export function PdfViewer({ pdf, onPages, onReachedEnd }: { pdf: Uint8Array; onPages: (n: number) => void; onReachedEnd: () => void }) {
  const { t } = useI18n();
  const host = useRef<HTMLDivElement>(null);
  const end = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    let cancelled = false;
    let destroy: (() => void) | null = null;
    (async () => {
      try {
        const pdfjs = await import("pdfjs-dist");
        const worker = await import("pdfjs-dist/build/pdf.worker.min.mjs?url");
        pdfjs.GlobalWorkerOptions.workerSrc = worker.default;
        const task = pdfjs.getDocument({ data: pdf.slice(), isEvalSupported: false, enableXfa: false, disableAutoFetch: true });
        const doc = await task.promise;
        destroy = () => void doc.destroy();
        if (cancelled || !host.current) return;
        host.current.replaceChildren();
        const width = Math.min(host.current.clientWidth || 800, 900);
        for (let p = 1; p <= doc.numPages; p++) {
          const page = await doc.getPage(p);
          if (cancelled) return;
          const base = page.getViewport({ scale: 1 });
          const scale = (width / base.width) * (window.devicePixelRatio || 1);
          const vp = page.getViewport({ scale });
          const canvas = document.createElement("canvas");
          canvas.width = Math.floor(vp.width);
          canvas.height = Math.floor(vp.height);
          canvas.style.width = "100%";
          canvas.className = "rounded-md border border-border bg-card shadow-sm";
          canvas.setAttribute("aria-label", t("sign.viewer.page", { n: p, total: doc.numPages }));
          host.current.appendChild(canvas);
          await page.render({ canvasContext: canvas.getContext("2d")!, viewport: vp, annotationMode: pdfjs.AnnotationMode.DISABLE }).promise;
        }
        if (!cancelled) {
          onPages(doc.numPages);
          setState("ready");
        }
      } catch {
        if (!cancelled) setState("error");
      }
    })();
    return () => {
      cancelled = true;
      destroy?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pdf]);

  useEffect(() => {
    if (state !== "ready" || !end.current) return;
    const io = new IntersectionObserver((entries) => entries.some((e) => e.isIntersecting) && onReachedEnd(), { threshold: 1 });
    io.observe(end.current);
    return () => io.disconnect();
  }, [state, onReachedEnd]);

  return (
    <div className="space-y-4">
      {state === "loading" && <p className="text-sm text-muted-foreground">{t("sign.viewer.loading")}</p>}
      {state === "error" && <p role="alert" className="text-sm text-destructive">{t("sign.viewer.error")}</p>}
      <div ref={host} className="space-y-4" />
      <div ref={end} aria-hidden className="h-1" />
    </div>
  );
}
