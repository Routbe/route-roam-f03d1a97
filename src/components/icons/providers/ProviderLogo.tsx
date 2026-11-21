import { useEffect, useRef, useState } from "react";
import { Building2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { DiditLogo } from "./DiditLogo";
import { WIdentityLogo } from "./WIdentityLogo";
import { PROVIDER_LOGO_FILES } from "./provider-logos";

const BOX = { sm: "h-8 w-8 rounded-lg", lg: "h-10 w-10 rounded-xl" } as const;

/**
 * One renderer for every provider mark, in a fixed square (32 or 40 px) so nothing shifts:
 * inline vectors for the active engines, the local official file for the others, and the
 * neutral Building2 icon when a provider has no file or the file fails to load.
 */
export function ProviderLogo({ name, size = "sm", className }: { name: string; size?: keyof typeof BOX; className?: string }) {
  const file = PROVIDER_LOGO_FILES[name];
  const [failed, setFailed] = useState(false);
  const img = useRef<HTMLImageElement>(null);
  // An error that fired before hydration has no listener yet; read the element's state instead.
  useEffect(() => {
    const el = img.current;
    if (el?.complete && el.naturalWidth === 0) setFailed(true);
  }, [file]);

  let mark;
  if (name === "didit") mark = <DiditLogo className="h-full w-full" />;
  else if (name === "w_identity") mark = <WIdentityLogo className="h-full w-full" />;
  else if (file && !failed)
    mark = <img ref={img} src={file} alt="" width={40} height={40} loading="lazy" decoding="async" draggable={false} onError={() => setFailed(true)} className="h-full w-full object-contain" />;
  else mark = <Building2 data-fallback="" className="h-1/2 w-1/2 text-muted-foreground" strokeWidth={1.75} aria-hidden />;

  const flush = name === "w_identity";
  return (
    <span
      aria-hidden
      data-provider-logo={name}
      className={cn("flex shrink-0 items-center justify-center overflow-hidden", BOX[size], flush ? "" : "border border-border bg-background p-1", className)}
    >
      {mark}
    </span>
  );
}
