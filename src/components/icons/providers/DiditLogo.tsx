import { useId, type SVGProps } from "react";

/**
 * Didit brand mark: the outline path is copied unchanged from didit.me/logos/switch/didit.svg
 * (the mark's clip path). Didit fills it with a raster gradient; here the same colours are drawn
 * as vector gradients sampled from Didit's own app icon, so nothing is loaded from didit.me.
 */
const MARK =
  "M132.72,264.47c-55.31,0-100.31-45-100.31-100.31v-62.87C32.41,45.98,77.41.98,132.72.98s100.31,45,100.31,100.31v62.87c.24,26.42-10,51.49-28.84,70.5-19.05,19.22-44.43,29.81-71.47,29.81ZM132.72,24.71c-42.23,0-76.58,34.35-76.58,76.58v62.87c0,42.23,34.35,76.58,76.58,76.58,20.66,0,40.05-8.09,54.61-22.78,14.35-14.48,22.15-33.54,21.97-53.69v-62.97c0-42.23-34.35-76.58-76.58-76.58Z";

export function DiditLogo({ title = "Didit", ...props }: SVGProps<SVGSVGElement> & { title?: string }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg viewBox="0.52 0.98 264.4 264.4" role="img" aria-label={title} {...props}>
      <defs>
        <linearGradient id={`${id}x`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#a8f0ff" />
          <stop offset="0.4" stopColor="#6cc2fb" />
          <stop offset="0.65" stopColor="#5f79de" />
          <stop offset="1" stopColor="#5049cc" />
        </linearGradient>
        <linearGradient id={`${id}y`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#0073e4" />
          <stop offset="0.2" stopColor="#1664dd" stopOpacity="0.85" />
          <stop offset="0.55" stopColor="#2858d7" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path
        fillRule="evenodd"
        fill={`url(#${id}x)`}
        d={MARK}
      />
      <path
        fillRule="evenodd"
        fill={`url(#${id}y)`}
        d={MARK}
      />
    </svg>
  );
}
