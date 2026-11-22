import { defineConfig } from "unocss";
import presetWind3 from "@unocss/preset-wind3";
import presetIcons from "@unocss/preset-icons";

export default defineConfig({
  content: {
    filesystem: ["src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}"],
  },
  safelist: [
    "i-ri-shield-flash-line",
    "i-ri-lock-2-line",
    "i-ri-flashlight-line",
    "i-ri-box-3-line",
    "i-ri-computer-line",
    "i-ri-router-line",
    "i-ri-download-cloud-2-line",
    "i-ri-dashboard-3-line",
    "i-ri-rocket-line",
    "i-ri-terminal-box-line",
    "i-ri-settings-3-line",
    "i-ri-speed-up-line",
    "text-rose-600",
    "dark:text-rose-400",
    "bg-rose-500/10",
    "text-sky-600",
    "dark:text-sky-400",
    "bg-sky-500/10",
    "text-amber-600",
    "dark:text-amber-400",
    "bg-amber-500/10",
    "text-emerald-600",
    "dark:text-emerald-400",
    "bg-emerald-500/10",
    "text-violet-600",
    "dark:text-violet-400",
    "bg-violet-500/10",
    "text-zinc-700",
    "dark:text-zinc-300",
    "bg-zinc-500/10",
  ],
  presets: [
    presetWind3({
      dark: "class",
    }),
    presetIcons({
      scale: 1.2,
      extraProperties: {
        display: "inline-block",
        "vertical-align": "middle",
      },
    }),
  ],
  theme: {
    fontFamily: {
      sans: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      mono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
    },
  },
});
