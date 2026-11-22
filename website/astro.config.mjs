import { defineConfig } from "astro/config";
import solidJs from "@astrojs/solid-js";
import UnoCSS from "@unocss/astro";

export default defineConfig({
  site: "https://crabdns.pages.dev",
  output: "static",
  compressHTML: true,
  build: {
    inlineStylesheets: "auto",
  },
  integrations: [
    solidJs(),
    UnoCSS({
      injectReset: true,
    }),
  ],
});
