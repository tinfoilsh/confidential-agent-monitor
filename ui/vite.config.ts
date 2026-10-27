import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import sri from "vite-plugin-sri-gen";
import monitorRelay from "./dev/relay";

// Hosted and detached builds get their own outputs, so neither can replace the embedded ui/dist.
const builds: Record<string, { base: string; outDir: string }> = {
  hosted: { base: "/", outDir: "dist-hosted" },
  static: { base: "./", outDir: "dist-static" },
};

// The hosted console's local HTTPS name, proxied to this dev server, so the
// tinfoil.sh passkey relying party accepts it.
const HOSTED_DEV_HOST = "local.tinfoil.sh";

export default defineConfig(({ mode }) => ({
  root: fileURLToPath(new URL(".", import.meta.url)),
  base: builds[mode]?.base ?? "/app/",
  // The hosted CSP allows no inline script, so integrity travels on modulepreload
  // links for every chunk, and one stylesheet carries all CSS.
  plugins: [
    solid(),
    mode === "hosted" && monitorRelay(),
    mode === "hosted" &&
      sri({ importMapIntegrity: false, runtimePatchDynamicLinks: false }),
  ],
  // Hosted routes, including /start, serve the console entry point.
  appType: mode === "hosted" ? "spa" : "mpa",
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    allowedHosts: mode === "hosted" ? [HOSTED_DEV_HOST] : [],
  },
  build: {
    outDir: builds[mode]?.outDir ?? "dist",
    cssCodeSplit: mode !== "hosted",
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL("index.html", import.meta.url)),
      },
    },
  },
}));
