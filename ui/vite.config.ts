import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv } from "vite";
import solid from "vite-plugin-solid";
import sri from "vite-plugin-sri-gen";
import local from "./dev/local";

// Hosted and detached builds get their own outputs, so neither can replace the embedded ui/dist.
const builds: Record<string, { base: string; outDir: string }> = {
  vercel: { base: "/", outDir: "dist-vercel" },
  static: { base: "./", outDir: "dist-static" },
};

// The hosted console's local HTTPS name, proxied to this dev server, so the production
// Clerk instance and the tinfoil.sh passkey RP accept it.
const HOSTED_DEV_HOST = "local.tinfoil.sh";

export default defineConfig(({ command, mode }) => ({
  root: fileURLToPath(new URL(".", import.meta.url)),
  base: builds[mode]?.base ?? "/app/",
  // The hosted CSP allows no inline script, so integrity travels on modulepreload
  // links for every chunk, and one stylesheet carries all CSS.
  plugins: [
    solid(),
    mode === "vercel" &&
      sri({ importMapIntegrity: false, runtimePatchDynamicLinks: false }),
    command === "serve" && !!loadEnv(mode, ".").VITE_LOCAL_MONITORS && local(),
  ],
  appType: "mpa",
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    allowedHosts: mode === "vercel" ? [HOSTED_DEV_HOST] : [],
  },
  build: {
    outDir: builds[mode]?.outDir ?? "dist",
    cssCodeSplit: mode !== "vercel",
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL("index.html", import.meta.url)),
      },
    },
  },
}));
