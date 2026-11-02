import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import sri from "vite-plugin-sri-gen";
import monitorRelay from "./dev/relay";
import localConsole from "./dev/local-console";
import { BACKEND, ORIGIN } from "./dev/fixtures";

// Hosted and detached builds get their own outputs, so neither can replace the embedded ui/dist.
const builds: Record<string, { base: string; outDir: string }> = {
  hosted: { base: "/", outDir: "dist-hosted" },
  static: { base: "./", outDir: "dist-static" },
};

// The hosted console's local HTTPS name, proxied to this dev server, which is
// the development passkey profile's relying party.
const HOSTED_DEV_HOST = "local.tinfoil.sh";

export default defineConfig(({ command, mode }) => {
  if (mode === "dev-console" && command !== "serve")
    throw new Error(
      "Local fake-account mode is development-only and cannot be built.",
    );
  const local = mode === "dev-console";
  return {
    root: fileURLToPath(new URL(".", import.meta.url)),
    base: local ? "/" : (builds[mode]?.base ?? "/app/"),
    define: local
      ? {
          "import.meta.env.VITE_DEV_API_ORIGIN": JSON.stringify(ORIGIN),
          "import.meta.env.VITE_DEV_DASHBOARD_RETURN": JSON.stringify(
            ORIGIN + "/",
          ),
        }
      : {},
    // The hosted CSP allows no inline script, so integrity travels on modulepreload
    // links for every chunk, and one stylesheet carries all CSS.
    plugins: [
      solid(),
      local && localConsole(),
      mode === "hosted" && monitorRelay(),
      mode === "hosted" &&
        sri({ importMapIntegrity: false, runtimePatchDynamicLinks: false }),
    ],
    // Hosted routes, including /start, serve the console entry point.
    appType: mode === "hosted" || local ? "spa" : "mpa",
    server: {
      host: "127.0.0.1",
      port: local ? Number(new URL(ORIGIN).port) : 5173,
      strictPort: true,
      allowedHosts: mode === "hosted" ? [HOSTED_DEV_HOST] : [],
      proxy: local
        ? {
            "/__dev/monitor": {
              target: BACKEND,
              rewrite: (path) => path.replace(/^\/__dev\/monitor/, "") || "/",
            },
          }
        : undefined,
      // The hosted build compiles in the Monitor's own trusted config template.
      fs: { allow: [".", "../tinfoil-config.yml"] },
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
  };
});
