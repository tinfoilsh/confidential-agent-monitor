import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import sri from "vite-plugin-sri-gen";
import monitorRelay from "./dev/relay.ts";
import localConsole from "./dev/local-console.ts";
import { BACKEND, ORIGIN } from "./dev/fixtures.ts";

// Hosted and detached builds cannot replace the Monitor's embedded ui/dist.
const builds: Record<string, { base: string; outDir: string }> = {
  hosted: { base: "/", outDir: "dist-hosted" },
  static: { base: "./", outDir: "dist-static" },
};
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
    plugins: [
      solid(),
      local && localConsole(),
      mode === "hosted" && monitorRelay(),
      mode === "hosted" &&
        sri({ importMapIntegrity: false, runtimePatchDynamicLinks: false }),
    ],
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
              rewrite: (path: string) =>
                path.replace(/^\/__dev\/monitor/, "") || "/",
            },
          }
        : undefined,
      fs: { allow: [".", "../tinfoil-config.yml"] },
    },
    build: {
      outDir: builds[mode]?.outDir ?? "dist",
      cssCodeSplit: mode !== "hosted",
      rolldownOptions: {
        input: { main: fileURLToPath(new URL("index.html", import.meta.url)) },
      },
    },
  };
});
