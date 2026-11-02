import { render } from "solid-js/web";
import "./dashboard.css";
import "./shell.css";

// Apply the saved palette before either the welcome screen or app first renders.
let theme = "system";
try {
  theme = localStorage.getItem("monitor-theme") || theme;
} catch {}
document.documentElement.dataset.theme =
  theme === "system"
    ? matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light"
    : theme;

// Each build only includes its own entry point and dependencies.
if (import.meta.env.DEV && import.meta.env.MODE === "dev-console")
  void import("../dev/main");
else if (import.meta.env.MODE === "hosted") void import("./hosted/main");
else
  void import("./App").then(({ default: App }) =>
    render(() => <App />, document.getElementById("root")!),
  );
