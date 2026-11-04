import { render } from "solid-js/web";
import "./monitor/dashboard.css";
import "./styles.css";

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
if (import.meta.env.MODE === "hosted") void import("./terminal/main");
else
  void import("./monitor/App").then(({ default: App }) =>
    render(() => <App />, document.getElementById("root")!),
  );
