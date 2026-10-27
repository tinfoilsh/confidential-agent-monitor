import { render } from "solid-js/web";
import "./dashboard.css";
import "./shell.css";

// Each build only includes its own entry point and dependencies.
if (import.meta.env.MODE === "hosted") void import("./hosted/main");
else
  void import("./App").then(({ default: App }) =>
    render(() => <App />, document.getElementById("root")!),
  );
