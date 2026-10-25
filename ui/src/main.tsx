import { render } from "solid-js/web";
import App from "./App";
import "./dashboard.css";
import "./shell.css";

// The constant check drops the hosted console, Clerk and key code from other builds.
if (import.meta.env.MODE === "hosted") void import("./hosted/main");
else render(() => <App />, document.getElementById("root")!);
