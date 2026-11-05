import { Route, Router } from "@solidjs/router";
import { lazy } from "solid-js";
import { render } from "solid-js/web";
import { TARGETS, profileError } from "./keys";

const PAGES = {
  monitor: () => import("./Monitor"),
  cli: () => import("./Cli"),
  console: () => import("./Console"),
};
const TITLES = {
  monitor: "Monitor",
  cli: "CLI key sync · Terminal",
  console: "Get started · Terminal",
};
const routeOf = (pathname: string): keyof typeof PAGES => {
  const path = pathname.replace(/\/+$/, "");
  return path.startsWith("/monitor/")
    ? "monitor"
    : path === "/cli" || path.startsWith("/cli/")
      ? "cli"
      : "console";
};
const route = routeOf(location.pathname);
const root = document.getElementById("root")!;
// A new launch fragment in this tab is captured by a fresh load, like the first.
// A Monitor's own pages navigate by fragment, so they never reload.
addEventListener(
  "hashchange",
  () =>
    routeOf(location.pathname) !== "monitor" &&
    location.hash &&
    location.reload(),
);

async function start() {
  const problem = profileError();
  if (problem) throw new Error(problem);
  const page = await PAGES[route]();
  // Launch fragments leave the URL before sign-in can redirect.
  page.capture();
  const [{ Clerk }, { createSession }] = await Promise.all([
    import("@clerk/clerk-js/no-rhc"),
    import("./session"),
  ]);
  const clerk = new Clerk(TARGETS.clerk_publishable_key);
  await clerk.load({ touchSession: false });
  const session = createSession(clerk);
  const view = (name: keyof typeof PAGES) => {
    const Page = lazy(PAGES[name]);
    return () => {
      document.title = TITLES[name];
      return <Page session={session} />;
    };
  };
  // Only links marked `link` navigate in place; a Monitor's fragment links stay native.
  render(
    () => (
      <Router explicitLinks>
        <Route path="/monitor/:id" component={view("monitor")} />
        <Route path="/cli/*" component={view("cli")} />
        <Route path="*" component={view("console")} />
      </Router>
    ),
    root,
  );
}

void start().catch((cause) =>
  render(
    () => (
      <main id="gate" class="auth">
        <h1>Could not load Tinfoil</h1>
        <section class="auth-card">
          <p role="alert">
            {cause instanceof Error
              ? cause.message
              : "Reload the page to try again."}
          </p>
          <button class="primary" onClick={() => location.reload()}>
            Reload
          </button>
        </section>
      </main>
    ),
    root,
  ),
);
