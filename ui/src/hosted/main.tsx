import { render } from "solid-js/web";
import { TARGETS, profileError } from "./keys";

const path = location.pathname.replace(/\/+$/, "");
const route = path.startsWith("/monitor/")
  ? "monitor"
  : path === "/cli" || path.startsWith("/cli/")
    ? "cli"
    : "console";
document.title =
  route === "monitor"
    ? "Monitor"
    : route === "cli"
      ? "CLI key sync · Tinfoil"
      : "Get started · Tinfoil";
const root = document.getElementById("root")!;
// A new launch fragment in this tab is captured by a fresh load, like the first.
// A Monitor's own pages navigate by fragment, so they never reload.
if (route !== "monitor")
  addEventListener("hashchange", () => location.hash && location.reload());

async function start() {
  const problem = profileError();
  if (problem) throw new Error(problem);
  const page = await (route === "monitor"
    ? import("./Monitor")
    : route === "cli"
      ? import("./Cli")
      : import("./Console"));
  // Launch fragments leave the URL before sign-in can redirect.
  page.capture();
  const [{ Clerk }, { createSession }] = await Promise.all([
    import("@clerk/clerk-js/no-rhc"),
    import("./session"),
  ]);
  const clerk = new Clerk(TARGETS.clerk_publishable_key);
  await clerk.load();
  const session = createSession(clerk);
  const Page = page.default;
  render(() => <Page session={session} />, root);
}

void start().catch((cause) =>
  render(
    () => (
      <main id="gate">
        <h1>Could not load Tinfoil</h1>
        <p role="alert">
          {cause instanceof Error
            ? cause.message
            : "Reload the page to try again."}
        </p>
        <button onClick={() => location.reload()}>Reload</button>
      </main>
    ),
    root,
  ),
);
