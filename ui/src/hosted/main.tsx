import { render } from "solid-js/web";
import { hasMonitorHandoff } from "./links";

const path = location.pathname.replace(/\/+$/, "");
const welcome = !path || path === "/start";
document.title = welcome ? "Get started · Tinfoil" : "Monitor";
// A new dashboard handoff may target a monitor already open in this tab.
addEventListener("hashchange", () => {
  if (!welcome && hasMonitorHandoff(location.hash)) location.reload();
});
void (welcome ? import("./Console") : import("./Monitor"))
  .then(({ default: Page }) =>
    render(() => <Page />, document.getElementById("root")!),
  )
  .catch(() =>
    render(
      () => (
        <main id="gate">
          <h1>Could not load Monitor</h1>
          <p role="alert">Reload the page to try again.</p>
          <button onClick={() => location.reload()}>Reload</button>
        </main>
      ),
      document.getElementById("root")!,
    ),
  );
