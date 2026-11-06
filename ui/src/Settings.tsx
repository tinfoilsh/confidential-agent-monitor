import { For } from "solid-js";
import * as owner from "./owner.js";
import { Icon } from "./components";
import { useMonitor } from "./monitor";

export function Settings(props: {
  theme: string;
  onThemeChange: (theme: string) => void;
}) {
  const m = useMonitor();
  return (
    <div id="pane">
      <p>Permissions save automatically.</p>
      <section class="settings-section">
        <h2>Appearance</h2>
        <div class="setting-row">
          <span>Color theme</span>
          <span class="seg" role="group" aria-label="Color theme">
            <For
              each={
                [
                  ["system", "System", "devices"],
                  ["light", "Light", "sun"],
                  ["dark", "Dark", "moon"],
                ] as const
              }
            >
              {([theme, title, icon]) => (
                <button
                  type="button"
                  classList={{ primary: props.theme === theme }}
                  aria-label={`${title} theme`}
                  aria-pressed={props.theme === theme}
                  title={`${title} theme`}
                  onClick={() => props.onThemeChange(theme)}
                >
                  <Icon name={icon} />
                </button>
              )}
            </For>
          </span>
        </div>
      </section>
      <section class="settings-section">
        <h2>Payments</h2>
        <label class="setting-row">
          <span>
            Ask before any payment
            <small>
              A sandbox must get your approval for anything that spends
              money.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={owner.effectMode(m.view()!, "pay") !== "allow"}
            onChange={(e) =>
              void m.edit(
                owner.edits.setEffect(
                  "pay",
                  e.currentTarget.checked ? "ask" : "allow",
                ),
              )
            }
          />
        </label>
        <label class="setting-row">
          <span>
            Allow AI inference without asking
            <small>
              Paid model calls (Tinfoil, OpenAI, …) go through without
              approval. Other payments still ask.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={m.view()!.config.allow_paid_inference}
            onChange={(e) =>
              void m.edit(owner.edits.setPaidInference(e.currentTarget.checked))
            }
          />
        </label>
      </section>
      <section class="settings-section settings-danger">
        <h2>Dangerous</h2>
        <label class="setting-row">
          <span>
            Allow everything
            <small>
              Ignore connections. Every sandbox can reach any host on any
              port, and nothing asks.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={owner.networkingOpen(m.view()!)}
            onChange={(e) => {
              const open = e.currentTarget.checked;
              if (
                open &&
                !confirm(
                  "Allow everything? Sandboxes will be able to reach any host without asking.",
                )
              ) {
                e.currentTarget.checked = false;
                return;
              }
              void m.edit(owner.edits.setNetworkingOpen(m.view()!, open));
            }}
          />
        </label>
      </section>
    </div>
  );
}
