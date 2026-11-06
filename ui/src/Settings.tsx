import { For } from "solid-js";
import * as owner from "./owner.js";
import { Icon, askConfirm } from "./components";
import { useMonitor } from "./monitor";

export function Settings(props: {
  theme: string;
  onThemeChange: (theme: string) => void;
}) {
  const m = useMonitor();
  return (
    <div id="pane" class="settings">
      <p class="settings-note">Permissions save automatically.</p>
      <section class="settings-section">
        <h2>Appearance</h2>
        <div class="settings-card">
          <span class="setting-title">Color theme</span>
          <div class="theme-options" role="group" aria-label="Color theme">
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
                  class="theme-option"
                  aria-pressed={props.theme === theme}
                  onClick={() => props.onThemeChange(theme)}
                >
                  <Icon name={icon} />
                  {title}
                </button>
              )}
            </For>
          </div>
        </div>
      </section>
      <section class="settings-section">
        <h2>Payments</h2>
        <label class="settings-card setting-toggle">
          <span>
            <span class="setting-title">Ask before any payment</span>
            <small>
              A bunker must get your approval for anything that spends
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
                  e.currentTarget.checked ? undefined : "allow",
                ),
              )
            }
          />
        </label>
        <label class="settings-card setting-toggle">
          <span>
            <span class="setting-title">Allow AI inference without asking</span>
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
        <label class="settings-card setting-toggle">
          <span>
            <span class="setting-title">Allow everything</span>
            <small>
              Ignore connections. Every bunker can reach any host on any
              port, and nothing asks.
            </small>
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={owner.networkingOpen(m.view()!)}
            onChange={async (e) => {
              const toggle = e.currentTarget,
                open = toggle.checked;
              if (
                open &&
                !(await askConfirm({
                  title: "Allow everything?",
                  description:
                    "Bunkers will be able to reach any host without asking.",
                  confirmLabel: "Allow everything",
                  destructive: true,
                }))
              ) {
                toggle.checked = false;
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
