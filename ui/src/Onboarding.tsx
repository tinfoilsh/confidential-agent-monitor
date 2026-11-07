import {
  For,
  Match,
  Show,
  Switch,
  createResource,
  createSignal,
  type JSX,
} from "solid-js";
import { createStore } from "solid-js/store";
import * as owner from "./owner.js";
import {
  AuthCard,
  AuthScreen,
  ConnectorIcon,
  Field,
  Icon,
  Loading,
} from "./components";
import { useMonitor } from "./monitor";

type Service = {
  preset: string;
  title: string;
  level: owner.Level;
  // Signed in to after setup, so this step takes no key.
  signIn?: boolean;
  keyUrl?: string;
};
// The agents and model providers offered at first setup, in the order shown.
const SERVICES: Service[] = [
  {
    preset: "tinfoil",
    title: "Tinfoil",
    level: "allow",
    keyUrl: "https://dash.tinfoil.sh/?tab=api-keys",
  },
  {
    preset: "anthropic",
    title: "Claude Code",
    level: "allow",
    keyUrl: "https://console.anthropic.com/settings/keys",
  },
  {
    preset: "codex",
    title: "Codex",
    level: "allow",
    signIn: true,
  },
  {
    preset: "openai",
    title: "OpenAI",
    level: "allow",
    keyUrl: "https://platform.openai.com/api-keys",
  },
  // Reads go through; changes such as pushes ask first.
  {
    preset: "github",
    title: "GitHub",
    level: "ask",
    signIn: true,
  },
  {
    preset: "google_gemini",
    title: "Gemini",
    level: "allow",
    keyUrl: "https://aistudio.google.com/apikey",
  },
  {
    preset: "open_router",
    title: "OpenRouter",
    level: "allow",
    keyUrl: "https://openrouter.ai/settings/keys",
  },
];
const NETWORK = [
  ["ask", "Ask", "Approve each new host from Activity."],
  [
    "allow",
    "Allow always",
    "Bunkers reach any host. The Perimeter still records where they connect.",
  ],
  ["off", "Reject", "Bunkers reach only the services you added."],
] as const;
// Enough of a key to tell keys apart without showing it.
const KEY_PREFIX_LENGTH = 8;

export function Onboarding(props: {
  busy: boolean;
  error: JSX.Element;
  onFinish(choices: owner.OnboardingChoices, signIns: string[]): void;
}) {
  const m = useMonitor();
  const [step, setStep] = createSignal<"services" | "keys" | "network">(
    "services",
  );
  const [picked, setPicked] = createSignal<string[]>([]);
  const [keys, setKeys] = createStore<Record<string, string>>({});
  const [network, setNetwork] =
    createSignal<owner.OnboardingChoices["network"]>("ask");
  const [missing, setMissing] = createSignal("");
  const offered = () => SERVICES.filter((s) => m.view()!.presets[s.preset]);
  const chosen = () => offered().filter((s) => picked().includes(s.preset));
  const toggle = (preset: string) =>
    setPicked((list) =>
      list.includes(preset)
        ? list.filter((p) => p !== preset)
        : [...list, preset],
    );
  const listKeys = m.options.tinfoilApiKeys;
  const [apiKeys, { refetch }] = createResource(
    () => listKeys && picked().includes("tinfoil"),
    () => listKeys!(),
  );
  // A single key needs no choosing.
  const loaded = () => (apiKeys.error ? undefined : apiKeys());
  const tinfoilKey = () =>
    keys.tinfoil || (loaded()?.length === 1 ? loaded()![0].key : "");
  const keyOf = (s: Service) =>
    s.preset === "tinfoil" ? tinfoilKey() : (keys[s.preset] ?? "");
  const credentialField = (preset: string) =>
    owner.setupFields(m.view()!, preset).find((f) => f.credential && !f.oauth);
  const checkKeys = () => {
    const without = chosen().find((s) => !s.signIn && !keyOf(s).trim());
    setMissing(
      without
        ? `Add a key for ${without.title}, or go back and unselect it.`
        : "",
    );
    if (!without) setStep("network");
  };
  const finish = () =>
    props.onFinish(
      {
        services: chosen().map((s) => ({
          preset: s.preset,
          level: s.level,
          credential: s.signIn ? undefined : keyOf(s),
        })),
        network: network(),
      },
      chosen()
        .filter((s) => s.signIn)
        .map((s) => s.preset),
    );
  return (
    <Switch>
      <Match when={step() === "services"}>
        <AuthScreen
          id="gate"
          title="What will your bunkers use?"
          description="Pick the services your agents need. You can add more from Permissions later."
        >
          <AuthCard>
            <div class="service-grid" role="group" aria-label="Services">
              <For each={offered()}>
                {(s) => (
                  <button
                    type="button"
                    class="service-tile"
                    aria-pressed={picked().includes(s.preset)}
                    onClick={() => toggle(s.preset)}
                  >
                    <ConnectorIcon preset={s.preset} />
                    {s.title}
                    <span class="service-check" aria-hidden="true">
                      <Icon name="check" />
                    </span>
                  </button>
                )}
              </For>
            </div>
            <button
              class="primary"
              onClick={() => setStep(picked().length ? "keys" : "network")}
            >
              Continue
            </button>
          </AuthCard>
        </AuthScreen>
      </Match>
      <Match when={step() === "keys"}>
        <AuthScreen
          id="gate"
          title="Add your keys"
          description="The Perimeter keeps your keys. Your bunkers never see them."
        >
          <form
            class="auth-card"
            onSubmit={(event) => {
              event.preventDefault();
              checkKeys();
            }}
          >
            <For each={chosen()}>
              {(s) => (
                <section class="onboarding-service">
                  <header>
                    <ConnectorIcon preset={s.preset} />
                    <h2>{s.title}</h2>
                    <Show when={s.keyUrl}>
                      {(url) => (
                        <a
                          href={url()}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Get a key
                          <Icon name="external" />
                        </a>
                      )}
                    </Show>
                  </header>
                  <Switch
                    fallback={
                      <Field
                        field={{
                          key: s.preset,
                          label: credentialField(s.preset)?.label ?? "API key",
                          secret: true,
                        }}
                        value={keys[s.preset] ?? ""}
                        onInput={(value) => setKeys(s.preset, value)}
                      />
                    }
                  >
                    <Match when={s.signIn}>
                      <p>
                        {owner.signInLabel(m.view()!, s.preset)} after setup.
                      </p>
                    </Match>
                    <Match when={s.preset === "tinfoil" && listKeys}>
                      <Switch>
                        <Match when={apiKeys.loading}>
                          <Loading label="Loading your API keys…" />
                        </Match>
                        <Match when={apiKeys.error}>
                          <p role="alert">
                            Your API keys could not be loaded.{" "}
                            <button
                              type="button"
                              class="link"
                              onClick={() => void refetch()}
                            >
                              Try again
                            </button>
                          </p>
                        </Match>
                        <Match when={!loaded()?.length}>
                          <p>
                            You have no Tinfoil API keys yet.{" "}
                            <a
                              href={s.keyUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              Create one in the dashboard
                            </a>
                            , then{" "}
                            <button
                              type="button"
                              class="link"
                              onClick={() => void refetch()}
                            >
                              check again
                            </button>
                            .
                          </p>
                        </Match>
                        <Match when={loaded()}>
                          {(list) => (
                            <select
                              aria-label="Tinfoil API key"
                              value={tinfoilKey()}
                              onChange={(event) =>
                                setKeys("tinfoil", event.currentTarget.value)
                              }
                            >
                              <option value="" disabled>
                                Choose an API key
                              </option>
                              <For each={list()}>
                                {(k) => (
                                  <option value={k.key}>
                                    {k.name || "Unnamed key"} ·{" "}
                                    {k.key.slice(0, KEY_PREFIX_LENGTH)}…
                                  </option>
                                )}
                              </For>
                            </select>
                          )}
                        </Match>
                      </Switch>
                    </Match>
                  </Switch>
                </section>
              )}
            </For>
            <Show when={missing()}>
              <p role="alert">{missing()}</p>
            </Show>
            <button class="primary">Continue</button>
            <button
              type="button"
              class="link"
              onClick={() => {
                setMissing("");
                setStep("services");
              }}
            >
              Back
            </button>
          </form>
        </AuthScreen>
      </Match>
      <Match when={step() === "network"}>
        <AuthScreen
          id="gate"
          title="Network access"
          description="When a bunker connects to a host that isn't one of your services:"
        >
          <form
            class="auth-card"
            onSubmit={(event) => {
              event.preventDefault();
              finish();
            }}
          >
            <div
              class="network-options"
              role="radiogroup"
              aria-label="Network access"
            >
              <For each={NETWORK}>
                {([value, title, description]) => (
                  <label class="network-option">
                    <input
                      type="radio"
                      name="network"
                      value={value}
                      checked={network() === value}
                      onChange={() => setNetwork(value)}
                    />
                    <span>
                      <strong>{title}</strong>
                      <small>{description}</small>
                    </span>
                  </label>
                )}
              </For>
            </div>
            {props.error}
            <button class="primary" disabled={props.busy}>
              {props.busy ? "Saving…" : "Finish setup"}
            </button>
            <button
              type="button"
              class="link"
              disabled={props.busy}
              onClick={() => setStep(picked().length ? "keys" : "services")}
            >
              Back
            </button>
          </form>
        </AuthScreen>
      </Match>
    </Switch>
  );
}
