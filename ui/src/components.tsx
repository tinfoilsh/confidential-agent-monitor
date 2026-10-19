import {
  For,
  Show,
  createMemo,
  createSignal,
  createUniqueId,
  onMount,
  onCleanup,
  type Accessor,
  type JSX,
} from "solid-js";
import * as owner from "./owner.js";
import { icons } from "./dashboard-icons.js";
import { useMonitor } from "./monitor";

// The only HTML insertion is our checked-in SVG icon set, never server data.
export function Icon(props: { name: string }) {
  return (
    <span
      class="icon"
      aria-hidden="true"
      innerHTML={icons[props.name as keyof typeof icons] ?? icons.accounts}
    />
  );
}
export function ConnectorIcon(props: { preset: string }) {
  const m = useMonitor();
  const icon = createMemo(() => owner.connectorIcon(m.icons(), props.preset));
  return (
    <span class="connector-icon" aria-hidden="true">
      <Show when={icon().dark}>
        <img
          class="dark-icon"
          loading="lazy"
          decoding="async"
          src={icon().dark}
          width="20"
          height="20"
          alt=""
        />
      </Show>
      <img
        class="light-icon"
        loading="lazy"
        decoding="async"
        src={icon().src}
        width="20"
        height="20"
        alt=""
      />
    </span>
  );
}
export const href = (kind: string, ...args: string[]) =>
  "#" + [kind, ...args].map(encodeURIComponent).join("/");
// Keep native keyboard disclosure behavior while animating the full row in
// browsers that cannot interpolate details-content from zero to auto.
export function ResourceDisclosure(props: {
  class: string;
  summaryClass?: string;
  open?: boolean;
  summary: JSX.Element;
  children: (active: Accessor<boolean>) => JSX.Element;
}) {
  const [expanded, setExpanded] = createSignal(!!props.open);
  const [visited, setVisited] = createSignal(!!props.open);
  let element!: HTMLDetailsElement, summary!: HTMLElement;
  let animation: Animation | undefined;
  const toggle = (event: MouseEvent) => {
    if (
      (event.target as HTMLElement).closest(
        "button, a, input, select, textarea",
      )
    )
      return;
    event.preventDefault();
    const from = element.getBoundingClientRect().height;
    animation?.cancel();
    animation = undefined;
    const opening = !expanded();
    setExpanded(opening);
    if (opening) {
      setVisited(true);
      element.open = true;
    }
    // The lazy contents must be mounted before measuring their natural height.
    queueMicrotask(() => {
      if (!element.isConnected) return;
      if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
        element.open = opening;
        return;
      }
      const border = element.offsetHeight - element.clientHeight;
      const to = opening
        ? element.getBoundingClientRect().height
        : summary.getBoundingClientRect().height + border;
      const next = element.animate(
        [{ height: `${from}px` }, { height: `${to}px` }],
        {
          duration: 120,
          easing: "ease-out",
          fill: "forwards",
        },
      );
      animation = next;
      next.onfinish = () => {
        if (animation !== next) return;
        element.open = opening;
        next.cancel();
        animation = undefined;
      };
    });
  };
  onCleanup(() => animation?.cancel());
  return (
    <details
      ref={element}
      class={`resource-disclosure ${props.class}`}
      open={props.open}
    >
      <summary
        ref={summary}
        class={`resource-row ${props.summaryClass ?? "collection-row"}`}
        aria-expanded={expanded()}
        onClick={toggle}
      >
        {props.summary}
      </summary>
      <div inert={!expanded()} aria-hidden={!expanded()}>
        <Show when={visited()}>{props.children(expanded)}</Show>
      </div>
    </details>
  );
}
// Native nested disclosures mount their potentially large contents on first open.
export function LazyDetails(props: {
  class?: string;
  summaryClass?: string;
  label?: string;
  "data-disclosure"?: string;
  summary: JSX.Element;
  children: () => JSX.Element;
}) {
  const [visited, setVisited] = createSignal(false);
  return (
    <details
      class={props.class}
      data-disclosure={props["data-disclosure"]}
      onToggle={(event) => {
        if (event.currentTarget.open) setVisited(true);
      }}
    >
      <summary class={props.summaryClass} aria-label={props.label}>
        {props.summary}
      </summary>
      <Show when={visited()}>{props.children()}</Show>
    </details>
  );
}
export function Empty(props: {
  title: string;
  icon?: string;
  children?: JSX.Element;
  action?: JSX.Element;
}) {
  return (
    <div class="empty-state">
      <Show when={props.icon}>
        <span class="empty-icon">
          <Icon name={props.icon!} />
        </span>
      </Show>
      <h2>{props.title}</h2>
      <Show when={props.children}>
        <p>{props.children}</p>
      </Show>
      <Show when={props.action}>
        <div class="empty-action">{props.action}</div>
      </Show>
    </div>
  );
}
export function Search(props: {
  label: string;
  value: string;
  onInput: (value: string) => void;
  autofocus?: boolean;
  onEnter?: () => void;
}) {
  let input!: HTMLInputElement;
  onMount(() => {
    if (props.autofocus) input.focus();
  });
  return (
    <div class="search-field">
      <Icon name="search" />
      <input
        ref={input}
        type="search"
        autofocus={props.autofocus}
        aria-label={props.label}
        placeholder={`${props.label}…`}
        value={props.value}
        onInput={(e) => props.onInput(e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.isComposing && props.onEnter) {
            e.preventDefault();
            props.onEnter();
          }
        }}
      />
    </div>
  );
}
export function Permission(props: {
  label: string;
  value: owner.Mode | null;
  inherited: owner.Mode;
  onChange: (value: owner.Mode | null) => void;
}) {
  return (
    <span class="seg" role="group" aria-label={`${props.label} permission`}>
      <For each={Object.keys(owner.MODES) as owner.Mode[]}>
        {(mode) => (
          <button
            type="button"
            classList={{
              primary: props.value === mode,
              inherited: !props.value && props.inherited === mode,
            }}
            aria-label={`${owner.MODES[mode]} ${props.label}`}
            aria-pressed={props.value === mode}
            title={
              props.value === mode
                ? "Click to use the inherited setting"
                : !props.value && props.inherited === mode
                  ? "Inherited setting"
                  : owner.MODES[mode]
            }
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              props.onChange(props.value === mode ? null : mode);
            }}
          >
            {owner.MODES[mode]}
          </button>
        )}
      </For>
    </span>
  );
}
export function EffectOptions(props: {
  scope: owner.EffectScope;
  class?: string;
}) {
  return (
    <LazyDetails
      class={`effect-options ${props.class ?? ""}`}
      summaryClass="effect-options-toggle"
      summary={
        <>
          <Icon name="arrow" />
          <span>Effect overrides</span>
        </>
      }
    >
      {() => <Effects scope={props.scope} />}
    </LazyDetails>
  );
}
export function Effects(props: { scope?: owner.EffectScope }) {
  const m = useMonitor();
  const settings = createMemo(() => {
    const view = m.view()!;
    const accounts = props.scope?.account
      ? [props.scope.account]
      : props.scope?.agent
        ? owner
            .agentAccess(view, props.scope.agent)
            .filter((access) => access.level !== "off")
            .map((access) => access.account)
        : Object.keys(view.config.accounts ?? {});
    // A root's effects already include all of its descendants.
    const used = new Set(
      accounts.flatMap((account) =>
        [
          ...new Set(
            Object.keys(owner.actionsOf(view, account)).map(
              (action) => action.split(".")[0],
            ),
          ),
        ].flatMap((action) => owner.effectsOf(view, account, action)),
      ),
    );
    // Keep this order independent of checked and inherited permission values.
    return owner
      .effectSettings(view, props.scope)
      .filter((setting) => used.has(setting.effect))
      .sort(
        (a, b) =>
          Number(["pay", "publish"].includes(b.effect)) -
          Number(["pay", "publish"].includes(a.effect)),
      );
  });
  const byEffect = createMemo(
    () => new Map(settings().map((setting) => [setting.effect, setting])),
  );
  const rows = () => (
    <For each={[...byEffect().keys()]}>
      {(effect) => {
        const setting = () => byEffect().get(effect)!;
        const title =
          effect === "pay"
            ? "Payments"
            : effect === "publish"
              ? "Publishing"
              : effect.charAt(0).toUpperCase() + effect.slice(1);
        return (
          <div class="access-action">
            <span
              title={`${owner.MODES[setting().mode]} · ${setting().source}`}
            >
              {title}
            </span>
            <Permission
              label={title}
              value={setting().own}
              inherited={setting().inherited}
              onChange={(value) =>
                void m.edit(owner.edits.setEffect(props.scope, effect, value))
              }
            />
          </div>
        );
      }}
    </For>
  );
  return (
    <Show
      when={settings().length}
      fallback={<p class="muted">No effects used by these actions.</p>}
    >
      <div class="access-actions effect-permissions">{rows()}</div>
    </Show>
  );
}

export function Field(props: {
  field: owner.PresetField;
  value: string;
  onInput: (value: string) => void;
  disabled?: boolean;
}) {
  const id = createUniqueId(),
    [shown, setShown] = createSignal(false);
  return (
    <div>
      <label for={id}>{props.field.label}</label>
      <Show
        when={props.field.multiline || props.field.json}
        fallback={
          <div class="secret-input">
            <input
              id={id}
              type="text"
              classList={{ "secret-value": !!props.field.secret }}
              data-concealed={props.field.secret && !shown()}
              data-1p-ignore={props.field.secret ? true : undefined}
              data-lpignore={props.field.secret ? "true" : undefined}
              autocomplete="off"
              spellcheck={false}
              placeholder={
                props.field.hint ||
                (props.field.secret ? "Paste your secret here" : undefined)
              }
              autocapitalize="off"
              disabled={props.disabled}
              value={props.value}
              onInput={(e) => props.onInput(e.currentTarget.value)}
            />
            <Show when={props.field.secret}>
              <button
                type="button"
                aria-controls={id}
                aria-label={`${shown() ? "Hide" : "Show"} ${props.field.label}`}
                aria-pressed={shown()}
                onClick={() => setShown(!shown())}
              >
                {shown() ? "Hide" : "Show"}
              </button>
            </Show>
          </div>
        }
      >
        <textarea
          id={id}
          rows={6}
          disabled={props.disabled}
          value={props.value}
          onInput={(e) => props.onInput(e.currentTarget.value)}
        />
      </Show>
    </div>
  );
}
export function DataPermissions(props: {
  value: owner.AccountAnswers;
  onChange: (value: owner.AccountAnswers) => void;
}) {
  return (
    <>
      <For
        each={
          [
            ["contents", "Confidentiality"],
            ["sends", "Visibility"],
          ] as const
        }
      >
        {([key, title]) => (
          <div class="setting-row data-permission">
            <span>{title}</span>
            <span class="seg" role="group" aria-label={title}>
              <For each={Object.keys(owner.AUDIENCES) as owner.Audience[]}>
                {(value) => (
                  <button
                    type="button"
                    classList={{ primary: props.value[key] === value }}
                    aria-pressed={props.value[key] === value}
                    onClick={() =>
                      props.onChange({ ...props.value, [key]: value })
                    }
                  >
                    {owner.AUDIENCES[value]}
                  </button>
                )}
              </For>
            </span>
          </div>
        )}
      </For>
      <label class="setting-row">
        Untrusted data source
        <input
          type="checkbox"
          role="switch"
          checked={props.value.strangers}
          onChange={(e) =>
            props.onChange({
              ...props.value,
              strangers: e.currentTarget.checked,
            })
          }
        />
      </label>
    </>
  );
}
export function Copy(props: {
  text: string;
  label?: string;
  target?: () => HTMLInputElement | HTMLPreElement;
}) {
  const m = useMonitor();
  return (
    <button
      type="button"
      aria-label={props.label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(props.text);
          m.notify("Copied");
        } catch (cause) {
          const target = props.target?.();
          if (!target) {
            m.report(cause);
            return;
          }
          if (target instanceof HTMLInputElement) {
            target.focus();
            target.select();
          } else {
            const range = document.createRange(),
              selection = window.getSelection();
            range.selectNodeContents(target);
            selection?.removeAllRanges();
            selection?.addRange(range);
          }
          m.notify("Text selected. Press Cmd-C or Ctrl-C to copy.");
        }
      }}
    >
      Copy
    </button>
  );
}
export function download(text: string, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
