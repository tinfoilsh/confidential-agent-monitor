import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  createUniqueId,
  lazy,
  onMount,
  onCleanup,
  splitProps,
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
export function Loading(props: { label: string }) {
  return (
    <p class="loading-status" role="status">
      <span class="loading-spinner" aria-hidden="true" />
      {props.label}
    </p>
  );
}

export function SkeletonRows(props: { label: string; cards?: boolean }) {
  return (
    <div
      class="loading-skeletons"
      classList={{ "loading-skeleton-cards": props.cards }}
      role="status"
      aria-label={props.label}
    >
      <span class="sr-only">{props.label}</span>
      <For each={[0, 1]}>
        {() => (
          <div class="loading-skeleton-row" aria-hidden="true">
            <span class="loading-skeleton loading-skeleton-icon" />
            <div class="loading-skeleton-lines">
              <span class="loading-skeleton loading-skeleton-title" />
              <span class="loading-skeleton loading-skeleton-description" />
            </div>
          </div>
        )}
      </For>
    </div>
  );
}

export function ConnectorIcon(props: { preset: string }) {
  const m = useMonitor();
  const icon = createMemo(() =>
    owner.connectorIcon(m.icons(), props.preset, "", import.meta.env.BASE_URL),
  );
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

export function SectionHeading(props: {
  title: string;
  description?: JSX.Element;
  small?: boolean;
}) {
  return (
    <header class="heading-text" classList={{ "heading-small": props.small }}>
      <Show
        when={props.small}
        fallback={<h3 class="section-title">{props.title}</h3>}
      >
        <h4 class="section-title">{props.title}</h4>
      </Show>
      <Show when={props.description}>
        <p class="section-description">{props.description}</p>
      </Show>
    </header>
  );
}

export function DisclosureHeading(props: {
  title: string;
  description?: string;
  count?: number;
  small?: boolean;
}) {
  return (
    <>
      <span class="heading-text" classList={{ "heading-small": props.small }}>
        <span class="heading-row">
          <strong class="section-title">{props.title}</strong>
          <Show when={props.count !== undefined}>
            <span class="count">{props.count}</span>
          </Show>
        </span>
        <Show when={props.description}>
          <small class="section-description">{props.description}</small>
        </Show>
      </span>
      <span class="collection-chevron">
        <Icon name="arrow" />
      </span>
    </>
  );
}

// Keep the native modal open until its exit animation finishes.
export function createDialogMotion(
  element: Accessor<HTMLDialogElement>,
  open: Accessor<boolean>,
) {
  let motion: Animation | undefined;
  createEffect(() => {
    const dialog = element(),
      opening = open();
    if (opening && dialog.open && !dialog.hasAttribute("data-closing")) return;
    if (!opening && !dialog.open) return;
    const style = dialog.open ? getComputedStyle(dialog) : undefined;
    const from = {
      opacity: style?.opacity ?? "0",
      transform: style?.transform ?? "scale(.98)",
    };
    motion?.cancel();
    motion = undefined;
    if (opening && !dialog.open) dialog.showModal();
    dialog.toggleAttribute("data-closing", !opening);
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
      if (!opening) dialog.close();
      dialog.removeAttribute("data-closing");
      return;
    }
    const next = dialog.animate(
      [
        from,
        {
          opacity: opening ? "1" : "0",
          transform: opening ? "none" : "scale(.98)",
        },
      ],
      {
        duration: 120,
        easing: opening ? "ease-out" : "ease-in",
        fill: "forwards",
      },
    );
    motion = next;
    next.onfinish = () => {
      if (motion !== next) return;
      if (!opening) dialog.close();
      next.cancel();
      motion = undefined;
      dialog.removeAttribute("data-closing");
    };
  });
  onCleanup(() => {
    motion?.cancel();
    element().close();
  });
}

export function Modal(
  props: Omit<JSX.DialogHtmlAttributes<HTMLDialogElement>, "onClose"> & {
    open: boolean;
    onClose(): void;
  },
) {
  const [own, rest] = splitProps(props, ["open", "onClose"]);
  let dialog!: HTMLDialogElement;
  createDialogMotion(
    () => dialog,
    () => own.open,
  );
  return (
    <dialog
      {...rest}
      ref={dialog}
      onCancel={(event) => {
        event.preventDefault();
        own.onClose();
      }}
      onClick={(event) => {
        const r = dialog.getBoundingClientRect();
        if (
          event.target === dialog &&
          (event.clientX < r.left ||
            event.clientX > r.right ||
            event.clientY < r.top ||
            event.clientY > r.bottom)
        )
          own.onClose();
      }}
    />
  );
}

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
      <Show when={props.value}>
        <button
          type="button"
          class="search-clear"
          aria-label="Clear search"
          onClick={() => {
            props.onInput("");
            input.focus();
          }}
        >
          <Icon name="close" />
        </button>
      </Show>
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
export function Effects(props: { scope?: owner.EffectScope }) {
  const m = useMonitor();
  const settings = createMemo(() => {
    const view = m.view()!;
    const accounts = props.scope?.account
      ? [props.scope.account]
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
  help?: JSX.Element;
}) {
  const id = createUniqueId(),
    [shown, setShown] = createSignal(false);
  const help = () => props.help ?? props.field.help;
  return (
    <div class="field">
      <label for={id}>{props.field.label}</label>
      <Show
        when={props.field.multiline || props.field.json}
        fallback={
          <div class="secret-input">
            <input
              id={id}
              aria-describedby={help() ? `${id}-help` : undefined}
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
          aria-describedby={help() ? `${id}-help` : undefined}
          rows={6}
          disabled={props.disabled}
          value={props.value}
          onInput={(e) => props.onInput(e.currentTarget.value)}
        />
      </Show>
      <Show when={help()}>
        <p id={`${id}-help`} class="muted field-help">
          {help()}
        </p>
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
  target?: () => HTMLElement;
  icon?: boolean;
}) {
  const m = useMonitor();
  return (
    <button
      type="button"
      classList={{ "icon-button": props.icon }}
      aria-label={props.label ?? "Copy"}
      title={props.icon ? (props.label ?? "Copy") : undefined}
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
      <Show when={props.icon} fallback="Copy">
        <Icon name="copy" />
      </Show>
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
const SandboxTerminal = /* @__PURE__ */ lazy(() => import("./SandboxTerminal"));
const SHELL_MIN_WIDTH = 320;
export type ShellTarget = {
  name: string;
  message: string;
  open?: owner.ShellOpener;
};
export function ShellSplit(props: {
  shell?: ShellTarget;
  onClose: () => void;
  children: JSX.Element;
}) {
  const [width, setWidth] = createSignal("50%");
  return (
    <div class="shell-split">
      {props.children}
      <Show when={props.shell} keyed>
        {(current) => (
          <aside
            class="shell-pane"
            aria-label="Sandbox shell"
            style={{ "--shell-width": width() }}
          >
            <div
              class="shell-pane-resize"
              onPointerDown={(event) =>
                drag(event, (move) =>
                  setWidth(
                    `${Math.max(SHELL_MIN_WIDTH, Math.min(innerWidth - move.clientX, innerWidth - SHELL_MIN_WIDTH))}px`,
                  ),
                )
              }
            />
            <Show
              when={current.open}
              fallback={
                <div class="dialog-body">
                  <h1>{current.name}</h1>
                  <p>{current.message}</p>
                  <button onClick={props.onClose}>Close</button>
                </div>
              }
            >
              <SandboxTerminal
                open={current.open!}
                name={current.name}
                onClose={props.onClose}
              />
            </Show>
          </aside>
        )}
      </Show>
    </div>
  );
}
export function drag(event: PointerEvent, move: (event: PointerEvent) => void) {
  const target = event.currentTarget as HTMLElement;
  event.preventDefault();
  target.setPointerCapture(event.pointerId);
  target.addEventListener("pointermove", move);
  target.addEventListener(
    "lostpointercapture",
    () => target.removeEventListener("pointermove", move),
    { once: true },
  );
}
