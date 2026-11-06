import {
  For,
  Show,
  createEffect,
  createMemo,
  createResource,
  createSignal,
  createUniqueId,
  lazy,
  on,
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
export type IconName = keyof typeof icons;

export function Icon(props: { name: IconName }) {
  return <span class="icon" aria-hidden="true" innerHTML={icons[props.name]} />;
}
export function Loading(props: { label: string }) {
  return (
    <p class="loading-status" role="status">
      <span class="loading-spinner" aria-hidden="true" />
      {props.label}
    </p>
  );
}

export function AuthScreen(props: {
  id?: string;
  title?: JSX.Element;
  description?: JSX.Element;
  account?: string;
  children: JSX.Element;
}) {
  const titleId = createUniqueId();
  return (
    <main
      id={props.id}
      class="auth"
      aria-labelledby={props.title ? titleId : undefined}
    >
      <Show when={props.title}>
        <h1 id={titleId}>{props.title}</h1>
      </Show>
      <Show when={props.description}>
        <p class="auth-description">{props.description}</p>
      </Show>
      <Show when={props.account}>
        {(account) => (
          <p class="auth-account">
            <Icon name="person" />
            <span>
              Signed in as <strong>{account()}</strong>
            </span>
          </p>
        )}
      </Show>
      {props.children}
    </main>
  );
}

export function AuthCard(props: {
  icon?: JSX.Element;
  title?: JSX.Element;
  children: JSX.Element;
}) {
  return (
    <section class="auth-card">
      <Show when={props.icon}>
        <span class="auth-icon">{props.icon}</span>
      </Show>
      <Show when={props.title}>
        <h2>{props.title}</h2>
      </Show>
      {props.children}
    </section>
  );
}

export function AuthOptions(props: { title?: string; children: JSX.Element }) {
  return (
    <section class="auth-card auth-options">
      <h2>{props.title ?? "Having problems?"}</h2>
      <ul>{props.children}</ul>
    </section>
  );
}

export function AuthTip(props: { children: JSX.Element }) {
  return (
    <p class="auth-tip">
      <strong>Tip:</strong> {props.children}
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

export function ConnectorIcon(props: { preset?: string; connection?: string }) {
  const m = useMonitor();
  const icon = createMemo(() =>
    owner.connectorIcon(
      m.icons(),
      props.preset ??
        m.view()?.config.connections?.[props.connection!]?.preset ??
        "",
      import.meta.env.BASE_URL,
    ),
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
}) {
  return (
    <header class="heading-text">
      <h3 class="section-title">{props.title}</h3>
      <Show when={props.description}>
        <p class="section-description">{props.description}</p>
      </Show>
    </header>
  );
}

export function DisclosureHeading(props: {
  title: string;
  description?: string;
  small?: boolean;
}) {
  return (
    <>
      <span class="heading-text" classList={{ "heading-small": props.small }}>
        <span class="heading-row">
          <strong class="section-title">{props.title}</strong>
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
    onClose?(): void;
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
        own.onClose?.();
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
          own.onClose?.();
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
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (!open) return;
        setExpanded(true);
        setVisited(true);
        element.open = true;
      },
    ),
  );
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
export function LazyDetails(props: {
  class?: string;
  summaryClass?: string;
  label?: string;
  summary: JSX.Element;
  children: () => JSX.Element;
}) {
  const [visited, setVisited] = createSignal(false);
  return (
    <details
      class={props.class}
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
  icon?: IconName;
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
  onEnter?: () => void;
}) {
  let input!: HTMLInputElement;
  onMount(() => input.focus());
  return (
    <div class="search-field">
      <Icon name="search" />
      <input
        ref={input}
        type="search"
        autofocus
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
export function Field(props: {
  field: owner.PresetField;
  value: string;
  onInput: (value: string) => void;
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
export function RuleText(props: { rule: owner.Rule; children?: JSX.Element }) {
  const m = useMonitor();
  const scope = () =>
    owner.scopeText(m.view()!, props.rule.connection, props.rule.scope);
  return (
    <span>
      <strong>{owner.ruleTitle(m.view()!, props.rule)}</strong>
      <small class="rule-scope">
        {(() => {
          const text = scope();
          return typeof text === "string" ? (
            <code title={text}>{text}</code>
          ) : (
            <For each={text} fallback="Any request">
              {(t) => <code title={t}>{t}</code>}
            </For>
          );
        })()}
      </small>
      {props.children}
    </span>
  );
}
export function RemoveRule(props: { agent: string; id: string }) {
  const m = useMonitor();
  return (
    <button
      disabled={m.busy()}
      onClick={(e) => {
        e.preventDefault();
        void m.edit(owner.edits.removeRule(props.agent, props.id));
      }}
    >
      Remove
    </button>
  );
}
export function createRecord<
  S extends { api: owner.OwnerApi; id: string; segment?: string },
>(source: Accessor<S | undefined>) {
  const lifetime = new AbortController();
  onCleanup(() => lifetime.abort());
  const key = createMemo(source, undefined, {
    equals: (a, b) =>
      !!a &&
      !!b &&
      (Object.keys(b) as (keyof S)[]).every((field) => a[field] === b[field]),
  });
  return createResource(key, (s) =>
    s.segment
      ? s.api.archived(s.segment, s.id, lifetime.signal)
      : s.api.request(s.id, lifetime.signal),
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
  open?: owner.ShellOpener;
};
export function ShellSplit(props: {
  shell?: ShellTarget;
  onClose: () => void;
  children: JSX.Element;
}) {
  const [width, setWidth] = createSignal("50%");
  let split!: HTMLDivElement;
  return (
    <div class="shell-split" ref={split}>
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
                drag(event, (move) => {
                  const box = split.getBoundingClientRect();
                  setWidth(
                    `${Math.max(SHELL_MIN_WIDTH, Math.min(box.right - move.clientX, box.width - SHELL_MIN_WIDTH))}px`,
                  );
                })
              }
            />
            <Show
              when={current.open}
              fallback={
                <div class="dialog-body">
                  <h1>{current.name}</h1>
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
