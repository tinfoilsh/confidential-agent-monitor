import {
  For,
  Show,
  createEffect,
  createSignal,
  on,
  onMount,
  onCleanup,
  type JSX,
} from "solid-js";
import { Dynamic } from "solid-js/web";
import "./TabBar.css";

export type TabOption<T extends string> = {
  value: T;
  label: JSX.Element;
  // Page tabs link to their view; options without one are buttons.
  href?: string;
  title?: string;
  ariaLabel?: string;
};

// An inherited value shows a faint pill; no value (a mixed group) shows none.
export function TabBar<T extends string>(props: {
  label: string;
  options: TabOption<T>[];
  value: T | null | undefined;
  inherited?: T;
  class?: string;
  compact?: boolean;
  onChange?: (value: T) => void;
}) {
  const tabs = new Map<T, HTMLElement>();
  const [pill, setPill] = createSignal<{ left: number; width: number }>();
  const [ready, setReady] = createSignal(false);
  let track!: HTMLElement;
  let resized: ResizeObserver | undefined;
  const shown = () => props.value ?? props.inherited;
  const place = () => {
    const value = shown();
    const tab = value == null ? undefined : tabs.get(value);
    setPill(
      tab?.offsetWidth
        ? { left: tab.offsetLeft, width: tab.offsetWidth }
        : undefined,
    );
    if (tab?.offsetWidth) {
      const padding = parseFloat(getComputedStyle(track).paddingLeft);
      const left = tab.offsetLeft - padding;
      const right = tab.offsetLeft + tab.offsetWidth + padding;
      if (
        left < track.scrollLeft ||
        tab.offsetWidth > track.clientWidth - padding * 2
      ) {
        track.scrollLeft = left;
      } else if (right > track.scrollLeft + track.clientWidth) {
        track.scrollLeft = right - track.clientWidth;
      }
    }
  };
  createEffect(on([shown, () => props.options], place));
  onMount(() => {
    let mounted = true;
    resized = new ResizeObserver(place);
    resized.observe(track);
    for (const tab of tabs.values()) resized.observe(tab);
    place();
    void document.fonts.ready.then(() => {
      if (mounted) place();
    });
    // The pill appears in place, then slides between options.
    const frame = requestAnimationFrame(() => setReady(true));
    onCleanup(() => {
      mounted = false;
      resized?.disconnect();
      cancelAnimationFrame(frame);
    });
  });
  const register = (value: T, element: HTMLElement) => {
    tabs.set(value, element);
    resized?.observe(element);
    onCleanup(() => {
      resized?.unobserve(element);
      if (tabs.get(value) === element) tabs.delete(value);
    });
  };
  const keyboard = (event: KeyboardEvent, value: T) => {
    const options = props.options;
    const index = options.findIndex((option) => option.value === value);
    let next: number;
    switch (event.key) {
      case "ArrowRight":
        next = (index + 1) % options.length;
        break;
      case "ArrowLeft":
        next = (index - 1 + options.length) % options.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = options.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    const option = options[next];
    if (!option) return;
    tabs.get(option.value)?.focus();
    if (!option.href) props.onChange?.(option.value);
  };
  const links = () => props.options.some((option) => option.href);
  return (
    <Dynamic
      component={links() ? "nav" : "span"}
      ref={track}
      class={`tab-bar ${props.class ?? ""}`}
      classList={{
        ready: ready(),
        compact: props.compact,
        inherited: props.value == null && props.inherited != null,
      }}
      role={links() ? undefined : "group"}
      aria-label={props.label}
    >
      <Show when={pill()}>
        {(at) => (
          <span
            class="tab-bar-pill"
            aria-hidden="true"
            style={{
              transform: `translateX(${at().left}px)`,
              width: `${at().width}px`,
            }}
          />
        )}
      </Show>
      <For each={props.options}>
        {(option) =>
          option.href ? (
            <a
              ref={(el) => register(option.value, el)}
              href={option.href}
              classList={{ shown: shown() === option.value }}
              aria-current={props.value === option.value ? "page" : undefined}
              aria-label={option.ariaLabel}
              title={option.title}
              onKeyDown={(event) => keyboard(event, option.value)}
            >
              {option.label}
            </a>
          ) : (
            <button
              ref={(el) => register(option.value, el)}
              type="button"
              classList={{ shown: shown() === option.value }}
              aria-pressed={props.value === option.value}
              aria-label={option.ariaLabel}
              title={option.title}
              onKeyDown={(event) => keyboard(event, option.value)}
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                props.onChange?.(option.value);
              }}
            >
              {option.label}
            </button>
          )
        }
      </For>
    </Dynamic>
  );
}
