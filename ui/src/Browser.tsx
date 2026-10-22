import { For, Show, createSignal, onCleanup, onMount } from "solid-js";
import type { BrowserFrame, Json } from "./owner.js";
import { useMonitor } from "./monitor";

export function Browser(props: { name: string; active: boolean }) {
  const m = useMonitor(),
    lifetime = new AbortController();
  const [frame, setFrame] = createSignal<BrowserFrame>(),
    [error, setError] = createSignal("");
  const [changing, setChanging] = createSignal(false),
    [url, setURL] = createSignal(""),
    [text, setText] = createSignal("");
  let address!: HTMLInputElement,
    shot!: HTMLImageElement,
    screen!: HTMLDivElement;
  let timer: ReturnType<typeof setTimeout>,
    polling = false,
    sequence = 0,
    accepted = 0;
  const queue: Record<string, Json | undefined>[] = [];
  const ready = () => frame()?.owner && frame()?.frame && !changing();
  const active = () =>
    props.active && !lifetime.signal.aborted && !document.hidden;
  async function request(body?: Record<string, Json | undefined>) {
    const revision = ++sequence;
    if (body) accepted = revision;
    const next = await m.api()!.browser(props.name, body, lifetime.signal);
    if (lifetime.signal.aborted || revision < accepted) return;
    accepted = revision;
    setFrame((previous) => ({
      ...next,
      screenshot: next.screenshot ?? previous?.screenshot,
    }));
    setError("");
    if (document.activeElement !== address) setURL(next.url ?? "");
  }
  function schedule() {
    clearTimeout(timer);
    if (!lifetime.signal.aborted) timer = setTimeout(poll, 1000);
  }
  async function poll() {
    if (!active() || polling || queue.length || changing()) {
      schedule();
      return;
    }
    polling = true;
    const revision = accepted;
    try {
      await request();
    } catch (cause) {
      if (!lifetime.signal.aborted && revision === accepted)
        setError(String(cause));
    } finally {
      polling = false;
      schedule();
    }
  }
  async function control() {
    if (changing()) return;
    setChanging(true);
    queue.splice(1);
    try {
      await request({ action: frame()?.owner ? "resume" : "pause" });
    } catch (cause) {
      if (!lifetime.signal.aborted) setError(String(cause));
    } finally {
      setChanging(false);
      schedule();
    }
  }
  function act(body: Record<string, Json | undefined>) {
    if (body.action === "dialog" ? !frame()?.owner || changing() : !ready())
      return;
    queue.push({ ...body, frame: frame()?.frame });
    if (queue.length === 1) void drain();
  }
  async function drain() {
    while (queue.length && !lifetime.signal.aborted) {
      try {
        await request(queue[0]);
      } catch (cause) {
        queue.splice(1);
        if (!lifetime.signal.aborted) setError(String(cause));
      }
      queue.shift();
    }
    schedule();
  }
  const point = (event: MouseEvent | WheelEvent) => {
    const bounds = shot.getBoundingClientRect(),
      scale = shot.naturalWidth / bounds.width;
    return {
      x: (event.clientX - bounds.left) * scale,
      y: (event.clientY - bounds.top) * scale,
    };
  };
  function key(event: KeyboardEvent) {
    if (!ready() || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key.length === 1) {
      event.preventDefault();
      act({ action: "type", text: event.key });
    } else if (
      [
        "Enter",
        "Tab",
        "Backspace",
        "Escape",
        "Delete",
        "ArrowLeft",
        "ArrowRight",
        "ArrowUp",
        "ArrowDown",
        "Home",
        "End",
        "PageUp",
        "PageDown",
      ].includes(event.key)
    ) {
      event.preventDefault();
      act({ action: "key", key: event.key });
    }
  }
  onMount(() => {
    void poll();
    const wheel = (event: WheelEvent) => {
      if (ready() && shot) {
        event.preventDefault();
        act({
          action: "scroll",
          ...point(event),
          dy: event.deltaY * (event.deltaMode ? 40 : 1),
        });
      }
    };
    screen.addEventListener("wheel", wheel, { passive: false });
    onCleanup(() => screen.removeEventListener("wheel", wheel));
  });
  onCleanup(() => {
    lifetime.abort();
    clearTimeout(timer);
    queue.length = 0;
  });
  return (
    <section class="account-card live" aria-label="Browser">
      <div class="section-heading">
        <h2>Browser</h2>
        <span role="status">
          {!frame()
            ? "Connecting…"
            : frame()?.owner
              ? "You have control. The agent is paused."
              : "The agent has control."}
        </span>
        <button
          class="primary"
          disabled={changing()}
          onClick={() => void control()}
        >
          {changing()
            ? "Updating control…"
            : frame()?.owner
              ? "Return to agent"
              : "Pause and take control"}
        </button>
      </div>
      <fieldset class="live-body" disabled={!ready()}>
        <form
          class="live-bar"
          onSubmit={(e) => {
            e.preventDefault();
            if (url().trim())
              act({
                action: "navigate",
                url: url().includes("://")
                  ? url().trim()
                  : "https://" + url().trim(),
              });
            screen.focus();
          }}
        >
          <button type="button" onClick={() => act({ action: "back" })}>
            Back
          </button>
          <input
            ref={address}
            aria-label="Address"
            value={url()}
            onInput={(e) => setURL(e.currentTarget.value)}
          />
          <button>Go</button>
        </form>
        <div class="live-tabs" role="group" aria-label="Tabs">
          <For each={frame()?.tabs?.map((t) => t.id)}>
            {(id) => {
              const tab = () => frame()?.tabs?.find((t) => t.id === id);
              return (
                <button
                  aria-pressed={tab()?.active}
                  title={tab()?.url}
                  onClick={() => act({ action: "tab", tab: id })}
                >
                  {tab()?.title || tab()?.url}
                </button>
              );
            }}
          </For>
        </div>
        <div
          ref={screen}
          class="live-screen"
          tabIndex={0}
          aria-label="Page. While you have control, click, scroll and type here."
          onKeyDown={key}
        >
          <Show when={frame()?.screenshot}>
            <img
              ref={shot}
              src={`data:image/jpeg;base64,${frame()?.screenshot}`}
              alt={frame()?.url ?? "Browser page"}
              onClick={(e) => {
                screen.focus();
                act({ action: "click", ...point(e) });
              }}
            />
          </Show>
        </div>
        <form
          class="live-bar"
          onSubmit={(e) => {
            e.preventDefault();
            if (text()) act({ action: "type", text: text() });
            setText("");
          }}
        >
          <input
            aria-label="Text to type"
            value={text()}
            onInput={(e) => setText(e.currentTarget.value)}
          />
          <button>Type</button>
          <For each={["Enter", "Tab", "Backspace", "Escape"]}>
            {(key) => (
              <button type="button" onClick={() => act({ action: "key", key })}>
                {key}
              </button>
            )}
          </For>
        </form>
      </fieldset>
      <Show when={error() || frame()?.error}>
        <p role="alert">
          {error() ||
            "Could not show the page. If it opened a dialog, accept or dismiss it."}
        </p>
      </Show>
      <fieldset class="form-actions" disabled={!frame()?.owner || changing()}>
        <legend>Page dialog</legend>
        <button onClick={() => act({ action: "dialog", accept: true })}>
          Accept
        </button>
        <button onClick={() => act({ action: "dialog", accept: false })}>
          Dismiss
        </button>
      </fieldset>
    </section>
  );
}
