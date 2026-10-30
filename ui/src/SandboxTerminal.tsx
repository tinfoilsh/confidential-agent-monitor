import { Show, createSignal, onCleanup, onMount } from "solid-js";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { Icon, drag } from "./components";
import * as owner from "./owner.js";
import "./terminal.css";

export default function SandboxTerminal(props: {
  open: owner.ShellOpener;
  name: string;
  onClose: () => void;
}) {
  const [status, setStatus] = createSignal<
    "connecting" | "open" | "exited" | "failed"
  >("connecting");
  const [message, setMessage] = createSignal("");
  const [floating, setFloating] = createSignal(false);
  const terminal = new Terminal({
    cursorBlink: true,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    fontSize: 13,
    theme: { background: "#121212", foreground: "#fafafa" },
  });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  let screen!: HTMLDivElement, session: AbortController | undefined;
  let panel!: HTMLElement;
  let shell: owner.Shell | undefined;
  const fail = (cause: unknown) => {
    shell = undefined;
    setStatus("failed");
    setMessage(cause instanceof Error ? cause.message : String(cause));
  };
  const connect = async () => {
    session?.abort();
    const current = (session = new AbortController());
    shell = undefined;
    terminal.reset();
    setStatus("connecting");
    setMessage("");
    try {
      const size = { cols: terminal.cols, rows: terminal.rows };
      const opened = await props.open(
        size,
        {
          output: (data) => terminal.write(data),
          exit: (code) => {
            shell = undefined;
            setStatus("exited");
            setMessage(
              code === undefined
                ? "Session closed."
                : `Exited with code ${code}.`,
            );
          },
          error: fail,
        },
        current.signal,
      );
      if (current.signal.aborted || status() !== "connecting") return;
      shell = opened;
      setStatus("open");
      if (terminal.cols !== size.cols || terminal.rows !== size.rows)
        shell.resize(terminal.cols, terminal.rows);
      terminal.focus();
    } catch (cause) {
      if (!current.signal.aborted) fail(cause);
    }
  };
  const encoder = new TextEncoder();
  terminal.onData((data) => shell?.input(encoder.encode(data)));
  terminal.onBinary((data) =>
    shell?.input(Uint8Array.from(data, (c) => c.charCodeAt(0))),
  );
  terminal.onResize(({ cols, rows }) => shell?.resize(cols, rows));
  onMount(() => {
    terminal.open(screen);
    const webgl = new WebglAddon();
    webgl.onContextLoss(() => webgl.dispose());
    terminal.loadAddon(webgl);
    fit.fit();
    const resized = new ResizeObserver(() => fit.fit());
    resized.observe(screen);
    onCleanup(() => resized.disconnect());
    void connect();
  });
  onCleanup(() => {
    session?.abort();
    terminal.dispose();
  });
  return (
    <section
      ref={panel}
      class="sandbox-terminal"
      classList={{ floating: floating() }}
      aria-label={`Shell in ${props.name}`}
    >
      <header
        onPointerDown={(event) => {
          if (!floating() || (event.target as Element).closest("button"))
            return;
          const { left, top } = panel.getBoundingClientRect();
          const x = event.clientX - left;
          const y = event.clientY - top;
          drag(event, (move) => {
            panel.style.left = `${Math.max(0, Math.min(move.clientX - x, innerWidth - panel.offsetWidth))}px`;
            panel.style.top = `${Math.max(0, Math.min(move.clientY - y, innerHeight - panel.offsetHeight))}px`;
          });
        }}
      >
        <strong title={props.name}>{props.name}</strong>
        <span role="status">
          {status() === "connecting"
            ? "Connecting…"
            : status() === "open"
              ? "Connected"
              : message()}
        </span>
        <Show when={status() === "exited" || status() === "failed"}>
          <button type="button" onClick={() => void connect()}>
            Reconnect
          </button>
        </Show>
        <button
          type="button"
          class="dialog-close icon-button"
          aria-label={floating() ? "Dock shell" : "Pop out shell"}
          aria-pressed={floating()}
          onClick={() => {
            panel.removeAttribute("style");
            setFloating(!floating());
          }}
        >
          <Icon name={floating() ? "dock" : "popout"} />
        </button>
        <button
          type="button"
          class="dialog-close icon-button"
          aria-label="Close shell"
          onClick={() => {
            session?.abort();
            props.onClose();
          }}
        >
          <Icon name="close" />
        </button>
      </header>
      <div ref={screen} class="sandbox-terminal-screen" />
    </section>
  );
}
