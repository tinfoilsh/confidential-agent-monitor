import { Show, createEffect, createSignal, onCleanup, onMount } from "solid-js";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import * as owner from "./owner.js";
import { colorScheme } from "./theme";
import "./terminal.css";

// Matches the page background; light mode uses GitHub Light's ANSI colors,
// since xterm's defaults are made for a dark background.
const THEMES = {
  dark: { background: "#121212", foreground: "#fafafa" },
  light: {
    background: "#ffffff",
    foreground: "#24292f",
    cursor: "#24292f",
    cursorAccent: "#ffffff",
    selectionBackground: "#0969da33",
    black: "#24292f",
    red: "#cf222e",
    green: "#116329",
    yellow: "#4d2d00",
    blue: "#0969da",
    magenta: "#8250df",
    cyan: "#1b7c83",
    white: "#6e7781",
    brightBlack: "#57606a",
    brightRed: "#a40e26",
    brightGreen: "#1a7f37",
    brightYellow: "#633c01",
    brightBlue: "#218bff",
    brightMagenta: "#a475f9",
    brightCyan: "#3192aa",
    brightWhite: "#8c959f",
  },
};

export default function SandboxTerminal(props: {
  open: owner.ShellOpener;
  name: string;
  // Whether its tab is shown; a hidden terminal keeps its session.
  active: boolean;
}) {
  const [status, setStatus] = createSignal<
    "connecting" | "open" | "exited" | "failed"
  >("connecting");
  const [message, setMessage] = createSignal("");
  const terminal = new Terminal({
    cursorBlink: true,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    fontSize: 13,
    theme: THEMES[colorScheme()],
  });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  let screen!: HTMLDivElement, session: AbortController | undefined;
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
    // A hidden tab has no size, and fitting it would shrink the remote shell.
    const resized = new ResizeObserver(() => {
      if (screen.offsetWidth && screen.offsetHeight) fit.fit();
    });
    resized.observe(screen);
    onCleanup(() => resized.disconnect());
    void connect();
  });
  createEffect(() => {
    if (props.active) terminal.focus();
  });
  createEffect(() => {
    terminal.options.theme = THEMES[colorScheme()];
  });
  onCleanup(() => {
    session?.abort();
    terminal.dispose();
  });
  return (
    <section class="sandbox-terminal" aria-label={`Shell in ${props.name}`}>
      <header>
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
      </header>
      <div ref={screen} class="sandbox-terminal-screen" />
    </section>
  );
}
