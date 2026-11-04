import { Show, createSignal, lazy, type JSX } from "solid-js";
import type { ShellOpener } from "../owner";

const SandboxTerminal = lazy(() => import("./SandboxTerminal"));
const SHELL_MIN_WIDTH = 320;
export type ShellTarget = {
  name: string;
  open: ShellOpener;
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
            <SandboxTerminal
              open={current.open}
              name={current.name}
              onClose={props.onClose}
            />
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
