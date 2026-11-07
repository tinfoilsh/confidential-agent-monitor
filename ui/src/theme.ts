import { createSignal } from "solid-js";

export const THEME = "monitor-theme";

// The scheme applyTheme last chose, for widgets that draw their own colors.
const [scheme, setScheme] = createSignal<"light" | "dark">("light");
export const colorScheme = scheme;

export function savedTheme() {
  try {
    return localStorage.getItem(THEME) || "system";
  } catch {
    return "system";
  }
}
export function applyTheme(
  theme: string,
  dark = matchMedia("(prefers-color-scheme: dark)").matches,
) {
  const resolved = theme === "system" ? (dark ? "dark" : "light") : theme;
  document.documentElement.dataset.theme = resolved;
  setScheme(resolved === "dark" ? "dark" : "light");
}
