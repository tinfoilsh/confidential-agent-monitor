export const THEME = "monitor-theme";

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
  document.documentElement.dataset.theme =
    theme === "system" ? (dark ? "dark" : "light") : theme;
}
