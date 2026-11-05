import { expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const src = fileURLToPath(new URL("../src/", import.meta.url));
const ts = new Bun.Transpiler({ loader: "ts" });
const tsx = new Bun.Transpiler({ loader: "tsx" });

// Follow static AND lazy imports. This guards the shipped module boundary, not
// just App's direct imports: shared components must not pull Terminal back in.
function dependencies(entry: string) {
  const files = new Set<string>();
  const packages = new Set<string>();
  function visit(file: string) {
    if (files.has(file)) return;
    files.add(file);
    if (!/\.[jt]sx?$/.test(file)) return;
    const { imports } = (file.endsWith(".tsx") ? tsx : ts).scan(
      readFileSync(file, "utf8"),
    );
    for (const { path } of imports) {
      if (!path.startsWith(".")) {
        packages.add(path);
        continue;
      }
      const base = resolve(
        dirname(file),
        path.split("?")[0].replace(/\.js$/, ""),
      );
      const next = [
        base,
        base + ".ts",
        base + ".tsx",
        base + ".js",
        join(base, "index.ts"),
        join(base, "index.tsx"),
        join(base, "index.js"),
      ].find(
        (candidate) => existsSync(candidate) && statSync(candidate).isFile(),
      );
      if (!next) throw new Error(`Unresolved import ${path} from ${file}`);
      visit(next);
    }
  }
  visit(resolve(src, entry));
  return { files, packages };
}

test("dependency traversal follows directory indexes and their transitive imports", () => {
  const directory = mkdtempSync(join(tmpdir(), "monitor-boundary-"));
  try {
    mkdirSync(join(directory, "terminal"));
    writeFileSync(join(directory, "entry.ts"), 'import "./terminal";');
    writeFileSync(
      join(directory, "terminal/index.ts"),
      'import "./implementation";',
    );
    writeFileSync(
      join(directory, "terminal/implementation.ts"),
      "export const value = 1;",
    );
    const graph = dependencies(join(directory, "entry.ts"));
    expect(graph.files.has(join(directory, "terminal/index.ts"))).toBe(true);
    expect(graph.files.has(join(directory, "terminal/implementation.ts"))).toBe(
      true,
    );
    expect(graph.files.has(join(directory, "terminal"))).toBe(false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("shared Monitor UI has no Terminal, account, attestation or shell dependencies", () => {
  const graph = dependencies("monitor/App.tsx");
  expect(
    [...graph.files].filter((file) =>
      file.startsWith(resolve(src, "terminal") + "/"),
    ),
  ).toEqual([]);
  expect(
    [...graph.packages].filter((name) =>
      /^(?:@clerk\/|@tinfoilsh\/|@xterm\/|tinfoil$)/.test(name),
    ),
  ).toEqual([]);
  // Exercise the recursive/lazy walk, so silently ignoring lazy imports cannot
  // make the boundary test pass when a Settings screen pulls in host code.
  expect(graph.files.has(resolve(src, "monitor/Settings.tsx"))).toBe(true);
  expect(graph.files.has(resolve(src, "monitor/owner.ts"))).toBe(true);
});

test("Terminal composes the same Monitor app and owns the sandbox shell", () => {
  const graph = dependencies("terminal/MonitorWorkspace.tsx");
  expect(graph.files.has(resolve(src, "monitor/App.tsx"))).toBe(true);
  expect(graph.files.has(resolve(src, "terminal/SandboxTerminal.tsx"))).toBe(
    true,
  );
  expect(graph.files.has(resolve(src, "terminal/sandboxes.ts"))).toBe(true);
  expect(graph.packages.has("@xterm/xterm")).toBe(true);
});
