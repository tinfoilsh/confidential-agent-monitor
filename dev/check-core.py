#!/usr/bin/env python3
"""Count physical Go lines by responsibility and check Monitor's package boundaries."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


PROTOCOLS = {
    "browser", "email", "mcp", "mqtt", "nats", "postgres", "redis",
    "session", "signer", "tcp", "tinfoil", "web",
}
MODULE = "github.com/tinfoilsh/monitor/"
SKIP = {".git", ".dev", "node_modules", "vendor", "dist", "dist-hosted", "dist-static"}


def category(path):
    if path.name.endswith("_test.go"):
        return "tests"
    if path.parts[0] == "dev":
        return "tooling"
    if path.parts[:3] == ("internal", "tinfoil", "sandbox"):
        return "sandbox"
    if len(path.parts) > 2 and path.parts[0] == "connector" and path.parts[1] in PROTOCOLS:
        return "protocols"
    return "core"


def imports(source):
    # Import declarations only; examples in comments and string literals are not dependencies.
    for declaration in re.finditer(r'^import\s+(?:\([^)]*\)|[^\n]+)', source, re.M):
        yield from re.findall(r'"([^"\n]+)"', declaration[0])


def forbidden(path, dependency):
    if not dependency.startswith(MODULE):
        return False
    dependency = dependency.removeprefix(MODULE)
    concrete = dependency.startswith("connector/") and dependency.split("/")[1] in PROTOCOLS
    if path.parts[0] == "facts":
        return dependency.startswith(("internal/", "connector", "presets"))
    if path.parts[:2] == ("internal", "policy"):
        return dependency != "facts"
    if path.parts[0] == "connector":
        return dependency.startswith("internal/")
    if path.parts[:2] == ("internal", "config"):
        return concrete or dependency.startswith(("internal/policy", "internal/monitor", "internal/tinfoil"))
    if path.parts[:2] == ("internal", "monitor"):
        return concrete
    if path.parts[:2] == ("internal", "store"):
        return dependency.startswith(("internal/monitor", "internal/policy", "internal/worker")) or concrete
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true", help="enforce boundaries, formatting and 4,999 core lines")
    parser.add_argument("--tracked", action="store_true", help="inspect only Git-tracked files")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.tracked:
        tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).decode().split("\0")
        paths = [Path(p) for p in tracked if p.endswith(".go") and (root / p).is_file()]
    else:
        paths = [p.relative_to(root) for p in root.rglob("*.go") if not SKIP.intersection(p.relative_to(root).parts)]
    totals = dict.fromkeys(("core", "protocols", "sandbox", "tooling", "tests"), 0)
    files, graph, violations, generated = {}, {}, [], {}
    for path in sorted(paths):
        source = (root / path).read_text()
        lines = len(source.splitlines())
        kind = category(path)
        totals[kind] += lines
        files[str(path)] = {"category": kind, "lines": lines}
        if re.search(r'^// Code generated .* DO NOT EDIT\.$', source, re.M):
            generated[str(path)] = lines
        if kind == "tests":
            continue
        deps = sorted(imports(source))
        graph[str(path)] = deps
        for dependency in deps:
            if forbidden(path, dependency):
                violations.append(f"{path}: forbidden import {dependency}")
    totals["all_non_test_go"] = sum(totals[k] for k in ("core", "protocols", "sandbox", "tooling"))
    totals["production_runtime_go"] = totals["all_non_test_go"] - totals["tooling"]
    totals["generated_go"] = sum(generated.values())
    rego = {str(p.relative_to(root)): len(p.read_text().splitlines()) for p in root.rglob("*.rego") if not SKIP.intersection(p.relative_to(root).parts)}
    result = {"root": str(root), "scope": "tracked" if args.tracked else "filesystem including ignored source", "totals": totals, "non_go_policy": rego, "files": files, "generated": generated, "imports": graph, "boundary_violations": violations}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{root} ({result['scope']})")
        for name, lines in totals.items():
            print(f"{name:24} {lines:6}")
        for path, lines in rego.items():
            print(f"{path:24} {lines:6}")
        print(f"boundary violations: {len(violations)}")
        for violation in violations:
            print(violation)
    if args.check:
        runtime = [str(root / p) for p in paths if category(p) != "tooling"]
        unformatted = subprocess.check_output(["gofmt", "-l", *runtime]).decode().splitlines() if runtime else []
        for path in unformatted:
            print(f"not gofmt: {path}", file=sys.stderr)
        return bool(totals["core"] > 4999 or violations or unformatted)
    return False


if __name__ == "__main__":
    sys.exit(main())
