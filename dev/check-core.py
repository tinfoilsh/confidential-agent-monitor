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
    "session", "signer", "tcp", "web",
}
MODULE = "github.com/tinfoilsh/confidential-agent-monitor/"
TINFOIL = ("github.com/tinfoilsh/tinfoil-go", MODULE + "cmd/")
FROZEN = re.compile("|".join(map(re.escape, (MODULE, "tinfoil-owner-http-v1", "tinfoil-owner-generation-v1", "X-Tinfoil-Session", "tinfoil owner session v1",
    "TINFOIL-MONITOR-STATE", '"tinfoil": {"": "tinfoil", "websearch": "tinfoil_websearch"}'))))
SKIP = {".git", ".dev", "node_modules", "vendor", "dist", "dist-hosted", "dist-static"}


def category(path):
    if path.name.endswith("_test.go"):
        return "tests"
    if path.parts[0] == "dev":
        return "tooling"
    if path.parts[0] == "cmd":
        return "protocols"
    if len(path.parts) > 2 and path.parts[0] == "connector" and path.parts[1] in PROTOCOLS:
        return "protocols"
    return "core"


def imports(source):
    # Import declarations only; examples in comments and string literals are not dependencies.
    for declaration in re.finditer(r'^import\s+(?:\([^)]*\)|[^\n]+)', source, re.M):
        yield from re.findall(r'"([^"\n]+)"', declaration[0])


def forbidden(path, dependency, main):
    if dependency in ("flag", "os/signal"):
        return not main and path.parts[0] != "dev"
    if dependency == MODULE + "ui":
        return not main
    if path.parts[0] == "cmd":
        return dependency.startswith(MODULE + "perimeter/internal/")
    if dependency.startswith(TINFOIL):
        return True
    if not dependency.startswith(MODULE):
        return False
    package = "/".join(path.parts[:-1])
    if package in ("core/netx", "core/sshx", "core/facts", "perimeter/credential", "perimeter/internal/sealedlog"):
        return True
    dependency = dependency.removeprefix(MODULE)
    concrete = dependency.startswith("connector/") and dependency.split("/")[1] in PROTOCOLS
    if package == "core":
        return dependency not in ("connector", "core/netx")
    if package == "core/identity":
        return dependency != "core/facts"
    if package == "core/frontdoor":
        return dependency not in ("core/facts", "core/identity", "core/netx", "core/sshx")
    if path.parts[0] == "connector":
        return dependency.startswith(("perimeter", "core/identity", "core/frontdoor", "connector/worker")) or dependency == "core"
    if package in ("perimeter/internal/tomledit", "perimeter/policy", "perimeter/presets"):
        return dependency != "core/facts"
    if package == "perimeter/policy/standard":
        return dependency not in ("core/facts", "perimeter/policy")
    if package == "perimeter/internal/authz":
        return dependency not in ("core/facts", "core/identity", "core/netx")
    if package == "perimeter/internal/config":
        return concrete or dependency in ("perimeter", "perimeter/monitor")
    if package == "perimeter":
        return concrete or dependency.startswith("perimeter/internal/")
    if package == "perimeter/monitor":
        return concrete or dependency.startswith("perimeter/policy/")
    if package.startswith("perimeter/internal/store"):
        return dependency.startswith(("perimeter/monitor", "perimeter/policy", "connector/worker")) or concrete
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tracked", action="store_true", help="inspect only Git-tracked files")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.tracked:
        tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).decode().split("\0")
        paths = [Path(p) for p in tracked if p.endswith(".go") and (root / p).is_file()]
    else:
        paths = [p.relative_to(root) for p in root.rglob("*.go") if not SKIP.intersection(p.relative_to(root).parts)]
    totals = dict.fromkeys(("core", "protocols", "tooling", "tests"), 0)
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
        if path.parts[0] not in ("cmd", "dev") and "tinfoil" in FROZEN.sub("", source).lower():
            violations.append(f"{path}: names tinfoil")
        deps = sorted(imports(source))
        graph[str(path)] = deps
        main = re.search(r'^package main$', source, re.M)
        for dependency in deps:
            if forbidden(path, dependency, main):
                violations.append(f"{path}: forbidden import {dependency}")
    totals["all_non_test_go"] = sum(totals[k] for k in ("core", "protocols", "tooling"))
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
    return bool(violations)


if __name__ == "__main__":
    sys.exit(main())
