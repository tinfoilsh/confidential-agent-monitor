#!/usr/bin/env python3
"""Count physical Go lines and enforce the composition-root dependency graph."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


PROTOCOLS = {
    "browser", "email", "mcp", "mqtt", "nats", "postgres", "redis",
    "session", "signer", "tcp", "web",
}
MODULE = "github.com/tinfoilsh/confidential-agent-monitor/"
CEDAR_PACKAGES = {"core", "core/facts", "connector/tcp", "core/transport/sshtransport", "core/transport/netx"}
# Every library may import these; each of them may import only those before it.
SHARED = ("core/facts", "core/transport/netx")
LIBRARIES = {
    "core", "core/identity", "core/admission", "core/approval", "core/sealedlog",
    "core/certificates", "core/attestation", "core/transport/sshtransport",
    "core/transport/noisetransport", "connector/credential", "connector/catalog",
    "connector/slots", "connector/worker", "cmd/perimeter/format",
    "cmd/perimeter/messages", "ui", *SHARED,
} | {"connector/" + name for name in PROTOCOLS}
SKIP = {".git", ".dev", "node_modules", "vendor", "dist", "dist-hosted", "dist-static"}


def category(path):
    if path.name.endswith("_test.go"):
        return "tests"
    if path.parts[0] == "dev":
        return "tooling"
    if path.parts[0] == "cmd":
        return "application"
    if len(path.parts) > 2 and path.parts[0] == "connector" and path.parts[1] in PROTOCOLS:
        return "protocols"
    return "core"


def imports(source):
    # Import declarations only; examples in comments and string literals are not dependencies.
    for declaration in re.finditer(r'^import\s+(?:\([^)]*\)|[^\n]+)', source, re.M):
        yield from re.findall(r'"([^"\n]+)"', declaration[0])


def forbidden(path, dependency, main):
    if path.parts[:2] == ("cmd", "other"):
        if dependency.startswith("github.com/open-policy-agent/"):
            return True
        if dependency.startswith(MODULE) and dependency.removeprefix(MODULE) not in CEDAR_PACKAGES:
            return True
    if main:
        return False
    if dependency in ("flag", "os/signal"):
        return True
    if not dependency.startswith(MODULE):
        return False
    package, target = "/".join(path.parts[:-1]), dependency.removeprefix(MODULE)
    if target in SHARED:
        return package in SHARED and SHARED.index(package) <= SHARED.index(target)
    # Connectors build on the primitives under core/, never on the table in core itself.
    return not (package.startswith("connector/") and (target == "connector/slots" or target.startswith("core/")))


def cedar_dependencies(root, violations):
    command = root / "cmd" / "other"
    if not (command / "go.mod").is_file():
        return []
    result = subprocess.run(
        ["go", "list", "-mod=readonly", "-deps", "."], cwd=command,
        env={**os.environ, "GOWORK": "off"}, capture_output=True, text=True,
    )
    if result.returncode:
        violations.append("cmd/other: cannot verify compiled dependencies: " + result.stderr.strip())
        return []
    dependencies = []
    for dependency in result.stdout.splitlines():
        if dependency.startswith(MODULE):
            package = dependency.removeprefix(MODULE)
            if package != "cmd/other":
                dependencies.append(package)
                if package not in CEDAR_PACKAGES:
                    violations.append(f"cmd/other: forbidden transitive dependency {dependency}")
        elif dependency.startswith("github.com/open-policy-agent/"):
            violations.append(f"cmd/other: forbidden transitive dependency {dependency}")
    return sorted(dependencies)


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
    totals = dict.fromkeys(("core", "protocols", "application", "tooling", "tests"), 0)
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
        main = re.search(r'^package main$', source, re.M)
        package = "/".join(path.parts[:-1])
        if not main and package not in LIBRARIES:
            violations.append(f"{path}: package is outside the approved dependency graph")
        if package == "core/facts" and re.search(
            r'^type\s+(Label|Context|Vocabulary|Obligations)\b|^func\s+\([^)]*\)\s*Resolve\(', source, re.M
        ):
            violations.append(f"{path}: facts must not define the application's access model")
        for dependency in deps:
            if forbidden(path, dependency, main):
                violations.append(f"{path}: forbidden import {dependency}")
    totals["all_non_test_go"] = sum(totals[k] for k in ("core", "protocols", "application", "tooling"))
    totals["production_runtime_go"] = totals["all_non_test_go"] - totals["tooling"]
    totals["generated_go"] = sum(generated.values())
    rego = {str(p.relative_to(root)): len(p.read_text().splitlines()) for p in root.rglob("*.rego") if not SKIP.intersection(p.relative_to(root).parts)}
    cedar = cedar_dependencies(root, violations)
    result = {"root": str(root), "scope": "tracked" if args.tracked else "filesystem including ignored source", "totals": totals, "non_go_policy": rego, "files": files, "generated": generated, "imports": graph, "cedar_dependencies": cedar, "boundary_violations": violations}
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
