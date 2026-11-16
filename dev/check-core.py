#!/usr/bin/env python3
"""Run the architecture checker from this checkout, independent of go.work."""

import argparse
import os
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("root", nargs="?", type=Path, default=root)
parser.add_argument("--tracked", action="store_true", help="inspect tracked source only")
parser.add_argument("--json", action="store_true", help="emit the complete report as JSON")
parser.add_argument("--base", help="compare package growth against this explicit Git revision")
args = parser.parse_args()
options = [flag for flag in ("--tracked", "--json") if getattr(args, flag[2:])]
if args.base:
    options.extend(["--base", args.base])
options.append(str(args.root.resolve()))
os.execvpe("go", ["go", "-C", str(root), "run", "-mod=readonly", "./dev/checkcore", *options],
          {**os.environ, "GOWORK": "off"})
