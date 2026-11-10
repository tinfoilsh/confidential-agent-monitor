#!/bin/sh
# Install or update the standalone client from this checkout.
set -eu

usage() {
    cat <<'EOF'
Usage: ./install.sh [--bin-dir DIR]

Install or update the Perimeter CLI from this checkout.
The default destination is ~/.local/bin/perimeter.
Requires Python 3.11 or newer and OpenSSH on Linux or macOS.
Run this command again after pulling changes to update the installed client.
EOF
}

bin_dir=${HOME}/.local/bin
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '%s\n' 'install: --bin-dir requires a directory' >&2
                exit 1
            fi
            bin_dir=$2
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1 ||
   ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    printf '%s\n' 'install: Python 3.11 or newer is required on PATH as python3' >&2
    exit 1
fi
if ! command -v ssh >/dev/null 2>&1; then
    printf '%s\n' 'install: OpenSSH is required on PATH as ssh' >&2
    exit 1
fi

source_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd)
mkdir -p -- "$bin_dir"
bin_dir=$(CDPATH= cd -P -- "$bin_dir" && pwd)
destination=$bin_dir/perimeter
if [ -d "$destination" ]; then
    printf 'install: destination is a directory: %s\n' "$destination" >&2
    exit 1
fi

# Stage alongside the destination so replacement is atomic, including updates
# while a client is running. A failed copy or check leaves the old client intact.
temporary=$(mktemp "$bin_dir/.perimeter.XXXXXXXX")
trap 'rm -f -- "$temporary"' EXIT
trap 'exit 1' HUP INT TERM
python3 - "$source_dir/client" "$temporary" <<'PY'
from pathlib import Path
import importlib.util
import sys
directory = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("monitor_vm", directory / "monitor_vm.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
Path(sys.argv[2]).write_bytes(module.bundle(directory / "perimeter"))
PY
chmod 755 "$temporary"
"$temporary" --help >/dev/null
mv -f -- "$temporary" "$destination"

printf 'Installed Perimeter CLI to %s\n' "$destination"
active=$(command -v perimeter || true)
if [ "$active" != "$destination" ]; then
    printf 'Put %s first on PATH to use this installation.\n' "$bin_dir"
    if [ -n "$active" ]; then
        printf 'Your current PATH selects: %s\n' "$active"
    fi
fi
