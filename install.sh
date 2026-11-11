#!/bin/sh
# Install or update the standalone client from this checkout.
set -eu

usage() {
    cat <<'EOF'
Usage: ./install.sh [--bin-dir DIR] [--daemon]

Install or update the Perimeter CLI from this checkout.
The default destination is ~/.local/bin/perimeter.
Requires Python 3.11 or newer and OpenSSH on Linux or macOS.
Run this command again after pulling changes to update the installed client.

--daemon also builds this checkout's Perimeter and runs it as a user service
with its state in ~/.local/share/perimeter/server. It requires Go and Bun.
Run it from another checkout to switch the daemon to that code.
EOF
}

bin_dir=${HOME}/.local/bin
daemon=
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
        --daemon) daemon=1; shift ;;
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
if [ -n "$daemon" ]; then
    for tool in go bun; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf 'install: --daemon requires %s on PATH\n' "$tool" >&2
            exit 1
        fi
    done
    case $(uname -s) in
        Linux|Darwin) ;;
        *) printf '%s\n' 'install: --daemon supports Linux and macOS' >&2; exit 1 ;;
    esac
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

[ -n "$daemon" ] || exit 0
# Beside a dev/setup Perimeter, which uses 8080 and 2223.
api=127.0.0.1:8081
listen=127.0.0.1:2224
state=$HOME/.local/share/perimeter/server
label=sh.tinfoil.perimeter
mkdir -p -m 700 -- "$state" "$state/store"
[ -f "$state/owner.key" ] || (umask 077 && head -c 32 /dev/urandom | base64 > "$state/owner.key")
(cd -- "$source_dir" && go generate ./ui && CGO_ENABLED=0 go build -o "$state/perimeter-server.new" .)
set -- "$state/perimeter-server" -api "$api" -listen "$listen" \
    -bucket "file://$state/store?no_tmp_dir=true" -owner-key-file "$state/owner.key"

case $(uname -s) in
    Linux) systemctl --user stop perimeter.service 2>/dev/null || true ;;
    Darwin) launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true ;;
esac
# A checkout may rewrite the store; keep the previous one to roll back to.
rm -rf -- "$state/store.prev"
cp -R -- "$state/store" "$state/store.prev"
mv -f -- "$state/perimeter-server.new" "$state/perimeter-server"
case $(uname -s) in
    Linux)
        unit=$HOME/.config/systemd/user/perimeter.service
        mkdir -p -- "${unit%/*}"
        cat > "$unit" <<EOF
[Unit]
Description=Perimeter from $source_dir

[Service]
WorkingDirectory=$state
ExecStart=$*
Restart=on-failure

[Install]
WantedBy=default.target
EOF
        systemctl --user daemon-reload
        systemctl --user enable --now perimeter.service
        ;;
    Darwin)
        plist=$HOME/Library/LaunchAgents/$label.plist
        mkdir -p -- "${plist%/*}"
        {
            printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
                '<plist version="1.0"><dict>' "<key>Label</key><string>$label</string>" \
                '<key>ProgramArguments</key><array>'
            printf '<string>%s</string>\n' "$@"
            printf '%s\n' '</array>' "<key>WorkingDirectory</key><string>$state</string>" \
                "<key>StandardErrorPath</key><string>$state/server.log</string>" \
                '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>' '</dict></plist>'
        } > "$plist"
        launchctl bootstrap "gui/$(id -u)" "$plist"
        ;;
esac

python3 - "$source_dir/client" "$state" "$api" "$listen" "$destination" <<'PY'
from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
READY_SECONDS = 30
POLL_SECONDS = 0.1
client, state, api, listen, perimeter = sys.argv[1:]
spec = importlib.util.spec_from_file_location("monitor_vm", Path(client) / "monitor_vm.py")
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
state, owner_url = Path(state), "http://" + api
owner = vm.OwnerClient(owner_url, (state / "owner.key").read_text())
deadline = time.monotonic() + READY_SECONDS
while True:
    try:
        view = owner.request()
        break
    except OSError:
        if time.monotonic() > deadline:
            sys.exit(f"install: the Perimeter did not start at {owner_url}; check its service log")
        time.sleep(POLL_SECONDS)
# Named as the web app names a trusted device.
public = " ".join(vm.keypair(state / "id").decode().split()[:2])
device = "device-" + hashlib.sha256(public.encode()).hexdigest()[:16]
if device not in (view["config"].get("identities") or {}):
    owner.edit([{"path": ["identities", device], "value": {"key": public, "routes": True, "connections": {}}}])
host, port = listen.rsplit(":", 1)
vm.private(state / "known_hosts", f"perimeter,*.perimeter,[{host}]:{port} {view['host_key'].strip()}\n".encode())
vm.private(state / "ssh_config", f"""Host perimeter
  HostName {host}
  Port {port}
Host *.perimeter
  ProxyJump perimeter
Host *
  User monitor
  IdentityFile {state / "id"}
  IdentitiesOnly yes
  UserKnownHostsFile {state / "known_hosts"}
  GlobalKnownHostsFile /dev/null
""".encode())
config = Path.home() / ".config/perimeter/client.json"
profiles = json.loads(config.read_text()).get("launch_profiles", {}) if config.exists() else {}
if sys.platform == "linux" and "default" not in profiles:
    subprocess.run([perimeter, "setup", "--owner-url", owner_url, "--endpoint", listen,
                    "--owner-key-file", str(state / "owner.key")], stdin=subprocess.DEVNULL, check=True)
PY

printf 'Perimeter from %s runs at http://%s/app/\n' "$source_dir" "$api"
printf 'Sign in with the owner key in %s/owner.key\n' "$state"
