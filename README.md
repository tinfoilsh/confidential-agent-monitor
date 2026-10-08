# Monitor

## Install or update the CLI

From this checkout on Linux or macOS, with Python 3.11 or newer and OpenSSH:

```sh
./install.sh
export PATH="$HOME/.local/bin:$PATH"
monitor --help
```

Add the `export` line to `~/.zshrc` or `~/.bashrc` to keep it in new terminals.
The installer copies the standalone client to `~/.local/bin/monitor`. It needs
no Go build, Python packages, or sudo. Choose another destination with
`./install.sh --bin-dir /path/to/bin`.

To update from this repository:

```sh
git pull --ff-only
./install.sh
```

Use the same `--bin-dir` when updating a custom installation. The installer uses
the files in your checkout, including local edits. It replaces the installed
client without changing SSH keys, pairing, or client profiles. Running sessions
keep their existing code; new invocations use the update.

The client connects to an existing, unlocked Monitor server through OpenSSH.
Pair your SSH public key in the Monitor web app, then configure a `monitor` host
alias in `~/.ssh/config` with the server address, SSH port, private key, and pinned
host key. Check access with `monitor connections`. Use `monitor run --help`,
`monitor shell --help`, or `monitor mcp serve --help` for command options.
