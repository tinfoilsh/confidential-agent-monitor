# Monitor

## Effect permissions

In **Settings → Effects**, choose Allow, Ask, or Deny for each effect. Payments
include paid model inference; payments and publishing default to Ask. Onboarding
checks **Allow paid AI inference** by default, allowing model operations marked
with both `generate` and `pay` without payment approval. Other payments still
default to Ask. Uncheck it during onboarding or in **Settings → Effects** to
keep payment approval for inference, too. The choice applies to existing and
future provider accounts. Existing monitors keep their settings until changed.
All other effects default to Allow. Approval requests identify the effect that
requires approval.

Override these defaults in an account's **Effects** section, an agent's
**Settings → Effects**, or **Effect overrides** beneath the agent's account access.
Precedence is global → account → agent → agent on an account. Click a selected
permission again to unset it and inherit. Explicit payment settings override
the paid-inference default at every scope. Payments, publishing, and overrides stay
visible; expand **Other effects** for the rest. When a request has several effects,
Deny takes precedence over Ask, which takes precedence over Allow.

Effect permissions apply alongside account access, action permissions, data-flow
restrictions, and custom policy. Allowing payments removes the payment approval
requirement; other restrictions still apply. Saved approvals cannot override Deny.
Changes also close affected open connector streams.

The same settings are editable in policy TOML (`off` means Deny):

```toml
[effects]
pay = "ask"

[accounts.anthropic.effects]
pay = "allow"

[identities.agent.effects]
publish = "off"

[identities.agent.accounts.anthropic.effects]
pay = "ask"
```

The account and agent must already exist, and the agent needs access to the account.

## Install or update the CLI

From this checkout on Linux or macOS, with Python 3.11 or newer and OpenSSH:

```sh
./install.sh
export PATH="$HOME/.local/bin:$PATH"
monitor --help
```

## Launch Claude in a VM

The VM runner uses Firecracker directly. It supports x86_64 Linux with
read/write access to `/dev/kvm`, bubblewrap, unprivileged user namespaces,
OpenSSH, GNU tar, and `mke2fs` from e2fsprogs. Podman or Docker is needed to
build an image. Launch runs as your user and requires no sudo or host network
configuration. The existing local client commands also work on macOS.

From this checkout, install the client and prepare an image once:

```sh
./install.sh
monitor image build
monitor setup
```

Image building downloads the Firecracker binary and guest kernel using the
SHA-256 pins in `client/vm/assets.json`. It builds an Ubuntu guest containing
Claude, Python, Git, and the Monitor transport. The default disk size is
8 GiB. The default Claude channel is `stable`; use `--claude-version VERSION`
to select an exact release. Images are stored in
`~/.local/share/monitor/images/default/`.

To use already downloaded assets:

```sh
monitor image build --output /path/to/image \
  --firecracker /path/to/static/firecracker \
  --kernel /path/to/vmlinux \
  --claude-binary /path/to/native/linux/claude
monitor setup --image /path/to/image
```

From a project directory, launch with one command:

```sh
monitor launch claude
monitor launch claude -- -p 'Run the tests and explain any failures'
```

Claude runs with permission prompts disabled inside the VM. Monitor still
applies its configured policy to external requests.

Exiting the agent shuts down its VM and bridge while retaining its disk and
identity. To stop an active session from another terminal:

```sh
monitor stop
```

To save guest work after the session ends:

```sh
monitor export --output /path/to/workspace.tar
```

Export boots the VM, writes its workspace archive, and shuts it down again.
It works without owner API access, including after identity revocation. Guest
archive paths are never extracted on the host. Choose a new output file;
existing files are not overwritten.

To revoke the identity and delete its disk:

```sh
monitor destroy
```

Stop an active session first. Revocation happens before disk deletion. If
cleanup fails, retry `monitor destroy`. All project commands accept
`--workspace PATH`; for launch, place it before `claude`. Export and destroy
also work after the original project directory is removed.

For noninteractive setup, put the owner key in a file with mode `0600`:

```sh
monitor --profile work setup \
  --image /path/to/image \
  --owner-url https://monitor.example.com \
  --owner-key-file /private/path/owner.key \
  --endpoint monitor.example.com:2223 \
  --connection anthropic \
  --account anthropic=allow --account github=ask
monitor --profile work launch claude
```

Launch profiles share `~/.config/monitor/client.json` with local client
profiles. `--client-config` selects another file. Keep it outside the project;
the CLI rejects projects containing its enrollment credentials. Setup preserves
existing profiles and refuses to overwrite a launch profile. Use a new profile
for another server, image, or initial account selection. For additional guest
tools, edit `client/vm/Dockerfile` and build into a new image directory.
