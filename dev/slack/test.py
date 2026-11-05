#!/usr/bin/env python3
"""Live Slack SDK test through the real connector and shipped JSON, locally.

Use hidden terminal prompts, or --env-file with an explicitly supplied private
0600 file. Tokens pass to the Go harness over stdin, never through command
arguments or environment variables.
Default behavior checks bot auth, receives events and acknowledges them. A Slack
post requires --post-test and an explicit --channel. No full Monitor policy or
sandbox enrollment is involved.
"""
import argparse
import getpass
import importlib.metadata
import json
import logging
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK_VERSION = "3.38.0"


class SetupError(ValueError):
    """Fixed, credential-free setup messages safe to show in the terminal."""


def private_tokens(path):
    fd = os.open(path.expanduser(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise SetupError("Token file must be a regular file owned by you with private permissions; use chmod 600 on it.")
        raw = file.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise SetupError("Token file exceeds the size limit.")
    values = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or key not in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN") or key in values:
            raise SetupError("Token file must contain only one SLACK_BOT_TOKEN and one SLACK_APP_TOKEN assignment.")
        if value[:1] in ("'", '"'):
            if len(value) < 2 or value[-1] != value[0]:
                raise SetupError("Token file has an unmatched quote.")
            value = value[1:-1]
        values[key] = value
    if set(values) != {"SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"}:
        raise SetupError("Token file needs both SLACK_BOT_TOKEN and SLACK_APP_TOKEN.")
    return values["SLACK_BOT_TOKEN"], values["SLACK_APP_TOKEN"]


def safe_error(error):
    response = getattr(error, "response", None)
    code = response.get("error") if response is not None else None
    return code if isinstance(code, str) and re.fullmatch(r"[a-z_]{1,60}", code) else type(error).__name__


def capture_sdk():
    """Manually inspect wire shapes without credentials or network requests."""
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse

    requests = []

    class Capture(WebClient):
        def _perform_urllib_http_request_internal(self, url, req):
            requests.append({"method": req.method, "url": url,
                             "authorization": req.get_header("Authorization"),
                             "content_type": req.get_header("Content-type"),
                             "body": (req.data or b"").decode()})
            return {"status": 200, "headers": {}, "body": '{"ok":true}'}

    Capture(token="tfm_bot_SYNTHETIC").apps_connections_open(app_token="tfm_socket_SYNTHETIC")
    responses = []
    socket = SocketModeClient.__new__(SocketModeClient)
    socket.send_message = lambda body: responses.append(json.loads(body))
    for payload in (None, {}, {"text": "SYNTHETIC reply"},
                    {"response_action": "update", "view": {"type": "modal"}},
                    {"options": [{"text": {"type": "plain_text", "text": "SYNTHETIC"}, "value": "1"}]}):
        socket.send_socket_mode_response(SocketModeResponse(envelope_id="SYNTHETIC-envelope", payload=payload))
    print(json.dumps({"sdk": "slack_sdk", "version": importlib.metadata.version("slack_sdk"),
                      "requests": requests, "responses": responses}, indent=2))
    return 0


def sdk_client():
    # SDK errors/logs can contain full connection URLs. Never render those.
    logging.disable(logging.CRITICAL)
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse

    config = json.loads(sys.stdin.read(64 * 1024))
    tls = ssl.create_default_context()
    tls.load_verify_locations(cafile=config["ca_file"])
    bot = WebClient(token="tfm_live_slack_bot", proxy=config["bot_proxy"], ssl=tls, timeout=15)
    opener = WebClient(token="tfm_live_slack_bot", proxy=config["socket_proxy"], ssl=tls, timeout=15)
    client = None
    try:
        bot.auth_test()
        print("PASS: bot auth.test through shipped Slack JSON and real credential injection", flush=True)
        if config["post_test"]:
            bot.chat_postMessage(channel=config["channel"], text="[Monitor Socket Mode test] Local connector HTTP test; no agent workload started.")
            print("PASS: explicitly requested test message posted through Slack HTTP connector", flush=True)
        counts = [0, 0]
        count_lock = threading.Lock()
        errors = threading.Event()

        def new_session(phase):
            socket = SocketModeClient(app_token="tfm_live_slack_socket", web_client=opener,
                                      proxy=config["socket_proxy"], trace_enabled=False,
                                      all_message_trace_enabled=False, ping_pong_trace_enabled=False)

            def event(source, request):
                try:
                    source.send_socket_mode_response(SocketModeResponse(envelope_id=request.envelope_id))
                    with count_lock:
                        counts[phase] += 1
                        count = counts[phase]
                    kind = request.type if request.type in ("events_api", "interactive", "slash_commands") else "other"
                    print(f"RECEIVED {kind}; acknowledgement queued; session={phase + 1} events={count} (content withheld)", flush=True)
                except Exception as error:  # noqa: BLE001 -- SDK error text can contain credentials
                    print("FAIL: acknowledgement: " + safe_error(error), flush=True)
                    errors.set()

            def socket_error(_error):
                print("NOTICE: SDK socket error (details withheld)", flush=True)

            socket.socket_mode_request_listeners.append(event)
            socket.on_error_listeners.append(socket_error)
            try:
                socket.connect()
                if not socket.is_connected():
                    raise SetupError("Socket Mode session did not connect.")
            except BaseException:
                socket.close()
                raise
            return socket

        client = new_session(0)
        print("PASS: Socket Mode connected through real HTTP/WebSocket connector", flush=True)
        print("Mention your test app in its test channel now. No event text or connection URLs will be printed.", flush=True)
        started = time.monotonic()
        reconnected = False
        while time.monotonic() - started < config["duration"] and not errors.is_set():
            if config["reconnect_after"] and not reconnected and time.monotonic() - started >= config["reconnect_after"]:
                # Join the old client's callbacks; they cannot count toward the new session.
                client.close()
                client = None
                client = new_session(1)
                reconnected = True
                print("CONNECTED: fresh session; send another mention to verify post-reconnect delivery", flush=True)
            time.sleep(0.2)
        client.close()
        client = None
        with count_lock:
            initial, after_reconnect = counts
        print(f"Finished: initial-session events={initial}, fresh-session events={after_reconnect}.", flush=True)
        if config["reconnect_after"] and (not reconnected or after_reconnect == 0):
            print("INCOMPLETE: no event received on the fresh session; reconnect delivery was not verified.", flush=True)
            return 1
        if config["reconnect_after"]:
            print("PASS: event received and acknowledgement queued on the fresh session", flush=True)
        return 1 if errors.is_set() or initial + after_reconnect == 0 else 0
    except Exception as error:  # noqa: BLE001 -- sanitize errors at the process boundary
        print("FAIL: live SDK test: " + safe_error(error) + " (raw details withheld)", flush=True)
        return 1
    finally:
        if client is not None:
            client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true", help="manually capture synthetic SDK wire shapes offline; no tokens needed")
    parser.add_argument("--env-file", type=Path, help="read literal token assignments from an explicitly supplied private 0600 file; never source it as shell code")
    parser.add_argument("--duration", type=int, default=180, help="listen for 10-600 seconds (default 180)")
    parser.add_argument("--reconnect-after", type=int, default=0, help="optionally request a fresh session after this many seconds")
    parser.add_argument("--channel", default="", help="test channel ID; required only with --post-test")
    parser.add_argument("--post-test", action="store_true", help="explicitly permit one labelled HTTP test message")
    parser.add_argument("--sdk-client", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.sdk_client:
        return sdk_client()
    if args.capture:
        return capture_sdk()
    if not args.env_file and not sys.stdin.isatty():
        parser.error("Use a terminal for hidden prompts, or --env-file with a private token file")
    if not 10 <= args.duration <= 600 or not 0 <= args.reconnect_after < args.duration:
        parser.error("Use duration 10-600 and reconnect-after smaller than duration")
    if args.post_test and not re.fullmatch(r"[CG][A-Z0-9]+", args.channel):
        parser.error("--post-test requires an explicit Slack channel ID")
    if importlib.metadata.version("slack_sdk") != SDK_VERSION:
        parser.error(f"Use a dedicated venv with slack_sdk=={SDK_VERSION}")
    with tempfile.TemporaryDirectory(prefix="monitor-slack-live-build-") as temporary:
        binary = str(Path(temporary) / "connector-harness")
        print("Building the local harness from this worktree (before credential entry)…", flush=True)
        subprocess.run(["go", "build", "-o", binary, "./dev/slack"], cwd=ROOT, check=True)
        print("Use a dedicated test app: concurrent Socket Mode clients can take events from each other.", flush=True)
        if args.env_file:
            bot_token, app_token = private_tokens(args.env_file)
            print("Loaded private token file (values withheld).", flush=True)
        else:
            bot_token = getpass.getpass("Slack bot token (xoxb-, hidden): ").strip()
            app_token = getpass.getpass("Slack app-level token (xapp-, connections:write, hidden): ").strip()
        if not bot_token.startswith("xoxb-") or not app_token.startswith("xapp-"):
            raise SetupError("Wrong or empty token types; no connection attempted.")
        print("Tokens pass only over stdin to the connector process; no additional credential files are created.", flush=True)
        helper = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        child = None
        try:
            helper.stdin.write(json.dumps({"bot_token": bot_token, "app_token": app_token,
                                          "channel": args.channel, "post_test": args.post_test}) + "\n")
            helper.stdin.close()
            bot_token = app_token = None
            line = helper.stdout.readline()
            if not line:
                raise RuntimeError("Connector harness failed before readiness")
            config = json.loads(line)
            config.update(duration=args.duration, reconnect_after=args.reconnect_after,
                          channel=args.channel, post_test=args.post_test)
            print("Loaded exact shipped JSON: Slack SHA-256=" + config["slack_sha256"], flush=True)
            print("Socket Mode SHA-256=" + config["socket_sha256"], flush=True)
            # No inherited service credentials or proxy bypass rules in the SDK process.
            env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")}
            env["NO_PROXY"] = ""
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--sdk-client"], stdin=subprocess.PIPE, text=True, env=env)
            child.communicate(json.dumps(config), timeout=args.duration + 60)
            return child.returncode
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            helper.terminate()
            try:
                helper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SetupError as error:
        print("FAIL: " + str(error), file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        print("Stopped. No additional token files were created.", file=sys.stderr)
        raise SystemExit(130) from None
    except Exception as error:  # noqa: BLE001 -- sanitize errors at the process boundary
        print("FAIL: " + safe_error(error) + " (details withheld to protect credentials)", file=sys.stderr)
        raise SystemExit(1) from None
