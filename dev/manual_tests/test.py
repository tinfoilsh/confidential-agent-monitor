#!/usr/bin/env python3
"""Manual connector tests using the real shipped JSON and local transport.

Service scenarios live in slack.py and grafana.py. Credentials come from hidden
prompts or an explicit private --env-file, then pass to the Go helper over stdin.
No full Monitor policy engine or sandbox enrollment is involved.
"""
import argparse
import getpass
import importlib.metadata
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import grafana
import slack
from common import SetupError, private_settings, safe_error

ROOT = Path(__file__).resolve().parents[2]


def run_client():
    logging.disable(logging.CRITICAL)
    config = json.loads(sys.stdin.read(64 * 1024))
    tls = ssl.create_default_context()
    tls.load_verify_locations(cafile=config["ca_file"])
    if config.get("service") == "grafana":
        return grafana.run(config, tls)
    return slack.run(config, tls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", nargs="?", default="slack", choices=("slack", "grafana"))
    parser.add_argument("--url", help="Grafana HTTPS origin, e.g. https://grafana.example.com")
    parser.add_argument("--capture", action="store_true", help="manually capture synthetic Slack SDK wire shapes offline; no tokens needed")
    parser.add_argument("--env-file", type=Path, help="read literal settings from an explicit private 0600 file; never source it as shell code")
    parser.add_argument("--duration", type=int, default=180, help="Slack: listen for 10-600 seconds (default 180)")
    parser.add_argument("--reconnect-after", type=int, default=0, help="Slack: optionally request a fresh session after this many seconds")
    parser.add_argument("--channel", default="", help="Slack channel ID; required only with --post-test")
    parser.add_argument("--post-test", action="store_true", help="Slack: explicitly permit one labelled HTTP test message")
    parser.add_argument("--client", "--sdk-client", dest="client", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.client:
        return run_client()
    if args.capture:
        if args.service != "slack":
            parser.error("Capture mode is currently Slack-specific")
        return slack.capture()
    if args.service == "grafana" and (args.post_test or args.reconnect_after):
        parser.error("Grafana tests are read-only and do not use reconnect options")
    if args.service == "slack" and not args.env_file and not sys.stdin.isatty():
        parser.error("Use a terminal for hidden prompts, or --env-file with a private token file")
    if not 10 <= args.duration <= 600 or not 0 <= args.reconnect_after < args.duration:
        parser.error("Use duration 10-600 and reconnect-after smaller than duration")
    if args.post_test and not re.fullmatch(r"[CG][A-Z0-9]+", args.channel):
        parser.error("--post-test requires an explicit Slack channel ID")
    if args.service == "slack" and importlib.metadata.version("slack_sdk") != slack.SDK_VERSION:
        parser.error(f"Use a dedicated venv with slack_sdk=={slack.SDK_VERSION}")
    with tempfile.TemporaryDirectory(prefix="monitor-manual-test-build-") as temporary:
        binary = str(Path(temporary) / "connector-harness")
        print("Building the local harness from this worktree (before credential entry)…", flush=True)
        subprocess.run(["go", "build", "-o", binary, "./dev/manual_tests"], cwd=ROOT, check=True)
        settings = private_settings(args.env_file) if args.env_file else {}
        if args.env_file:
            print("Loaded private settings (values withheld).", flush=True)
        supplied = {"service": args.service, "channel": args.channel, "post_test": args.post_test}
        if args.service == "slack":
            print("Use a dedicated test app: concurrent Socket Mode clients can take events from each other.", flush=True)
            bot_token = settings.get("SLACK_BOT_TOKEN", "") if args.env_file else getpass.getpass("Slack bot token (xoxb-, hidden): ").strip()
            app_token = settings.get("SLACK_APP_TOKEN", "") if args.env_file else getpass.getpass("Slack app-level token (xapp-, connections:write, hidden): ").strip()
            if not bot_token.startswith("xoxb-") or not app_token.startswith("xapp-"):
                raise SetupError("Wrong or empty token types; no connection attempted.")
            supplied.update(bot_token=bot_token, app_token=app_token)
            bot_token = app_token = None
        else:
            origin = (args.url or settings.get("GRAFANA_URL", "")).rstrip("/")
            url = urlsplit(origin)
            if url.scheme != "https" or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
                raise SetupError("Provide a credential-free Grafana HTTPS origin with --url or GRAFANA_URL.")
            supplied.update(grafana_url=origin, grafana_token=settings.get("GRAFANA_API_KEY", ""))
            print("Grafana test is read-only: health, plus search only if an API key is supplied.", flush=True)
        settings.clear()
        print("Credentials pass only over stdin to the connector process; no additional credential files are created.", flush=True)
        helper = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        child = None
        try:
            helper.stdin.write(json.dumps(supplied) + "\n")
            helper.stdin.close()
            supplied.clear()
            line = helper.stdout.readline()
            if not line:
                raise RuntimeError("Connector harness failed before readiness")
            config = json.loads(line)
            config.update(duration=args.duration, reconnect_after=args.reconnect_after,
                          channel=args.channel, post_test=args.post_test)
            if args.service == "grafana":
                print("Loaded exact shipped JSON: Grafana SHA-256=" + config["grafana_sha256"], flush=True)
            else:
                print("Loaded exact shipped JSON: Slack SHA-256=" + config["slack_sha256"], flush=True)
                print("Socket Mode SHA-256=" + config["socket_sha256"], flush=True)
            env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")}
            env["NO_PROXY"] = ""
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--client"], stdin=subprocess.PIPE, text=True, env=env)
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
