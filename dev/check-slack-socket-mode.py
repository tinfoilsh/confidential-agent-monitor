#!/usr/bin/env python3
"""Capture Slack SDK Socket Mode wire shapes with synthetic credentials only.

Offline by default. --online additionally makes bounded unauthenticated requests
against Slack: no real token, workspace events, messages, or app changes.
"""
import argparse
import importlib.metadata
import json
import urllib.error
import urllib.request
from pathlib import Path

SDK_VERSION = "3.38.0"


def capture():
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse

    if importlib.metadata.version("slack_sdk") != SDK_VERSION:
        raise RuntimeError(f"Use slack_sdk=={SDK_VERSION} to reproduce these fixtures")

    requests = []

    class Capture(WebClient):
        def _perform_urllib_http_request_internal(self, url, req):
            requests.append({"method": req.method, "url": url,
                             "authorization": req.get_header("Authorization"),
                             "content_type": req.get_header("Content-type"),
                             "body": (req.data or b"").decode()})
            return {"status": 200, "headers": {}, "body": '{"ok":true}'}

    client = Capture(token="tfm_bot_SYNTHETIC")
    client.apps_connections_open(app_token="tfm_socket_SYNTHETIC")
    if requests[-1]["method"] != "POST" or requests[-1]["body"]:
        raise RuntimeError("SDK connection-opening wire shape changed")
    if requests[-1]["authorization"] != "Bearer tfm_socket_SYNTHETIC":
        raise RuntimeError("SDK did not use the app token separately from the bot token")
    responses = []
    # Exercise the SDK serializer without constructing a live Socket Mode client.
    socket = SocketModeClient.__new__(SocketModeClient)
    socket.send_message = lambda body: responses.append(json.loads(body))
    for payload in (None, {}, {"text": "SYNTHETIC reply"},
                    {"response_action": "update", "view": {"type": "modal"}},
                    {"options": [{"text": {"type": "plain_text", "text": "SYNTHETIC"}, "value": "1"}]}):
        socket.send_socket_mode_response(SocketModeResponse(envelope_id="SYNTHETIC-envelope", payload=payload))
    return {"sdk": "slack_sdk", "version": SDK_VERSION, "requests": requests, "responses": responses}


def online():
    """Auth errors prove endpoint reachability, NOT successful Socket Mode support."""
    for body, content_type in ((None, None), (b"{}", "application/json"),
                               (b"", "application/x-www-form-urlencoded")):
        headers = {"User-Agent": "Monitor-Slack-Socket-Mode-compatibility-check"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request("https://slack.com/api/apps.connections.open",
                                     data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as response:
                result = json.load(response)
                if result.get("ok") is not False or result.get("error") != "not_authed":
                    raise RuntimeError("Unexpected unauthenticated Slack response; inspect privately")
                print(f"ONLINE {content_type or 'no body'}: not_authed (expected; no credential sent)")
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"Slack endpoint returned HTTP {error.code}") from None
    req = urllib.request.Request("https://wss-primary.slack.com/link/?ticket=SYNTHETIC-INVALID",
        headers={"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
                 "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="})
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            print(f"ONLINE WS invalid ticket: HTTP {response.status}; not a successful authenticated session")
    except urllib.error.HTTPError as error:
        print(f"ONLINE WS invalid ticket: HTTP {error.code}; not a successful authenticated session")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="compare SDK capture with a reviewed synthetic fixture")
    parser.add_argument("--online", action="store_true", help="also test public endpoints without authentication")
    args = parser.parse_args()
    captured = capture()
    if args.check:
        if json.loads(args.check.read_text()) != captured:
            raise SystemExit("SDK wire capture differs; review before updating definitions/fixture")
        print("PASS: pinned Slack SDK wire fixture matches")
    else:
        print(json.dumps(captured, indent=2))
    if args.online:
        online()


if __name__ == "__main__":
    main()
