"""Slack SDK capture and Socket Mode scenarios for the manual connector runner."""
import importlib.metadata
import json
import logging
import threading
import time

from common import SetupError, safe_error

SDK_VERSION = "3.38.0"


def capture():
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


def run(config, tls):
    # SDK errors/logs can contain full connection URLs. Never render those.
    logging.disable(logging.CRITICAL)
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse

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
