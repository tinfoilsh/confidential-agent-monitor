import base64
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import runpy
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from urllib.parse import urlsplit


client = runpy.run_path(str(Path(__file__).parent / "client" / "monitor"))


class MCPConnectionTests(unittest.TestCase):
    def test_ready_connections_have_separate_working_endpoints(self):
        class MCPHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if "id" not in request:
                    self.send_response(202)
                    self.end_headers()
                    return
                result = ({"protocolVersion": "2025-11-25"} if request["method"] == "initialize"
                          else {"tools": [{"name": "echo"}]})
                body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), MCPHandler)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(upstream.shutdown)
        connections = [{"name": name, "kind": kind, "state": state} for name, kind, state in [
            ("work-mcp", "mcp", "ready"), ("waiting", "mcp", "connecting"),
            ("api", "http", "ready"), ("mcp", "mcp", "ready")]]
        session = client["Session"](SimpleNamespace(connections=lambda: connections, timeout=2))
        self.addCleanup(session.__exit__)
        targets = []

        @contextlib.contextmanager
        def stream(host, port, route):
            targets.append((host, port, route))
            with socket.create_connection(upstream.server_address, timeout=2) as connection:
                yield connection

        session.stream = stream
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            servers, count = client["mcp_servers"](session)
        self.assertEqual(count, 2)
        self.assertEqual(set(servers), {"work-mcp", "mcp"})
        self.assertEqual(len({entry["url"] for entry in servers.values()}), 2)
        self.assertEqual(set(targets), {("work-mcp.monitor", 80, False), ("mcp.monitor", 80, False)})
        self.assertIn("waiting is connecting", output.getvalue())
        for name, entry in servers.items():
            endpoint = urlsplit(entry["url"])
            self.assertEqual(entry["type"], "http")
            self.assertEqual(client["mcp_probe"](endpoint.hostname, endpoint.port, 2), 1)
            self.assertEqual(targets[-1], (f"{name}.monitor", 80, False))


class OwnerCredentialTests(unittest.TestCase):
    def test_signing_credentials_require_attested_cli(self):
        record = json.dumps({"version": 2, "key": base64.b64encode(bytes(32)).decode(),
                             "signing_seed": base64.b64encode(bytes(range(32))).decode()})
        with self.assertRaisesRegex(client["MonitorError"], "attested client"):
            client["OwnerClient"]("https://monitor.example.com", record)

    def test_passphrase_bytes_and_cli_record(self):
        value = "  Café workspace 🔐\n"
        token = client["owner_token"](value)
        self.assertEqual(base64.b64decode(token), value.encode())
        record = json.dumps({"version": 1, "key": token})
        self.assertEqual(client["owner_token"](record), token)

    def test_legacy_and_invalid_lengths(self):
        token = base64.b64encode(bytes(range(32))).decode()
        self.assertEqual(client["owner_token"](" " + token + "\n"), token)
        for value in ["short", "é" * 2049]:
            with self.assertRaises(client["MonitorError"]):
                client["owner_token"](value)
        self.assertEqual(len(base64.b64decode(client["owner_token"]("é" * 8))), 16)

    def test_owner_client_uses_encoded_transport(self):
        value = "keep these spaces   "
        owner = client["OwnerClient"]("https://monitor.example.com", value)
        self.assertEqual(base64.b64decode(owner.key), value.encode())

    def test_private_file_preserves_all_newlines(self):
        value = "first line\r\nsecond line\rlast line\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owner.key"
            client["private_write"](path, value)
            restored = client["private_read"](path)
            self.assertEqual(restored, value)
            self.assertEqual(base64.b64decode(client["owner_token"](restored)), value.encode())

    def test_json_text_can_be_a_passphrase(self):
        value = '{"version": "my passphrase"}'
        self.assertEqual(base64.b64decode(client["owner_token"](value)), value.encode())


if __name__ == "__main__":
    unittest.main()
