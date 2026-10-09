"""Exercise CLI enrollment against the existing owner API and a VM driver fixture."""
import base64
import copy
import json
import os
import runpy
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENT = Path(__file__).with_name("monitor")


def apply_edits(target, changes):
    for change in changes:
        parent = target
        for key in change["path"][:-1]:
            parent = parent.setdefault(key, {})
        key = change["path"][-1]
        if change.get("delete"):
            parent.pop(key, None)
        else:
            parent[key] = change["value"]


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / "project 'with spaces'"
        self.project.mkdir()
        self.config = self.root / "settings/client.json"
        self.key = base64.b64encode(b"x" * 32).decode()
        self.keyfile = self.root / "owner.key"
        self.keyfile.write_text(self.key)
        self.keyfile.chmod(0o600)
        self.view = {"host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                     "config": {"accounts": {"model": {"preset": "anthropic", "connections": {"": {"http": {}}}},
                                              "github": {"preset": "github", "connections": {"": {"http": {}}}}},
                                "identities": {}}}
        self.calls = []
        self.status = 200
        self.drop_patch_reply = False
        case = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond(None)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                self.respond(body)

            def respond(self, body):
                case.calls.append((self.command, self.path, body))
                if self.headers.get("Authorization") != "Bearer " + case.key:
                    self.send_error(401)
                    return
                if body is not None and case.status == 200:
                    apply_edits(case.view["config"], body["changes"])
                    if case.drop_patch_reply:
                        self.close_connection = True
                        return
                data = json.dumps(case.view).encode()
                self.send_response(case.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        self.owner_url = f"http://127.0.0.1:{server.server_port}"
        self.image = self.root / "image"
        self.image.mkdir()
        self.log = self.root / "launches.jsonl"
        self.driver = self.root / "driver.py"
        self.driver.write_text(f'''import pathlib, sys

def preflight(image):
    return pathlib.Path(image)

def ensure_stopped(directory):
    pass

def export(machine, destination):
    pathlib.Path(destination).write_bytes(b'workspace archive')

class VM:
    def __init__(self, profile, directory, workspace, source, endpoint):
        self.directory = directory
    def __enter__(self):
        (self.directory / 'initialized').write_text('1')
        (self.directory / 'rootfs.ext4').write_text('fixture disk')
        return self
    def __exit__(self, *args):
        pass
    def check(self):
        pass
    def agent(self, arguments, mcp=False):
        script = "import json,os,sys; f=open(" + repr({str(self.log)!r}) + ", 'a'); f.write(json.dumps([sys.argv[1:],dict(os.environ)])+'\\\\n'); f.close(); sys.exit(23)"
        return [sys.executable, '-c', script, '--', *arguments]
''')
        self.env = {**os.environ, "ANTHROPIC_API_KEY": "host-provider-secret", "GITHUB_TOKEN": "host-github-secret",
                    "MONITOR_OWNER_KEY": self.key}

    def run_cli(self, *args):
        runner = """import runpy,sys,types
client = runpy.run_path(sys.argv[1])
driver = types.SimpleNamespace(**runpy.run_path(sys.argv[2]))
client['main'].__globals__['vm_module'] = lambda: driver
sys.exit(client['main'](sys.argv[3:]))
"""
        return subprocess.run([sys.executable, "-c", runner, str(CLIENT), str(self.driver),
                               "--client-config", str(self.config), *args],
                              env=self.env, capture_output=True, timeout=15)

    def setup_profile(self):
        result = self.run_cli("setup", "--image", str(self.image), "--owner-url", self.owner_url,
                              "--owner-key-file", str(self.keyfile), "--endpoint", "127.0.0.1:2223",
                              "--connection", "model", "--account", "model=allow", "--account", "github=ask")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.key.encode(), result.stdout + result.stderr)

    def launch(self, *args):
        return self.run_cli("launch", "--workspace", str(self.project), "claude", "--", *args)

    def test_launch_resume_preserves_permissions_arguments_and_exit_code(self):
        self.setup_profile()
        result = self.launch("-p", "$(touch should-not-execute)")
        self.assertEqual(result.returncode, 23, result.stderr)
        name, identity = next(iter(self.view["config"]["identities"].items()))
        self.assertEqual(identity["accounts"]["github"], {"level": "ask"})
        identity["accounts"]["github"] = {"level": "off"}
        before = copy.deepcopy(identity)
        patches = len([call for call in self.calls if call[0] == "POST"])
        self.assertEqual(self.launch().returncode, 23)
        self.assertEqual(identity, before)
        self.assertEqual(patches, len([call for call in self.calls if call[0] == "POST"]))
        args, env = json.loads(self.log.read_text().splitlines()[0])
        self.assertEqual(args[-3:], ["--", "-p", "$(touch should-not-execute)"])
        for secret in (self.key, "host-provider-secret", "host-github-secret"):
            self.assertNotIn(secret, json.dumps([args, env]))
        self.assertTrue(all(path == ("/policy/edits" if method == "POST" else "/") for method, path, _ in self.calls))

    def test_revocation_is_not_undone_by_launch_and_destroy_allows_fresh_identity(self):
        self.setup_profile()
        self.launch()
        name, previous = next(iter(self.view["config"]["identities"].items()))
        del self.view["config"]["identities"][name]
        result = self.launch()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"revoked", result.stderr)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)
        result = self.run_cli("destroy", "--workspace", str(self.project))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.launch().returncode, 23)
        self.assertNotEqual(self.view["config"]["identities"][name]["key"], previous["key"])

    def test_destroy_removes_identity_and_keeps_peer_settings(self):
        self.setup_profile()
        self.launch()
        name = next(iter(self.view["config"]["identities"]))
        peer = {"key": "peer-key", "accounts": {"web": {"level": "read"}}}
        self.view["config"]["identities"]["peer"] = peer
        result = self.run_cli("destroy", "--workspace", str(self.project))
        self.assertEqual(result.returncode, 0, result.stderr)
        ids = self.view["config"]["identities"]
        self.assertNotIn(name, ids)
        self.assertEqual(ids["peer"], peer)

    def test_changed_key_is_not_overwritten_or_revoked(self):
        self.setup_profile()
        self.launch()
        name = next(iter(self.view["config"]["identities"]))
        self.view["config"]["identities"][name]["key"] = "replacement"
        for result in (self.launch(), self.run_cli("destroy", "--workspace", str(self.project))):
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"different key", result.stderr)
        self.assertEqual(self.view["config"]["identities"][name]["key"], "replacement")

    def test_destroy_after_project_directory_is_removed(self):
        self.setup_profile()
        self.launch()
        self.project.rmdir()
        result = self.run_cli("destroy", "--workspace", str(self.project))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.view["config"]["identities"], {})
        self.assertEqual(list((self.config.parent / "launch/default/instances").iterdir()), [])

    def test_locked_owner_stops_before_launch_and_does_not_delete_vm(self):
        self.setup_profile()
        self.launch()
        self.status = 423
        self.assertEqual(self.launch().returncode, 1)
        self.assertEqual(self.run_cli("destroy", "--workspace", str(self.project)).returncode, 1)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)
        self.assertEqual(len(list((self.config.parent / "launch/default/instances").glob("*/rootfs.ext4"))), 1)

    def test_export_needs_neither_owner_credentials_nor_endpoint_resolution(self):
        self.setup_profile()
        self.launch()
        config = json.loads(self.config.read_text())
        profile = config["launch_profiles"]["default"]
        profile["endpoint"] = "does-not-exist.invalid:2223"
        self.config.write_text(json.dumps(config))
        (Path(profile["root"]) / "owner.key").unlink()
        self.status = 423
        calls = len(self.calls)
        archive = self.root / "workspace.tar"
        result = self.run_cli("export", "--workspace", str(self.project), "--output", str(archive))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls), calls)
        self.assertEqual(archive.read_bytes(), b"workspace archive")

    def test_owner_key_symlink_and_world_readable_file_are_rejected(self):
        self.keyfile.chmod(0o644)
        result = self.run_cli("setup", "--image", str(self.image), "--owner-url", self.owner_url, "--owner-key-file", str(self.keyfile))
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"owner-only", result.stderr)
        self.assertEqual(self.calls, [])
        self.keyfile.chmod(0o600)
        alias = self.root / "alias"
        alias.symlink_to(self.keyfile)
        result = self.run_cli("setup", "--image", str(self.image), "--owner-url", self.owner_url, "--owner-key-file", str(alias))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls, [])

    def test_missing_profile_has_actionable_error(self):
        result = self.launch()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"monitor setup", result.stderr)

    def test_project_cannot_contain_host_enrollment_credentials(self):
        self.setup_profile()
        result = self.run_cli("launch", "--workspace", str(self.root), "claude")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"contains Monitor's host credentials", result.stderr)
        self.assertFalse(self.log.exists())

    def test_lost_enrollment_response_cannot_resurrect_a_revoked_identity(self):
        self.setup_profile()
        self.drop_patch_reply = True
        result = self.launch()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.log.exists())
        self.view["config"]["identities"].clear()
        self.drop_patch_reply = False
        result = self.launch()
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"revoked", result.stderr)
        self.assertFalse(self.log.exists())


class GuestAgentTests(unittest.TestCase):
    def test_model_mapping_mcp_loopback_and_argument_preservation(self):
        runtime = runpy.run_path(str(CLIENT))
        globals_ = runtime["guest_agent"].__globals__
        with tempfile.TemporaryDirectory() as directory:
            class Session:
                def __init__(self, client):
                    self.directory = Path(directory)
                    self.routes = [{"name": "model", "placeholders": {"token": "tfm_model_token"}}]

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    pass

                def environment(self, *args):
                    return {"HTTP_PROXY": "http://127.0.0.1:9999", "ANTHROPIC_AUTH_TOKEN": "stale",
                            "ANTHROPIC_BASE_URL": "https://wrong.example", "NO_PROXY": ""}

                def listen(self, *args):
                    return 8401

            captured = []
            def child(session, command, env):
                captured.append((command, env))
                return 17

            args = SimpleNamespace(connection="model", mcp=True, argv=["--", "-p", "literal $(text)"])
            client = SimpleNamespace(timeout=1, connections=lambda: [{"name": "model", "state": "ready"}])
            with patch.dict(globals_, {"Session": Session, "mcp_probe": lambda *args: 2, "run_child": child}):
                self.assertEqual(runtime["guest_agent"](client, args), 17)
            command, env = captured[0]
            self.assertEqual(command[-2:], ["-p", "literal $(text)"])
            self.assertEqual(env["ANTHROPIC_API_KEY"], "tfm_model_token")
            self.assertNotIn("ANTHROPIC_AUTH_TOKEN", env)
            self.assertNotIn("ANTHROPIC_BASE_URL", env)
            self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:9999")
            self.assertIn("127.0.0.1", env["NO_PROXY"])
            config = json.loads((Path(directory) / "mcp.json").read_text())
            self.assertEqual(config["mcpServers"]["monitor"]["url"], "http://127.0.0.1:8401/")


if __name__ == "__main__":
    unittest.main()
