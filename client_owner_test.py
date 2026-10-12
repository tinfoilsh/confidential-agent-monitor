import base64
import json
from pathlib import Path
import runpy
import tempfile
import unittest


client = runpy.run_path(str(Path(__file__).parent / "client" / "monitor"))


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
