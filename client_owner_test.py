import base64
import json
from pathlib import Path
import runpy
import unittest


client = runpy.run_path(str(Path(__file__).parent / "client" / "monitor"))


class OwnerCredentialTests(unittest.TestCase):
    def test_passphrase_bytes_and_cli_record(self):
        value = "  Café workspace 🔐\n"
        token = client["owner_token"](value)
        self.assertEqual(base64.b64decode(token), value.encode())
        record = json.dumps({"version": 1, "key": token, "argon2id": "public commitment"})
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


if __name__ == "__main__":
    unittest.main()
