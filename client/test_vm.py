"""Transport tests plus optional real Firecracker boots with MONITOR_VM_IMAGE."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

import monitor_vm as vm

CLIENT = Path(__file__).with_name('monitor').resolve()


@contextlib.contextmanager
def echo_server(wait_for_eof=True):
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen()
    server.settimeout(0.2)
    stopping = threading.Event()

    def serve():
        while not stopping.is_set():
            try:
                client, _ = server.accept()
            except TimeoutError:
                continue
            with client:
                client.settimeout(3)
                data = bytearray()
                while block := client.recv(65536):
                    if wait_for_eof:
                        data.extend(block)
                    else:
                        client.sendall(block)
                if wait_for_eof:
                    client.sendall(data)
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield server.getsockname()
    finally:
        stopping.set()
        thread.join(timeout=5)
        server.close()


class TransportTests(unittest.TestCase):
    def test_vsock_ack_does_not_consume_coalesced_ssh_banner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vsock'
            server = socket.socket(socket.AF_UNIX)
            server.bind(str(path))
            server.listen()
            def accept():
                with server.accept()[0] as client:
                    self.assertEqual(client.recv(64), b'CONNECT 22\n')
                    client.sendall(b'OK 1073741824\nSSH-2.0-fixture\r\n')
            thread = threading.Thread(target=accept)
            thread.start()
            try:
                with vm.connect_vsock(path) as client:
                    self.assertEqual(client.recv(64), b'SSH-2.0-fixture\r\n')
            finally:
                thread.join(timeout=3)
                server.close()

    def test_install_bundle_runs_from_a_directory_with_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'bin with spaces'
            result = subprocess.run([str(CLIENT.parents[1] / 'install.sh'), '--bin-dir', str(target)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(target / 'monitor'), 'image', 'build', '--help'], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b'--claude-version', result.stdout)

    def test_failed_boot_reaps_process_and_removes_runtime_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = {'image': str(root), 'cpus': 1, 'memory': 512}
            with patch.object(vm, 'preflight', return_value=root), patch.object(vm, 'prepare_disk'), \
                 patch.object(vm, 'seed_image'), patch.object(vm, 'sandbox', return_value=[sys.executable, '-c', 'raise SystemExit(7)']):
                machine = vm.VM(profile, root, root, CLIENT, ('127.0.0.1', 1))
                with self.assertRaisesRegex(vm.Error, 'Firecracker exited'):
                    with machine:
                        self.fail('dead VM was ready')
            self.assertIsNotNone(machine.process.returncode)
            self.assertFalse(machine.runtime.exists())
            self.assertFalse((root / 'runtime.json').exists())

    def test_export_does_not_interpret_guest_archive_paths(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            entry = tarfile.TarInfo('../../outside')
            entry.size = 6
            archive.addfile(entry, io.BytesIO(b'unsafe'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'rootfs.ext4').write_bytes(b'\0' * 16384)
            class Machine:
                directory = root
                def check(self): pass
                def ssh(self):
                    return [sys.executable, '-c', 'import sys;sys.stdout.buffer.write(' + repr(data.getvalue()) + ')']
            target = root / 'export.tar'
            vm.export(Machine(), target)
            self.assertEqual(target.read_bytes(), data.getvalue())
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['export.tar', 'rootfs.ext4'])


@unittest.skipUnless(os.environ.get('MONITOR_VM_IMAGE'), 'set MONITOR_VM_IMAGE for real Firecracker tests')
class NativeVMTests(unittest.TestCase):
    def test_boot_monitor_bridge_no_nic_disk_reuse_and_export(self):
        with tempfile.TemporaryDirectory(prefix='monitor-native-') as directory, echo_server() as endpoint:
            root = Path(directory)
            state, workspace = root / 'state with spaces', root / 'project'
            state.mkdir(mode=0o700)
            workspace.mkdir()
            (workspace / 'original.txt').write_text('first copy')
            (workspace / '.env').write_text('must not enter guest')
            (root / 'owner.key').write_text('host-only-owner-secret')
            vm.keypair(state / 'id')
            vm.private(root / 'host_key', vm.keypair(state / 'monitor-host') + b'\n')
            profile = {'image': os.environ['MONITOR_VM_IMAGE'], 'root': str(root), 'cpus': 2, 'memory': 1024, 'connection': 'model'}
            def command(machine, argv, monitor=False):
                result = subprocess.run(machine.ssh(monitor=monitor) + ['agent@monitor-vm', shlex.join(argv)], capture_output=True,
                                        env=vm.environment(), timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                return result.stdout
            with vm.VM(profile, state, workspace, CLIENT, endpoint) as machine:
                self.assertEqual(command(machine, ['ls', '/sys/class/net']).strip(), b'lo')
                self.assertEqual(command(machine, ['cat', '/workspace/original.txt']), b'first copy')
                self.assertEqual(command(machine, ['sh', '-c', 'test ! -e /workspace/.env && test ! -e /run/seed/owner.key; echo safe']).strip(), b'safe')
                payload = 'literal $(touch /tmp/injected) with quotes \' "'
                script = "import socket,sys;s=socket.create_connection(('127.0.0.1',2223));s.sendall(sys.argv[1].encode());s.shutdown(socket.SHUT_WR);print(s.recv(1000).decode())"
                self.assertEqual(command(machine, ['python3', '-c', script, payload], monitor=True).decode().strip(), payload)
                self.assertIn(b'Claude Code', command(machine, ['claude', '--version']))
                status = subprocess.run(machine.ssh() + ['agent@monitor-vm', 'exit 23'], env=vm.environment(), timeout=10)
                self.assertEqual(status.returncode, 23)
                command(machine, ['sh', '-c', "printf '%s' changed > /workspace/original.txt"])
                config = json.loads((machine.runtime / 'firecracker.json').read_text())
                self.assertEqual(config['network-interfaces'], [])
                first_pid = machine.process.pid
            self.assertIsNone(vm.process_identity(first_pid))
            self.assertIn(b'Restarting system', bytes(machine.boot_log))
            self.assertEqual(machine.process.returncode, 0)
            self.assertNotIn(b'Kernel panic', bytes(machine.boot_log))
            (workspace / 'original.txt').write_text('host edit must not replace guest work')
            with vm.VM(profile, state, workspace, CLIENT, endpoint) as machine:
                self.assertEqual(command(machine, ['cat', '/workspace/original.txt']), b'changed')
                archive = root / 'work.tar'
                vm.export(machine, archive)
                with tarfile.open(archive) as data:
                    self.assertEqual(data.extractfile('./original.txt').read(), b'changed')
                vm.stop(state)
                with self.assertRaisesRegex(vm.Error, 'stopped'):
                    machine.check()
            self.assertFalse((state / 'runtime.json').exists())


if __name__ == '__main__':
    unittest.main()
