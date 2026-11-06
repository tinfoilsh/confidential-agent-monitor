"""Linux Firecracker lifecycle. No guest NIC or shared host directories."""
import argparse
import base64
import contextlib
from concurrent.futures import ThreadPoolExecutor
import fcntl
import getpass
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import select
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.parse import urlsplit
import urllib.request
import uuid
import zipfile


ASSETS = ('Dockerfile', 'guest.py', 'init.sh', 'assets.json')


class Error(ValueError):
    pass


def asset(name):
    return __loader__.get_data(str(Path(__file__).parent / 'vm' / name))


def program(source):
    source = Path(source).resolve()
    # In an installed zipapp, __file__ points inside the executable archive.
    return source.parent if source.parent.is_file() else source


def bundle(source):
    source = program(source)
    if zipfile.is_zipfile(source):
        return source.read_bytes()
    output = io.BytesIO()
    output.write(b'#!/usr/bin/env python3\n')
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('__main__.py', source.read_bytes())
        archive.writestr('monitor_vm.py', Path(__file__).read_bytes())
        for name in ASSETS:
            archive.writestr('vm/' + name, asset(name))
    return output.getvalue()


def environment():
    return {key: value for key, value in os.environ.items()
            if key in {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'TERM', 'TMPDIR', 'TZ', 'XDG_RUNTIME_DIR'} or key.startswith('LC_')}


def run(command, **kwargs):
    result = subprocess.run(command, env=environment(), **kwargs)
    if result.returncode:
        detail = result.stderr.decode(errors='replace').strip()[-2000:] if result.stderr else ''
        raise Error(f'{Path(command[0]).name} exited with status {result.returncode}' + (': ' + detail if detail else ''))
    return result


def private(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.monitor-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(url, destination, expected):
    if not url.startswith('https://'):
        raise Error('VM assets require HTTPS')
    with urllib.request.urlopen(urllib.request.Request(url, method='HEAD'), timeout=20) as response:
        size = int(response.headers.get('Content-Length', '0'))
        ranges = response.headers.get('Accept-Ranges') == 'bytes'
    if not 0 < size <= 256 << 20:
        raise Error('VM asset must have a known size of at most 256 MiB')
    with destination.open('wb') as output:
        if ranges:
            output.truncate(size)
            canceled = threading.Event()
            def fetch(start):
                end = min(start + (1 << 20), size) - 1
                for attempt in range(3):
                    if canceled.is_set():
                        return
                    try:
                        request = urllib.request.Request(url, headers={'Range': f'bytes={start}-{end}'})
                        with urllib.request.urlopen(request, timeout=20) as response:
                            if response.status != 206 or response.headers.get('Content-Range') != f'bytes {start}-{end}/{size}':
                                raise Error('asset server returned an invalid byte range')
                            data = response.read(end - start + 2)
                        if len(data) != end - start + 1:
                            raise Error('asset download ended before the full byte range')
                        os.pwrite(output.fileno(), data, start)
                        return
                    except (OSError, http.client.HTTPException):
                        if attempt == 2:
                            raise
            pool = ThreadPoolExecutor(8)
            try:
                list(pool.map(fetch, range(0, size, 1 << 20)))
            finally:
                canceled.set()
                pool.shutdown(wait=True, cancel_futures=True)
        else:
            with urllib.request.urlopen(url, timeout=20) as response:
                count = 0
                while block := response.read(1 << 20):
                    count += len(block)
                    if count > size:
                        raise Error('VM asset exceeded its declared size')
                    output.write(block)
    if digest(destination) != expected:
        raise Error('VM asset checksum mismatch: ' + destination.name)


def build_image(args):
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise Error('image building currently requires x86_64 Linux')
    if not 2 <= args.disk_size <= 128:
        raise Error('image disk size must be between 2 and 128 GiB')
    if not re.fullmatch(r'(stable|latest|[0-9]+\.[0-9]+\.[0-9]+)', args.claude_version):
        raise Error('Claude version must be stable, latest, or a version such as 2.1.0')
    engine = shutil.which(args.engine) if args.engine else shutil.which('podman') or shutil.which('docker')
    if not engine:
        raise Error('image building requires Podman or Docker')
    destination = Path(args.output).expanduser().resolve()
    if destination.exists():
        raise Error('image destination already exists; build into a new directory to update it')
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='.monitor-build-', dir=destination.parent) as temporary:
        build = Path(temporary)
        output, context, disks = build / 'image', build / 'context', build / 'disks'
        for path in (output, context, disks):
            path.mkdir(mode=0o700)
        manifest = json.loads(asset('assets.json'))
        for name, override in [('vmlinux', args.kernel), ('firecracker', args.firecracker)]:
            if override:
                shutil.copyfile(Path(override).expanduser().resolve(), output / name)
            elif name == 'vmlinux':
                download(manifest[name]['url'], output / name, manifest[name]['sha256'])
            else:
                archive = build / 'firecracker.tgz'
                download(manifest[name]['url'], archive, manifest[name]['sha256'])
                with tarfile.open(archive) as source:
                    member = source.getmember(manifest[name]['member'])
                    if not member.isfile():
                        raise Error('Firecracker release member is not a regular file')
                    with source.extractfile(member) as binary, (output / name).open('wb') as target:
                        shutil.copyfileobj(binary, target)
        (output / 'firecracker').chmod(0o700)
        for name in ASSETS:
            (context / name).write_bytes(asset(name))
        if args.claude_binary:
            binary = Path(args.claude_binary).expanduser().resolve()
            with binary.open('rb') as stream:
                if stream.read(4) != b'\x7fELF':
                    raise Error('--claude-binary must be a native Linux executable')
            shutil.copyfile(binary, context / 'claude-local')
        else:
            (context / 'claude-local').touch()
        tag = 'localhost/monitor-image:' + build.name.removeprefix('.')
        container = None
        try:
            print('Building the Monitor guest image...', file=sys.stderr, flush=True)
            run([engine, 'build', '--tag', tag, '--build-arg', 'CLAUDE_VERSION=' + args.claude_version,
                 str(context)], timeout=1800)
            container = run([engine, 'create', tag, '/bin/true'], capture_output=True, timeout=30).stdout.decode().strip()
            if not re.fullmatch('[0-9a-f]{12,64}', container):
                raise Error('container engine returned an invalid container ID')
            producer = subprocess.Popen([engine, 'export', container], env=environment(), stdout=subprocess.PIPE)
            try:
                run([engine, 'run', '--rm', '-i', '--network=none', '-v', str(disks) + ':/out:Z', tag,
                     'sh', '-ec', 'mkdir /tmp/fs; tar -xpf - -C /tmp/fs; '
                     'truncate -s "$1"G /out/rootfs.ext4; '
                     'mke2fs -q -F -t ext4 -O ^orphan_file,^metadata_csum_seed -d /tmp/fs /out/rootfs.ext4; '
                     'chmod 644 /out/rootfs.ext4', 'sh', str(args.disk_size)], stdin=producer.stdout, timeout=1200)
                producer.stdout.close()
                if producer.wait(timeout=10):
                    raise Error('container export failed')
            finally:
                producer.stdout.close()
                if producer.poll() is None:
                    producer.kill()
                producer.wait()
            run(['cp', '--reflink=auto', '--sparse=always', str(disks / 'rootfs.ext4'), str(output / 'rootfs.ext4')], timeout=300)
            (output / 'rootfs.ext4').chmod(0o600)
            info = {'version': 1, 'architecture': platform.machine(),
                    'claude_version': 'local' if args.claude_binary else args.claude_version,
                    'sha256': {name: digest(output / name) for name in ('firecracker', 'vmlinux', 'rootfs.ext4')}}
            private(output / 'image.json', json.dumps(info, indent=2).encode() + b'\n')
            preflight(output)
            os.rename(output, destination)
        finally:
            if container:
                subprocess.run([engine, 'rm', '-f', container], env=environment(), capture_output=True, timeout=30)
            subprocess.run([engine, 'rmi', tag], env=environment(), capture_output=True, timeout=30)
    print(f'Built VM image at {destination}')
    return 0


def image_info(directory):
    directory = Path(directory).expanduser().resolve()
    try:
        info = json.loads((directory / 'image.json').read_text())
    except (OSError, ValueError) as error:
        raise Error(f'no valid VM image at {directory}; run monitor image build') from error
    if info.get('version') != 1 or info.get('architecture') != platform.machine():
        raise Error('VM image version or architecture is unsupported')
    for name in ('firecracker', 'vmlinux', 'rootfs.ext4'):
        if not (directory / name).is_file() or not re.fullmatch('[0-9a-f]{64}', info.get('sha256', {}).get(name, '')):
            raise Error(f'VM image is missing {name} or its checksum')
    return directory, info


def sandbox(binary, mounts=()):
    bwrap = shutil.which('bwrap')
    if not bwrap:
        raise Error('install bubblewrap (bwrap) to isolate the Firecracker process')
    return [bwrap, '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--proc', '/proc', '--dev', '/dev',
            '--dev-bind', '/dev/kvm', '/dev/kvm', '--ro-bind', str(binary), '/firecracker',
            *mounts, '--', '/firecracker']


def preflight(image):
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise Error('Monitor VMs currently require x86_64 Linux with KVM')
    if sys.version_info < (3, 11):
        raise Error('VM launch requires Python 3.11 or newer')
    for executable in ('ssh', 'ssh-keygen', 'mke2fs', 'tar', 'cp'):
        if not shutil.which(executable):
            raise Error(f'{executable} is required for VM launch')
    import fcntl
    try:
        with open('/dev/kvm', 'rb+') as kvm:
            if fcntl.ioctl(kvm, 0xAE00, 0) != 12:
                raise Error('unsupported KVM API version')
    except OSError as error:
        raise Error('VM launch needs read/write access to /dev/kvm') from error
    directory, info = image_info(image)
    for name in ('firecracker', 'vmlinux'):
        if digest(directory / name) != info['sha256'][name]:
            raise Error(f'{name} checksum changed; rebuild the VM image')
    result = subprocess.run(sandbox(directory / 'firecracker') + ['--version'], env=environment(),
                            capture_output=True, timeout=15)
    if result.returncode:
        raise Error('Firecracker sandbox failed; bubblewrap needs unprivileged user namespaces and a static Firecracker binary: '
                    + result.stderr.decode(errors='replace')[-2000:])
    return directory


def keypair(path):
    if not path.exists():
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'monitor-vm', '-f', str(path)],
            capture_output=True, timeout=15)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Error(f'{path} must be an owner-only regular file')
    return run(['ssh-keygen', '-y', '-f', str(path)], capture_output=True, timeout=15).stdout.strip()


def prepare_disk(directory, image):
    disk = directory / 'rootfs.ext4'
    if disk.exists():
        info = disk.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Error('VM disk must be an owner-only regular file')
        return
    image, info = image_info(image)
    if digest(image / 'rootfs.ext4') != info['sha256']['rootfs.ext4']:
        raise Error('rootfs image checksum changed; rebuild the VM image')
    temporary = directory / 'rootfs.partial'
    try:
        run(['cp', '--reflink=auto', '--sparse=always', str(image / 'rootfs.ext4'), str(temporary)], timeout=300)
        temporary.chmod(0o600)
        os.replace(temporary, disk)
    finally:
        temporary.unlink(missing_ok=True)


def process_identity(pid):
    try:
        # comm may contain spaces and parentheses. Fields after the final ')'
        # start at field 3; starttime is field 22.
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if fields[0] == 'Z':
            return None
        return [Path('/proc/sys/kernel/random/boot_id').read_text().strip(), fields[19]]
    except (FileNotFoundError, ProcessLookupError):
        return None


def ensure_stopped(directory):
    try:
        state = json.loads((Path(directory) / 'runtime.json').read_text())
    except FileNotFoundError:
        return
    deadline = time.monotonic() + 5
    while state.get('process') and process_identity(state['pid']) == state['process']:
        if time.monotonic() > deadline:
            raise Error('the previous VM process is still shutting down; retry shortly')
        time.sleep(0.1)


def seed_image(directory, runtime, profile, workspace, source, fresh):
    admin = keypair(directory / 'admin')
    host = keypair(directory / 'host_key')
    private(directory / 'known_hosts', b'monitor-vm ' + host + b'\n')
    with tempfile.TemporaryDirectory(prefix='seed-', dir=runtime) as temporary:
        seed = Path(temporary)
        private(seed / 'authorized_keys', admin + b'\n')
        private(seed / 'host_key', (directory / 'host_key').read_bytes())
        private(seed / 'id', (directory / 'id').read_bytes())
        private(seed / 'known_hosts', b'monitor-server ' + (Path(profile['root']) / 'host_key').read_bytes().strip() + b'\n')
        private(seed / 'monitor', bundle(source))
        private(seed / 'ssh_config', b'''Host monitor
  HostName 127.0.0.1
  Port 2223
  User monitor
  HostKeyAlias monitor-server
  StrictHostKeyChecking yes
  IdentitiesOnly yes
  IdentityAgent none
  ForwardAgent no
  ProxyCommand none
  IdentityFile /home/agent/.config/monitor/id
  UserKnownHostsFile /home/agent/.config/monitor/known_hosts
  GlobalKnownHostsFile /dev/null
''')
        archive = seed / 'workspace.tar'
        if fresh:
            # GNU tar preserves symlinks without following them. Project files
            # are data only; nothing from the project runs on the host.
            run(['tar', '-cf', str(archive), '-C', str(workspace), '--exclude-vcs-ignores',
                 '--exclude=.env', '--exclude=.env.*', '--exclude=node_modules', '--exclude=.venv', '--', '.'], timeout=300)
        else:
            with tarfile.open(archive, 'w'):
                pass
        size = max(64 << 20, sum(p.stat().st_size for p in seed.iterdir()) * 2 + (32 << 20))
        path = runtime / 'seed.ext4'
        with path.open('wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.truncate((size + 4095) // 4096 * 4096)
        run(['mke2fs', '-q', '-t', 'ext4', '-F', '-b', '4096', '-O', '^orphan_file,^metadata_csum_seed',
             '-d', str(seed), str(path)], capture_output=True, timeout=120)


def connect_vsock(path, port=22, timeout=5):
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(timeout)
    try:
        stream.connect(str(path))
        stream.sendall(f'CONNECT {int(port)}\n'.encode())
        line = b''
        while not line.endswith(b'\n') and len(line) < 64:
            char = stream.recv(1)
            if not char:
                break
            line += char
        if not re.fullmatch(rb'OK [0-9]+\n', line):
            raise Error('guest vsock service is not ready')
        stream.settimeout(None)
        return stream
    except BaseException:
        stream.close()
        raise


def proxy(path):
    with connect_vsock(path) as stream:
        inputs = [stream, sys.stdin.buffer]
        while inputs:
            ready, _, _ = select.select(inputs, [], [])
            for item in ready:
                if item is stream:
                    data = stream.recv(65536)
                    if not data:
                        return 0
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                else:
                    data = os.read(sys.stdin.fileno(), 65536)
                    if data:
                        stream.sendall(data)
                    else:
                        stream.shutdown(socket.SHUT_WR)
                        inputs.remove(item)
    return 0


class VM:
    def __init__(self, profile, directory, workspace, source, endpoint):
        self.profile, self.directory = profile, Path(directory)
        self.workspace, self.source = Path(workspace), program(source)
        self.endpoint = endpoint
        self.process = self.control = self.temporary = None
        self.control_thread = self.log_thread = None
        self.boot_log = bytearray()
        self.stopping = threading.Event()

    def __enter__(self):
        try:
            image = preflight(self.profile['image'])
            ensure_stopped(self.directory)
            self.temporary = tempfile.TemporaryDirectory(prefix='monitor-vm-')
            self.runtime = Path(self.temporary.name)
            fresh = not (self.directory / 'initialized').exists()
            prepare_disk(self.directory, image)
            seed_image(self.directory, self.runtime, self.profile, self.workspace, self.source, fresh)
            config = {
                'boot-source': {'kernel_image_path': '/kernel', 'boot_args':
                    'console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/monitor-init'},
                'drives': [
                    {'drive_id': 'rootfs', 'path_on_host': '/rootfs.ext4', 'is_root_device': True, 'is_read_only': False,
                     'cache_type': 'Writeback'},
                    {'drive_id': 'seed', 'path_on_host': '/seed.ext4', 'is_root_device': False, 'is_read_only': True}],
                'machine-config': {'vcpu_count': self.profile['cpus'], 'mem_size_mib': self.profile['memory']},
                'network-interfaces': [],
                'vsock': {'guest_cid': 3, 'uds_path': '/run/monitor/vsock'},
            }
            private(self.runtime / 'firecracker.json', json.dumps(config).encode())
            mounts = ['--ro-bind', str(image / 'vmlinux'), '/kernel',
                      '--bind', str(self.directory / 'rootfs.ext4'), '/rootfs.ext4',
                      '--ro-bind', str(self.runtime / 'seed.ext4'), '/seed.ext4',
                      '--bind', str(self.runtime), '/run/monitor']
            # Socket path is fixed and owned by this launch. No saved PID is ever
            # signaled, and no guest data determines a host command or filename.
            self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.control.bind(str(self.runtime / 'control.sock'))
            self.control.listen(4)
            self.control.settimeout(0.2)
            self.control_thread = threading.Thread(target=self.control_loop, daemon=True)
            self.control_thread.start()
            self.process = subprocess.Popen(sandbox(image / 'firecracker', mounts) + [
                '--api-sock', '/run/monitor/api.sock', '--config-file', '/run/monitor/firecracker.json'],
                env=environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            private(self.directory / 'runtime.json', json.dumps({
                'control': str(self.runtime / 'control.sock'), 'pid': self.process.pid,
                'process': process_identity(self.process.pid)}).encode())
            self.log_thread = threading.Thread(target=self.read_log, daemon=True)
            self.log_thread.start()
            self.wait_ready()
            private(self.directory / 'initialized', b'1\n')
            return self
        except BaseException:
            self.close()
            raise

    def read_log(self):
        for block in iter(lambda: self.process.stdout.read(4096), b''):
            self.boot_log.extend(block)
            del self.boot_log[:-65536]

    def control_loop(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.control.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with client:
                client.settimeout(1)
                with contextlib.suppress(OSError):
                    if client.recv(16) == b'stop\n':
                        self.stopping.set()
                        client.sendall(b'ok\n')

    def check(self):
        if self.stopping.is_set():
            raise Error('VM stopped by monitor stop')
        if self.process.poll() is not None:
            raise Error('Firecracker exited; the VM disk was retained. Boot log: ' +
                        bytes(self.boot_log[-4000:]).decode(errors='replace'))

    def ssh(self, monitor=False):
        transport = shlex.join([sys.executable, str(self.source), '_vm-connect', str(self.runtime / 'vsock')]).replace('%', '%%')
        forwards = ['-o', 'ClearAllForwardings=yes']
        if monitor:
            host, port = self.endpoint
            host = f'[{host}]' if ':' in host else host
            forwards = ['-o', 'ClearAllForwardings=no', '-o', 'ExitOnForwardFailure=yes',
                        '-R', f'127.0.0.1:2223:{host}:{port}']
        return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no', *forwards,
                '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile="' + str(self.directory / 'known_hosts').replace('\\', '\\\\').replace('"', '\\"') + '"',
                '-o', 'HostKeyAlias=monitor-vm', '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR',
                '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
                '-o', 'ProxyCommand=' + transport, '-i', str(self.directory / 'admin')]

    def wait_ready(self):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            self.check()
            try:
                with connect_vsock(self.runtime / 'vsock', timeout=1):
                    pass
                probe = subprocess.run(self.ssh() + ['agent@monitor-vm', 'true'], env=environment(),
                                       capture_output=True, timeout=7)
                if probe.returncode == 0:
                    return
            except (OSError, Error, subprocess.TimeoutExpired):
                pass
            time.sleep(0.2)
        raise Error('VM boot timed out; disk retained. Boot log: ' + bytes(self.boot_log[-4000:]).decode(errors='replace'))

    def agent(self, arguments, mcp=False):
        command = ['python3', '/opt/monitor/monitor', '--ssh-config', '/home/agent/.config/monitor/ssh_config',
                   '_agent', '--connection', self.profile['connection']]
        if mcp:
            command.append('--mcp')
        command += ['--', *arguments]
        return self.ssh(monitor=True) + (['-t'] if sys.stdin.isatty() else []) + ['agent@monitor-vm', 'cd /workspace && exec ' + shlex.join(command)]

    def close(self):
        self.stopping.set()
        if self.process:
            if self.process.poll() is None:
                with contextlib.suppress(OSError, http.client.HTTPException):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                        stream.settimeout(2)
                        stream.connect(str(self.runtime / 'api.sock'))
                        connection = http.client.HTTPConnection('localhost', timeout=2)
                        connection.sock = stream
                        try:
                            connection.request('PUT', '/actions', json.dumps({'action_type': 'SendCtrlAltDel'}), {'Content-Type': 'application/json'})
                            connection.getresponse().read()
                        finally:
                            connection.close()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            if self.log_thread:
                self.log_thread.join(timeout=1)
            self.process.stdout.close()
        if self.control:
            self.control.close()
            if self.control_thread:
                self.control_thread.join(timeout=2)
            (self.directory / 'runtime.json').unlink(missing_ok=True)
        if self.temporary:
            self.temporary.cleanup()

    def __exit__(self, *_):
        self.close()


def stop(directory):
    try:
        state = json.loads((Path(directory) / 'runtime.json').read_text())
    except FileNotFoundError as error:
        raise Error('this VM is not running') from error
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        try:
            client.connect(state['control'])
            client.sendall(b'stop\n')
            if client.recv(16) != b'ok\n':
                raise Error('VM did not acknowledge the stop request')
        except (FileNotFoundError, ConnectionRefusedError) as error:
            raise Error('this VM is not running') from error


def export(vm, destination):
    """Write an opaque archive. Guest paths are never extracted on the host."""
    destination = Path(destination).expanduser().absolute()
    if destination.exists():
        raise Error('export destination already exists; choose a new file')
    fd, temporary = tempfile.mkstemp(prefix='.monitor-export-', dir=destination.parent)
    child = None
    try:
        with os.fdopen(fd, 'wb') as output:
            child = subprocess.Popen(vm.ssh() + ['agent@monitor-vm', 'tar -C /workspace -cf - .'],
                                     env=environment(), stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
            deadline, count = time.monotonic() + 300, 0
            limit = (vm.directory / 'rootfs.ext4').stat().st_size * 2
            while True:
                vm.check()
                if time.monotonic() > deadline:
                    raise Error('workspace export timed out')
                if not select.select([child.stdout], [], [], 0.2)[0]:
                    continue
                block = os.read(child.stdout.fileno(), 65536)
                if not block:
                    break
                count += len(block)
                if count > limit:
                    raise Error('workspace export exceeds twice the VM disk size')
                output.write(block)
            if child.wait(timeout=10):
                raise Error('guest could not export its workspace')
        os.link(temporary, destination)  # Fails if another writer created it.
    finally:
        if child:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
        Path(temporary).unlink(missing_ok=True)


def private_read(path):
    """Read host credentials/state without following a final-component symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8", newline="") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Error(f"{path} must be an owner-only regular file (chmod 600)")
        return source.read()


@contextlib.contextmanager
def launch_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Error("another Monitor setup or launch is using this state") from error
        yield


def owner_token(value):
    """Preserve supplied text; recognize old random keys and CLI key records."""
    try:
        record = json.loads(value)
    except (ValueError, TypeError):
        record = None
    if isinstance(record, dict) and record.get("version") == 2:
        raise Error("owner signing requires an attested client; use tinfoil monitor open")
    if isinstance(record, dict) and {"version", "key"} <= record.keys():
        if record.get("version") != 1 or not isinstance(record.get("key"), str):
            raise Error("invalid owner key record")
        try:
            raw = base64.b64decode(record["key"], validate=True)
        except (ValueError, TypeError) as error:
            raise Error("invalid owner key record") from error
    else:
        legacy = value.strip()
        try:
            raw = base64.b64decode(legacy, validate=True)
            if len(raw) == 32 and base64.b64encode(raw).decode() == legacy:
                return legacy
        except (ValueError, TypeError):
            pass
        raw = value.encode("utf-8")
    if not 16 <= len(raw) <= 4096:
        raise Error("use an owner key or passphrase between 16 and 4096 UTF-8 bytes")
    return base64.b64encode(raw).decode()


class OwnerClient:
    """Use the existing owner API. Owner credentials never enter the VM."""
    def __init__(self, url, key, timeout=30):
        self.url = urlsplit(url)
        self.key = owner_token(key)
        self.timeout = timeout
        if self.url.username or self.url.password or self.url.query or self.url.fragment or not self.url.hostname:
            raise Error("owner URL must be an HTTP(S) URL without credentials, query or fragment")
        try:
            loopback = ipaddress.ip_address(self.url.hostname).is_loopback
        except ValueError:
            loopback = self.url.hostname == "localhost"
        if self.url.scheme != "https" and not (self.url.scheme == "http" and loopback):
            raise Error("use HTTPS for a remote owner API, or HTTP on loopback through a trusted tunnel")

    def request(self, method="GET", body=None, path="/"):
        cls = http.client.HTTPSConnection if self.url.scheme == "https" else http.client.HTTPConnection
        connection = cls(self.url.hostname, self.url.port, timeout=self.timeout)
        try:
            # http.client neither follows redirects nor uses proxy environment variables.
            connection.request(method, self.url.path.rstrip("/") + path,
                               body=json.dumps(body).encode() if body is not None else None,
                               headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read(16 * 1024 * 1024 + 1)
            if response.status != 200:
                raise Error(f"owner API returned HTTP {response.status}: {data.decode(errors='replace').strip()}")
            if len(data) > 16 * 1024 * 1024:
                raise Error("owner API response is too large")
            return json.loads(data)
        finally:
            connection.close()

    def edit(self, changes):
        return self.request("POST", {"changes": changes}, path="/policy/edits")


def profile_name(args):
    name = args.profile or "default"
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name):
        raise Error("profile name must contain only letters, digits, underscores and hyphens")
    return name


def setup_value(value, prompt, default=None):
    if value is not None:
        return value
    if not sys.stdin.isatty():
        if default is not None:
            return default
        raise Error(f"{prompt} is required; use monitor setup --help for noninteractive options")
    answer = input(prompt + (f" [{default}]" if default else "") + ": ").strip()
    return answer or default


def endpoint_address(value):
    parsed = urlsplit("ssh://" + value)
    if not parsed.hostname or not parsed.port or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise Error("SSH endpoint must be HOST:PORT or [IPv6]:PORT")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
    address = addresses[0][4][0]
    return f"[{address}]:{parsed.port}" if ":" in address else f"{address}:{parsed.port}"


def setup_launch(args):
    if sys.platform != "linux":
        raise Error("Monitor VM launch currently requires Linux/Firecracker")
    name = profile_name(args)
    config_path = Path(args.client_config).expanduser().resolve()
    with launch_lock(config_path.with_suffix(".lock")):
        config = json.loads(private_read(config_path)) if config_path.exists() else {}
        if name in config.get("launch_profiles", {}):
            raise Error(f"launch profile {name!r} already exists; choose a new --profile to change its server or permissions")
        root = config_path.parent / "launch" / name
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not 1 <= args.cpus <= 32 or not 512 <= args.memory <= 65536:
            raise Error("choose 1–32 CPUs and 512–65536 MiB of memory")
        image = str(preflight(args.image))
        owner_url = setup_value(args.owner_url, "Monitor owner URL", "http://127.0.0.1:8080")
        endpoint = setup_value(args.endpoint, "Monitor SSH endpoint as reached by this host", "127.0.0.1:2223")
        endpoint_address(endpoint)
        if args.owner_key_file:
            key = private_read(Path(args.owner_key_file).expanduser())
        elif sys.stdin.isatty():
            key = getpass.getpass("Monitor owner key or passphrase (saved only on this host): ")
        else:
            raise Error("pass --owner-key-file pointing to an owner-only file")
        owner = OwnerClient(owner_url, key)
        view = owner.request()
        connections = view["config"].get("connections", {})
        # A connection's kind is its key naming a connector, such as "http".
        candidates = [name for name, settings in connections.items()
                      if settings.get("preset") == "anthropic" and "http" in settings]
        connection = setup_value(args.connection, "Anthropic HTTP connection", candidates[0] if len(candidates) == 1 else None)
        if "http" not in connections.get(connection, {}):
            raise Error("choose an existing HTTP connection for the Anthropic API")
        access_spec = args.access or [item.strip() for item in setup_value(
            None, "Connection access, comma-separated name=read|ask|allow", connection + "=allow").split(",")]
        access = {}
        for item in access_spec:
            name, sep, level = item.partition("=")
            if not sep or name not in connections or level not in ("read", "ask", "allow"):
                raise Error(f"invalid connection access {item!r}; use an existing connection and read, ask or allow")
            access[name] = {"level": level}
        if connection not in access:
            raise Error("the Anthropic connection must be included in --access")
        host_key = view["host_key"].strip()
        if "\n" in host_key or not host_key.startswith(("ssh-", "ecdsa-")):
            raise Error("owner API returned an invalid SSH host key")
        private(root / "owner.key", key.encode())
        private(root / "host_key", host_key.encode() + b"\n")
        profile = {"version": 3, "id": uuid.uuid4().hex, "owner_url": owner_url, "endpoint": endpoint,
                   "root": str(root), "image": image, "cpus": args.cpus, "memory": args.memory,
                   "connection": connection, "access": access, "mcp": args.mcp}
        config.setdefault("launch_profiles", {})[name] = profile
        private(config_path, json.dumps(config, indent=2).encode() + b"\n")
        print(f"Saved launch profile {name!r}. Owner key stays in {root / 'owner.key'}.")
        prefix = "monitor" + (" --profile " + name if name != "default" else "")
        print(f"From a project directory, run: {prefix} launch claude")
    return 0


def enroll_identity(owner, state, state_path, public_key, access):
    view = owner.request()
    existing = view["config"].get("identities", {}).get(state["name"])
    if existing:
        if existing["key"].strip() != public_key.strip():
            raise Error("this VM's Monitor identity has a different key; refusing to replace it")
        # Never replay initial access over permissions edited in the web app.
    elif state["enrolled"]:
        raise Error("this VM's Monitor identity was revoked; destroy the VM before creating a new identity")
    else:
        # Record the attempt first. A lost response followed by owner revocation
        # must not cause a later launch to restore the initial grant.
        state["enrolled"] = True
        private(state_path, json.dumps(state, indent=2).encode() + b"\n")
        owner.edit([{"path": ["identities", state["name"]], "value": {"key": public_key, "connections": access}}])
    state["enrolled"] = True
    private(state_path, json.dumps(state, indent=2).encode() + b"\n")


def revoke_identity(owner, name, public_key):
    ids = owner.request()["config"].get("identities", {})
    if name not in ids:
        return
    if ids[name]["key"].strip() != public_key.strip():
        raise Error("this VM's Monitor identity has a different key; refusing to revoke it")
    owner.edit([{"path": ["identities", name], "delete": True}])


def launch_vm(args, cli):
    if sys.platform != "linux":
        raise Error("Monitor VM launch currently requires Linux/Firecracker")
    name = profile_name(args)
    config_path = Path(args.client_config).expanduser().resolve()
    try:
        profile = json.loads(private_read(config_path))["launch_profiles"][name]
    except (FileNotFoundError, KeyError) as error:
        raise Error("run monitor setup first for this profile") from error
    if profile["version"] != 3:
        raise Error("this launch profile is from an older monitor; run monitor setup with a new --profile")
    root = Path(profile["root"])
    workspace = Path(args.workspace).expanduser().resolve()
    if workspace == Path.home().resolve() or workspace.parent == workspace:
        raise Error("choose a project directory, not your home or filesystem root")
    if args.command == "launch" and not workspace.is_dir():
        raise Error("choose an existing project directory")
    if workspace == root.resolve() or workspace in root.resolve().parents:
        raise Error("the project contains Monitor's host credentials; choose a project outside the launch configuration directory")
    identity = "vm-" + hashlib.sha256((profile["id"] + "\0" + str(workspace)).encode()).hexdigest()[:32]
    directory = root / "instances" / identity
    if args.command == "stop":
        stop(directory)
        print("Requested VM shutdown; its disk and identity will be retained.")
        return 0
    with launch_lock(root / "locks" / identity):
        state_path = directory / "state.json"
        if state_path.exists():
            state = json.loads(private_read(state_path))
            if state["workspace"] != str(workspace) or state["name"] != identity:
                raise Error("VM state does not match this project")
        elif args.command != "launch":
            raise Error("no Monitor VM is recorded for this project")
        else:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            state = {"name": identity, "workspace": str(workspace), "enrolled": False, "revoked": False}
            private(state_path, json.dumps(state).encode() + b"\n")
        public_key = keypair(directory / "id").decode() + "\n"
        if args.command in ("launch", "destroy"):
            owner = OwnerClient(profile["owner_url"], private_read(root / "owner.key"))
        if args.command == "destroy":
            ensure_stopped(directory)
            revoke_identity(owner, identity, public_key)
            state["revoked"] = True
            private(state_path, json.dumps(state).encode() + b"\n")
            shutil.rmtree(directory)
            print("Revoked the Monitor identity and destroyed the VM.")
            return 0
        if args.command == "launch" and state.get("revoked"):
            raise Error("this VM is being destroyed; retry monitor destroy")
        preflight(profile["image"])
        if args.command == "launch":
            enroll_identity(owner, state, state_path, public_key, profile["access"])
        elif not (directory / "initialized").exists():
            raise Error("this VM has no initialized workspace to export")
        endpoint = None
        if args.command == "launch":
            address = urlsplit("ssh://" + endpoint_address(profile["endpoint"]))
            endpoint = (address.hostname, address.port)
        with VM(profile, directory, workspace, cli.__file__, endpoint) as vm:
            if args.command == "export":
                export(vm, args.output)
                print(f"Saved workspace archive to {args.output}")
                return 0
            arguments = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
            return cli.run_child(vm, vm.agent(arguments, profile.get("mcp", False)), environment())


def guest_agent(cli, client, args):
    with cli.Session(client) as session:
        env = session.environment([], None)
        connection = next((c for c in session.connections if c["name"] == args.connection), None)
        if connection is None:
            raise Error("the model connection is not accessible to this VM")
        if connection["state"] != "ready":
            raise Error("the model connection is not ready; check its access and status in Monitor")
        values = connection["placeholders"]
        variable = next((key for key in ("ANTHROPIC_API_KEY", "token") if key in values), None)
        if variable is None:
            raise Error("model connection needs a token or ANTHROPIC_API_KEY credential slot")
        for name in ("ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            env.pop(name, None)
        env["ANTHROPIC_API_KEY"] = values[variable]
        env["DISABLE_AUTOUPDATER"] = "1"
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
        arguments = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        command = ["claude", "--dangerously-skip-permissions"]
        if args.mcp:
            servers, count = cli.mcp_servers(session)
            if not count:
                raise Error("no MCP tools are available; review connection access and tools in Monitor")
            mcp_config = session.directory / "mcp.json"
            mcp_config.write_text(json.dumps({"mcpServers": servers}))
            # These endpoints live in the guest. Sending them through the HTTP
            # proxy would ask the Monitor server to connect to its own loopback.
            env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost,::1"
            command += ["--mcp-config", str(mcp_config)]
        return cli.run_child(session, command + arguments, env)


def owner_policy(args):
    if not args.owner_url or not args.owner_key_file:
        raise Error("provide both --owner-url and --owner-key-file")
    if args.policy_action in ("propose", "status"):
        raise Error("proposal commands use the agent's SSH identity; omit owner options")
    owner = OwnerClient(args.owner_url, private_read(Path(args.owner_key_file).expanduser()))
    if args.policy_action == "show":
        result = owner.request(path="/policy?effective" if args.effective else "/policy")
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(result["effective" if args.effective else "source"], end="")
        return 0
    body = {"source": sys.stdin.read() if args.file == "-" else Path(args.file).read_text()}
    if args.policy_action == "diff":
        preview = owner.request("POST", body, path="/policy/preview")
        print(preview["source_diff"] or "No source changes.")
        print("Effective policy changes:")
        print(preview["effective_diff"] or "No effective changes.")
    else:
        owner.request("POST", body, path="/policy")
        print("Policy applied")
    return 0


COMMANDS = ("setup", "launch", "destroy", "stop", "export", "image", "_vm-connect", "_agent")


def add_commands(commands, policy_commands):
    policy = commands.choices["policy"]
    policy.add_argument("--owner-url", help="owner API URL for the full source, diff and apply")
    policy.add_argument("--owner-key-file", help="owner key or passphrase file; never needed for agent proposals")
    policy_commands.choices["show"].add_argument("--effective", action="store_true", help="expand presets and defaults; requires owner authentication")
    for action in ("diff", "apply"):
        command = policy_commands.add_parser(action, help={"diff": "validate and preview a replacement policy", "apply": "apply a replacement policy"}[action])
        command.add_argument("file", help="TOML file, or - for stdin")
    setup = commands.add_parser("setup", help="configure one-command Linux VM launch")
    setup.add_argument("--owner-url", help="unlocked Monitor owner API URL")
    setup.add_argument("--owner-key-file", help="owner-only file containing a key or passphrase; otherwise prompt privately")
    setup.add_argument("--endpoint", help="Monitor SSH HOST:PORT as reached by this host")
    setup.add_argument("--image", default=str(Path.home() / ".local/share/monitor/images/default"), help="prepared VM image directory")
    setup.add_argument("--cpus", type=int, default=2, help="VM CPU count (default: 2)")
    setup.add_argument("--memory", type=int, default=4096, help="VM memory in MiB (default: 4096)")
    setup.add_argument("--connection", help="Anthropic HTTP connection name")
    setup.add_argument("--access", action="append", help="initial connection access NAME=read|ask|allow; repeat for several")
    setup.add_argument("--mcp", action="store_true", help="also connect Claude to Monitor's MCP connections")
    launch = commands.add_parser("launch", help="launch an agent in a Monitor-connected Linux VM")
    launch.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    launch.add_argument("agent", choices=["claude"])
    launch.add_argument("argv", nargs=argparse.REMAINDER, help="-- ARGUMENTS passed to Claude")
    destroy = commands.add_parser("destroy", help="revoke the project's Monitor identity and destroy its VM")
    destroy.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    stop = commands.add_parser("stop", help="stop the project's running VM and retain its disk")
    stop.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    export = commands.add_parser("export", help="save the stopped VM's workspace as a tar archive")
    export.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    export.add_argument("--output", required=True, help="new archive file to create on this host")
    image = commands.add_parser("image", help="prepare a Firecracker guest image")
    build = image.add_subparsers(dest="action", required=True).add_parser("build", help="build the image with Podman or Docker")
    build.add_argument("--output", default=str(Path.home() / ".local/share/monitor/images/default"))
    build.add_argument("--engine", help="container engine executable (default: podman or docker)")
    build.add_argument("--firecracker", help="use a local static Firecracker binary")
    build.add_argument("--kernel", help="use a local Firecracker-compatible guest kernel")
    build.add_argument("--claude-version", default="stable", help="Claude release to install (default: stable)")
    build.add_argument("--claude-binary", help="use an existing native Linux Claude binary instead of downloading")
    build.add_argument("--disk-size", type=int, default=8, help="VM disk size in GiB (default: 8)")
    proxy = commands.add_parser("_vm-connect")
    proxy.add_argument("socket")
    agent = commands.add_parser("_agent")
    agent.add_argument("--connection", required=True)
    agent.add_argument("--mcp", action="store_true")
    agent.add_argument("argv", nargs=argparse.REMAINDER)


def handles(args):
    if args.command == "policy":
        return bool(args.owner_url or args.owner_key_file or getattr(args, "effective", False)
                    or args.policy_action in ("diff", "apply"))
    return args.command in COMMANDS


def command(args, cli):
    """Run an owner or VM command. cli is the main monitor module."""
    if args.command == "policy":
        return owner_policy(args)
    if args.command == "setup":
        return setup_launch(args)
    if args.command == "image":
        with launch_lock(Path(args.output).expanduser().resolve().with_suffix(".lock")):
            return build_image(args)
    if args.command == "_vm-connect":
        return proxy(args.socket)
    if args.command == "_agent":
        if sys.version_info < (3, 11):
            raise Error("the VM agent requires Python 3.11 or newer")
        return guest_agent(cli, cli.connect(args), args)
    return launch_vm(args, cli)
