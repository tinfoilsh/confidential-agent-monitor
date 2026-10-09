"""Linux Firecracker lifecycle. No guest NIC or shared host directories."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import io
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
import urllib.request
import zipfile


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
        for name in ('Dockerfile', 'guest.py', 'init.sh', 'assets.json'):
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
        for name in ('Dockerfile', 'guest.py', 'init.sh'):
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
