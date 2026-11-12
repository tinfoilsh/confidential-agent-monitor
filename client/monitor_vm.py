"""Linux bunkers in Firecracker, vfkit, Podman/Docker or bubblewrap. The Perimeter link is their only network."""
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


ASSETS = ('guest.py', 'assets.json', 'agents.json')
BACKENDS = ('firecracker', 'vfkit', 'podman', 'docker', 'bwrap')
DEFAULT_BACKEND = 'vfkit' if sys.platform == 'darwin' else 'firecracker'
ARCH = {'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
TAR = 'gtar' if shutil.which('gtar') else 'tar'
CACHE = Path.home() / '.local/share/perimeter'
# A directory of dev/vm-artifacts output to use instead of downloading.
ARTIFACTS_ENV = 'PERIMETER_ARTIFACTS'
MAX_ASSET_BYTES = 4 << 30
DISK_GIB = 8
# The guest's 127.0.0.1 port that carries its Perimeter link.
LINK_PORT = 2223
# These mirror sandbox.BootstrapUser and the Perimeter's wildcard route forward.
ROUTE_USER, WILDCARD_FORWARD, WILDCARD_OPEN = "sandbox-v2:", "127.0.0.1:1080", "127.0.0.2:*"
GUEST_CLI = ['python3', '/opt/monitor/perimeter', '--ssh-config', '/home/agent/.config/perimeter/ssh_config']
GUEST_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
AGENT_UID = 1000
READY_SECONDS = 90
STOP_SECONDS = 10
# Containers share agents through this engine volume, mounted read-only at /nix.
AGENT_VOLUME = 'perimeter-agents'
GUEST_SSHD = ['/usr/sbin/sshd', '-i', '-f', '/etc/ssh/sshd_config.monitor']
VFKIT_CMDLINE = 'console=hvc0 root=/dev/vda rw init=/sbin/monitor-init panic=1'
# vfkit requires an initrd; this empty newc archive leaves the kernel to mount root=.
EMPTY_INITRD = b'070701' + b'00000000' * 4 + b'00000001' + b'00000000' * 6 + b'0000000B' + b'00000000' + b'TRAILER!!!\0\0\0\0'


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
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.perimeter-')
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
    if not 0 < size <= MAX_ASSET_BYTES:
        raise Error(f'VM asset must have a known size of at most {MAX_ASSET_BYTES >> 30} GiB')
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


def manifest():
    return json.loads(asset('assets.json'))


def fetch(entry):
    """Return the verified local copy of a pinned asset, fetching it once."""
    path = CACHE / 'artifacts' / entry['sha256']
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.partial')
    local = os.environ.get(ARTIFACTS_ENV)
    try:
        if local and 'file' in entry:
            shutil.copyfile(Path(local) / entry['file'], temporary)
            if digest(temporary) != entry['sha256']:
                raise Error('VM asset checksum mismatch: ' + entry['file'])
        else:
            url = entry.get('url') or manifest()['base_url'] + entry['file']
            print('Downloading ' + url.rsplit('/', 1)[-1] + '...', file=sys.stderr, flush=True)
            download(url, temporary, entry['sha256'])
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def derived(entry, suffix, build):
    """Cache build(asset, temporary) beside the pinned asset it comes from."""
    path = CACHE / 'artifacts' / (entry['sha256'] + suffix)
    if not path.exists():
        source = fetch(entry)
        temporary = path.with_name(path.name + '.partial')
        shutil.rmtree(temporary, ignore_errors=True)
        temporary.unlink(missing_ok=True)
        build(source, temporary)
        os.rename(temporary, path)
    return path


def extract_firecracker(source, target):
    with tarfile.open(source) as archive:
        member = archive.getmember(manifest()['firecracker']['member'])
        if not member.isfile():
            raise Error('Firecracker release member is not a regular file')
        with archive.extractfile(member) as binary:
            private(target, binary.read())
    target.chmod(0o700)


def untar(source, target):
    target.mkdir(mode=0o700)
    run(['tar', '-xzpf', str(source), '-C', str(target)], capture_output=True, timeout=1200)


def ext4(source, path):
    """Write a guest disk holding source's tree, a directory or tarball."""
    if Path(source).is_dir():
        sizes = [entry.lstat().st_size for entry in Path(source).rglob('*')]
    else:
        with tarfile.open(source) as archive:
            sizes = [member.size for member in archive]
    size = sum(-(-length // 4096) * 4096 for length in sizes) * 5 // 4 + (64 << 20)
    with path.open('wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.truncate(size)
    run(['mke2fs', '-q', '-t', 'ext4', '-F', '-b', '4096', '-N', str(len(sizes) + 1024),
         '-O', '^orphan_file,^metadata_csum_seed', '-d', str(source), str(path)], capture_output=True, timeout=1200)


def fetch_agents(names):
    """Fetch the named agents; return the pins of every agent fetched so far."""
    pins = manifest()[ARCH]['agents']
    for name in names:
        fetch(pins[name])
    return {name: pin for name, pin in pins.items() if (CACHE / 'artifacts' / pin['sha256']).exists()}


def agent_store(agents):
    """Unpack agents into the host store bwrap bunkers mount read-only."""
    root = CACHE / 'agents'
    store = root / 'nix/store'
    store.mkdir(parents=True, exist_ok=True)
    with launch_lock(root.with_suffix('.lock')):
        for name, pin in agents.items():
            marker = root / pin['sha256']
            if not marker.exists():
                print(f'Unpacking {name}...', file=sys.stderr, flush=True)
                run(['tar', '-xzpf', str(fetch(pin)), '-C', str(root), '--skip-old-files'],
                    capture_output=True, timeout=1200)
                marker.touch()
    return store


def agent_disks(agents):
    """Each agent as its own read-only guest disk, mounted under /nix/agents and linked into /nix/store."""
    with launch_lock(CACHE / 'agents.lock'):
        return [derived(pin, '.ext4', ext4) for pin in agents.values()]


def agent_volume(engine, agents):
    """Unpack agents into AGENT_VOLUME, recording each in a host marker per engine."""
    markers = CACHE / 'volumes'
    markers.mkdir(parents=True, exist_ok=True, mode=0o700)
    with launch_lock(CACHE / 'agents.lock'):
        if subprocess.run([engine, 'volume', 'inspect', AGENT_VOLUME], env=environment(), capture_output=True, timeout=30).returncode:
            for marker in markers.glob(engine + '-*'):
                marker.unlink()
        for name, pin in agents.items():
            marker = markers / f'{engine}-{pin["sha256"]}'
            if not marker.exists():
                print(f'Unpacking {name}...', file=sys.stderr, flush=True)
                with fetch(pin).open('rb') as closure:
                    run([engine, 'run', '--rm', '-i', '--network', 'none', '-v', f'{AGENT_VOLUME}:/nix', base_image(engine),
                         'tar', '-xzC', '/'], stdin=closure, capture_output=True, timeout=1200)
                marker.touch()


def sandbox(binary, mounts=()):
    bwrap = shutil.which('bwrap')
    if not bwrap:
        raise Error('install bubblewrap (bwrap) to isolate the Firecracker process')
    return [bwrap, '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--proc', '/proc', '--dev', '/dev',
            '--dev-bind', '/dev/kvm', '/dev/kvm', '--ro-bind', str(binary), '/firecracker',
            *mounts, '--', '/firecracker']


def require(*executables):
    for executable in executables:
        if not shutil.which(executable):
            raise Error(f'{executable} is required for this bunker backend')


def preflight(backend):
    if sys.version_info < (3, 11):
        raise Error('bunker launch requires Python 3.11 or newer')
    if 'base' not in manifest().get(ARCH, {}):
        raise Error(f'no bunker base is pinned for {ARCH}; build one with dev/vm-artifacts')
    require('ssh', 'ssh-keygen', TAR, 'cp')
    BUNKERS[backend].preflight(backend)


def keypair(path):
    if not path.exists():
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'monitor-vm', '-f', str(path)],
            capture_output=True, timeout=15)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Error(f'{path} must be an owner-only regular file')
    return run(['ssh-keygen', '-y', '-f', str(path)], capture_output=True, timeout=15).stdout.strip()


def prepare_disk(directory, base, gib):
    disk = directory / 'rootfs.ext4'
    if disk.exists():
        info = disk.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Error('VM disk must be an owner-only regular file')
        return
    temporary = directory / 'rootfs.partial'
    try:
        with temporary.open('wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.truncate(gib << 30)
        # Reading a tarball keeps its owners; mke2fs gained this in e2fsprogs 1.47.1.
        run(['mke2fs', '-q', '-t', 'ext4', '-O', '^orphan_file,^metadata_csum_seed', '-d', str(base), str(temporary)],
            capture_output=True, timeout=300)
        os.replace(temporary, disk)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_stopped(directory):
    """Return the bunker's run lock, which a launch's VMM inherits and holds until it exits."""
    lock = os.fdopen(os.open(Path(directory) / 'running.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), 'w')
    deadline = time.monotonic() + 5
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock
        except BlockingIOError:
            if time.monotonic() > deadline:
                lock.close()
                raise Error('the previous VM process is still shutting down; retry shortly') from None
            time.sleep(0.1)


def write_seed(directory, seed, profile, workspace, source, fresh, agents):
    admin = keypair(directory / 'admin')
    host = keypair(directory / 'host_key')
    private(directory / 'known_hosts', b'monitor-vm ' + host + b'\n')
    seed.mkdir(mode=0o700)
    private(seed / 'authorized_keys', admin + b'\n')
    private(seed / 'host_key', (directory / 'host_key').read_bytes())
    private(seed / 'id', (directory / 'id').read_bytes())
    private(seed / 'known_hosts', b'monitor-server ' + (Path(profile['root']) / 'host_key').read_bytes().strip() + b'\n')
    private(seed / 'perimeter', bundle(source))
    # launch_vm names each instance directory after its identity.
    private(seed / 'ssh_config', f'''Host perimeter-route
  User {ROUTE_USER}{directory.name}
  RemoteForward {WILDCARD_FORWARD}
  PermitRemoteOpen {WILDCARD_OPEN}
  ExitOnForwardFailure yes
Host perimeter perimeter-route
  HostName 127.0.0.1
  Port {LINK_PORT}
  User monitor
  HostKeyAlias monitor-server
  StrictHostKeyChecking yes
  IdentitiesOnly yes
  IdentityAgent none
  ForwardAgent no
  ProxyCommand none
  IdentityFile /home/agent/.config/perimeter/id
  UserKnownHostsFile /home/agent/.config/perimeter/known_hosts
  GlobalKnownHostsFile /dev/null
'''.encode())
    archive = seed / 'workspace.tar'
    if fresh:
        # GNU tar preserves symlinks without following them. Project files
        # are data only; nothing from the project runs on the host.
        run([TAR, '-cf', str(archive), '-C', str(workspace), '--exclude-vcs-ignores',
             '--exclude=.env', '--exclude=.env.*', '--exclude=node_modules', '--exclude=.venv', '--', '.'], timeout=300)
    else:
        with tarfile.open(archive, 'w'):
            pass
    private(seed / 'guest.py', asset('guest.py'))
    private(seed / 'agents.json', json.dumps({name: pin['path'] for name, pin in agents.items()}).encode())


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


def relay(left, right):
    with left, right:
        for stream in (left, right):
            stream.settimeout(None)
        streams = {left: right, right: left}
        while streams:
            ready, _, _ = select.select(list(streams), [], [], 1)
            for source in ready:
                data = source.recv(65536)
                if data:
                    streams[source].sendall(data)
                else:
                    with contextlib.suppress(OSError):
                        streams[source].shutdown(socket.SHUT_WR)
                    del streams[source]


def runtime_directory(directory):
    # Containers bind this fixed path, and a short one fits the Unix socket path limit.
    parent = Path('/tmp') / f'perimeter-{os.getuid()}'
    with contextlib.suppress(FileExistsError):
        parent.mkdir(mode=0o700)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Error(f'{parent} must be an owner-only directory')
    return parent / hashlib.sha256(str(directory).encode()).hexdigest()[:16]


class Bunker:
    """One launch: the seed, the Perimeter link and the stop control. Backends boot and enter the guest."""
    link_name = 'link'

    def __init__(self, profile, directory, workspace, source, endpoint, agents):
        self.profile, self.directory = profile, Path(directory)
        self.workspace, self.source = Path(workspace), program(source)
        self.endpoint, self.agents = endpoint, agents
        self.runtime = runtime_directory(self.directory)
        self.process = self.control = self.link = self.log_thread = self.running = None
        self.threads = []
        self.boot_log = bytearray()
        self.stopping = threading.Event()

    def __enter__(self):
        try:
            self.running = ensure_stopped(self.directory)
            shutil.rmtree(self.runtime, ignore_errors=True)
            self.runtime.mkdir(mode=0o700)
            fresh = not (self.directory / 'initialized').exists()
            write_seed(self.directory, self.runtime / 'seed', self.profile, self.workspace, self.source, fresh, self.agents)
            # Socket path is fixed and owned by this launch. No saved PID is ever
            # signaled, and no guest data determines a host command or filename.
            self.control = self.serve('control.sock', 4, self.control_client)
            if self.endpoint and self.link_name:
                self.link = self.serve(self.link_name, 32, self.forward)
            self.boot()
            if self.process:
                self.log_thread = threading.Thread(target=self.read_log, daemon=True)
                self.log_thread.start()
            private(self.directory / 'runtime.json', json.dumps({'control': str(self.runtime / 'control.sock')}).encode())
            self.ready()
            private(self.directory / 'initialized', b'1\n')
            return self
        except BaseException:
            self.close()
            raise

    def serve(self, name, limit, handle):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.runtime / name))
        server.listen(limit)
        server.settimeout(0.2)
        slots = threading.BoundedSemaphore(limit)

        def client(stream):
            try:
                with stream:
                    handle(stream)
            except OSError:
                pass
            finally:
                slots.release()

        def accept():
            while not self.stopping.is_set():
                try:
                    stream, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                if not slots.acquire(blocking=False):
                    stream.close()
                    continue
                threading.Thread(target=client, args=(stream,), daemon=True).start()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        self.threads.append(thread)
        return server

    def control_client(self, stream):
        stream.settimeout(1)
        if stream.recv(16) == b'stop\n':
            self.stopping.set()
            stream.sendall(b'ok\n')

    def forward(self, stream):
        relay(stream, socket.create_connection(self.endpoint, timeout=10))

    def read_log(self):
        for block in iter(lambda: self.process.stdout.read(4096), b''):
            self.boot_log.extend(block)
            del self.boot_log[:-65536]

    def check(self):
        if self.stopping.is_set():
            raise Error('bunker stopped by perimeter stop')
        if self.process and self.process.poll() is not None:
            raise Error(f'the {self.profile.get("backend", "firecracker")} bunker exited; its disk was retained. Log: '
                        + bytes(self.boot_log[-4000:]).decode(errors='replace'))

    def ready(self):
        pass

    def halt(self):
        pass

    def close(self):
        self.stopping.set()
        if self.process:
            if self.process.poll() is None:
                self.halt()
                try:
                    self.process.wait(timeout=STOP_SECONDS)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
            if self.log_thread:
                self.log_thread.join(timeout=1)
            self.process.stdout.close()
        for server in (self.link, self.control):
            if server:
                server.close()
        for thread in self.threads:
            thread.join(timeout=2)
        if self.control:
            (self.directory / 'runtime.json').unlink(missing_ok=True)
        shutil.rmtree(self.runtime, ignore_errors=True)
        if self.running:
            self.running.close()

    def __exit__(self, *_):
        self.close()

    @staticmethod
    def remove(profile, directory):
        pass


class Guest(Bunker):
    """Reached through the guest's sshd. The master connection carries the Perimeter link as a remote forward."""
    link_name = None

    def ssh(self):
        transport = shlex.join(self.transport()).replace('%', '%%')
        return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'UserKnownHostsFile="' + str(self.directory / 'known_hosts').replace('\\', '\\\\').replace('"', '\\"') + '"',
                '-o', 'HostKeyAlias=monitor-vm', '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR',
                '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
                '-o', 'ProxyCommand=' + transport, '-S', str(self.runtime / 'ssh.ctl'), '-i', str(self.directory / 'admin')]

    def ready(self):
        master = self.ssh() + ['-M', '-fN']
        if self.endpoint:
            host, port = self.endpoint
            # -f returns only once the guest listens on LINK_PORT.
            master += ['-o', 'ExitOnForwardFailure=yes', '-R', f'127.0.0.1:{LINK_PORT}:' + (f'[{host}]' if ':' in host else host) + f':{port}']
        log = self.runtime / 'ssh.log'
        deadline = time.monotonic() + READY_SECONDS
        with log.open('ab') as errors:
            while time.monotonic() < deadline:
                self.check()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    if subprocess.run(master + ['agent@monitor-vm'], env=environment(), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=errors, timeout=15).returncode == 0:
                        return
                time.sleep(0.2)
        raise Error('bunker start timed out; disk retained. Log: '
                    + (bytes(self.boot_log[-4000:]) + log.read_bytes()[-2000:]).decode(errors='replace'))

    def exec(self, argv, tty):
        return self.ssh() + ['-o', 'ClearAllForwardings=yes'] + (['-t'] if tty else []) + [
            'agent@monitor-vm', 'cd /workspace && exec ' + shlex.join(argv)]


class Firecracker(Guest):
    """No guest NIC or shared host directories; the guest's sshd is reached over Firecracker's vsock socket."""

    @staticmethod
    def preflight(_):
        if sys.platform != 'linux' or ARCH != 'x86_64':
            raise Error('Firecracker bunkers require x86_64 Linux')
        require('bwrap', 'mke2fs')
        try:
            with open('/dev/kvm', 'rb+') as kvm:
                if fcntl.ioctl(kvm, 0xAE00, 0) != 12:
                    raise Error('unsupported KVM API version')
        except OSError as error:
            raise Error('Firecracker bunkers need read/write access to /dev/kvm') from error
        result = subprocess.run(sandbox(derived(manifest()['firecracker'], '.bin', extract_firecracker)) + ['--version'],
                                env=environment(), capture_output=True, timeout=15)
        if result.returncode:
            raise Error('Firecracker sandbox failed; bubblewrap needs unprivileged user namespaces and a static Firecracker binary: '
                        + result.stderr.decode(errors='replace')[-2000:])

    def boot(self):
        assets = manifest()
        prepare_disk(self.directory, fetch(assets[ARCH]['base']), self.profile.get('disk', DISK_GIB))
        ext4(self.runtime / 'seed', self.runtime / 'seed.ext4')
        drives = [
            {'drive_id': 'rootfs', 'path_on_host': '/rootfs.ext4', 'is_root_device': True, 'is_read_only': False,
             'cache_type': 'Writeback'},
            {'drive_id': 'seed', 'path_on_host': '/seed.ext4', 'is_root_device': False, 'is_read_only': True}]
        mounts = ['--ro-bind', str(fetch(assets[ARCH]['kernel'])), '/kernel',
                  '--bind', str(self.directory / 'rootfs.ext4'), '/rootfs.ext4',
                  '--ro-bind', str(self.runtime / 'seed.ext4'), '/seed.ext4',
                  '--bind', str(self.runtime), '/run/monitor']
        for index, disk in enumerate(agent_disks(self.agents)):
            drives.append({'drive_id': f'agent{index}', 'path_on_host': f'/agent{index}.ext4', 'is_root_device': False, 'is_read_only': True})
            mounts += ['--ro-bind', str(disk), f'/agent{index}.ext4']
        config = {
            'boot-source': {'kernel_image_path': '/kernel', 'boot_args':
                # i8042.nopnp would hide the keyboard that SendCtrlAltDel needs.
                'console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd '
                'root=/dev/vda rw init=/sbin/monitor-init'},
            'drives': drives,
            'machine-config': {'vcpu_count': self.profile['cpus'], 'mem_size_mib': self.profile['memory']},
            'network-interfaces': [],
            'vsock': {'guest_cid': 3, 'uds_path': '/run/monitor/vsock'},
        }
        private(self.runtime / 'firecracker.json', json.dumps(config).encode())
        self.process = subprocess.Popen(sandbox(derived(assets['firecracker'], '.bin', extract_firecracker), mounts) + [
            '--api-sock', '/run/monitor/api.sock', '--config-file', '/run/monitor/firecracker.json'],
            env=environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            pass_fds=(self.running.fileno(),))

    def transport(self):
        return [sys.executable, str(self.source), '_vm-connect', str(self.runtime / 'vsock')]

    def halt(self):
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


class Container(Guest):
    """--network none. The container layer is the bunker's disk; the seed, agents and sshd go through the engine."""

    @staticmethod
    def preflight(backend):
        require(backend)

    def __init__(self, *args):
        super().__init__(*args)
        self.engine = self.profile['backend']
        self.name = container_name(self.profile, self.directory)

    def inspect(self, field):
        result = subprocess.run([self.engine, 'inspect', '-f', '{{' + field + '}}', self.name], env=environment(),
                                capture_output=True, timeout=30)
        return result.stdout.decode().strip() if result.returncode == 0 else None

    def boot(self):
        agent_volume(self.engine, self.agents)
        if self.inspect('.Id') is None:
            run([self.engine, 'create', '--init', '--name', self.name, '--hostname', self.directory.name, '--network', 'none',
                 '--tmpfs', '/run', '--tmpfs', '/tmp', '-v', f'{AGENT_VOLUME}:/nix:ro',
                 base_image(self.engine), 'sleep', 'infinity'], capture_output=True, timeout=120)
        if self.inspect('.HostConfig.NetworkMode') != 'none':
            raise Error(f'container {self.name} has a network; destroy this bunker and launch it again')
        subprocess.run([self.engine, 'stop', '-t', str(STOP_SECONDS), self.name], env=environment(), capture_output=True, timeout=60)
        self.process = subprocess.Popen([self.engine, 'start', '--attach', self.name], env=environment(),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        start_new_session=True)

    def ready(self):
        deadline = time.monotonic() + READY_SECONDS
        while time.monotonic() < deadline:
            self.check()
            if subprocess.run([self.engine, 'exec', self.name, 'true'], env=environment(),
                              capture_output=True, timeout=30).returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise Error('container start timed out. Log: ' + bytes(self.boot_log[-4000:]).decode(errors='replace'))
        with tarfile.open(self.runtime / 'seed.tar', 'w') as archive:
            archive.add(self.runtime / 'seed', '.')
        with (self.runtime / 'seed.tar').open('rb') as seed:
            run([self.engine, 'exec', '-i', '-u', 'root', self.name, 'sh', '-c',
                 'mkdir /run/seed && tar -xC /run/seed --no-same-owner && exec python3 /run/seed/guest.py container'],
                stdin=seed, capture_output=True, timeout=300)
        if self.endpoint:
            run([self.engine, 'exec', '-d', self.name, 'python3', '/run/seed/guest.py', 'publish'], capture_output=True, timeout=30)
        super().ready()

    def transport(self):
        return [self.engine, 'exec', '-i', '-u', 'root', self.name, *GUEST_SSHD]

    def halt(self):
        subprocess.run([self.engine, 'stop', '-t', str(STOP_SECONDS), self.name], env=environment(), capture_output=True, timeout=60)

    @staticmethod
    def remove(profile, directory):
        run([profile['backend'], 'rm', '-f', '--ignore' if profile['backend'] == 'podman' else '--force',
             container_name(profile, directory)], capture_output=True, timeout=60)


def container_name(profile, directory):
    return f'perimeter-{profile["id"][:8]}-{Path(directory).name}'


def base_image(engine):
    entry = manifest()[ARCH]['base']
    tag = 'localhost/perimeter-base:' + entry['sha256'][:16]
    if subprocess.run([engine, 'image', 'inspect', tag], env=environment(), capture_output=True, timeout=30).returncode:
        print('Importing the bunker base image...', file=sys.stderr, flush=True)
        run([engine, 'import', str(fetch(entry)), tag], capture_output=True, timeout=600)
    return tag


class Bwrap(Bunker):
    """Unprivileged namespaces with only loopback. The base tree is a shared lower layer under each bunker's upper."""

    @staticmethod
    def preflight(_):
        if sys.platform != 'linux':
            raise Error('bwrap bunkers require Linux')
        require('bwrap', 'script')

    def boot(self):
        self.tree = derived(manifest()[ARCH]['base'], '.tree', untar)
        self.store = agent_store(self.agents)
        for name in ('upper', 'work'):
            (self.directory / name).mkdir(mode=0o700, exist_ok=True)

    def exec(self, argv, tty):
        command = [shutil.which('bwrap'), '--unshare-all', '--unshare-user', '--die-with-parent', '--cap-drop', 'ALL',
                   '--uid', str(AGENT_UID), '--gid', str(AGENT_UID), '--hostname', self.directory.name,
                   '--overlay-src', str(self.tree), '--overlay', str(self.directory / 'upper'), str(self.directory / 'work'), '/',
                   '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/run',
                   '--ro-bind', str(self.store), '/nix/store', '--ro-bind', str(self.runtime), '/run/host',
                   '--clearenv', '--setenv', 'HOME', '/home/agent', '--setenv', 'USER', 'agent', '--setenv', 'PATH', GUEST_PATH,
                   '--setenv', 'TERM', os.environ.get('TERM', 'dumb'), '--chdir', '/workspace',
                   # Without a terminal of its own, the sandbox could inject input into the host's.
                   *([] if tty else ['--new-session']),
                   '--', 'python3', '/run/host/seed/guest.py', 'process', *argv]
        return ['script', '-qec', shlex.join(command), '/dev/null'] if tty else command

    @staticmethod
    def remove(profile, directory):
        # The kernel leaves overlay work directories without permissions.
        if Path(directory).exists():
            run(['chmod', '-R', 'u+rwX', str(directory)], capture_output=True, timeout=300)


class Vfkit(Guest):
    """A Virtualization.framework VM with no NIC; vfkit exposes the guest's sshd vsock port as a host Unix socket."""

    @staticmethod
    def preflight(_):
        if sys.platform != 'darwin' or ARCH != 'aarch64':
            raise Error('vfkit bunkers require an Apple silicon Mac')
        require('mke2fs', 'nc')

    def boot(self):
        assets = manifest()
        prepare_disk(self.directory, fetch(assets[ARCH]['base']), self.profile.get('disk', DISK_GIB))
        ext4(self.runtime / 'seed', self.runtime / 'seed.ext4')
        private(self.runtime / 'initrd', EMPTY_INITRD)
        vfkit = fetch(assets['vfkit'])
        vfkit.chmod(0o700)
        disks = [f'path={self.directory / "rootfs.ext4"}', f'path={self.runtime / "seed.ext4"},readonly',
                 *(f'path={disk},readonly' for disk in agent_disks(self.agents))]
        self.process = subprocess.Popen([
            str(vfkit), '--cpus', str(self.profile['cpus']), '--memory', str(self.profile['memory']),
            '--bootloader', f'linux,kernel={fetch(assets[ARCH]["kernel"])},initrd={self.runtime / "initrd"},cmdline="{VFKIT_CMDLINE}"',
            *(argument for disk in disks for argument in ('--device', 'virtio-blk,' + disk)),
            '--device', f'virtio-vsock,port=22,socketURL={self.runtime / "vsock"},connect',
            '--device', f'virtio-serial,logFilePath={self.directory / "console.log"}'],
            env=environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            pass_fds=(self.running.fileno(),))

    def transport(self):
        return ['nc', '-U', str(self.runtime / 'vsock')]

    def halt(self):
        # guest.py, the guest's PID 1, shuts down on SIGTERM but has no power button handler.
        with contextlib.suppress(subprocess.TimeoutExpired):
            subprocess.run(self.ssh() + ['agent@monitor-vm', 'sudo kill -TERM 1'], env=environment(), capture_output=True, timeout=10)


BUNKERS = {'firecracker': Firecracker, 'vfkit': Vfkit, 'podman': Container, 'docker': Container, 'bwrap': Bwrap}


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
    fd, temporary = tempfile.mkstemp(prefix='.perimeter-export-', dir=destination.parent)
    child = None
    try:
        with os.fdopen(fd, 'wb') as output:
            child = subprocess.Popen(vm.exec(['tar', '-C', '/workspace', '-cf', '-', '.'], False),
                                     env=environment(), stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
            deadline, count = time.monotonic() + 300, 0
            limit = vm.profile.get('disk', DISK_GIB) << 31
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
                    raise Error('workspace export exceeds twice the bunker disk size')
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
            raise Error("another Perimeter setup or launch is using this state") from error
        yield


def owner_token(value):
    """Preserve supplied text; recognize old random keys and CLI key records."""
    try:
        record = json.loads(value)
    except (ValueError, TypeError):
        record = None
    if isinstance(record, dict) and record.get("version") == 2:
        raise Error("owner signing requires an attested client; use tinfoil perimeter open")
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
        raise Error(f"{prompt} is required; use perimeter setup --help for noninteractive options")
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
    name = profile_name(args)
    config_path = Path(args.client_config).expanduser().resolve()
    with launch_lock(config_path.with_suffix(".lock")):
        config = json.loads(private_read(config_path)) if config_path.exists() else {}
        if name in config.get("launch_profiles", {}):
            raise Error(f"launch profile {name!r} already exists; choose a new --profile to change its server or permissions")
        root = config_path.parent / "launch" / name
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not 1 <= args.cpus <= 32 or not 512 <= args.memory <= 65536 or not 2 <= args.disk_size <= 128:
            raise Error("choose 1–32 CPUs, 512–65536 MiB of memory and a 2–128 GiB disk")
        owner_url = setup_value(args.owner_url, "Perimeter owner URL", "http://127.0.0.1:8080")
        endpoint = setup_value(args.endpoint, "Perimeter SSH endpoint as reached by this host", "127.0.0.1:2223")
        endpoint_address(endpoint)
        if args.owner_key_file:
            key = private_read(Path(args.owner_key_file).expanduser())
        elif sys.stdin.isatty():
            key = getpass.getpass("Perimeter owner key or passphrase (saved only on this host): ")
        else:
            raise Error("pass --owner-key-file pointing to an owner-only file")
        owner = OwnerClient(owner_url, key)
        view = unlock(owner, root)
        connections = view["config"].get("connections") or {}
        access_spec = args.access or [item.strip() for item in setup_value(
            None, "Service access, comma-separated name=read|ask|allow", "").split(",") if item.strip()]
        access = {}
        for item in access_spec:
            name, sep, level = item.partition("=")
            if not sep or name not in connections or level not in ("read", "ask", "allow"):
                raise Error(f"invalid service access {item!r}; use an existing service and read, ask or allow")
            access[name] = {"level": level}
        host_key = view["host_key"].strip()
        if "\n" in host_key or not host_key.startswith(("ssh-", "ecdsa-")):
            raise Error("owner API returned an invalid SSH host key")
        private(root / "owner.key", key.encode())
        private(root / "host_key", host_key.encode() + b"\n")
        profile = {"version": 3, "id": uuid.uuid4().hex, "owner_url": owner_url, "endpoint": endpoint,
                   "root": str(root), "backend": args.backend, "cpus": args.cpus, "memory": args.memory,
                   "disk": args.disk_size, "access": access, "mcp": args.mcp}
        config.setdefault("launch_profiles", {})[name] = profile
        private(config_path, json.dumps(config, indent=2).encode() + b"\n")
        print(f"Saved launch profile {name!r}. Owner key stays in {root / 'owner.key'}.")
        prefix = "perimeter" + (" --profile " + name if name != "default" else "")
        print(f"From a project directory, run: {prefix} launch AGENT, where AGENT is shell or one of "
              + ", ".join(json.loads(asset("agents.json"))))
    return 0


def agent_service(view, recipe, chosen):
    """Pick the HTTP service an agent uses: the first of its presets with exactly one candidate."""
    connections = view["config"].get("connections") or {}
    for preset in recipe["via"]:
        # A connection's kind is its key naming a connector, such as "http".
        names = [name for name, settings in connections.items()
                 if settings.get("preset") == preset and "http" in settings and chosen in (None, name)]
        if len(names) > 1:
            raise Error(f"several {preset} services exist; choose one with --service")
        if names:
            return names[0], preset
    raise Error("add " + " or ".join(recipe["via"]) + " service in the Perimeter"
                + (f", or choose another than {chosen!r}" if chosen else ""))


def unlock(owner, root):
    # Like the web app, never unlock a state older than the newest generation seen from this host.
    floor = Path(root) / "generation"
    view = owner.request("POST", {"generation": int(private_read(floor)) if floor.exists() else 0}, path="/unlock")
    private(floor, str(view["generation"]).encode())
    return view


def enroll_identity(owner, state, state_path, public_key, access):
    view = owner.request()
    existing = (view["config"].get("identities") or {}).get(state["name"])
    if existing:
        if existing["key"].strip() != public_key.strip():
            raise Error("this VM's Perimeter identity has a different key; refusing to replace it")
        # Never replay initial access over permissions edited in the web app.
    elif state["enrolled"]:
        raise Error("this VM's Perimeter identity was revoked; destroy the VM before creating a new identity")
    else:
        # Record the attempt first. A lost response followed by owner revocation
        # must not cause a later launch to restore the initial grant.
        state["enrolled"] = True
        private(state_path, json.dumps(state, indent=2).encode() + b"\n")
        owner.edit([{"path": ["identities", state["name"]], "value": {"key": public_key, "connections": access}}])
    state["enrolled"] = True
    private(state_path, json.dumps(state, indent=2).encode() + b"\n")


def revoke_identity(owner, name, public_key):
    ids = owner.request()["config"].get("identities") or {}
    if name not in ids:
        return
    if ids[name]["key"].strip() != public_key.strip():
        raise Error("this VM's Perimeter identity has a different key; refusing to revoke it")
    owner.edit([{"path": ["identities", name], "delete": True}])


def launch_vm(args, cli):
    name = profile_name(args)
    config_path = Path(args.client_config).expanduser().resolve()
    try:
        profile = json.loads(private_read(config_path))["launch_profiles"][name]
    except (FileNotFoundError, KeyError) as error:
        raise Error("run perimeter setup first for this profile") from error
    if profile["version"] != 3:
        raise Error("this launch profile is from an older Perimeter; run perimeter setup with a new --profile")
    if args.name and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args.name):
        raise Error("bunker name must contain only lowercase letters, digits and hyphens")
    root = Path(profile["root"])
    workspace = Path(args.workspace).expanduser().resolve()
    if workspace == Path.home().resolve() or workspace.parent == workspace:
        raise Error("choose a project directory, not your home or filesystem root")
    if args.command == "launch" and not workspace.is_dir():
        raise Error("choose an existing project directory")
    if workspace == root.resolve() or workspace in root.resolve().parents:
        raise Error("the project contains the Perimeter's host credentials; choose a project outside the launch configuration directory")
    identity = args.name or "vm-" + hashlib.sha256((profile["id"] + "\0" + str(workspace)).encode()).hexdigest()[:32]
    directory = root / "instances" / identity
    backend = profile.get("backend", "firecracker")
    if args.command == "stop":
        stop(directory)
        print("Requested bunker shutdown; its disk and identity will be retained.")
        return 0
    with launch_lock(root / "locks" / identity):
        state_path = directory / "state.json"
        if state_path.exists():
            state = json.loads(private_read(state_path))
            if state["workspace"] != str(workspace) or state["name"] != identity:
                raise Error("bunker state does not match this project")
        elif args.command != "launch":
            raise Error("no Perimeter bunker is recorded for this project")
        else:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            state = {"name": identity, "workspace": str(workspace), "enrolled": False, "revoked": False}
            private(state_path, json.dumps(state).encode() + b"\n")
        public_key = keypair(directory / "id").decode() + "\n"
        if args.command in ("launch", "destroy"):
            owner = OwnerClient(profile["owner_url"], private_read(root / "owner.key"))
            view = unlock(owner, root)
        if args.command == "destroy":
            ensure_stopped(directory).close()
            revoke_identity(owner, identity, public_key)
            state["revoked"] = True
            private(state_path, json.dumps(state).encode() + b"\n")
            BUNKERS[backend].remove(profile, directory)
            shutil.rmtree(directory)
            print("Revoked the Perimeter identity and destroyed the bunker.")
            return 0
        if args.command == "launch" and state.get("revoked"):
            raise Error("this bunker is being destroyed; retry perimeter destroy")
        preflight(backend)
        agent = args.command == "launch" and args.agent != "shell"
        if agent:
            recipe = json.loads(asset("agents.json"))[args.agent]
            service, via = agent_service(view, recipe, args.service)
            profile["access"].setdefault(service, {"level": "allow"})
        if args.command == "launch":
            enroll_identity(owner, state, state_path, public_key, profile["access"])
        elif not (directory / "initialized").exists():
            raise Error("this bunker has no initialized workspace to export")
        agents = fetch_agents([args.agent] if agent else [])
        endpoint = None
        if args.command == "launch":
            address = urlsplit("ssh://" + endpoint_address(profile["endpoint"]))
            endpoint = (address.hostname, address.port)
        with BUNKERS[backend](profile, directory, workspace, cli.__file__, endpoint, agents) as bunker:
            if args.command == "export":
                export(bunker, args.output)
                print(f"Saved workspace archive to {args.output}")
                return 0
            if agent:
                mcp = profile.get("mcp", False) and "mcp" in recipe
                command = GUEST_CLI + ["_agent", "--service", service, "--via", via,
                                       *(["--mcp"] if mcp else []), args.agent, "--", *args.argv]
            else:
                command = GUEST_CLI + (["run", "--", *args.argv] if args.argv else ["shell"])
            return cli.run_child(bunker, bunker.exec(command, sys.stdin.isatty()), environment())


def guest_agent(cli, client, args):
    recipe = json.loads(asset("agents.json"))[args.agent]
    via = recipe["via"][args.via]
    with cli.Session(client) as session:
        env = session.environment([], None)
        connection = next((c for c in session.connections if c["name"] == args.service), None)
        if connection is None:
            raise Error(f"the {args.service} service is not accessible to this bunker; grant it access in the Perimeter")
        if connection["state"] != "ready":
            raise Error("the model service is not ready; check its access and status in the Perimeter")
        values = connection["placeholders"] or {}
        variable = via["key"]
        key = values.get(variable) or values.get("token") or (next(iter(values.values())) if len(values) == 1 else None)
        if key is None:
            raise Error(f"model service needs a token or {variable} credential slot")
        for name in recipe.get("unset", []):
            env.pop(name, None)
        env.update(recipe.get("env", {}))
        env[variable] = key
        arguments = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        command = recipe["command"] + via.get("args", [])
        if args.mcp:
            servers, count = cli.mcp_servers(session)
            if not count:
                raise Error("no MCP tools are available; review service access and tools in the Perimeter")
            mcp_config = session.directory / "mcp.json"
            mcp_config.write_text(json.dumps({"mcpServers": servers}))
            # These endpoints live in the guest. Sending them through the HTTP
            # proxy would ask the Monitor server to connect to its own loopback.
            env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost,::1"
            command += [part.replace("{config}", str(mcp_config)) for part in recipe["mcp"]]
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


COMMANDS = ("setup", "launch", "destroy", "stop", "export", "_vm-connect", "_agent")


def add_commands(commands, policy_commands):
    policy = commands.choices["policy"]
    policy.add_argument("--owner-url", help="owner API URL for the full source, diff and apply")
    policy.add_argument("--owner-key-file", help="owner key or passphrase file; never needed for agent proposals")
    policy_commands.choices["show"].add_argument("--effective", action="store_true", help="expand presets and defaults; requires owner authentication")
    for action in ("diff", "apply"):
        command = policy_commands.add_parser(action, help={"diff": "validate and preview a replacement policy", "apply": "apply a replacement policy"}[action])
        command.add_argument("file", help="TOML file, or - for stdin")
    setup = commands.add_parser("setup", help="configure one-command Linux bunker launch")
    setup.add_argument("--owner-url", help="unlocked Perimeter owner API URL")
    setup.add_argument("--owner-key-file", help="owner-only file containing a key or passphrase; otherwise prompt privately")
    setup.add_argument("--endpoint", help="Perimeter SSH HOST:PORT as reached by this host")
    setup.add_argument("--backend", choices=BACKENDS, default=DEFAULT_BACKEND, help=f"isolation for bunkers (default: {DEFAULT_BACKEND})")
    setup.add_argument("--cpus", type=int, default=2, help="VM CPU count (default: 2)")
    setup.add_argument("--memory", type=int, default=4096, help="VM memory in MiB (default: 4096)")
    setup.add_argument("--disk-size", type=int, default=DISK_GIB, help=f"VM disk size in GiB (default: {DISK_GIB})")
    setup.add_argument("--access", action="append", help="initial service access NAME=read|ask|allow; repeat for several")
    setup.add_argument("--mcp", action="store_true", help="also connect agents that support it to the Perimeter's MCP services")
    agents = list(json.loads(asset("agents.json")))
    launch = commands.add_parser("launch", help="launch an agent in a Perimeter-connected Linux bunker")
    launch.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    launch.add_argument("--service", help="model service for the agent (default: the only one of a kind it supports)")
    launch.add_argument("agent", choices=agents + ["shell"], help="an agent, or a shell routed through the Perimeter")
    launch.add_argument("argv", nargs="*", help="-- ARGUMENTS passed to the agent, or a COMMAND to run instead of the shell")
    destroy = commands.add_parser("destroy", help="revoke the project's Perimeter identity and destroy its bunker")
    destroy.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    stop = commands.add_parser("stop", help="stop the project's running bunker and retain its disk")
    stop.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    export = commands.add_parser("export", help="save the bunker's workspace as a tar archive")
    export.add_argument("--workspace", default=".", help="project directory (default: current directory)")
    export.add_argument("--output", required=True, help="new archive file to create on this host")
    for command in (launch, destroy, stop, export):
        command.add_argument("--name", help="bunker identity name instead of one derived from the project directory")
    proxy = commands.add_parser("_vm-connect")
    proxy.add_argument("socket")
    agent = commands.add_parser("_agent")
    agent.add_argument("agent", choices=agents)
    agent.add_argument("--service", required=True)
    agent.add_argument("--via", required=True)
    agent.add_argument("--mcp", action="store_true")
    agent.add_argument("argv", nargs=argparse.REMAINDER)


def handles(args):
    if args.command == "policy":
        return bool(args.owner_url or args.owner_key_file or getattr(args, "effective", False)
                    or args.policy_action in ("diff", "apply"))
    return args.command in COMMANDS


def command(args, cli):
    """Run an owner or VM command. cli is the main perimeter module."""
    if args.command == "policy":
        return owner_policy(args)
    if args.command == "setup":
        return setup_launch(args)
    if args.command == "_vm-connect":
        return proxy(args.socket)
    if args.command == "_agent":
        if sys.version_info < (3, 11):
            raise Error("the bunker agent requires Python 3.11 or newer")
        return guest_agent(cli, cli.connect(args), args)
    return launch_vm(args, cli)
