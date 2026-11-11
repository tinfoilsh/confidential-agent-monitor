"""Guest PID 1 for every backend. Only management and the Perimeter link are exposed.

vm: Firecracker or vfkit init with sshd on vsock. container: setup before the host's sshd -i sessions.
publish: a container's wildcard listener publisher. process: bubblewrap's init, running one command.
"""
import contextlib
import ctypes
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

# Mirrors monitor_vm.LINK_PORT, the loopback port that carries the Perimeter link.
LINK_PORT = 2223
AGENT = 1000
ROOT = os.getuid() == 0


def copy(source, destination, mode=0o600, agent=False):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)
    if agent and ROOT:
        os.chown(destination, AGENT, AGENT)


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


def listen(family, address, connect):
    server = socket.socket(family)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(address)
    server.listen(32)
    slots = threading.BoundedSemaphore(64)

    def serve(client):
        try:
            with client:
                relay(client, connect())
        except OSError:
            pass
        finally:
            slots.release()

    def accept():
        while True:
            client, _ = server.accept()
            if not slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=serve, args=(client,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()


def unix(path):
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(10)
    stream.connect(path)
    return stream


def publish():
    # Each Perimeter link reconnection republishes this bunker's wildcard listeners.
    user = {'user': AGENT, 'group': AGENT, 'extra_groups': []} if ROOT else {}
    while True:
        subprocess.run(['ssh', '-F', '/home/agent/.config/perimeter/ssh_config', '-NT', 'perimeter-route'],
                       **user, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        time.sleep(2)


def setup(seed):
    for directory in ('/opt/monitor', '/workspace', '/var/lib/monitor'):
        Path(directory).mkdir(parents=True, exist_ok=True)
    for directory in ('/home/agent/.ssh', '/home/agent/.config', '/home/agent/.config/perimeter'):
        Path(directory).mkdir(parents=True, exist_ok=True, mode=0o700)
        if ROOT:
            os.chown(directory, AGENT, AGENT)
    copy(seed / 'perimeter', '/opt/monitor/perimeter', 0o755)
    for name in ('id', 'known_hosts', 'ssh_config'):
        copy(seed / name, '/home/agent/.config/perimeter/' + name, agent=True)
    store = Path('/nix/store')
    for path in Path('/nix/agents').glob('*/nix/store/*'):
        if not os.path.lexists(store / path.name):
            (store / path.name).symlink_to(path)
    programs = Path('/usr/local/bin')
    for program in programs.iterdir():
        if program.is_symlink() and os.readlink(program).startswith('/nix/store/'):
            program.unlink()
    for path in json.loads((seed / 'agents.json').read_text()).values():
        for program in Path(path, 'bin').iterdir():
            if not os.path.lexists(programs / program.name):
                (programs / program.name).symlink_to(program)
    marker = Path('/var/lib/monitor/workspace-ready')
    if not marker.exists():
        subprocess.run(['tar', '-xf', str(seed / 'workspace.tar'), '-C', '/workspace', '--no-same-owner'], check=True)
        if ROOT:
            subprocess.run(['chown', '-R', f'{AGENT}:{AGENT}', '/workspace'], check=True)
        marker.touch()
        os.sync()


def run(command):
    child = subprocess.Popen(command, process_group=0)
    if os.isatty(0):
        # The terminal's foreground group lies outside this PID namespace, where the command cannot see it.
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        with contextlib.suppress(ProcessLookupError):
            os.tcsetpgrp(0, child.pid)
    signal.signal(signal.SIGTERM, lambda *_: child.terminate())
    code = child.wait()
    return code if code >= 0 else 128 - code


def main():
    kind = sys.argv[1]
    if kind == 'publish':
        publish()
    if kind == 'process':
        link = Path('/run/host/link')
        setup(Path('/run/host/seed'))
        if link.exists():
            listen(socket.AF_INET, ('127.0.0.1', LINK_PORT), lambda: unix(str(link)))
            threading.Thread(target=publish, daemon=True).start()
        sys.exit(run(sys.argv[2:]))
    seed = Path('/run/seed')
    Path('/run/sshd').mkdir(parents=True, exist_ok=True)
    copy(seed / 'authorized_keys', '/home/agent/.ssh/authorized_keys', agent=True)
    copy(seed / 'host_key', '/run/sshd/host_key')
    setup(seed)
    if kind == 'container':
        return
    threading.Thread(target=publish, daemon=True).start()
    sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', '/etc/ssh/sshd_config.monitor'])
    listen(socket.AF_VSOCK, (socket.VMADDR_CID_ANY, 22), lambda: socket.create_connection(('127.0.0.1', 22), 10))
    stopping = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGPWR):
        signal.signal(signum, lambda *_: stopping.set())
    while not stopping.wait(0.2):
        if sshd.pid in reap():
            stopping.set()
    os.kill(-1, signal.SIGTERM)
    time.sleep(0.5)
    os.kill(-1, signal.SIGKILL)
    os.sync()
    subprocess.run(['mount', '-o', 'remount,ro', '/'], check=False)
    # Firecracker exits on guest reset. Some CI kernels merely halt on poweroff,
    # leaving the VMM running, so flush and remount before issuing a restart.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.reboot(0x01234567) != 0:  # LINUX_REBOOT_CMD_RESTART
        raise OSError(ctypes.get_errno(), 'guest shutdown failed')
    while True:
        time.sleep(1)


def reap():
    # PID 1 must reap orphaned agent children.
    reaped = []
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return reaped
        if pid == 0:
            return reaped
        reaped.append(pid)


if __name__ == '__main__':
    main()
