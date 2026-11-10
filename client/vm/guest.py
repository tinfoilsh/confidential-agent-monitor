"""Guest PID 1. Only vsock management and Monitor transport are exposed."""
import contextlib
import ctypes
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import threading
import time

# Mirrors monitor_vm.LINK_PORT: the host relays this vsock port to the Perimeter.
LINK_PORT = 2223


def copy(source, destination, mode=0o600, agent=False):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)
    if agent:
        os.chown(destination, 1000, 1000)


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


def host(port):
    stream = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    stream.settimeout(10)
    stream.connect((socket.VMADDR_CID_HOST, port))
    return stream


def publish():
    # Each Perimeter link reconnection republishes this VM's wildcard listeners.
    while True:
        subprocess.run(['ssh', '-F', '/home/agent/.config/perimeter/ssh_config', '-NT', 'perimeter-route'],
                       user=1000, group=1000, extra_groups=[], stdin=subprocess.DEVNULL, check=False)
        time.sleep(2)


def main():
    seed = Path('/run/seed')
    for directory in ('/run/sshd', '/opt/monitor', '/workspace', '/var/lib/monitor'):
        Path(directory).mkdir(parents=True, exist_ok=True)
    for directory in ('/home/agent/.ssh', '/home/agent/.config/perimeter'):
        Path(directory).mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(directory, 1000, 1000)
    copy(seed / 'authorized_keys', '/home/agent/.ssh/authorized_keys', agent=True)
    copy(seed / 'host_key', '/run/sshd/host_key')
    copy(seed / 'perimeter', '/opt/monitor/perimeter', 0o755)
    for name in ('id', 'known_hosts', 'ssh_config'):
        copy(seed / name, '/home/agent/.config/perimeter/' + name, agent=True)
    marker = Path('/var/lib/monitor/workspace-ready')
    if not marker.exists():
        subprocess.run(['tar', '-xf', str(seed / 'workspace.tar'), '-C', '/workspace', '--no-same-owner'], check=True)
        subprocess.run(['chown', '-R', '1000:1000', '/workspace'], check=True)
        marker.touch()
        os.sync()
    sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', '/etc/ssh/sshd_config.monitor'])
    listen(socket.AF_VSOCK, (socket.VMADDR_CID_ANY, 22), lambda: socket.create_connection(('127.0.0.1', 22), 10))
    listen(socket.AF_INET, ('127.0.0.1', LINK_PORT), lambda: host(LINK_PORT))
    threading.Thread(target=publish, daemon=True).start()
    stopping = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGPWR):
        signal.signal(signum, lambda *_: stopping.set())
    while not stopping.wait(0.2):
        # PID 1 must reap orphaned agent children as well as observe sshd.
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
            if pid == sshd.pid:
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


if __name__ == '__main__':
    main()
