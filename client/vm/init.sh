#!/bin/sh
set -eu
if [ $# = 0 ]; then
    # The shared image is this read-only root; the bunker's own disk holds a writable layer over it.
    mount -t proc proc /proc
    mount -t tmpfs tmpfs /run
    mkdir /run/image /run/state /run/root
    mount --bind / /run/image
    mount -t ext4 /dev/vdb /run/state
    mkdir -p /run/state/upper /run/state/work
    mount -t overlay overlay -o lowerdir=/run/image,upperdir=/run/state/upper,workdir=/run/state/work /run/root
    cd /run/root
    mount --move . /
    exec chroot . /sbin/monitor-init root
fi
mount -t proc proc /proc
echo 0 > /proc/sys/kernel/ctrl-alt-del
mount -t sysfs sysfs /sys
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /run /tmp
mount -t devpts devpts /dev/pts
ln -s /proc/self/fd /dev/fd
ln -s /proc/self/fd/0 /dev/stdin
ln -s /proc/self/fd/1 /dev/stdout
ln -s /proc/self/fd/2 /dev/stderr
mount -t tmpfs -o mode=755 tmpfs /run
mount -t tmpfs -o mode=1777 tmpfs /tmp
ip link set lo up
mkdir -p /run/seed
mount -t ext4 -o ro,nosuid,nodev,noexec /dev/vdc /run/seed
exec /usr/bin/python3 /run/seed/guest.py vm
