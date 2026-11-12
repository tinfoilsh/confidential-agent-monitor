#!/bin/sh
set -eu
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
mkdir -p /run/seed /nix/store
mount -t ext4 -o ro,nosuid,nodev,noexec /dev/vdb /run/seed
mount -t tmpfs -o mode=755 tmpfs /nix/store
for disk in /dev/vd[c-z]; do
    [ -b "$disk" ] || continue
    mkdir -p "/nix/agents/${disk#/dev/}"
    mount -t ext4 -o ro,nodev "$disk" "/nix/agents/${disk#/dev/}"
done
exec /usr/bin/python3 /run/seed/guest.py vm
