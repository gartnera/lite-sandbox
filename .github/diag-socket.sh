#!/usr/bin/env bash
# TEMPORARY: diagnose unix socket connects under bwrap on ubuntu-26.04.
set -u
uname -a
head -3 /etc/os-release
bwrap --version
nc -h 2>&1 | head -2
sudo aa-status 2>&1 | head -30
ls /etc/apparmor.d | grep -iE 'bwrap|userns|unpriv' || true
sysctl kernel.apparmor_restrict_unprivileged_userns kernel.apparmor_restrict_unprivileged_unconfined || true

d=$HOME/lsdiag
mkdir -p "$d/run"
chmod 700 "$d" "$d/run"
sock=$d/run/bus
python3 - "$sock" <<'PY' &
import os, socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(5)
while True:
    c, _ = s.accept()
    c.send(b"ok\n")
    c.close()
PY
sleep 1
ls -la "$d/run"

echo "== host"
nc -U "$sock" </dev/null; echo "rc=$?"
try() {
  echo "== bwrap $*"
  bwrap "$@" -- nc -U "$sock" </dev/null
  echo "rc=$?"
}
try --dev-bind / /
try --ro-bind / / --dev /dev --proc /proc
try --dev-bind / / --unshare-user
try --dev-bind / / --unshare-ipc
try --dev-bind / / --unshare-pid
try --dev-bind / / --unshare-uts
try --dev-bind / / --unshare-cgroup
try --dev-bind / / --unshare-all --share-net
try --ro-bind / / --dev /dev --proc /proc --unshare-all --share-net
try --ro-bind / / --bind "$sock" "$sock" --dev /dev --proc /proc --unshare-all --share-net
try --ro-bind / / --perms 0755 --tmpfs "$HOME" --ro-bind "$sock" "$sock" --remount-ro "$HOME" --dev /dev --proc /proc --unshare-all --share-net
try --ro-bind / / --perms 0755 --tmpfs "$HOME" --bind "$sock" "$sock" --remount-ro "$HOME" --dev /dev --proc /proc --unshare-all --share-net
try --ro-bind / / --perms 0755 --tmpfs "$HOME" --bind "$sock" "$sock" --dev /dev --proc /proc --unshare-all --share-net

sudo dmesg | grep -iE 'apparmor|denied' | tail -40
exit 0
