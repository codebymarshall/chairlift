#!/usr/bin/env bash
# Provision only the disposable rootless Podman systemd container. No host state.
set -euo pipefail
UID_NUMBER="${1:?fixture uid required}"
GID_NUMBER="${2:?fixture gid required}"
[ "$(id -u)" = 0 ] || { echo "fixture setup requires container root" >&2; exit 1; }
[ "$(cat /proc/1/comm)" = systemd ] || { echo "fixture requires native systemd PID 1" >&2; exit 1; }
for _ in {1..300}; do
    [ -S /run/systemd/private ] && break
    sleep 0.1
done
[ -S /run/systemd/private ] || { echo "fixture systemd manager did not become ready" >&2; exit 1; }
ROOT="${3:?checkout path required}"
if [ "${4:-}" = verify ]; then
    # The test account cannot traverse Docker's root-owned data directory.
    # Check it here after the real GUI has stopped both native system units.
    test -d /var/lib/docker/volumes/chairlift-system-integration/_data
    test -s /var/lib/docker/volumes/metadata.db
    for unit in docker.socket docker.service; do
        [ "$(systemctl show "$unit" --property=LoadState --value)" = loaded ]
        [ "$(systemctl show "$unit" --property=ActiveState --value)" = inactive ]
    done
    getent group docker
    test -s /usr/share/chairlift-docker-fixture/packages.json
    echo 'LIVE DOCKER DATA PROOF: native units stopped; installed packages and daemon-managed volume retained'
    exit 0
fi
# Boot only the native services this fixture needs, not image preinstall jobs.
timeout 90 systemctl start basic.target dbus.socket
systemctl is-active --quiet basic.target dbus.socket
# Native boot can mount /home after Podman's initial bind mounts. Keep the
# checkout reachable at its original absolute path through a stable /opt bind.
# ROOT is the checkout mounted by the enclosing rootless Podman harness.
if [ ! -e "$ROOT" ]; then
    mkdir -p "$(dirname "$ROOT")"
    ln -s /opt/chairlift-checkout "$ROOT"
fi
setpriv --reuid="$UID_NUMBER" --regid="$GID_NUMBER" --clear-groups test -r "$ROOT/go.mod" || {
    stat "$ROOT" "$(dirname "$ROOT")" /opt/chairlift-checkout >&2
    echo "fixture checkout is not readable by its test account" >&2
    exit 1
}
ACCOUNT="$(getent passwd "$UID_NUMBER" | cut -d: -f1)"
[ -n "$ACCOUNT" ] || { echo "fixture account is missing" >&2; exit 1; }

# Engine packages are an image-build prerequisite, never an application install.
for command in dockerd docker containerd iptables ip6tables; do
    command -v "$command"
done
test -s /usr/share/chairlift-docker-fixture/packages.json
systemctl daemon-reload
systemctl disable --now docker.socket docker.service
for unit in docker.socket docker.service; do
    [ "$(systemctl show "$unit" --property=LoadState --value)" = loaded ]
    [ "$(systemctl show "$unit" --property=ActiveState --value)" = inactive ]
done
# A disposable password authenticates through real PolicyKit, never a rule
# granting passwordless access. All account changes live in this container.
command -v pkttyagent
command -v chpasswd
getent group wheel || groupadd wheel
usermod -aG wheel "$ACCOUNT"
printf '%s:%s\n' "$ACCOUNT" 'chairlift-private-fixture-only' | chpasswd
for group in docker incus-admin libvirt dialout; do
    getent group "$group" || groupadd "$group"
    gpasswd -d "$ACCOUNT" "$group" || true
done
# Install this checkout's real helper and matching policies, not an image copy.
install -m755 "${CHAIRLIFT_E2E_BUILD_DIR:-$ROOT/build}/chairlift-helper" /usr/bin/chairlift-helper
install -m644 "$ROOT/data/io.projectbluefin.chairlift.ublue.policy" /usr/share/polkit-1/actions/io.projectbluefin.chairlift.ublue.policy
systemctl start polkit.service

mkdir -p /tmp/home
chown "$UID_NUMBER:$GID_NUMBER" /tmp/home
usermod --home /tmp/home "$ACCOUNT"
systemctl start "user@$UID_NUMBER.service" || {
    journalctl -b -u "user@$UID_NUMBER.service" --no-pager >&2
    exit 1
}
# The target is this container's private manager, never the host's /run/user.
# The compositor wrapper deliberately refuses literal /run/user runtime paths.
ln -s "/run/user/$UID_NUMBER" /tmp/chairlift-docker-runtime
setpriv --reuid="$UID_NUMBER" --regid="$GID_NUMBER" --clear-groups \
    env HOME=/tmp/home XDG_RUNTIME_DIR=/tmp/chairlift-docker-runtime \
    systemctl --user show-environment
