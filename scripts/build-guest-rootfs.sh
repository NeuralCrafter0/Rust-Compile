#!/usr/bin/env bash
set -euo pipefail

# Builds an immutable, rootless ext4 Firecracker microVM rootfs containing
# /sbin/init + static musl /usr/local/bin/proofline-guest-agent.
# Usage: ./scripts/build-guest-rootfs.sh [guest_agent_bin] [output_ext4] [base_image] [size_mb]

GUEST_AGENT_BIN="${1:-./target/release/proofline-guest-agent}"
OUTPUT_EXT4="${2:-$HOME/.local/share/proofline/firecracker/rootfs.ext4}"
BASE_IMAGE="${3:-docker.io/library/alpine:latest}"
SIZE_MB="${4:-64}"

if [[ ! -x "$GUEST_AGENT_BIN" ]]; then
  echo "ERROR: proofline-guest-agent binary not found or not executable at: $GUEST_AGENT_BIN" >&2
  exit 1
fi

command -v podman >/dev/null 2>&1 || { echo "ERROR: podman is required" >&2; exit 1; }
command -v mkfs.ext4 >/dev/null 2>&1 || { echo "ERROR: mkfs.ext4 (e2fsprogs) is required" >&2; exit 1; }

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
ROOTFS_DIR="$WORK_DIR/rootfs"
mkdir -p "$ROOTFS_DIR"

CID="$(podman create "$BASE_IMAGE" /bin/true)"
podman export "$CID" | tar -C "$ROOTFS_DIR" -xf -
podman rm "$CID" >/dev/null

find "$ROOTFS_DIR" -type d -exec chmod u+rwx {} +
mkdir -p "$ROOTFS_DIR/usr/local/bin" "$ROOTFS_DIR/sbin" "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev" "$ROOTFS_DIR/tmp" "$ROOTFS_DIR/run"
rm -f "$ROOTFS_DIR/sbin/init" "$ROOTFS_DIR/usr/local/bin/proofline-guest-agent"
cp "$GUEST_AGENT_BIN" "$ROOTFS_DIR/usr/local/bin/proofline-guest-agent"
chmod 0755 "$ROOTFS_DIR/usr/local/bin/proofline-guest-agent"

cat > "$ROOTFS_DIR/sbin/init" << 'EOF'
#!/bin/sh
export PATH=/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /tmp /run
mount -t tmpfs -o mode=1777 tmpfs /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
ip link set lo up 2>/dev/null || true
exec /usr/local/bin/proofline-guest-agent --vsock-port 5050
EOF
chmod 0755 "$ROOTFS_DIR/sbin/init"

mkdir -p "$(dirname "$OUTPUT_EXT4")"
rm -f "$OUTPUT_EXT4"
truncate -s "${SIZE_MB}M" "$OUTPUT_EXT4"
mkfs.ext4 -q -F -d "$ROOTFS_DIR" -L proofline-rootfs "$OUTPUT_EXT4"
echo "Built Firecracker ext4 rootfs at $OUTPUT_EXT4 (${SIZE_MB} MiB from $BASE_IMAGE)"
