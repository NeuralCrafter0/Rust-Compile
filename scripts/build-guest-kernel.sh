#!/usr/bin/env bash
set -euo pipefail

# Documents reproducible minimal hermetic guest kernel build parameters for Firecracker KVM
# per RFC-001 Section 11.5 (network drivers disabled, virtio-vsock + virtio-blk enabled).

KERNEL_VERSION="${KERNEL_VERSION:-6.12.0}"
OUT_DIR="${1:-./artifacts/guest-kernel}"

cat <<EOF
Proofline Hermetic Guest Kernel Specification
  Target Kernel Version : ${KERNEL_VERSION}
  Output Directory      : ${OUT_DIR}
  Required Config Flags :
    - CONFIG_VIRTIO_VSOCKETS=y (Host <-> Guest IPC)
    - CONFIG_VIRTIO_BLK=y      (Read-only rootfs)
    - CONFIG_NET=n             (Air-gapped by default)
    - CONFIG_VIRTIO_NET=n      (Zero guest NIC drivers)
    - CONFIG_PCI=n             (Minimal attack surface)

To build locally with verified upstream kernel sources:
  1. Download and verify GPG signature of linux-${KERNEL_VERSION}.tar.xz from kernel.org.
  2. Apply the config flags above via scripts/config or menuconfig.
  3. Build vmlinux: make -j"\$(nproc)" vmlinux
EOF
