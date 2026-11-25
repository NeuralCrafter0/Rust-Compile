#!/usr/bin/env bash
set -euo pipefail

# Host prerequisite verification & setup helper for Fedora / RHEL-family systems.
# Inspects required virtualization, container, and Rust components before installing.

echo "Checking Proofline host prerequisites..."
for cmd in podman git rustc cargo; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "  [ok] $cmd -> $(command -v "$cmd")"
  else
    echo "  [missing] $cmd"
  fi
done

if [ -e /dev/kvm ]; then
  echo "  [ok] /dev/kvm present (hardware KVM available for Firecracker microVMs)"
else
  echo "  [warn] /dev/kvm not present; falling back to rootless Podman sandbox isolation"
fi

echo
echo "To install missing packages on Fedora, run as an administrator:"
echo "  sudo dnf install -y podman firecracker gcc clang lld git"
echo "  podman pull docker.io/library/alpine:latest"
echo "  podman pull docker.io/library/rust:alpine"
