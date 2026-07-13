#!/bin/bash
# FilterREX Connector Host — Offline Bundle Builder
#
# Assembles a self-contained offline install bundle from release artifacts.
# Used by CI (connector-publish.public.yml) or manually by release engineers.
#
# Usage:
#   ./build-offline-bundle.sh <version> <os> <arch> [binary-path]
#
# Examples:
#   ./build-offline-bundle.sh v0.8.0 linux amd64
#   ./build-offline-bundle.sh v0.8.0 linux arm64 /tmp/connector-agent-linux-arm64
#
# Output:
#   /tmp/filterrex-connector-offline-v0.8.0-linux-amd64.tar.gz
#   /tmp/filterrex-connector-offline-v0.8.0-linux-amd64.tar.gz.sha256

set -euo pipefail

VERSION="${1:?Usage: $0 <version> <os> <arch> [binary-path]}"
OS="${2:?Usage: $0 <version> <os> <arch> [binary-path]}"
ARCH="${3:?Usage: $0 <version> <os> <arch> [binary-path]}"
BINARY_PATH="${4:-connector-agent-${OS}-${ARCH}}"

BUNDLE_NAME="filterrex-connector-offline-${VERSION}-${OS}-${ARCH}"
BUNDLE_DIR="/tmp/${BUNDLE_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building offline bundle: ${BUNDLE_NAME}"
echo "  Version: ${VERSION}"
echo "  Platform: ${OS}/${ARCH}"
echo "  Binary: ${BINARY_PATH}"
echo ""

# ── Validate inputs ──

if [ ! -f "$BINARY_PATH" ]; then
  echo "❌ Binary not found: ${BINARY_PATH}"
  exit 1
fi

# ── Assemble bundle ──

rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}"

# Binary (bundle name is 'connector-agent'; installer renames to 'filterrex-connector')
cp "${BINARY_PATH}" "${BUNDLE_DIR}/connector-agent"
chmod +x "${BUNDLE_DIR}/connector-agent"

# Packaging assets
ASSETS=(
  install-offline.sh
  filterrex-connector.service
  connector.env.template
  VERIFICATION.md
  README-offline.md
)

for asset in "${ASSETS[@]}"; do
  if [ -f "${SCRIPT_DIR}/${asset}" ]; then
    cp "${SCRIPT_DIR}/${asset}" "${BUNDLE_DIR}/"
  else
    echo "⚠️  Missing packaging asset: ${asset}"
    exit 1
  fi
done

chmod +x "${BUNDLE_DIR}/install-offline.sh"

# ── Generate checksums for ALL files in bundle ──

echo "→ Generating checksums..."
cd "${BUNDLE_DIR}"
sha256sum \
  connector-agent \
  install-offline.sh \
  filterrex-connector.service \
  connector.env.template \
  VERIFICATION.md \
  README-offline.md \
  > SHA256SUMS
cd - > /dev/null

echo "→ Bundle contents:"
ls -la "${BUNDLE_DIR}/"
echo ""

# ── Create tarball ──

echo "→ Creating tarball..."
cd /tmp
tar czf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}/"
cd - > /dev/null

# ── Generate tarball checksum ──

echo "→ Generating tarball checksum..."
sha256sum "/tmp/${BUNDLE_NAME}.tar.gz" > "/tmp/${BUNDLE_NAME}.tar.gz.sha256"

echo ""
echo "✅ Offline bundle created:"
echo "   Tarball:   /tmp/${BUNDLE_NAME}.tar.gz"
echo "   Checksum:  /tmp/${BUNDLE_NAME}.tar.gz.sha256"
echo ""
echo "Next steps:"
echo "  1. Sign the tarball:  cosign sign-blob --yes --bundle ${BUNDLE_NAME}.tar.gz.bundle ${BUNDLE_NAME}.tar.gz"
echo "  2. Upload to release: tarball + .sha256 + .bundle"
