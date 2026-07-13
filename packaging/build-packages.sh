#!/bin/bash
# ──────────────────────────────────────────────────────────────
# ForgeAI Connector Host — System Package Builder
# ──────────────────────────────────────────────────────────────
#
# Builds .deb and .rpm packages from a pre-compiled binary using
# native packaging tools (dpkg-deb + rpmbuild). No fpm dependency.
#
# Usage:
#   ./build-packages.sh <version> <goarch> <binary-path>
#
# Example:
#   ./build-packages.sh 0.8.0 amd64 /tmp/connector-agent-linux-amd64
#
# Produces (in /tmp/):
#   forgeai-host_0.8.0_amd64.deb
#   forgeai-host-0.8.0-1.x86_64.rpm
#   forgeai-host-0.8.0-packages.sha256
#
# Requirements:
#   dpkg-deb (for .deb)
#   rpmbuild + systemd-rpm-macros (for .rpm)
# ──────────────────────────────────────────────────────────────

set -euo pipefail

VERSION="${1:?Usage: $0 <version> <goarch> <binary-path>}"
GOARCH="${2:?Missing goarch (amd64 or arm64)}"
BINARY="${3:?Missing path to pre-built binary}"

# Strip leading 'v' from version for package versioning
PKG_VERSION="${VERSION#v}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="/tmp"

# ── Architecture mapping ──
case "${GOARCH}" in
  amd64)
    DEB_ARCH="amd64"
    RPM_ARCH="x86_64"
    ;;
  arm64)
    DEB_ARCH="arm64"
    RPM_ARCH="aarch64"
    ;;
  *)
    echo "Error: unsupported architecture '${GOARCH}'" >&2
    exit 1
    ;;
esac

echo "=== Building packages: forgeai-host ${PKG_VERSION} (${GOARCH}) ==="
echo "    Binary: ${BINARY}"
echo "    Output: ${OUT_DIR}"
echo ""

# Verify binary exists and is executable
if [ ! -f "${BINARY}" ]; then
  echo "Error: binary not found at ${BINARY}" >&2
  exit 1
fi

# ──────────────────────────────────────────────────────────────
# .deb package (native dpkg-deb)
# ──────────────────────────────────────────────────────────────

build_deb() {
  echo "── Building .deb package ──"

  local DEB_NAME="forgeai-host_${PKG_VERSION}_${DEB_ARCH}"
  local DEB_ROOT="${OUT_DIR}/${DEB_NAME}"

  # Clean and create directory structure
  rm -rf "${DEB_ROOT}"
  mkdir -p "${DEB_ROOT}/DEBIAN"
  mkdir -p "${DEB_ROOT}/usr/bin"
  mkdir -p "${DEB_ROOT}/lib/systemd/system"
  mkdir -p "${DEB_ROOT}/etc/forgeai"

  # Install binary
  install -m 0755 "${BINARY}" "${DEB_ROOT}/usr/bin/forgeai-host"

  # Install systemd unit
  install -m 0644 "${SCRIPT_DIR}/forgeai-host.service" \
    "${DEB_ROOT}/lib/systemd/system/forgeai-host.service"

  # Install default config (with placeholder values)
  install -m 0640 "${SCRIPT_DIR}/connector.env.template" \
    "${DEB_ROOT}/etc/forgeai/connector.env"

  # Generate control file with correct version and arch
  sed -e "s/__VERSION__/${PKG_VERSION}/" \
      -e "s/__ARCH__/${DEB_ARCH}/" \
      "${SCRIPT_DIR}/deb/control" > "${DEB_ROOT}/DEBIAN/control"

  # Calculate installed size (in KiB)
  local INSTALLED_SIZE
  INSTALLED_SIZE=$(du -sk "${DEB_ROOT}" | cut -f1)
  echo "Installed-Size: ${INSTALLED_SIZE}" >> "${DEB_ROOT}/DEBIAN/control"

  # Copy maintainer scripts
  for script in preinst postinst prerm postrm; do
    if [ -f "${SCRIPT_DIR}/deb/${script}" ]; then
      install -m 0755 "${SCRIPT_DIR}/deb/${script}" "${DEB_ROOT}/DEBIAN/${script}"
    fi
  done

  # Copy conffiles
  install -m 0644 "${SCRIPT_DIR}/deb/conffiles" "${DEB_ROOT}/DEBIAN/conffiles"

  # Build the package
  dpkg-deb --build --root-owner-group "${DEB_ROOT}" "${OUT_DIR}/${DEB_NAME}.deb"
  rm -rf "${DEB_ROOT}"

  echo "✓ ${DEB_NAME}.deb"
}

# ──────────────────────────────────────────────────────────────
# .rpm package (native rpmbuild)
# ──────────────────────────────────────────────────────────────

build_rpm() {
  echo "── Building .rpm package ──"

  local RPM_NAME="forgeai-host-${PKG_VERSION}-1.${RPM_ARCH}"

  # Set up rpmbuild directory structure
  local RPM_TOPDIR="${OUT_DIR}/rpmbuild-${GOARCH}"
  rm -rf "${RPM_TOPDIR}"
  mkdir -p "${RPM_TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

  # Create staging directory with installed layout
  local STAGE_DIR="${RPM_TOPDIR}/STAGE"
  mkdir -p "${STAGE_DIR}/usr/bin"
  mkdir -p "${STAGE_DIR}/etc/forgeai"

  # Determine systemd unit directory for rpmbuild
  local UNITDIR
  UNITDIR=$(pkg-config --variable=systemdsystemunitdir systemd 2>/dev/null || echo "/usr/lib/systemd/system")
  mkdir -p "${STAGE_DIR}${UNITDIR}"

  # Install files into staging
  install -m 0755 "${BINARY}" "${STAGE_DIR}/usr/bin/forgeai-host"
  install -m 0644 "${SCRIPT_DIR}/forgeai-host.service" "${STAGE_DIR}${UNITDIR}/forgeai-host.service"
  install -m 0640 "${SCRIPT_DIR}/connector.env.template" "${STAGE_DIR}/etc/forgeai/connector.env"

  # Copy and configure spec file
  cp "${SCRIPT_DIR}/rpm/forgeai-host.spec" "${RPM_TOPDIR}/SPECS/forgeai-host.spec"

  # Build RPM
  rpmbuild \
    --define "_topdir ${RPM_TOPDIR}" \
    --define "_version ${PKG_VERSION}" \
    --define "_build_arch ${RPM_ARCH}" \
    --define "_stagedir ${STAGE_DIR}" \
    --define "_unitdir ${UNITDIR}" \
    --buildroot "${RPM_TOPDIR}/BUILDROOT" \
    -bb "${RPM_TOPDIR}/SPECS/forgeai-host.spec"

  # Move RPM to output directory
  find "${RPM_TOPDIR}/RPMS" -name "*.rpm" -exec mv {} "${OUT_DIR}/" \;
  rm -rf "${RPM_TOPDIR}"

  echo "✓ ${RPM_NAME}.rpm"
}

# ──────────────────────────────────────────────────────────────
# Build both packages
# ──────────────────────────────────────────────────────────────

build_deb
build_rpm

# ──────────────────────────────────────────────────────────────
# Generate checksums for all package artifacts
# ──────────────────────────────────────────────────────────────

echo ""
echo "── Generating checksums ──"

CHECKSUM_FILE="${OUT_DIR}/forgeai-host-${PKG_VERSION}-packages.sha256"

cd "${OUT_DIR}"
sha256sum \
  "forgeai-host_${PKG_VERSION}_${DEB_ARCH}.deb" \
  forgeai-host-${PKG_VERSION}-1.${RPM_ARCH}.rpm \
  > "${CHECKSUM_FILE}"

echo "✓ ${CHECKSUM_FILE}"
echo ""
echo "=== Package build complete ==="
echo ""
echo "Artifacts:"
echo "  ${OUT_DIR}/forgeai-host_${PKG_VERSION}_${DEB_ARCH}.deb"
echo "  ${OUT_DIR}/forgeai-host-${PKG_VERSION}-1.${RPM_ARCH}.rpm"
echo "  ${CHECKSUM_FILE}"
