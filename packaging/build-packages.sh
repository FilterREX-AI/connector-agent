#!/bin/bash
# ──────────────────────────────────────────────────────────────
# FilterREX Connector Host — System Package Builder
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
#   filterrex-connector_0.8.0_amd64.deb
#   filterrex-connector-0.8.0-1.x86_64.rpm
#   filterrex-connector-0.8.0-packages.sha256
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

# RPM Version: field forbids '-'. Convert pre-release separator to '~' so that
# rpm sorts 0.1.0~preview.5 < 0.1.0 (correct pre-release ordering). Deb keeps
# the upstream '-' form since dpkg allows it in upstream_version.
              # NOTE: '\~' is required — bash performs tilde expansion on the
              # replacement string in ${var//pat/repl}, so a bare '~' would
              # expand to $HOME and mangle the version (e.g. 0.1.0-preview.10
              # → 0.1.0/home/runnerpreview.10). Escaping keeps the literal '~'.
RPM_VERSION="${PKG_VERSION//-/\~}"

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

echo "=== Building packages: filterrex-connector ${PKG_VERSION} (${GOARCH}) ==="
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

  local DEB_NAME="filterrex-connector_${PKG_VERSION}_${DEB_ARCH}"
  local DEB_ROOT="${OUT_DIR}/${DEB_NAME}"

  # Clean and create directory structure
  rm -rf "${DEB_ROOT}"
  mkdir -p "${DEB_ROOT}/DEBIAN"
  mkdir -p "${DEB_ROOT}/usr/bin"
  mkdir -p "${DEB_ROOT}/lib/systemd/system"
  mkdir -p "${DEB_ROOT}/etc/filterrex"

  # Install binary
  install -m 0755 "${BINARY}" "${DEB_ROOT}/usr/bin/filterrex-connector"

  # Install systemd unit
  install -m 0644 "${SCRIPT_DIR}/filterrex-connector.service" \
    "${DEB_ROOT}/lib/systemd/system/filterrex-connector.service"

  # Install default config (with placeholder values)
  install -m 0640 "${SCRIPT_DIR}/connector.env.template" \
    "${DEB_ROOT}/etc/filterrex/connector.env"

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

  local RPM_NAME="filterrex-connector-${RPM_VERSION}-1.${RPM_ARCH}"

  # Set up rpmbuild directory structure
  local RPM_TOPDIR="${OUT_DIR}/rpmbuild-${GOARCH}"
  rm -rf "${RPM_TOPDIR}"
  mkdir -p "${RPM_TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

  # Create staging directory with installed layout
  local STAGE_DIR="${RPM_TOPDIR}/STAGE"
  mkdir -p "${STAGE_DIR}/usr/bin"
  mkdir -p "${STAGE_DIR}/etc/filterrex"

  # Determine systemd unit directory for rpmbuild
  local UNITDIR
  UNITDIR=$(pkg-config --variable=systemdsystemunitdir systemd 2>/dev/null || echo "/usr/lib/systemd/system")
  mkdir -p "${STAGE_DIR}${UNITDIR}"

  # Install files into staging
  install -m 0755 "${BINARY}" "${STAGE_DIR}/usr/bin/filterrex-connector"
  install -m 0644 "${SCRIPT_DIR}/filterrex-connector.service" "${STAGE_DIR}${UNITDIR}/filterrex-connector.service"
  install -m 0640 "${SCRIPT_DIR}/connector.env.template" "${STAGE_DIR}/etc/filterrex/connector.env"

  # Copy and configure spec file
  cp "${SCRIPT_DIR}/rpm/filterrex-connector.spec" "${RPM_TOPDIR}/SPECS/filterrex-connector.spec"

  # Build RPM
  rpmbuild \
    --define "_topdir ${RPM_TOPDIR}" \
    --define "_version ${RPM_VERSION}" \
    --define "_build_arch ${RPM_ARCH}" \
    --define "_stagedir ${STAGE_DIR}" \
    --define "_unitdir ${UNITDIR}" \
    --buildroot "${RPM_TOPDIR}/BUILDROOT" \
    -bb "${RPM_TOPDIR}/SPECS/filterrex-connector.spec"

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

CHECKSUM_FILE="${OUT_DIR}/filterrex-connector-${PKG_VERSION}-packages.sha256"

cd "${OUT_DIR}"
sha256sum \
  "filterrex-connector_${PKG_VERSION}_${DEB_ARCH}.deb" \
  filterrex-connector-${PKG_VERSION}-1.${RPM_ARCH}.rpm \
  > "${CHECKSUM_FILE}"

echo "✓ ${CHECKSUM_FILE}"
echo ""
echo "=== Package build complete ==="
echo ""
echo "Artifacts:"
echo "  ${OUT_DIR}/filterrex-connector_${PKG_VERSION}_${DEB_ARCH}.deb"
echo "  ${OUT_DIR}/filterrex-connector-${PKG_VERSION}-1.${RPM_ARCH}.rpm"
echo "  ${CHECKSUM_FILE}"
