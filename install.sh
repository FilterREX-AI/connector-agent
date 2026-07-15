#!/bin/bash
# FilterREX SAN Connector — Quick Install Script (public SAN-only build)
#
# This is the installer shipped in the PUBLIC connector-agent repo. It installs
# the read-only Brocade SAN evidence connector as a systemd service.
#
# The public connector is enrollment-first: the host registers with the backend
# using an enrollment token, then Brocade FC switches are assigned remotely from
# the FilterREX dashboard. There is no local target-credential entry flow — that
# surface belongs to the private FilterREX platform, not this repo.
#
# Token:
#   frc_...  = Enrollment/connector token from the FilterREX dashboard. Used to
#             enroll the host, then retained as its persistent connector token.
#
# Usage — Enrollment (recommended):
#   curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
#     | bash -s -- --enroll-token 'frc_your_enrollment_token' \
#         --backend-url 'https://qugzesfapcdhiyrhegdx.supabase.co'
#
# Usage — Pinned version:
#   curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
#     | bash -s -- --enroll-token 'frc_...' --version v0.1.0-preview.5
#
# After enrollment, Brocade switches are managed remotely from the FilterREX
# dashboard. No reinstall is needed to add, update, or remove targets.

set -euo pipefail

REPO="filterrex-ai/connector-agent"
# Backend this agent reports to. Installers should pass --backend-url explicitly;
# this default must match the FilterREX instance that issued the token.
BACKEND_URL="${BACKEND_URL:-https://qugzesfapcdhiyrhegdx.supabase.co}"
ENROLLMENT_TOKEN=""
CONNECTOR_TOKEN=""
HOST_LABEL=""
PINNED_VERSION=""

INSECURE_SKIP_VERIFY="false"
POLL_INTERVAL_SECONDS="30"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/filterrex"
SERVICE_USER="filterrex"
FORCE_RESET_STATE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --enroll-token)         ENROLLMENT_TOKEN="$2";      shift 2 ;;
    --backend-url)          BACKEND_URL="$2";           shift 2 ;;
    --token)                CONNECTOR_TOKEN="$2";       shift 2 ;;
    --label)                HOST_LABEL="$2";            shift 2 ;;
    --version)              PINNED_VERSION="$2";        shift 2 ;;
    --insecure)             INSECURE_SKIP_VERIFY="true"; shift ;;
    --poll-interval)        POLL_INTERVAL_SECONDS="$2"; shift 2 ;;
    --config-dir)           CONFIG_DIR="$2";            shift 2 ;;
    --force-reset-state)    FORCE_RESET_STATE=true;     shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Token validation ──

if [ -z "$ENROLLMENT_TOKEN" ] && [ -z "$CONNECTOR_TOKEN" ]; then
  echo "Error: an authentication token is required."
  echo ""
  echo "  Enrollment (recommended):"
  echo "    --enroll-token 'frc_...'   Enrollment token from the FilterREX dashboard."
  echo "                                The host uses this to register, then retains it as its"
  echo "                                connector token. Brocade switches are assigned remotely."
  echo ""
  echo "  Reusing an existing identity:"
  echo "    --token 'frc_...'           Persistent connector token from a prior enrollment."
  exit 1
fi

# Enrollment and connector tokens share the frc_ prefix (the dashboard issues one
# frc_ token that is used for enrollment and then retained as the connector token),
# so no prefix-based token-type warning is emitted here.

echo "╔══════════════════════════════════════════════╗"
echo "║  FilterREX SAN Connector — Installer            ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "→ Mode: Host enrollment (bootstrap)"
  echo "  The host will self-register with the backend using the enrollment token."
  echo "  After enrollment, Brocade switches are assigned from the FilterREX dashboard."
else
  echo "→ Mode: Reusing persistent connector token"
fi

# ── Version / release channel ──

if [ -n "$PINNED_VERSION" ]; then
  RELEASE_MODE="pinned"
  echo "→ Release: pinned version ${PINNED_VERSION}"
else
  RELEASE_MODE="latest"
  echo "→ Release: latest"
fi

# ── Handle --force-reset-state ──

if [ "$FORCE_RESET_STATE" = true ]; then
  echo ""
  echo "⚠️  --force-reset-state: Clearing persisted host enrollment state..."
  echo "   This will remove:"
  echo "     - ${CONFIG_DIR}/host.json.enc  (encrypted host identity & config)"
  echo "     - ${CONFIG_DIR}/host.key       (encryption key material)"
  echo "     - ${CONFIG_DIR}/secrets/*      (per-target encrypted credentials)"
  echo ""
  sudo rm -f "${CONFIG_DIR}/host.json.enc" "${CONFIG_DIR}/host.key" 2>/dev/null || true
  sudo rm -f "${CONFIG_DIR}/secrets/"*.enc 2>/dev/null || true
  echo "   State cleared. Host will re-enroll on next start."
  echo ""
fi

# ── Check for existing installation ──

EXISTING_INSTALL=false
if [ -f "${CONFIG_DIR}/host.json.enc" ] || [ -f "${CONFIG_DIR}/host.key" ]; then
  EXISTING_INSTALL=true
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  ℹ️  Existing Connector Host state detected                   ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Config dir: ${CONFIG_DIR}"
  echo "  The host will reuse its existing enrollment identity and connector token."
  echo "  Any FILTERREX_ENROLLMENT_TOKEN provided will NOT be used for a new enrollment."
  echo ""
  echo "  If the stored connector token is invalid or revoked (e.g. the host"
  echo "  registration was deleted from the dashboard), desired-state sync will fail."
  echo ""
  echo "  To force a clean re-enrollment:"
  echo "    • Rerun this installer with --force-reset-state"
  echo "    • Or manually clear state:"
  echo "        sudo rm -f ${CONFIG_DIR}/host.json.enc ${CONFIG_DIR}/host.key"
  echo "        sudo rm -f ${CONFIG_DIR}/secrets/*.enc"
  echo ""
  echo "  Proceeding with binary upgrade (existing config preserved)."
  echo ""
fi

# ── Detect architecture ──

ARCH=$(uname -m)
case $ARCH in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
echo "→ Detected: ${OS}/${ARCH}"

# ── Construct download URL ──

ASSET_NAME="connector-agent-${OS}-${ARCH}.tar.gz"
RELEASES_URL="https://github.com/${REPO}/releases"

if [ "$RELEASE_MODE" = "pinned" ]; then
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${PINNED_VERSION}/${ASSET_NAME}"
else
  DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
fi

# ── Download with detailed diagnostics on failure ──

echo ""
echo "→ Checking release availability..."
echo "  Asset:   ${ASSET_NAME}"
echo "  Channel: ${RELEASE_MODE}"
echo "  URL:     ${DOWNLOAD_URL}"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -L "$DOWNLOAD_URL" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "000" ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  ❌ Binary download failed                                    ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Diagnostics:"
  echo "    HTTP status:     ${HTTP_CODE}"
  echo "    OS / Arch:       ${OS} / ${ARCH}"
  echo "    Asset name:      ${ASSET_NAME}"
  echo "    Release channel: ${RELEASE_MODE}"
  echo "    Download URL:    ${DOWNLOAD_URL}"
  echo ""

  if [ "$HTTP_CODE" = "404" ]; then
    echo "  Cause: Release asset not found (HTTP 404)."
    echo ""
    echo "  This usually means one of:"
    echo "    1. No release has been published yet for this platform (${OS}/${ARCH})."
    echo "    2. The installer script (fetched from 'main' branch) is newer than the"
    echo "       latest published release. The script and binary releases are updated"
    echo "       independently — 'main' can be ahead of the latest release tag."
    if [ "$RELEASE_MODE" = "pinned" ]; then
      echo "    3. The pinned version '${PINNED_VERSION}' does not exist or has no asset"
      echo "       for ${OS}/${ARCH}."
    fi
    echo ""
    echo "  Check available releases: ${RELEASES_URL}"
  else
    echo "  Cause: Network error, DNS failure, or connectivity issue (HTTP ${HTTP_CODE})."
    echo "  Verify internet connectivity and try again."
  fi

  echo ""
  echo "  ── Fallback: Docker (recommended) ──"
  echo ""
  echo "  Use Docker to run the SAN connector without a binary release:"
  echo ""
  echo "    docker run -d --name filterrex-connector \\"
  echo "      --pull always \\"
  echo "      --restart unless-stopped \\"
  echo "      -v filterrex-config:/etc/filterrex \\"
  echo "      -e BACKEND_URL='${BACKEND_URL}' \\"
  if [ -n "$ENROLLMENT_TOKEN" ]; then
    echo "      -e FILTERREX_ENROLLMENT_TOKEN='<your_frc_token>' \\"
  else
    echo "      -e CONNECTOR_TOKEN='<your_frc_token>' \\"
  fi
  [ -n "$HOST_LABEL" ] && echo "      -e HOST_LABEL='${HOST_LABEL}' \\"
  [ "$INSECURE_SKIP_VERIFY" = "true" ] && echo "      -e INSECURE_SKIP_VERIFY=true \\"
  echo "      ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.5"
  echo ""
  echo "  Note: Docker fallback uses the current pinned preview image. For a different"
  echo "  image tag, replace ':0.1.0-preview.5' with the desired version."
  echo ""
  echo "  If you prefer a bind mount instead of a named volume:"
  echo "    sudo mkdir -p /etc/filterrex/secrets"
  echo "    sudo chown -R 1000:1000 /etc/filterrex"
  echo "    sudo chmod 700 /etc/filterrex /etc/filterrex/secrets"
  echo "    # Then replace '-v filterrex-config:/etc/filterrex' with '-v /etc/filterrex:/etc/filterrex'"
  echo ""
  exit 1
fi

echo "→ Downloading connector host..."
curl -fsSL -o "/tmp/${ASSET_NAME}" "$DOWNLOAD_URL" || {
  echo "Download failed. Check: ${RELEASES_URL}"
  exit 1
}

# ── Extract ──

echo "→ Extracting..."
tar xzf "/tmp/${ASSET_NAME}" -C /tmp/
chmod +x "/tmp/connector-agent-${OS}-${ARCH}"

# ── Stop existing service before replacing binary ──

if systemctl is-active --quiet filterrex-connector 2>/dev/null; then
  echo "→ Stopping existing host service..."
  sudo systemctl stop filterrex-connector
fi

# ── Install binary ──

echo "→ Installing to ${INSTALL_DIR}..."
sudo mv "/tmp/connector-agent-${OS}-${ARCH}" "${INSTALL_DIR}/filterrex-connector"
rm -f "/tmp/${ASSET_NAME}"

# ── Create service user ──

if ! id "$SERVICE_USER" &>/dev/null; then
  echo "→ Creating service user: ${SERVICE_USER}"
  sudo useradd -r -s /bin/false "$SERVICE_USER" 2>/dev/null || true
fi

# ── Create config directory with proper permissions ──

echo "→ Creating config directory..."
sudo mkdir -p "${CONFIG_DIR}/secrets"
sudo chmod 700 "${CONFIG_DIR}"
sudo chmod 700 "${CONFIG_DIR}/secrets"
sudo chown -R "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}"

# ── Write environment file (new installs only) ──

if [ "$EXISTING_INSTALL" = false ]; then
  echo "→ Writing configuration..."

  if [ -n "$ENROLLMENT_TOKEN" ]; then
    # Enrollment mode — host registers on first run, receives persistent identity.
    # NOTE: CONNECTOR_TOKEN is NOT set here. The host receives its persistent
    # connector identity from the backend after successful enrollment.
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
BACKEND_URL=${BACKEND_URL}
FILTERREX_ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}
CONFIG_DIR=${CONFIG_DIR}
HOST_LABEL=${HOST_LABEL}
INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY}
POLL_INTERVAL_SECONDS=${POLL_INTERVAL_SECONDS}
EOF
  else
    # Reuse an existing persistent connector token.
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
BACKEND_URL=${BACKEND_URL}
CONNECTOR_TOKEN=${CONNECTOR_TOKEN}
CONFIG_DIR=${CONFIG_DIR}
HOST_LABEL=${HOST_LABEL}
INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY}
POLL_INTERVAL_SECONDS=${POLL_INTERVAL_SECONDS}
EOF
  fi

  sudo chmod 600 "${CONFIG_DIR}/connector.env"
  sudo chown "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}/connector.env"
else
  echo "→ Preserving existing configuration"
fi

# ── Create systemd unit ──

echo "→ Creating systemd service..."
cat <<EOF | sudo tee /etc/systemd/system/filterrex-connector.service > /dev/null
[Unit]
Description=FilterREX SAN Connector Host
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
EnvironmentFile=${CONFIG_DIR}/connector.env
ExecStart=${INSTALL_DIR}/filterrex-connector
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${CONFIG_DIR}
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# ── Enable and start ──

echo "→ Starting connector host..."
sudo systemctl daemon-reload
sudo systemctl enable filterrex-connector
sudo systemctl restart filterrex-connector

echo ""
echo "✅ FilterREX SAN Connector installed and running!"
if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "   Mode: Enrollment (host will self-register with backend)"
  echo "   After enrollment, assign Brocade switches from the FilterREX dashboard."
fi
if [ -n "$PINNED_VERSION" ]; then
  echo "   Version: ${PINNED_VERSION} (pinned)"
else
  echo "   Version: latest release"
fi
echo "   Config dir: ${CONFIG_DIR}"
echo ""
echo "Useful commands:"
echo "  Status:    sudo systemctl status filterrex-connector"
echo "  Logs:      sudo journalctl -u filterrex-connector -f"
echo "  Stop:      sudo systemctl stop filterrex-connector"
echo "  Uninstall: sudo systemctl stop filterrex-connector && sudo systemctl disable filterrex-connector && sudo rm ${INSTALL_DIR}/filterrex-connector /etc/systemd/system/filterrex-connector.service && sudo rm -rf ${CONFIG_DIR}"
echo ""
echo "Brocade switches are managed from the FilterREX dashboard — no reinstall needed."
