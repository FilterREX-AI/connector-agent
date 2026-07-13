#!/bin/bash
# ForgeAI Connector Host — Offline Installer
#
# Installs the connector host from a local bundle without network access
# to GitHub or any package registry. Part of the offline install bundle
# for restricted / air-gapped enterprise deployments.
#
# Deployment modes:
#   Restricted network:  No GitHub access, but ForgeAI backend is reachable.
#                        Use --enroll-token as normal; enrollment happens on first start.
#
#   Fully disconnected:  No outbound connectivity at install time.
#                        Pre-populate connector.env with a persistent connector token
#                        (fgc_...) or use a pre-seeded config artifact. See README-offline.md.
#
# Usage:
#   sudo bash install-offline.sh --enroll-token 'fgbt_...'
#   sudo bash install-offline.sh --enroll-token 'fgbt_...' --verify
#   sudo bash install-offline.sh --verify    # verify bundle integrity only, no install
#
# The binary in this bundle is named 'connector-agent'. The installer copies it
# to /usr/local/bin/forgeai-host (the production binary name used by the systemd
# unit and all documentation).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ──

ENROLLMENT_TOKEN=""
CONNECTOR_TOKEN=""
HOST_LABEL=""
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/forgeai"
SERVICE_USER="forgeai"
FORCE_RESET_STATE=false
REMOTE_LIVE_QUERY=false
REMOTE_RESTART=false
VERIFY_ONLY=false
DO_VERIFY=false

# ── Parse arguments ──

while [[ $# -gt 0 ]]; do
  case $1 in
    --enroll-token)          ENROLLMENT_TOKEN="$2";      shift 2 ;;
    --token)                 CONNECTOR_TOKEN="$2";       shift 2 ;;
    --label)                 HOST_LABEL="$2";            shift 2 ;;
    --config-dir)            CONFIG_DIR="$2";            shift 2 ;;
    --force-reset-state)     FORCE_RESET_STATE=true;     shift ;;
    --enable-remote-actions) REMOTE_LIVE_QUERY=true; REMOTE_RESTART=true; shift ;;
    --enable-live-query)     REMOTE_LIVE_QUERY=true;     shift ;;
    --enable-remote-restart) REMOTE_RESTART=true;        shift ;;
    --verify)                DO_VERIFY=true;             shift ;;
    --verify-only)           VERIFY_ONLY=true; DO_VERIFY=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Bundle integrity verification ──

if [ "$DO_VERIFY" = true ]; then
  echo "→ Verifying bundle integrity..."
  if [ ! -f "${SCRIPT_DIR}/SHA256SUMS" ]; then
    echo "❌ SHA256SUMS file not found in bundle directory."
    echo "   Expected at: ${SCRIPT_DIR}/SHA256SUMS"
    exit 1
  fi
  cd "${SCRIPT_DIR}"
  if sha256sum -c SHA256SUMS --strict; then
    echo "✓ All checksums verified."
  else
    echo "❌ Checksum verification FAILED. Bundle may be corrupted or tampered with."
    exit 1
  fi
  cd - > /dev/null

  if [ "$VERIFY_ONLY" = true ]; then
    echo ""
    echo "Verification complete. No installation performed (--verify-only)."
    exit 0
  fi
  echo ""
fi

# ── Token validation ──

if [ -z "$ENROLLMENT_TOKEN" ] && [ -z "$CONNECTOR_TOKEN" ]; then
  # Check if an existing install is present — allow token-less upgrades
  if [ ! -f "${CONFIG_DIR}/host.json.enc" ] && [ ! -f "${CONFIG_DIR}/host.key" ]; then
    # Check for a pre-seeded connector.env with a valid token (fully disconnected path)
    PRESEEDED_TOKEN=""
    if [ -f "${CONFIG_DIR}/connector.env" ]; then
      PRESEEDED_TOKEN=$(grep -E '^\s*(FORGEAI_ENROLLMENT_TOKEN|CONNECTOR_TOKEN)\s*=' \
        "${CONFIG_DIR}/connector.env" 2>/dev/null \
        | head -1 | sed 's/^[^=]*=//' | xargs)
    fi
    if [ -n "$PRESEEDED_TOKEN" ]; then
      echo "→ Detected pre-seeded token in ${CONFIG_DIR}/connector.env"
      echo "  Skipping token requirement — using existing config file."
    else
      echo "Error: an authentication token is required for new installations."
      echo ""
      echo "  Restricted network (backend reachable):"
      echo "    --enroll-token 'fgbt_...'   Bootstrap enrollment token from the ForgeAI dashboard."
      echo ""
      echo "  Fully disconnected (no backend at install time):"
      echo "    --token 'fgc_...'           Pre-provisioned persistent connector token."
      echo "    Or pre-populate ${CONFIG_DIR}/connector.env before running this installer."
      echo "    See README-offline.md for fully disconnected setup instructions."
      exit 1
    fi
  fi
fi

# Warn on likely token-type misuse
if [ -n "$ENROLLMENT_TOKEN" ] && [[ "$ENROLLMENT_TOKEN" == fgc_* ]]; then
  echo "⚠️  Warning: --enroll-token value starts with 'fgc_', which looks like a persistent"
  echo "   connector token. Enrollment tokens typically start with 'fgbt_'."
  echo ""
fi

if [ -n "$CONNECTOR_TOKEN" ] && [[ "$CONNECTOR_TOKEN" == fgbt_* ]]; then
  echo "⚠️  Warning: --token value starts with 'fgbt_', which looks like a bootstrap enrollment"
  echo "   token. Use --enroll-token instead for enrollment mode."
  echo ""
fi

# ── Verify bundle binary exists ──

BINARY_PATH="${SCRIPT_DIR}/connector-agent"
if [ ! -f "$BINARY_PATH" ]; then
  echo "❌ Binary not found: ${BINARY_PATH}"
  echo "   This installer must be run from an extracted offline bundle directory."
  exit 1
fi

echo "╔══════════════════════════════════════════════════════╗"
echo "║  ForgeAI Connector Host — Offline Installer           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "→ Mode: Host enrollment (restricted network — backend reachable)"
elif [ -n "$CONNECTOR_TOKEN" ]; then
  echo "→ Mode: Pre-provisioned token (fully disconnected capable)"
else
  echo "→ Mode: Binary upgrade (existing config preserved)"
fi

# Print binary version
BINARY_VERSION=$("${BINARY_PATH}" --version 2>&1 || echo "unknown")
echo "→ Bundle binary: ${BINARY_VERSION}"

# ── Handle --force-reset-state ──

if [ "$FORCE_RESET_STATE" = true ]; then
  echo ""
  echo "⚠️  --force-reset-state: Clearing persisted host enrollment state..."
  echo "   Removing: ${CONFIG_DIR}/host.json.enc, host.key, secrets/*.enc"
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
  echo "ℹ️  Existing Connector Host state detected at ${CONFIG_DIR}"
  echo "   The host will reuse its existing enrollment identity."
  echo "   To force re-enrollment: rerun with --force-reset-state"
  echo ""
fi

# ── Stop existing service before replacing binary ──

if systemctl is-active --quiet forgeai-host 2>/dev/null; then
  echo "→ Stopping existing host service..."
  sudo systemctl stop forgeai-host
fi

# ── Install binary ──
# Bundle binary is named 'connector-agent'; production name is 'forgeai-host'.

echo "→ Installing binary to ${INSTALL_DIR}/forgeai-host..."
sudo cp "${BINARY_PATH}" "${INSTALL_DIR}/forgeai-host"
sudo chmod +x "${INSTALL_DIR}/forgeai-host"

# Backward-compatible symlink
sudo ln -sf "${INSTALL_DIR}/forgeai-host" "${INSTALL_DIR}/forgeai-connector"

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

# ── Write environment file ──
# For new installs: write config from CLI args, or preserve pre-seeded file.
# For upgrades: always preserve existing config.

if [ "$EXISTING_INSTALL" = false ]; then
  if [ -n "$ENROLLMENT_TOKEN" ]; then
    echo "→ Writing configuration (enrollment token)..."
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
FORGEAI_ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}
CONFIG_DIR=${CONFIG_DIR}
HOST_LABEL=${HOST_LABEL}
FORGEAI_REMOTE_LIVE_QUERY=${REMOTE_LIVE_QUERY}
FORGEAI_REMOTE_RESTART=${REMOTE_RESTART}
EOF
    sudo chmod 600 "${CONFIG_DIR}/connector.env"
    sudo chown "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}/connector.env"
  elif [ -n "$CONNECTOR_TOKEN" ]; then
    echo "→ Writing configuration (connector token)..."
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
CONNECTOR_TOKEN=${CONNECTOR_TOKEN}
CONFIG_DIR=${CONFIG_DIR}
HOST_LABEL=${HOST_LABEL}
FORGEAI_REMOTE_LIVE_QUERY=${REMOTE_LIVE_QUERY}
FORGEAI_REMOTE_RESTART=${REMOTE_RESTART}
EOF
    sudo chmod 600 "${CONFIG_DIR}/connector.env"
    sudo chown "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}/connector.env"
  elif [ -f "${CONFIG_DIR}/connector.env" ]; then
    echo "→ Preserving pre-seeded configuration at ${CONFIG_DIR}/connector.env"
    sudo chmod 600 "${CONFIG_DIR}/connector.env"
    sudo chown "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}/connector.env"
  fi
else
  echo "→ Preserving existing configuration"
fi

# ── Install systemd unit ──

echo "→ Installing systemd service..."
UNIT_SOURCE="${SCRIPT_DIR}/forgeai-host.service"
if [ -f "$UNIT_SOURCE" ]; then
  # Substitute paths if non-default
  sudo cp "$UNIT_SOURCE" /etc/systemd/system/forgeai-host.service
  sudo sed -i "s|EnvironmentFile=.*|EnvironmentFile=${CONFIG_DIR}/connector.env|" /etc/systemd/system/forgeai-host.service
  sudo sed -i "s|ExecStart=.*|ExecStart=${INSTALL_DIR}/forgeai-host|" /etc/systemd/system/forgeai-host.service
  sudo sed -i "s|ReadWritePaths=.*|ReadWritePaths=${CONFIG_DIR}|" /etc/systemd/system/forgeai-host.service
else
  echo "❌ Bundled service unit not found: ${UNIT_SOURCE}"
  echo "   The offline bundle appears incomplete or corrupted."
  echo "   Re-extract the bundle and try again, or run with --verify first."
  exit 1
fi

# ── Migrate from legacy single-target service ──

if systemctl is-enabled --quiet forgeai-connector 2>/dev/null; then
  echo "→ Migrating from legacy single-target service..."
  sudo systemctl stop forgeai-connector 2>/dev/null || true
  sudo systemctl disable forgeai-connector 2>/dev/null || true
  sudo rm -f /etc/systemd/system/forgeai-connector.service
fi

# ── Enable and start ──

echo "→ Starting connector host..."
sudo systemctl daemon-reload
sudo systemctl enable forgeai-host
sudo systemctl restart forgeai-host

echo ""
echo "✅ ForgeAI Connector Host installed from offline bundle!"
echo "   Binary:     ${INSTALL_DIR}/forgeai-host"
echo "   Config dir: ${CONFIG_DIR}"
echo "   Version:    ${BINARY_VERSION}"
echo ""
echo "Useful commands:"
echo "  Status:    sudo systemctl status forgeai-host"
echo "  Logs:      sudo journalctl -u forgeai-host -f"
echo "  Stop:      sudo systemctl stop forgeai-host"
echo ""
if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "The host will enroll with the ForgeAI backend on first start."
  echo "After enrollment, manage targets from the ForgeAI dashboard."
elif [ -n "$CONNECTOR_TOKEN" ]; then
  echo "The host is configured with a pre-provisioned connector token."
  echo "Targets are managed from the ForgeAI dashboard."
fi
