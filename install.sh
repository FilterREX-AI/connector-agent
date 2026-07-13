#!/bin/bash
# FilterREX Connector Host — Quick Install Script
#
# Installs the connector host as a systemd service that can manage
# multiple infrastructure targets simultaneously from a single host.
#
# Token types:
#   frbt_...  = Bootstrap enrollment token (temporary, used once to register the host)
#   frc_...   = Persistent connector token (issued by backend after enrollment)
#
# Usage — Enrollment (recommended):
#   curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
#     | bash -s -- --enroll-token 'frbt_your_enrollment_token' \
#         --backend-url 'https://qugzesfapcdhiyrhegdx.supabase.co'
#
# Usage — Pinned version:
#   curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
#     | bash -s -- --enroll-token 'frbt_...' --version v0.7.1
#
# Usage — Legacy mode (backward compatible, persistent connector token):
#   curl -fsSL ... | bash -s -- --token 'frc_...' --target-type 'proxmox' ...
#
# After enrollment, targets are managed remotely from the FilterREX dashboard.
# No reinstall needed to add, update, or remove targets.

set -euo pipefail

REPO="filterrex-ai/connector-agent"
# Backend this agent reports to. Installers should pass --backend-url explicitly;
# this default must match the FilterREX instance that issued the token.
BACKEND_URL="${BACKEND_URL:-https://qugzesfapcdhiyrhegdx.supabase.co}"
ENROLLMENT_TOKEN=""
CONNECTOR_TOKEN=""
TARGET_TYPE=""
HOST_LABEL=""
PINNED_VERSION=""

# Proxmox
PROXMOX_BASE_URL=""
PROXMOX_USERNAME=""
PROXMOX_PASSWORD=""
PROXMOX_TOKEN_ID=""
PROXMOX_TOKEN_SECRET=""

# TrueNAS
TRUENAS_URL=""
TRUENAS_API_KEY=""

# Nutanix
NUTANIX_URL=""
NUTANIX_USERNAME=""
NUTANIX_PASSWORD=""

INSECURE_SKIP_VERIFY="false"
POLL_INTERVAL_SECONDS="30"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/filterrex"
SERVICE_USER="filterrex"
FORCE_RESET_STATE=false
REMOTE_LIVE_QUERY=false
REMOTE_RESTART=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --enroll-token)         ENROLLMENT_TOKEN="$2";      shift 2 ;;
    --backend-url)          BACKEND_URL="$2";           shift 2 ;;
    --token)                CONNECTOR_TOKEN="$2";       shift 2 ;;
    --target-type)          TARGET_TYPE="$2";           shift 2 ;;
    --label)                HOST_LABEL="$2";            shift 2 ;;
    --version)              PINNED_VERSION="$2";        shift 2 ;;
    --proxmox-url)          PROXMOX_BASE_URL="$2";      shift 2 ;;
    --proxmox-user)         PROXMOX_USERNAME="$2";      shift 2 ;;
    --proxmox-token-id)     PROXMOX_TOKEN_ID="$2";      shift 2 ;;
    --proxmox-token-secret) PROXMOX_TOKEN_SECRET="$2";  shift 2 ;;
    --truenas-url)          TRUENAS_URL="$2";           shift 2 ;;
    --truenas-api-key)      TRUENAS_API_KEY="$2";       shift 2 ;;
    --nutanix-url)          NUTANIX_URL="$2";           shift 2 ;;
    --nutanix-username)     NUTANIX_USERNAME="$2";      shift 2 ;;
    --insecure)             INSECURE_SKIP_VERIFY="true"; shift ;;
    --poll-interval)        POLL_INTERVAL_SECONDS="$2"; shift 2 ;;
    --config-dir)           CONFIG_DIR="$2";            shift 2 ;;
    --force-reset-state)    FORCE_RESET_STATE=true;     shift ;;
    --enable-remote-actions) REMOTE_LIVE_QUERY=true; REMOTE_RESTART=true; shift ;;
    --enable-live-query)    REMOTE_LIVE_QUERY=true;     shift ;;
    --enable-remote-restart) REMOTE_RESTART=true;       shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Token validation ──

if [ -z "$ENROLLMENT_TOKEN" ] && [ -z "$CONNECTOR_TOKEN" ]; then
  echo "Error: an authentication token is required."
  echo ""
  echo "  Enrollment (recommended):"
  echo "    --enroll-token 'frbt_...'   Bootstrap enrollment token from the FilterREX dashboard."
  echo "                                The host uses this once to register, then receives a"
  echo "                                persistent identity. Targets are managed remotely."
  echo ""
  echo "  Legacy (single-target, backward compatible):"
  echo "    --token 'frc_...'           Persistent connector token, requires --target-type."
  exit 1
fi

# Warn on likely token-type misuse
if [ -n "$ENROLLMENT_TOKEN" ] && [[ "$ENROLLMENT_TOKEN" == frc_* ]]; then
  echo "⚠️  Warning: --enroll-token value starts with 'frc_', which looks like a persistent"
  echo "   connector token. Enrollment tokens typically start with 'frbt_'."
  echo "   Continuing, but enrollment may fail if the token type is wrong."
  echo ""
fi

if [ -n "$CONNECTOR_TOKEN" ] && [[ "$CONNECTOR_TOKEN" == frbt_* ]]; then
  echo "⚠️  Warning: --token value starts with 'frbt_', which looks like a bootstrap enrollment"
  echo "   token. Legacy --token expects a persistent connector token (frc_...)."
  echo "   Use --enroll-token instead for enrollment mode."
  echo ""
fi

echo "╔══════════════════════════════════════════════╗"
echo "║  FilterREX Connector Host — Installer           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "→ Mode: Host enrollment (bootstrap)"
  echo "  The host will self-register with the backend using the enrollment token."
  echo "  After enrollment, targets are assigned from the FilterREX dashboard."
else
  echo "→ Mode: Legacy single-target (persistent connector token)"
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

# ── Credential validation (only for new installs with a target type) ──

if [ -n "$TARGET_TYPE" ]; then
  echo "→ Initial target type: ${TARGET_TYPE}"

  case "$TARGET_TYPE" in
    proxmox)
      if [ -n "$PROXMOX_TOKEN_ID" ] && [ -n "$PROXMOX_TOKEN_SECRET" ]; then
        echo "→ Auth: Proxmox API token"
      elif [ -n "$PROXMOX_USERNAME" ]; then
        echo "→ Auth: Proxmox username/password (password will be prompted)"
        if [ -z "$PROXMOX_PASSWORD" ]; then
          if [ -t 0 ]; then
            echo ""
            read -s -p "  Enter Proxmox password for ${PROXMOX_USERNAME}: " PROXMOX_PASSWORD
            echo ""
          else
            echo "  ⚠️  No interactive terminal detected."
            echo "  Set PROXMOX_PASSWORD as an environment variable before running:"
            echo "    export PROXMOX_PASSWORD='...'"
            exit 1
          fi
        else
          echo "  (using PROXMOX_PASSWORD from environment)"
        fi
        if [ -z "$PROXMOX_PASSWORD" ]; then
          echo "Error: password cannot be empty"
          exit 1
        fi
      elif [ -n "$PROXMOX_BASE_URL" ]; then
        echo "Error: Proxmox URL provided but no auth credentials."
        echo "  Use --proxmox-token-id and --proxmox-token-secret (recommended)"
        echo "  Or  --proxmox-user to be prompted for a password"
        exit 1
      fi
      ;;

    truenas)
      if [ -z "$TRUENAS_URL" ]; then
        echo "Error: --truenas-url is required for TrueNAS targets"
        exit 1
      fi
      if [ -z "$TRUENAS_API_KEY" ]; then
        echo "Error: --truenas-api-key is required for TrueNAS targets"
        echo "  Generate one in TrueNAS: Settings → API Keys → Add"
        exit 1
      fi
      echo "→ Auth: TrueNAS API key"
      ;;

    nutanix)
      if [ -z "$NUTANIX_URL" ]; then
        echo "Error: --nutanix-url is required for Nutanix targets"
        exit 1
      fi
      if [ -z "$NUTANIX_USERNAME" ]; then
        echo "Error: --nutanix-username is required for Nutanix targets"
        exit 1
      fi
      if [ -z "$NUTANIX_PASSWORD" ]; then
        if [ -t 0 ]; then
          echo "→ Auth: Nutanix username/password (password will be prompted)"
          echo ""
          read -s -p "  Enter Nutanix password for ${NUTANIX_USERNAME}: " NUTANIX_PASSWORD
          echo ""
        else
          echo "  ⚠️  No interactive terminal detected."
          echo "  Set NUTANIX_PASSWORD as an environment variable before running:"
          echo "    export NUTANIX_PASSWORD='...'"
          exit 1
        fi
      else
        echo "→ Auth: Nutanix username/password (from environment)"
      fi
      if [ -z "$NUTANIX_PASSWORD" ]; then
        echo "Error: password cannot be empty"
        exit 1
      fi
      ;;

    *)
      echo "Error: unsupported --target-type '${TARGET_TYPE}'"
      echo "  Supported: proxmox, truenas, nutanix, prometheus, grafana, ollama,"
      echo "             generic-http, pure-storage, netapp-ontap, powerstore, powermax, powerflex"
      echo ""
      echo "  Tip: Use --enroll-token instead of --token to enroll a multi-target host."
      echo "  Targets are then assigned remotely from the FilterREX dashboard."
      exit 1
      ;;
  esac
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
  echo "    HTTP status:    ${HTTP_CODE}"
  echo "    OS / Arch:      ${OS} / ${ARCH}"
  echo "    Asset name:     ${ASSET_NAME}"
  echo "    Release channel: ${RELEASE_MODE}"
  echo "    Download URL:   ${DOWNLOAD_URL}"
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
  echo "  Use Docker to run the Connector Host without a binary release:"
  echo ""
  echo "    docker run -d --name filterrex-connector \\"
  echo "      --pull always \\"
  echo "      --restart unless-stopped \\"
  echo "      -v filterrex-config:/etc/filterrex \\"
  echo "      -e BACKEND_URL='${BACKEND_URL}' \\"
  if [ -n "$ENROLLMENT_TOKEN" ]; then
    echo "      -e FILTERREX_ENROLLMENT_TOKEN='<your_frbt_token>' \\"
  else
    echo "      -e CONNECTOR_TOKEN='<your_frc_token>' \\"
  fi
  [ -n "$HOST_LABEL" ] && echo "      -e HOST_LABEL='${HOST_LABEL}' \\"
  [ -n "$TARGET_TYPE" ] && echo "      -e TARGET_TYPE='${TARGET_TYPE}' \\"
  case "$TARGET_TYPE" in
    proxmox)
      [ -n "$PROXMOX_BASE_URL" ]     && echo "      -e PROXMOX_BASE_URL='${PROXMOX_BASE_URL}' \\"
      [ -n "$PROXMOX_TOKEN_ID" ]     && echo "      -e PROXMOX_TOKEN_ID='...' \\"
      [ -n "$PROXMOX_TOKEN_SECRET" ] && echo "      -e PROXMOX_TOKEN_SECRET='...' \\"
      [ -n "$PROXMOX_USERNAME" ]     && echo "      -e PROXMOX_USERNAME='${PROXMOX_USERNAME}' \\"
      ;;
    truenas)
      echo "      -e TRUENAS_URL='${TRUENAS_URL}' \\"
      echo "      -e TRUENAS_API_KEY='...' \\"
      ;;
    nutanix)
      echo "      -e NUTANIX_URL='${NUTANIX_URL}' \\"
      echo "      -e NUTANIX_USERNAME='${NUTANIX_USERNAME}' \\"
      ;;
  esac
  [ "$INSECURE_SKIP_VERIFY" = "true" ] && echo "      -e INSECURE_SKIP_VERIFY=true \\"
  echo "      ghcr.io/filterrex-ai/connector-agent/connector-agent:latest"
  echo ""
  echo "  Note: Docker fallback always uses ':latest'. For a pinned image tag,"
  echo "  replace ':latest' with the desired version (e.g., ':v0.7.1')."
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

# Backward-compatible symlink
sudo ln -sf "${INSTALL_DIR}/filterrex-connector" "${INSTALL_DIR}/filterrex-connector"

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
    # Only store the bootstrap token and host-level config.
    # NOTE: CONNECTOR_TOKEN is NOT set here. The host agent receives its
    # persistent connector identity from the backend after successful enrollment.
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
BACKEND_URL=${BACKEND_URL}
FILTERREX_ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}
CONFIG_DIR=${CONFIG_DIR}
HOST_LABEL=${HOST_LABEL}
FILTERREX_REMOTE_LIVE_QUERY=${REMOTE_LIVE_QUERY}
FILTERREX_REMOTE_RESTART=${REMOTE_RESTART}
EOF

    # If initial target settings are provided, store them as bootstrap hints.
    # These help the host register its first target during enrollment, but
    # ongoing target management happens via the FilterREX dashboard.
    if [ -n "$TARGET_TYPE" ]; then
      cat <<EOF | sudo tee -a "${CONFIG_DIR}/connector.env" > /dev/null
INITIAL_TARGET_TYPE=${TARGET_TYPE}
INITIAL_PROXMOX_BASE_URL=${PROXMOX_BASE_URL}
INITIAL_PROXMOX_USERNAME=${PROXMOX_USERNAME}
INITIAL_PROXMOX_PASSWORD=${PROXMOX_PASSWORD}
INITIAL_PROXMOX_TOKEN_ID=${PROXMOX_TOKEN_ID}
INITIAL_PROXMOX_TOKEN_SECRET=${PROXMOX_TOKEN_SECRET}
INITIAL_TRUENAS_URL=${TRUENAS_URL}
INITIAL_TRUENAS_API_KEY=${TRUENAS_API_KEY}
INITIAL_NUTANIX_URL=${NUTANIX_URL}
INITIAL_NUTANIX_USERNAME=${NUTANIX_USERNAME}
INITIAL_NUTANIX_PASSWORD=${NUTANIX_PASSWORD}
INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY}
POLL_INTERVAL_SECONDS=${POLL_INTERVAL_SECONDS}
EOF
    fi
  else
    # Legacy mode — persistent connector token, single target.
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
BACKEND_URL=${BACKEND_URL}
CONNECTOR_TOKEN=${CONNECTOR_TOKEN}
TARGET_TYPE=${TARGET_TYPE}
CONFIG_DIR=${CONFIG_DIR}
PROXMOX_BASE_URL=${PROXMOX_BASE_URL}
PROXMOX_USERNAME=${PROXMOX_USERNAME}
PROXMOX_PASSWORD=${PROXMOX_PASSWORD}
PROXMOX_TOKEN_ID=${PROXMOX_TOKEN_ID}
PROXMOX_TOKEN_SECRET=${PROXMOX_TOKEN_SECRET}
TRUENAS_URL=${TRUENAS_URL}
TRUENAS_API_KEY=${TRUENAS_API_KEY}
NUTANIX_URL=${NUTANIX_URL}
NUTANIX_USERNAME=${NUTANIX_USERNAME}
NUTANIX_PASSWORD=${NUTANIX_PASSWORD}
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
Description=FilterREX Connector Host
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

# ── Migrate from legacy single-target service ──

if systemctl is-enabled --quiet filterrex-connector 2>/dev/null; then
  echo "→ Migrating from legacy single-target service..."
  sudo systemctl stop filterrex-connector 2>/dev/null || true
  sudo systemctl disable filterrex-connector 2>/dev/null || true
  sudo rm -f /etc/systemd/system/filterrex-connector.service
fi

# ── Enable and start ──

echo "→ Starting connector host..."
sudo systemctl daemon-reload
sudo systemctl enable filterrex-connector
sudo systemctl restart filterrex-connector

echo ""
echo "✅ FilterREX Connector Host installed and running!"
if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "   Mode: Enrollment (host will self-register with backend)"
  echo "   After enrollment, manage targets from the FilterREX dashboard."
fi
if [ -n "$TARGET_TYPE" ]; then
  echo "   Initial target hint: ${TARGET_TYPE} (will be registered during enrollment)"
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
echo "Targets are managed from the FilterREX dashboard — no reinstall needed."
