# FilterREX Connector Host — Offline Install Bundle

Self-contained installation bundle for enterprise deployments where GitHub and public package registries are not reachable. No internet downloads are performed during installation.

## Deployment Modes

### Restricted Network (recommended)

The host has no access to GitHub, but **can reach the FilterREX backend** (outbound HTTPS).

- Use `--enroll-token 'frbt_...'` as normal
- The host enrolls with the backend on first start
- Targets are managed remotely from the FilterREX dashboard

### Fully Disconnected (install-time only)

The host has **no outbound connectivity at install time**.

- Pre-populate `/etc/filterrex/connector.env` with a persistent connector token (`CONNECTOR_TOKEN=frc_...`)
- Or use `--token 'frc_...'` with the offline installer
- The token must be provisioned in advance through an out-of-band process

> **Important:** "Fully disconnected" describes the **installation and bootstrap** step only. At runtime, the agent requires outbound HTTPS connectivity to the FilterREX control plane for heartbeat, target management, desired-state sync, and snapshot relay. If the host never has backend connectivity, the agent will install and start but will not be able to receive target assignments, report snapshots, or sync configuration. A future release may add a local-only operating mode for permanent air-gap scenarios.

## What This Bundle Does NOT Do

- **Does not remove the need for backend connectivity at runtime.** The agent must reach the FilterREX control plane to function normally (see above).
- **Does not include target-specific collectors or plugins.** Target support is built into the agent binary; no additional downloads are needed after installation.
- **Does not auto-update.** The installed version is fixed. To upgrade, deploy a newer bundle.
- **Does not configure targets.** Target configuration is managed from the FilterREX dashboard once the agent is enrolled and connected.

## Prerequisites

- Linux (amd64 or arm64)
- systemd
- Root or sudo access

## Bundle Contents

| File | Purpose |
|------|---------|
| `connector-agent` | Pre-built binary (installed as `/usr/bin/filterrex-connector`) |
| `install-offline.sh` | Offline installer script |
| `filterrex-connector.service` | systemd unit template (hardened) |
| `connector.env.template` | Commented environment config template |
| `SHA256SUMS` | Checksums for all files in this bundle |
| `VERIFICATION.md` | Cosign + checksum verification instructions |
| `README-offline.md` | This file |

### Binary Naming

The bundle ships the binary as `connector-agent` (the build artifact name). The installer copies it to `/usr/bin/filterrex-connector` (the production name used by the systemd unit). A backward-compatible symlink `filterrex-connector` is also created.

## Verify Bundle Integrity

### Step 1: Verify the tarball itself (before extraction)

The release includes a detached checksum and cosign signature for the tarball:

```bash
# Verify tarball checksum
sha256sum -c filterrex-connector-offline-<version>-linux-amd64.tar.gz.sha256

# Verify tarball signature (requires network for Sigstore transparency log)
cosign verify-blob \
  --bundle filterrex-connector-offline-<version>-linux-amd64.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/filterrex-ai/connector-agent/.github/workflows/connector-publish.public.yml@refs/tags/<version>" \
  filterrex-connector-offline-<version>-linux-amd64.tar.gz
```

> **Note on `--certificate-identity`:** Replace `<version>` with the exact Git tag (e.g., `v0.8.0`). This pins verification to the specific workflow file and tag that produced the artifact, rather than a broad repository match. If you cannot determine the exact tag, you may use `--certificate-identity-regexp 'github.com/filterrex-ai/connector-agent/.github/workflows/connector-publish'` as a fallback.

**Offline cosign verification:** Cosign keyless signing relies on the Sigstore transparency log, which requires network access to verify. For fully offline environments:
- Verify the tarball checksum and cosign signature on a **connected machine** before transferring
- Transfer the verified tarball to the air-gapped host via approved media (USB, secure file transfer)
- On the air-gapped host, verify internal checksums with `--verify` (see below) — this step is fully offline

### Step 2: Verify bundle contents (after extraction)

```bash
tar xzf filterrex-connector-offline-<version>-linux-amd64.tar.gz
cd filterrex-connector-offline-<version>-linux-amd64/
sha256sum -c SHA256SUMS
```

Or use the installer's built-in verification:

```bash
sudo bash install-offline.sh --verify-only
```

## Install

### Quick Start (restricted network)

```bash
tar xzf filterrex-connector-offline-<version>-linux-amd64.tar.gz
cd filterrex-connector-offline-<version>-linux-amd64/
sudo bash install-offline.sh --verify --enroll-token 'frbt_your_token'
```

### Fully Disconnected

```bash
tar xzf filterrex-connector-offline-<version>-linux-amd64.tar.gz
cd filterrex-connector-offline-<version>-linux-amd64/

# Option A: Use a pre-provisioned token via CLI
sudo bash install-offline.sh --verify --token 'frc_your_token'

# Option B: Pre-seed config, then install without a token argument
sudo mkdir -p /etc/filterrex
sudo cp connector.env.template /etc/filterrex/connector.env
# Edit /etc/filterrex/connector.env — set CONNECTOR_TOKEN=frc_...
sudo bash install-offline.sh --verify
```

### Options

| Flag | Description |
|------|-------------|
| `--enroll-token TOKEN` | Bootstrap enrollment token (restricted network) |
| `--token TOKEN` | Pre-provisioned persistent connector token (fully disconnected) |
| `--label NAME` | Human-readable host label |
| `--config-dir DIR` | Config directory (default: `/etc/filterrex`) |
| `--verify` | Verify SHA256SUMS before installing |
| `--verify-only` | Verify checksums and exit (no install) |
| `--force-reset-state` | Clear existing enrollment state before install |
| `--enable-remote-actions` | Enable both live query and remote restart |
| `--enable-live-query` | Enable live query only |
| `--enable-remote-restart` | Enable remote restart only |

## Manual Installation

For customers who prefer not to run scripts:

```bash
# 1. Verify checksums
sha256sum -c SHA256SUMS

# 2. Install binary
sudo cp connector-agent /usr/bin/filterrex-connector
sudo chmod +x /usr/bin/filterrex-connector

# 3. Create service user
sudo useradd -r -s /bin/false filterrex

# 4. Create config
sudo mkdir -p /etc/filterrex/secrets
sudo chmod 700 /etc/filterrex /etc/filterrex/secrets
sudo cp connector.env.template /etc/filterrex/connector.env
# Edit connector.env — set token and other values
sudo chmod 600 /etc/filterrex/connector.env
sudo chown -R filterrex:filterrex /etc/filterrex

# 5. Install systemd unit
sudo cp filterrex-connector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now filterrex-connector
```

## State and Writable Paths

The agent writes state to the config directory (`/etc/filterrex` by default):

| Path | Purpose |
|------|---------|
| `/etc/filterrex/connector.env` | Environment configuration |
| `/etc/filterrex/host.json.enc` | Encrypted host identity (created after enrollment) |
| `/etc/filterrex/host.key` | Encryption key material |
| `/etc/filterrex/secrets/*.enc` | Per-target encrypted credentials |

The systemd unit uses `ProtectSystem=strict` with `ReadWritePaths=/etc/filterrex`, so the agent can only write to the config directory. All logs go to the systemd journal (`journalctl -u filterrex-connector`).

## Useful Commands

```bash
sudo systemctl status filterrex-connector      # Service status
sudo journalctl -u filterrex-connector -f      # Follow logs
sudo systemctl restart filterrex-connector     # Restart
sudo systemctl stop filterrex-connector        # Stop
```
