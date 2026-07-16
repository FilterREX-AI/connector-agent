# FilterREX Connector Host

> **This repository is the public release surface for the FilterREX Connector Host.**
> It is automatically synced from the private application source repository.
> The full FilterREX platform lives in a separate, private repo.

A lightweight, outbound-only agent that performs **read-only Brocade SAN evidence collection** for the FilterREX platform. It runs on your LAN, connects outbound only, and needs no inbound firewall ports.

## Quick Start

### 1. Enroll a Host

Go to [Local Systems](https://san.filterrex.com/account/local-systems) in the FilterREX dashboard to register a host and receive an enrollment token.

### 2. Install & Run (Docker — Recommended)

```bash
docker run -d --name filterrex-connector \
  --pull always \
  --restart unless-stopped \
  -v /etc/filterrex:/etc/filterrex \
  -e FILTERREX_ENROLLMENT_TOKEN='frc_your_token_here' \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.8
```

### 3. Assign Brocade Switches

After the host enrolls, go to **Connector Management** in the FilterREX dashboard to assign the Brocade FC switches to collect from, with their endpoints and read-only credentials. Targets are managed remotely — no reinstall needed.

## Alternative Install Methods

### Docker Compose

```bash
FILTERREX_ENROLLMENT_TOKEN=frc_... docker compose up -d
```

See `docker-compose.yml` for the full template.

### Linux Service (install.sh)

```bash
curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
  | bash -s -- --enroll-token 'frc_...'
```

### Build from Source

```bash
git clone https://github.com/filterrex-ai/connector-agent.git
cd connector-agent
go build -o connector-agent .

export FILTERREX_ENROLLMENT_TOKEN='frc_...'
./connector-agent
```

Requires [Go 1.22+](https://go.dev/dl/).

## What It Collects (Read-Only)

The host collects read-only Brocade FC fabric evidence — chassis and switch
info, port and SFP (media) diagnostics, and zoning configuration — via the
FOS REST API, and can package it into a FilterREX Evidence Bundle. All
collection is strictly read-only; the agent never issues configuration changes.

**Supported targets:** Brocade FC switches (FOS 8.2+).

## Updating the Agent

To update to the latest image while preserving your enrollment and target configuration:

```bash
docker stop filterrex-connector && docker rm filterrex-connector
docker run -d --name filterrex-connector \
  --pull always \
  --restart unless-stopped \
  -v filterrex-config:/etc/filterrex \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.8
```

> **Note:** The enrollment token is **not** needed for updates. Your host identity and target credentials are persisted in the `filterrex-config` volume and reused automatically.

## Troubleshooting

### Stale Image / Wrong Binary

If you see these messages in logs:

```
[agent] FilterREX Local Connector v0.1.0 starting
[config] CONNECTOR_TOKEN is required
```

You are running an **outdated image**. The current host binary identifies as `FilterREX Connector Host v...` and uses `FILTERREX_ENROLLMENT_TOKEN`.

**Fix:**

```bash
# Stop and remove the old container
docker stop filterrex-connector && docker rm filterrex-connector

# Pull the latest image and re-run
docker run -d --name filterrex-connector \
  --pull always \
  --restart unless-stopped \
  -v /etc/filterrex:/etc/filterrex \
  -e FILTERREX_ENROLLMENT_TOKEN='frc_your_token_here' \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.8
```

### Verify Correct Binary

After starting, check logs:

```bash
docker logs filterrex-connector
```

**Expected:** `[host.startup] FilterREX Connector Host v0.1.0-preview.8 starting`
**Problem:** `[agent] FilterREX Local Connector v0.1.0` → stale image, see fix above.

### GHCR reports `unauthorized`

The FilterREX connector image is publicly available and does **not** require `docker login`.

Confirm you are using the exact image and version:

```bash
docker pull \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.8
```

If Docker previously authenticated to GHCR with another account, clear that session and retry:

```bash
docker logout ghcr.io
docker pull \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.8
```

An `unauthorized` response normally means the package is not public, or the requested image path/version is incorrect.

## Architecture

- **Outbound-only** — no inbound ports needed
- **Read-only** — collects Brocade FC fabric evidence; never makes changes
- **Enrollment-first** — host enrolls once, switches are assigned remotely
- **Encrypted credentials** — target credentials are delivered encrypted, never in install commands
- **Auto-update** — signed binary updates with automatic rollback
- **Non-root** — runs as unprivileged user

## Reusing Existing State / Re-enrollment

When reinstalling or redeploying a Connector Host with an existing named volume or config directory, the host **reuses its prior enrollment** instead of re-enrolling. If the backend registration was deleted or the connector token was revoked, desired-state sync will fail with an auth error.

### Force a Clean Re-enrollment

**Docker (named volume):**

```bash
docker stop filterrex-connector && docker rm filterrex-connector
docker volume rm filterrex-config
docker run -d --name filterrex-connector \
  --pull always --restart unless-stopped \
  -v filterrex-config:/etc/filterrex \
  -e FILTERREX_ENROLLMENT_TOKEN='frc_new_token_here' \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.8
```

**Bind mount / systemd:**

```bash
sudo systemctl stop filterrex-connector
sudo rm -f /etc/filterrex/host.json.enc /etc/filterrex/host.key
sudo rm -f /etc/filterrex/secrets/*.enc
# Update FILTERREX_ENROLLMENT_TOKEN in /etc/filterrex/connector.env
sudo systemctl start filterrex-connector
```

**Installer with reset flag:**

```bash
curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
  | bash -s -- --enroll-token 'frc_...' --force-reset-state
```

**Runtime reset flag:**

```bash
./connector-agent --force-reset-state
```

The `--force-reset-state` flag removes `host.json.enc`, `host.key`, and all files in `secrets/`, allowing the host to re-enroll cleanly.

## Releases & Docker Images

- **GitHub Releases**: Pre-built binaries for linux/amd64 and linux/arm64
- **GHCR**: `ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.8`

Docker `:latest` is updated on every sync to main. Tagged releases (e.g. `v0.2.0`) produce versioned images and binary assets.

## License

Source code is licensed under the **Apache License 2.0** (see `LICENSE`).

The FilterREX name, logos, and brand assets are **not** covered by that
license (see `NOTICE` and `TRADEMARKS.md`). Documentation and media in this
repository are All Rights Reserved unless a file states otherwise.
