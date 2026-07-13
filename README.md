# ForgeAI Connector Host

> **This repository is the public release surface for the ForgeAI Connector Host.**
> It is automatically synced from the private application source repository.
> The full ForgeAI platform lives in a separate, private repo.

A lightweight, outbound-only agent that bridges your local infrastructure with the ForgeAI platform. One host manages **multiple targets** (Proxmox, TrueNAS, Nutanix, and more) simultaneously. No inbound firewall ports needed.

## Quick Start

### 1. Enroll a Host

Go to [Local Systems](https://san.filterrex.com/account/local-systems) in the ForgeAI dashboard to register a host and receive an enrollment token.

### 2. Install & Run (Docker — Recommended)

```bash
docker run -d --name forgeai-host \
  --pull always \
  --restart unless-stopped \
  -v /etc/forgeai:/etc/forgeai \
  -e FORGEAI_ENROLLMENT_TOKEN='fgbt_your_token_here' \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:latest
```

### 3. Assign Targets

After the host enrolls, go to **Connector Management** in the ForgeAI dashboard to assign infrastructure targets (Proxmox, TrueNAS, Nutanix, etc.) with their endpoints and credentials. Targets are managed remotely — no reinstall needed.

## Alternative Install Methods

### Docker Compose

```bash
FORGEAI_ENROLLMENT_TOKEN=fgbt_... docker compose up -d
```

See `docker-compose.yml` for the full template.

### Linux Service (install.sh)

```bash
curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
  | bash -s -- --enroll-token 'fgbt_...'
```

### Build from Source

```bash
git clone https://github.com/filterrex-ai/connector-agent.git
cd connector-agent
go build -o connector-agent .

export FORGEAI_ENROLLMENT_TOKEN='fgbt_...'
./connector-agent
```

Requires [Go 1.22+](https://go.dev/dl/).

## What It Collects (Read-Only)

The host collects infrastructure telemetry for the targets you assign. All collection is read-only.

**Supported targets:** Proxmox VE, TrueNAS, Nutanix, Prometheus, Grafana, Ollama, Pure Storage, NetApp ONTAP, Dell PowerStore, Dell PowerMax, Dell PowerFlex, and generic HTTP endpoints.

## Updating the Agent

To update to the latest image while preserving your enrollment and target configuration:

```bash
docker stop forgeai-host && docker rm forgeai-host
docker run -d --name forgeai-host \
  --pull always \
  --restart unless-stopped \
  -v forgeai-config:/etc/forgeai \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:latest
```

> **Note:** The enrollment token is **not** needed for updates. Your host identity and target credentials are persisted in the `forgeai-config` volume and reused automatically.

## Troubleshooting

### Stale Image / Wrong Binary

If you see these messages in logs:

```
[agent] ForgeAI Local Connector v0.1.0 starting
[config] CONNECTOR_TOKEN is required
```

You are running an **outdated image**. The current host binary identifies as `ForgeAI Connector Host v...` and uses `FORGEAI_ENROLLMENT_TOKEN`.

**Fix:**

```bash
# Stop and remove the old container
docker stop forgeai-host && docker rm forgeai-host

# Pull the latest image and re-run
docker run -d --name forgeai-host \
  --pull always \
  --restart unless-stopped \
  -v /etc/forgeai:/etc/forgeai \
  -e FORGEAI_ENROLLMENT_TOKEN='fgbt_your_token_here' \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:latest
```

### Verify Correct Binary

After starting, check logs:

```bash
docker logs forgeai-host
```

**Expected:** `[host] ForgeAI Connector Host v0.7.x starting`
**Problem:** `[agent] ForgeAI Local Connector v0.1.0` → stale image, see fix above.

## Architecture

- **Outbound-only** — no inbound ports needed
- **Multi-target** — one host manages multiple infrastructure targets as independent workers
- **Enrollment-first** — host enrolls once, targets are assigned remotely
- **Encrypted credentials** — target credentials are delivered encrypted, never in install commands
- **Auto-update** — signed binary updates with automatic rollback
- **Non-root** — runs as unprivileged user

## Reusing Existing State / Re-enrollment

When reinstalling or redeploying a Connector Host with an existing named volume or config directory, the host **reuses its prior enrollment** instead of re-enrolling. If the backend registration was deleted or the connector token was revoked, desired-state sync will fail with an auth error.

### Force a Clean Re-enrollment

**Docker (named volume):**

```bash
docker stop forgeai-host && docker rm forgeai-host
docker volume rm forgeai-config
docker run -d --name forgeai-host \
  --pull always --restart unless-stopped \
  -v forgeai-config:/etc/forgeai \
  -e FORGEAI_ENROLLMENT_TOKEN='fgbt_new_token_here' \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:latest
```

**Bind mount / systemd:**

```bash
sudo systemctl stop forgeai-host
sudo rm -f /etc/forgeai/host.json.enc /etc/forgeai/host.key
sudo rm -f /etc/forgeai/secrets/*.enc
# Update FORGEAI_ENROLLMENT_TOKEN in /etc/forgeai/connector.env
sudo systemctl start forgeai-host
```

**Installer with reset flag:**

```bash
curl -fsSL https://raw.githubusercontent.com/filterrex-ai/connector-agent/main/install.sh \
  | bash -s -- --enroll-token 'fgbt_...' --force-reset-state
```

**Runtime reset flag:**

```bash
./connector-agent --force-reset-state
```

The `--force-reset-state` flag removes `host.json.enc`, `host.key`, and all files in `secrets/`, allowing the host to re-enroll cleanly.

## Releases & Docker Images

- **GitHub Releases**: Pre-built binaries for linux/amd64 and linux/arm64
- **GHCR**: `ghcr.io/filterrex-ai/connector-agent/connector-agent:latest`

Docker `:latest` is updated on every sync to main. Tagged releases (e.g. `v0.2.0`) produce versioned images and binary assets.

## License

MIT
