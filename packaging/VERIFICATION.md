# Verifying FilterREX Connector Host Releases

All release artifacts are signed using [Sigstore cosign](https://docs.sigstore.dev/) with keyless signing (GitHub OIDC identity). No public key management required.

## Verify Docker Image

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'github.com/filterrex-ai/connector-agent' \
  ghcr.io/filterrex-ai/connector-agent/connector-agent:0.1.0-preview.7
```

## Verify Binary Tarball

Download the `.tar.gz` and its `.bundle` file from the [GitHub Release](https://github.com/filterrex-ai/connector-agent/releases), then:

```bash
cosign verify-blob \
  --bundle connector-agent-linux-amd64.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'github.com/filterrex-ai/connector-agent' \
  connector-agent-linux-amd64.tar.gz
```

## Verify Checksums

```bash
sha256sum -c connector-agent-linux-amd64.tar.gz.sha256
```

## SBOM

The SPDX SBOM (`connector-agent-sbom.spdx.json`) is attached to each GitHub Release for supply-chain auditing.
