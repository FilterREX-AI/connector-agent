# Verifying FilterREX Connector Host .deb Packages

## SHA-256 Checksum

Each release includes a `filterrex-connector-<version>-packages.sha256` file.

```bash
sha256sum -c filterrex-connector-0.8.0-packages.sha256
```

## Cosign Signature Verification

Packages are signed using [cosign](https://github.com/sigstore/cosign) keyless
signing via GitHub Actions OIDC. This proves the package was built by the
official CI pipeline.

```bash
# Install cosign: https://docs.sigstore.dev/cosign/installation/
# Pin to the exact workflow + tag for tightest trust:
cosign verify-blob \
  --bundle filterrex-connector_0.8.0_amd64.deb.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/filterrex-ai/connector-agent/.github/workflows/connector-publish.public.yml@refs/tags/v0.8.0" \
  filterrex-connector_0.8.0_amd64.deb
```

> **Tip:** Replace `v0.8.0` with the actual release tag. If unsure of the exact tag, use `--certificate-identity-regexp` as a broader fallback:
> ```
> --certificate-identity-regexp 'github.com/filterrex-ai/connector-agent/.github/workflows/connector-publish'
> ```

## Package Contents Inspection

Before installing, you can inspect the package contents:

```bash
# .deb
dpkg-deb --contents filterrex-connector_0.8.0_amd64.deb

# .rpm
rpm -qlp filterrex-connector-0.8.0-1.x86_64.rpm
```

## Binary Version

After installation, verify the installed binary version:

```bash
filterrex-connector --version
```
