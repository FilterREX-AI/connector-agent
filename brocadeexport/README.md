# brocadeexport — local "Export Brocade Evidence Bundle" operation (Phase 3B-3)

The agent's first product-facing, **local-only** operation. It composes the two
already-proven pieces into a deliberate operator action:

```text
brocadecli      → read-only SSH capture of raw Brocade CLI output
evidencebundle  → Evidence Bundle v1.0 ZIP writer (collection_method: "agent")
```

## Flow

```text
authorized local request (CLI on the agent host)
  → capability gate check (brocade_bundle_export, default OFF)
  → load local Brocade targets (local JSON config only)
  → brocadecli.Collect (read-only SSH, host-key verified, key-based auth)
  → evidencebundle.BuildEvidenceBundle (collection_method: "agent")
  → write immutable, timestamped ZIP to the local artifact dir (0600)
  → append a local audit record (0600 JSONL) + structured log event
  → print artifact path + metadata JSON
```

## Run it

```sh
connector-agent export-brocade-bundle --config /etc/filterrex/brocade-export.json
# optional: --out /var/lib/filterrex/artifacts
```

On success it prints:

```json
{
  "ok": true,
  "artifact_type": "evidence_bundle",
  "vendor": "brocade-fos",
  "collection_method": "agent",
  "path": "/var/lib/filterrex/artifacts/filterrex-agent-evidence-bundle-20260713T143022Z.zip",
  "switches": 2,
  "parsed_files": 12,
  "supporting_files": 8,
  "warnings": 1,
  "sha256": "…",
  "started_at": "…",
  "finished_at": "…"
}
```

On failure it prints `{"ok": false, "error": "..."}` and exits non-zero.

## Config (JSON — no YAML dependency added)

See `example-config.json`. The capability gate is off by default; nothing runs
unless `brocade_bundle_export` is `true`.

## Safety model / boundaries

- **Capability gate, default OFF.** `RunExport` refuses unless the operator
  enables it locally.
- **Local-only.** No network surface of its own — not reachable over the cloud
  relay or the local API. The CLI is a deliberate on-host invocation.
- **No upload.** The operator uploads the ZIP manually later (Phase 2B); this
  operation never touches `service_request_evidence`.
- **Restrictive filesystem.** Artifact dir `0700`, ZIP `0600`, audit log `0600`.
  World-writable and `/tmp` artifact dirs are rejected by default.
- **Immutable artifacts.** Timestamped filenames; existing files are never
  silently overwritten.
- **Read-only, key-based SSH with mandatory host-key verification** (inherited
  from `brocadecli`). No passwords, no arbitrary commands.
- **No secrets in the audit trail.** Only switch_name/host/fabric_role identity,
  command/target counts, output path, sha256, timings, and a non-secret config
  path — never key material or key paths.

## Future network boundary

In this local CLI phase the full local artifact path is returned. When this
operation later becomes a local-API or relay-mediated capability, return an
artifact ID/handle instead — do not expose host filesystem paths to
cloud-visible contexts.

## Not in this phase (3B-3)

No auto-upload, relay call, `/v1/execute` route, cloud trigger, customer
one-click, Cisco capture, or REST-to-CLI rendering. Customer/operator upload →
admin validate → wizard handoff is Phase 2B.

## Test

```sh
cd connector-agent && go test ./brocadeexport/
```

Tests use a fake `brocadecli.CommandRunner` (no real switch): happy path,
capability gate off, partial-failure warnings, config validation, and an
audit-record no-secrets assertion.
