# evidencebundle — FilterREX Evidence Bundle v1.0 writer (agent producer)

Phase 3B-1. Shared Go package that packages **already-captured** read-only
Brocade command output into an Evidence Bundle v1.0 ZIP with
`collection_method: "agent"`.

## Contract

The output must be **indistinguishable to the FilterREX importer** from a bundle
produced by the Python collector (`collectors/brocade/filterrex_collect_brocade.py`),
except for `collection_method`.

- Manifest schema is v1.0 exactly (see `src/lib/evidenceBundle/evidenceBundleTypes.ts`):
  no `support_level`, no `generated_at`. Support level is derived by the importer
  from the command catalog; provenance lives in `collection-summary.json`.
- `brocade_command_profile.json` here is a **byte-identical copy** of
  `collectors/brocade/brocade_command_profile.json` and is `go:embed`ed. The
  `TestProfileParity` test enforces this in single-repo checkouts. Keep the copy
  in sync — the JSON profile is the shared Python ↔ Go ↔ TS contract.

## What this package does NOT do

No SSH, no REST, no credential/host-key handling, no upload, no relay/local-API
wiring. It is pure packaging. SSH capture is Phase 3B-2; export operation wiring
is Phase 3B-3.

## Regenerate the committed TS fixture

The agent fixture consumed by the TS conformance/equivalence tests is produced by
this writer (never hand-edited). From `connector-agent/`:

```sh
go run ./cmd/mk-agent-fixture \
  -input evidencebundle/testdata/input \
  -inventory evidencebundle/testdata/inventory.json \
  -out ../src/lib/evidenceBundle/__tests__/fixtures/brocade-valid-agent-output.zip
```

Or via the test with `UPDATE_AGENT_FIXTURE=1 go test ./evidencebundle/`.

## Test

```sh
go test ./evidencebundle/
```
