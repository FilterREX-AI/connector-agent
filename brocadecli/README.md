# brocadecli — FilterREX agent read-only Brocade SSH capture (Phase 3B-2)

Internal, test-driven module that answers one question: **how does the agent
obtain raw Brocade CLI text safely?** It SSHes to Brocade switches, runs only the
commands in the embedded read-only profile, captures raw stdout/stderr/exit/timing,
and feeds `[]evidencebundle.CommandCapture` into the existing
`evidencebundle.BuildEvidenceBundle` writer — producing an Evidence Bundle v1.0
ZIP with `collection_method: "agent"`.

## Pipeline

```text
embedded Brocade command profile (evidencebundle.ProfileCommands)
  → safe command resolver (resolveProfileCommands + assertSafeExec)
  → CommandRunner (sshRunner in prod, fakeRunner in tests)
  → []evidencebundle.CommandCapture
  → evidencebundle.BuildEvidenceBundle
  → filterrex-agent-evidence-bundle.zip
```

## Safety model

- **No arbitrary commands.** No public API accepts a free-form command string;
  the command set is derived only from the embedded profile. `assertSafeExec`
  rejects shell-control characters (`; | & \` $ > <` newline/CR) as
  defense-in-depth against profile tampering.
- **Non-interactive key-based SSH only.** No password or keyboard-interactive
  auth path exists. Host-key verification is **required** — `NewSSHRunner` fails
  fast without a readable `KnownHostsPath`.
- **No credential leakage.** Private-key bytes are zeroed after building the
  signer and never enter logs, captures, the manifest, or the ZIP.
- **FID is metadata only.** Recorded in the manifest; no virtual-fabric context
  switch (`setcontext`/`fosexec`) is run.

## Failure behaviour

`ContinueOnError` defaults to true. Failed/timed-out commands are handed to the
writer too, which excludes them from `manifest.files[]` while recording them in
`collection-summary.json` / `collection-log.txt` — matching the Python
collector. Failures never poison the bundle's evidence.

## Not in this phase (3B-2)

No relay call, local-API endpoint, `/v1/execute` wiring, cloud-triggered export,
Cisco capture, or REST-to-CLI rendering. Export/operation wiring is Phase 3B-3;
customer upload → admin validate → wizard handoff is Phase 2B.

## Test

```sh
cd connector-agent && go test ./brocadecli/
```

Tests use a fake `CommandRunner` (no real switch). `equivalence_test.go` proves
the capture path yields the same evidence manifest as the directory producer that
generates the committed TS conformance fixture.
