# brocaderest

Connector-side HTTPS REST client for Brocade FC switches — the Workbench
live-query path in the [two-path authentication model](../../docs/brocade-target-two-path-auth.md).

Preview.3 status: **scaffold**. This package publishes the public types and
fixed operation resolver so the rest of the connector (dispatch, audit,
heartbeat readiness) can compile against it. The `http.Client` implementation,
per-target `transport_mode` enforcement, on-demand password read, and
sanitized error mapping land in a follow-up commit within the same preview.3
milestone.

## Contract

The browser sends only:

```json
{ "target_profile_id": "…", "operation_id": "…", "parameters": {} }
```

The resolver rejects everything else. There is no path in this package that
accepts a raw URL, raw REST path, Authorization header, arbitrary CLI command,
transport override, or credential selector from a caller.
