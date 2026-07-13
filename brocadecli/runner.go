package brocadecli

import (
	"context"
	"time"
)

// CommandResult is the raw outcome of running one already-resolved read-only
// command against a target. It never carries credentials or key material.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	TimedOut bool
	Started  time.Time
	Elapsed  time.Duration
	// Err carries a transport/connection error (dial, auth, host-key). It is
	// informational for the collection log; its message must not contain
	// credentials or private-key material.
	Err error
}

// CommandRunner abstracts command execution so the collector can be tested
// without a real Brocade switch. It receives an already-resolved, profile-safe
// exec string — it is never given a caller-supplied command.
//
// Implementations MUST be non-interactive and read-only. The production
// implementation (sshRunner) uses key-based SSH with host-key verification.
type CommandRunner interface {
	Run(ctx context.Context, target BrocadeTarget, exec string) CommandResult
}
