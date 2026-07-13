package brocadecli

import (
	"fmt"
	"strings"

	"github.com/filterrex-ai/connector-agent/evidencebundle"
)

// resolvedCommand is one profile command resolved into an executable form for a
// specific target. It is produced only from the embedded profile — never from
// caller input.
type resolvedCommand struct {
	id       string // canonical command id (manifest label)
	exec     string // concrete read-only command string to run over SSH
	filename string // canonical bundle filename
}

// shellMetaChars are rejected in any exec string as defense-in-depth, even
// though the profile is trusted. Their presence signals profile tampering.
const shellMetaChars = ";|&`$><\n\r"

// assertSafeExec rejects an exec string containing shell-control characters.
// The embedded profile is trusted, so a violation here is a hard error that
// aborts the whole run rather than a per-command skip.
func assertSafeExec(exec string) error {
	if strings.TrimSpace(exec) == "" {
		return fmt.Errorf("empty exec string in command profile")
	}
	if i := strings.IndexAny(exec, shellMetaChars); i >= 0 {
		return fmt.Errorf(
			"refusing exec %q: contains shell-control character %q (possible profile tampering)",
			exec, string(exec[i]))
	}
	return nil
}

// resolveProfileCommands expands the embedded read-only Brocade command profile
// into concrete, safe commands for a target. There is no code path that lets a
// caller add, remove, or alter this command set — it comes only from the
// embedded profile. Every resolved exec is validated by assertSafeExec.
func resolveProfileCommands(target BrocadeTarget) ([]resolvedCommand, error) {
	profile, err := evidencebundle.ProfileCommands()
	if err != nil {
		return nil, err
	}
	if len(profile) == 0 {
		return nil, fmt.Errorf("embedded command profile is empty")
	}

	portRange := strings.TrimSpace(target.PortRange)
	if portRange == "" {
		portRange = evidencebundle.DefaultPortRange()
	}

	out := make([]resolvedCommand, 0, len(profile))
	for _, pc := range profile {
		exec := strings.ReplaceAll(pc.Exec, "{port_range}", portRange)
		if err := assertSafeExec(exec); err != nil {
			return nil, err
		}
		out = append(out, resolvedCommand{
			id:       pc.ID,
			exec:     exec,
			filename: pc.Filename,
		})
	}
	return out, nil
}
