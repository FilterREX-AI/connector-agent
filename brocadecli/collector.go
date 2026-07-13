package brocadecli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/forgeai/connector-agent/evidencebundle"
)

// CollectOptions tunes capture behaviour. Zero values give safe defaults.
type CollectOptions struct {
	// ContinueOnError, when nil, defaults to true: a failed command or a failed
	// switch connection does not abort the run (evidence gathering is
	// best-effort). Set to a pointer to false to make any failure fatal.
	ContinueOnError *bool
	// CollectedAt stamps the captures and the bundle. Zero → time.Now().UTC().
	CollectedAt time.Time
}

// BoolPtr is a small helper for setting *bool option fields.
func BoolPtr(v bool) *bool { return &v }

// LogEntry is one structured, credential-free record of a command attempt.
type LogEntry struct {
	Host          string
	SwitchName    string
	CommandID     string
	Started       time.Time
	Finished      time.Time
	ExitCode      int
	TimedOut      bool
	Included      bool   // true when the capture became a manifest file
	StderrSummary string // truncated, credential-free
	Note          string // e.g. connection error summary
}

// CollectionLog is the ordered set of per-command records for a run.
type CollectionLog struct {
	Entries []LogEntry
}

// String renders the log as plain text (no credentials).
func (l CollectionLog) String() string {
	var b strings.Builder
	for _, e := range l.Entries {
		status := fmt.Sprintf("exit=%d", e.ExitCode)
		if e.TimedOut {
			status = "timeout"
		}
		incl := "included"
		if !e.Included {
			incl = "excluded"
		}
		fmt.Fprintf(&b, "[%s] %s (%s) %s -> %s", status, e.SwitchName, e.Host, e.CommandID, incl)
		if e.StderrSummary != "" {
			fmt.Fprintf(&b, " stderr=%q", e.StderrSummary)
		}
		if e.Note != "" {
			fmt.Fprintf(&b, " note=%q", e.Note)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

const stderrSummaryMax = 200

func summarizeStderr(stderr []byte) string {
	s := strings.TrimSpace(string(stderr))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > stderrSummaryMax {
		s = s[:stderrSummaryMax] + "…"
	}
	return s
}

// Collect runs the embedded read-only Brocade command profile against every
// target using the supplied runner and returns one CommandCapture per attempted
// command plus a structured, credential-free collection log.
//
// The downstream evidencebundle.BuildEvidenceBundle writer decides evidence
// inclusion: only OK captures (exit 0, not timed out, non-empty stdout) become
// manifest files, while failed/timed-out captures are counted in
// collection-summary.json and recorded in collection-log.txt — so failures are
// visible but never poison the bundle's evidence.
func Collect(ctx context.Context, runner CommandRunner, targets []BrocadeTarget, opts CollectOptions) ([]evidencebundle.CommandCapture, CollectionLog, error) {
	if runner == nil {
		return nil, CollectionLog{}, fmt.Errorf("a CommandRunner is required")
	}
	if len(targets) == 0 {
		return nil, CollectionLog{}, fmt.Errorf("at least one target is required")
	}

	continueOnError := true
	if opts.ContinueOnError != nil {
		continueOnError = *opts.ContinueOnError
	}

	collectedAt := opts.CollectedAt
	if collectedAt.IsZero() {
		collectedAt = time.Now().UTC()
	}

	var captures []evidencebundle.CommandCapture
	log := CollectionLog{}

	for _, target := range targets {
		commands, err := resolveProfileCommands(target)
		if err != nil {
			// Profile-resolution failure is a hard error (possible tampering),
			// independent of ContinueOnError.
			return nil, log, err
		}

		for _, cmd := range commands {
			result := runner.Run(ctx, target, cmd.exec)

			ok := result.Err == nil && result.ExitCode == 0 && !result.TimedOut &&
				strings.TrimSpace(string(result.Stdout)) != ""

			entry := LogEntry{
				Host:          target.Host,
				SwitchName:    target.SwitchName,
				CommandID:     cmd.id,
				Started:       result.Started,
				Finished:      result.Started.Add(result.Elapsed),
				ExitCode:      result.ExitCode,
				TimedOut:      result.TimedOut,
				Included:      ok,
				StderrSummary: summarizeStderr(result.Stderr),
			}
			if result.Err != nil {
				entry.Note = result.Err.Error()
			}
			log.Entries = append(log.Entries, entry)

			if !ok && !continueOnError {
				return captures, log, fmt.Errorf(
					"command %q failed on switch %q and ContinueOnError is false", cmd.id, target.SwitchName)
			}

			// All attempted commands (ok and failed) are handed to the writer.
			// evidencebundle.BuildEvidenceBundle excludes non-OK captures from
			// manifest files while still counting them in collection-summary.json
			// and recording them in collection-log.txt — matching the Python
			// collector. Failures therefore never poison the bundle's evidence.
			captures = append(captures, evidencebundle.CommandCapture{
				SwitchName:  target.SwitchName,
				FabricRole:  target.FabricRole,
				Command:     cmd.id,
				Filename:    cmd.filename,
				Stdout:      result.Stdout,
				Stderr:      result.Stderr,
				ExitCode:    result.ExitCode,
				TimedOut:    result.TimedOut,
				CollectedAt: collectedAt,
			})
		}
	}

	return captures, log, nil
}

// CollectBundle is a convenience that runs Collect and packages the captures
// into an Evidence Bundle v1.0 ZIP (collection_method: "agent") using the shared
// evidencebundle writer. Per-switch metadata (FID, notes) is recorded in the
// manifest; FID is metadata only — no virtual-fabric context switch is run.
func CollectBundle(ctx context.Context, runner CommandRunner, targets []BrocadeTarget, opts CollectOptions) (*evidencebundle.BuildResult, CollectionLog, error) {
	captures, log, err := Collect(ctx, runner, targets, opts)
	if err != nil {
		return nil, log, err
	}

	collectedAt := opts.CollectedAt
	if collectedAt.IsZero() {
		collectedAt = time.Now().UTC()
	}

	meta := make([]evidencebundle.SwitchMeta, 0, len(targets))
	for _, t := range targets {
		meta = append(meta, evidencebundle.SwitchMeta{
			SwitchName: t.SwitchName,
			FID:        t.FID,
			Notes:      t.Notes,
		})
	}

	res, err := evidencebundle.BuildEvidenceBundle(captures, evidencebundle.BuildOptions{
		CollectionMethod: evidencebundle.CollectionMethodAgent,
		CollectedAt:      collectedAt,
		SwitchMeta:       meta,
		Collector:        "filterrex_agent_brocade_ssh",
	})
	if err != nil {
		return nil, log, err
	}
	return res, log, nil
}
