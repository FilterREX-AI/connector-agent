// Tests for the Option-B target_id resolver and the readiness-snapshot
// loader that consumes it. These lock in the acceptance cases required for
// preview.13:
//
//	1. profile key = UUID, target_id absent               → published under UUID
//	2. profile key = "faba", target_id = UUID             → published under UUID
//	3. profile key = "faba", target_id absent             → omitted; warned
//	4. two records share one target_id                    → neither published; warned
//	5. invalid target_id                                  → record rejected
//	6. uppercase/lowercase UUIDs canonicalize to one key  → dedup deterministic
//	7. one invalid record does not block a valid record   → partial publish OK
package targetconfigure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	uuidA       = "426cd1e7-76f7-40c7-8fdf-f5f09a471989"
	uuidAUpper  = "426CD1E7-76F7-40C7-8FDF-F5F09A471989"
	uuidB       = "91a3c882-1111-4111-8111-111111111111"
	invalidUUID = "not-a-uuid"
)

func writeTargetsJSON(t *testing.T, dir string, doc *targetsDoc) {
	t.Helper()
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, targetsFile), b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sshOnlyRecord(targetID string) *targetRecord {
	return &targetRecord{
		TargetID: targetID,
		Address:  "192.168.40.211",
		SSHPort:  22,
		SSH: &sshEntry{
			Username:             "filterrex_ro",
			KeyPath:              "/config/keys/x",
			KnownHostsPath:       "/config/known_hosts",
			KeyAlgorithm:         "rsa",
			KeyBits:              3072,
			KeyOrigin:            "generated",
			KeyFingerprintSHA256: "SHA256:aaa",
		},
		Readiness: readiness{
			SSHReady:      true,
			SSHProbeStage: "command_succeeded",
		},
	}
}

// EffectiveTargetID contract.
func TestEffectiveTargetID_Rules(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		rec     *targetRecord
		want    string
		wantErr error
	}{
		{"target_id set canonical", "faba", &targetRecord{TargetID: uuidA}, uuidA, nil},
		{"target_id set uppercase canonicalizes", "faba", &targetRecord{TargetID: uuidAUpper}, uuidA, nil},
		{"target_id invalid → fail closed", "faba", &targetRecord{TargetID: invalidUUID}, "", ErrInvalidTargetID},
		{"target_id empty, profile UUID → fallback", uuidA, &targetRecord{}, uuidA, nil},
		{"target_id empty, profile uppercase UUID → canonical", uuidAUpper, &targetRecord{}, uuidA, nil},
		{"target_id empty, profile non-UUID → missing", "faba", &targetRecord{}, "", ErrTargetIDMissing},
		{"nil record → missing", uuidA, nil, "", ErrTargetIDMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EffectiveTargetID(c.profile, c.rec)
			if err != c.wantErr {
				t.Fatalf("err: got %v want %v", err, c.wantErr)
			}
			if got != c.want {
				t.Fatalf("id: got %q want %q", got, c.want)
			}
		})
	}
}

// Rule 1: profile key = UUID, no target_id → published under that UUID.
func TestLoadSSHReadinessSnapshot_UUIDProfileNoTargetID(t *testing.T) {
	dir := t.TempDir()
	rec := sshOnlyRecord("") // no target_id set; fallback rule applies
	writeTargetsJSON(t, dir, &targetsDoc{Version: 1, Targets: map[string]*targetRecord{
		uuidA: rec,
	}})
	snap, warns, err := LoadSSHReadinessSnapshot(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %+v", warns)
	}
	if _, ok := snap[uuidA]; !ok {
		t.Fatalf("expected publish under %s; got %+v", uuidA, snap)
	}
}

// Rule 2: profile key = non-UUID, target_id = UUID → published under UUID
// and NOT under the profile label.
func TestLoadSSHReadinessSnapshot_LabelProfileWithTargetID(t *testing.T) {
	dir := t.TempDir()
	writeTargetsJSON(t, dir, &targetsDoc{Version: 1, Targets: map[string]*targetRecord{
		"faba": sshOnlyRecord(uuidA),
	}})
	snap, warns, err := LoadSSHReadinessSnapshot(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %+v", warns)
	}
	if _, ok := snap["faba"]; ok {
		t.Fatalf("must NOT publish under profile label; got %+v", snap)
	}
	if _, ok := snap[uuidA]; !ok {
		t.Fatalf("expected publish under %s; got %+v", uuidA, snap)
	}
}

// Rule 3: profile key = non-UUID, no target_id → omitted; target_id_missing warned.
func TestLoadSSHReadinessSnapshot_LabelProfileNoTargetIDOmitted(t *testing.T) {
	dir := t.TempDir()
	writeTargetsJSON(t, dir, &targetsDoc{Version: 1, Targets: map[string]*targetRecord{
		"faba": sshOnlyRecord(""),
	}})
	snap, warns, err := LoadSSHReadinessSnapshot(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(snap) != 0 {
		t.Fatalf("must not publish; got %+v", snap)
	}
	if len(warns) != 1 || warns[0].Reason != "target_id_missing" || warns[0].ProfileName != "faba" {
		t.Fatalf("expected target_id_missing warning for faba; got %+v", warns)
	}
}

// Rule 4: two records share one target_id → neither published; duplicate warning.
func TestLoadSSHReadinessSnapshot_DuplicateTargetIDDropsAll(t *testing.T) {
	dir := t.TempDir()
	writeTargetsJSON(t, dir, &targetsDoc{Version: 1, Targets: map[string]*targetRecord{
		"faba":  sshOnlyRecord(uuidA),
		"fabb":  sshOnlyRecord(uuidAUpper), // same UUID after canonicalization
	}})
	snap, warns, err := LoadSSHReadinessSnapshot(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := snap[uuidA]; ok {
		t.Fatalf("duplicate mapping must publish nothing; got %+v", snap)
	}
	found := false
	for _, w := range warns {
		if w.Reason == "duplicate_target_id" && w.TargetID == uuidA && w.Count == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected duplicate_target_id warning; got %+v", warns)
	}
}

// Rule 5: invalid target_id → record rejected, others still publish.
func TestLoadSSHReadinessSnapshot_InvalidTargetIDDoesNotBlockValid(t *testing.T) {
	dir := t.TempDir()
	writeTargetsJSON(t, dir, &targetsDoc{Version: 1, Targets: map[string]*targetRecord{
		"bad":  sshOnlyRecord(invalidUUID),
		"good": sshOnlyRecord(uuidB),
	}})
	snap, warns, err := LoadSSHReadinessSnapshot(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := snap[uuidB]; !ok {
		t.Fatalf("valid record must publish; got %+v", snap)
	}
	if len(snap) != 1 {
		t.Fatalf("only the valid record must publish; got %+v", snap)
	}
	found := false
	for _, w := range warns {
		if w.Reason == "invalid_target_id" && w.ProfileName == "bad" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected invalid_target_id warning; got %+v", warns)
	}
}

// CLI resolver: --profile faba without --target-id must be rejected.
func TestResolveTargetIDArgs_LabelWithoutTargetID(t *testing.T) {
	_, err := resolveTargetIDArgs("faba", "")
	if err == nil || !strings.Contains(err.Error(), "target_id_required") {
		t.Fatalf("expected target_id_required error; got %v", err)
	}
}

// CLI resolver: uppercase UUID canonicalizes.
func TestResolveTargetIDArgs_CanonicalizesCase(t *testing.T) {
	got, err := resolveTargetIDArgs("faba", uuidAUpper)
	if err != nil {
		t.Fatal(err)
	}
	if got != uuidA {
		t.Fatalf("got %q want %q", got, uuidA)
	}
}

// End-to-end via Run: non-interactive `target configure --profile faba`
// without --target-id exits 2.
func TestRun_LabelProfileWithoutTargetIDIsRefused(t *testing.T) {
	dir := t.TempDir()
	var code int
	out := captureStderr(t, func() {
		code = Run([]string{"--profile", "faba", "--config-dir", dir, "--state-dir", dir})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(out, "target_id_required") {
		t.Fatalf("stderr missing target_id_required: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "targets.json")); err == nil {
		t.Fatal("wizard must not create targets.json when target_id is missing")
	}
}

// End-to-end via Run: --target-id must be a valid UUID.
func TestRun_InvalidTargetIDIsRefused(t *testing.T) {
	dir := t.TempDir()
	var code int
	out := captureStderr(t, func() {
		code = Run([]string{"--profile", "faba", "--target-id", "nope", "--config-dir", dir, "--state-dir", dir})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(out, "must be a valid target-profile UUID") {
		t.Fatalf("stderr missing UUID validation message: %q", out)
	}
}

// End-to-end via RunProbe: --target-id mismatch is refused without probing.
func TestRunProbe_TargetIDMismatchIsRefused(t *testing.T) {
	dir := t.TempDir()
	rec := sshOnlyRecord(uuidA)
	writeTargetsJSON(t, dir, &targetsDoc{Version: 1, Targets: map[string]*targetRecord{
		"faba": rec,
	}})
	var code int
	out := captureStderr(t, func() {
		code = RunProbe([]string{"--profile", "faba", "--target-id", uuidB, "--config-dir", dir})
	})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(out, "target_id_mismatch") {
		t.Fatalf("stderr missing target_id_mismatch: %q", out)
	}
}

// End-to-end via RunProbe: --profile faba without persisted target_id → missing.
func TestRunProbe_MissingTargetIDIsRefused(t *testing.T) {
	dir := t.TempDir()
	rec := sshOnlyRecord("") // no target_id, non-UUID profile
	writeTargetsJSON(t, dir, &targetsDoc{Version: 1, Targets: map[string]*targetRecord{
		"faba": rec,
	}})
	var code int
	out := captureStderr(t, func() {
		code = RunProbe([]string{"--profile", "faba", "--config-dir", dir})
	})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(out, "target_id_missing") {
		t.Fatalf("stderr missing target_id_missing: %q", out)
	}
}
