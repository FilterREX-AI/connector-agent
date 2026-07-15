package targetconfigure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr for the duration of fn and returns
// whatever was written. Run refuses secrets on the CLI, so we only capture
// the human-facing refusal messages.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		var out strings.Builder
		for {
			n, err := r.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- out.String()
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

func TestRun_DashYIsRefused(t *testing.T) {
	dir := t.TempDir()
	var code int
	out := captureStderr(t, func() {
		code = Run([]string{"-y", "--profile", "p", "--config-dir", dir, "--state-dir", dir})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(out, "-y is not supported") {
		t.Fatalf("stderr missing -y refusal: %q", out)
	}
	// The wizard must not have written a targets.json.
	if _, err := os.Stat(filepath.Join(dir, "targets.json")); err == nil {
		t.Fatal("wizard must not create targets.json when -y is rejected")
	}
}

func TestRun_MissingProfileIsRefused(t *testing.T) {
	dir := t.TempDir()
	var code int
	out := captureStderr(t, func() {
		code = Run([]string{"--config-dir", dir, "--state-dir", dir})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	if !strings.Contains(out, "--profile is required") {
		t.Fatalf("stderr missing --profile message: %q", out)
	}
}

func TestRun_UnknownFlagIsRefusedNotExited(t *testing.T) {
	// With flag.ContinueOnError, an unknown flag must return exit 2 without
	// tearing down the test process (which flag.ExitOnError would do).
	dir := t.TempDir()
	var code int
	_ = captureStderr(t, func() {
		code = Run([]string{"--not-a-flag", "--profile", "p", "--config-dir", dir})
	})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
}
