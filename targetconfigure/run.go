// Package targetconfigure is the interactive, one-shot local wizard that
// prepares a Brocade FC switch for the two-path FilterREX runtime (Workbench
// HTTPS REST + Evidence Bundle SSH). See:
//   - connector-agent/RELEASE-v0.1.0-preview.3.md
//   - docs/brocade-target-two-path-auth.md
//
// Boundaries this wizard preserves:
//   - Never accepts switch credentials on the command line.
//   - Never echoes password, private-key bytes, connector token, or signed
//     URLs to stdout/stderr or to any audit line.
//   - Never writes secrets outside the operator-supplied --config-dir.
//   - Refuses to trust an SSH host key returned by the network fetch until the
//     operator confirms an out-of-band comparison AND passes a fingerprint
//     challenge.
//   - Copies imported keys into managed storage; targets.json only ever
//     references files under --config-dir.
//   - Atomic writes: temp file → fsync → rename → fsync parent dir.
//   - Partial success is allowed: REST-only ready or SSH-only ready are valid
//     terminal states, saved with precise reason codes.
//
// This package exposes a single entry point, Run, so the wizard is reachable
// both from the standalone binary (cmd/targetconfigure) and as a
// `target configure` subcommand of the top-level connector-agent binary.
// Run never calls os.Exit — the caller owns process termination — so the
// package is testable and safe to embed.
package targetconfigure

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/filterrex-ai/connector-agent/brocaderest"
)

// ─── config-file layout ──────────────────────────────────────────────────────

const (
	targetsFile   = "targets.json"
	restSecretDir = "secrets/rest"
	sshKeyDir     = "keys"
	tlsDir        = "tls"
	knownHostsFn  = "known_hosts"
)

type targetsDoc struct {
	Version int                      `json:"version"`
	Targets map[string]*targetRecord `json:"targets"`
}

type targetRecord struct {
	Address    string     `json:"address"`
	RESTPort   int        `json:"rest_port,omitempty"`
	SSHPort    int        `json:"ssh_port,omitempty"`
	REST       *restEntry `json:"rest,omitempty"`
	SSH        *sshEntry  `json:"ssh,omitempty"`
	LastWizard string     `json:"last_wizard_at,omitempty"`
	Readiness  readiness  `json:"readiness"`
}

type restEntry struct {
	TransportMode string `json:"transport_mode"` // https-verified | http-lab-only
	Username      string `json:"username"`
	PasswordFile  string `json:"password_file"`
	CAFile        string `json:"ca_file,omitempty"`
}

type sshEntry struct {
	Username       string `json:"username"`
	KeyPath        string `json:"key_path"`
	PublicKeyPath  string `json:"public_key_path,omitempty"`
	KnownHostsPath string `json:"known_hosts_path"`
}

type readiness struct {
	RESTReady         bool   `json:"rest_ready"`
	RESTReason        string `json:"rest_reason,omitempty"`
	RESTSecurityState string `json:"rest_security_state,omitempty"`
	SSHReady          bool   `json:"ssh_ready"`
	SSHReason         string `json:"ssh_reason,omitempty"`
}

// ─── entry point ─────────────────────────────────────────────────────────────

// Run parses args and executes the wizard. It never calls os.Exit; the caller
// receives the intended process exit code:
//
//	0 — success (including partial REST-only / SSH-only readiness saved)
//	1 — wizard flow error (details already printed to stderr)
//	2 — invalid CLI usage (flag parse failure, missing/rejected flags)
func Run(args []string) int {
	fs := flag.NewFlagSet("target configure", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configDir := fs.String("config-dir", "/config", "Writable target-config directory.")
	profile := fs.String("profile", "", "target_profile_id being configured.")
	stateDir := fs.String("state-dir", "/var/lib/filterrex", "Read-only mount of the connector state volume (identity).")
	nonInteractive := fs.Bool("y", false, "Reserved: refuse to run unattended. Always false in preview.3.")

	if err := fs.Parse(args); err != nil {
		// flag package already printed the usage/error to stderr
		return 2
	}

	if *nonInteractive {
		fmt.Fprintln(os.Stderr, "target configure: -y is not supported: the wizard requires interactive out-of-band fingerprint verification.")
		return 2
	}
	if strings.TrimSpace(*profile) == "" {
		fmt.Fprintln(os.Stderr, "target configure: --profile is required.")
		return 2
	}
	if strings.TrimSpace(*configDir) == "" {
		fmt.Fprintln(os.Stderr, "target configure: --config-dir is required.")
		return 2
	}

	if err := run(*configDir, *stateDir, *profile); err != nil {
		fmt.Fprintln(os.Stderr, "target configure:", err.Error())
		return 1
	}
	return 0
}

// ─── main flow ───────────────────────────────────────────────────────────────

func run(configDir, stateDir, profile string) error {
	uid, gid := os.Geteuid(), os.Getegid()
	fmt.Printf("target configure (preview.3)\n  config-dir: %s\n  state-dir:  %s\n  profile:    %s\n  euid/egid:  %d/%d\n\n",
		configDir, stateDir, profile, uid, gid)

	if err := ensureDirs(configDir); err != nil {
		return err
	}

	// Sanitized cloud-side lookup would go here — authenticated using the
	// connector identity from stateDir. In this build we perform local
	// enrollment validation only (identity file existence) so the wizard can
	// operate on air-gapped hosts too. When the connector-identity-aware
	// lookup lands, it slots in here without changing the operator UX.
	if err := verifyConnectorIdentity(stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v (proceeding with local-only configuration)\n\n", err)
	}

	doc, err := loadTargets(configDir)
	if err != nil {
		return err
	}
	existing := doc.Targets[profile]
	if existing != nil {
		fmt.Println("Existing configuration detected for this profile — you will be prompted to reuse or replace each artifact.")
	}

	rec := &targetRecord{Address: "", Readiness: readiness{}}
	if existing != nil {
		rec = existing
	}

	// 1) address + ports
	addr, restPort, sshPort, err := promptAddressAndPorts(rec)
	if err != nil {
		return err
	}
	rec.Address = addr
	rec.RESTPort = restPort
	rec.SSHPort = sshPort

	// 2) account username
	restUser := prompt("REST username", firstNonEmpty(existingUser(rec, "rest"), "filterrex_ro"))
	sshUser := prompt("SSH username", firstNonEmpty(existingUser(rec, "ssh"), restUser))

	// 3) REST password
	restPasswordFile, restSecState, err := configureRESTPassword(configDir, profile, rec)
	if err != nil {
		return err
	}

	// 4) SSH key
	sshKeyPath, sshPubPath, err := configureSSHKey(configDir, profile, rec)
	if err != nil {
		return err
	}

	// 5) host-key enrollment with out-of-band challenge
	knownHostsPath, hkErr := enrollHostKey(configDir, addr, sshPort, rec)
	if hkErr != nil {
		fmt.Fprintf(os.Stderr, "\nhost-key enrollment failed: %v\n", hkErr)
	}

	// Assemble the working record before probes.
	rec.REST = &restEntry{
		TransportMode: string(brocaderest.TransportHTTPSVerified),
		Username:      restUser,
		PasswordFile:  restPasswordFile,
	}
	if existing != nil && existing.REST != nil && existing.REST.CAFile != "" {
		rec.REST.CAFile = existing.REST.CAFile
	}
	rec.SSH = &sshEntry{
		Username:       sshUser,
		KeyPath:        sshKeyPath,
		PublicKeyPath:  sshPubPath,
		KnownHostsPath: knownHostsPath,
	}

	// 6) REST probe
	restReady, restReason := probeREST(rec, restSecState)
	rec.Readiness.RESTReady = restReady
	rec.Readiness.RESTReason = restReason
	rec.Readiness.RESTSecurityState = restSecState

	// 7) SSH probe (only if host-key enrollment succeeded)
	sshReady, sshReason := false, "known_hosts_missing"
	if hkErr == nil {
		sshReady, sshReason = probeSSH(rec)
	}
	rec.Readiness.SSHReady = sshReady
	rec.Readiness.SSHReason = sshReason

	rec.LastWizard = time.Now().UTC().Format(time.RFC3339)

	// 8) atomic write, preserving other profiles' entries.
	if doc.Targets == nil {
		doc.Targets = map[string]*targetRecord{}
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	doc.Targets[profile] = rec
	if err := writeTargets(configDir, doc); err != nil {
		return err
	}

	fmt.Println("\nSaved.")
	fmt.Printf("  Live Workbench queries        %s\n", stateLine(restReady, restReason))
	fmt.Printf("  SSH evidence collection       %s\n", stateLine(sshReady, sshReason))
	if !restReady || !sshReady {
		fmt.Println("\nRe-run this wizard against the same --profile to repair the failed path.")
	}
	if sshPubPath != "" {
		fmt.Printf("\nSSH public key to install on the switch (read-only account):\n  %s\n", sshPubPath)
	}
	return nil
}

func stateLine(ready bool, reason string) string {
	if ready {
		return "Ready"
	}
	if reason == "" {
		reason = "setup_required"
	}
	return "Setup required: " + reason
}

// ─── steps ───────────────────────────────────────────────────────────────────

func ensureDirs(configDir string) error {
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{
		{configDir, 0o700},
		{filepath.Join(configDir, restSecretDir), 0o700},
		{filepath.Join(configDir, sshKeyDir), 0o700},
		{filepath.Join(configDir, tlsDir), 0o700},
	} {
		if err := os.MkdirAll(d.p, d.mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.p, err)
		}
		if err := os.Chmod(d.p, d.mode); err != nil {
			return fmt.Errorf("chmod %s: %w", d.p, err)
		}
	}
	return nil
}

func verifyConnectorIdentity(stateDir string) error {
	candidates := []string{
		filepath.Join(stateDir, "identity.json"),
		filepath.Join(stateDir, "connector.json"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return nil
		}
	}
	return errors.New("no connector identity found in state-dir")
}

var (
	hostRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
)

func promptAddressAndPorts(existing *targetRecord) (string, int, int, error) {
	defAddr := existing.Address
	for {
		addr := prompt("Management hostname or address", defAddr)
		if err := validateHost(addr); err != nil {
			fmt.Fprintln(os.Stderr, "invalid:", err)
			continue
		}
		restPort := promptPort("REST port", firstNonZero(existing.RESTPort, 443))
		sshPort := promptPort("SSH port", firstNonZero(existing.SSHPort, 22))
		return addr, restPort, sshPort, nil
	}
}

func validateHost(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("required")
	}
	if strings.Contains(s, "://") || strings.Contains(s, "/") || strings.Contains(s, "?") || strings.Contains(s, "@") {
		return errors.New("enter a bare hostname or address; no scheme, path, query, or user@")
	}
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return errors.New("malformed IPv6 literal")
		}
		if ip := net.ParseIP(s[1 : len(s)-1]); ip == nil {
			return errors.New("malformed IPv6 literal")
		}
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			if os.Getenv("FILTERREX_LAB_MODE") != "1" {
				return errors.New("loopback/link-local requires FILTERREX_LAB_MODE=1")
			}
		}
		return nil
	}
	if !hostRe.MatchString(s) {
		return errors.New("hostname contains disallowed characters")
	}
	if _, err := url.Parse("//" + s); err != nil {
		return errors.New("hostname is not parseable")
	}
	return nil
}

func promptPort(label string, def int) int {
	for {
		v := prompt(label, strconv.Itoa(def))
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 && n < 65536 {
			return n
		}
		fmt.Fprintln(os.Stderr, "port must be 1..65535")
	}
}

func configureRESTPassword(configDir, profile string, rec *targetRecord) (string, string, error) {
	slug := profileSlug(profile)
	path := filepath.Join(configDir, restSecretDir, slug)

	if existsRegularSecret(path) {
		switch confirmChoice("REST password file exists. Reuse / Replace / Abort", "reuse") {
		case "reuse":
			return path, "production_verified", nil
		case "abort":
			return "", "", errors.New("aborted by operator")
		}
	}
	pw, err := readSecretNoEcho("REST password for " + rec.Address + " (input hidden): ")
	if err != nil {
		return "", "", err
	}
	if len(pw) == 0 {
		return "", "", errors.New("password is empty")
	}
	defer zeroBytes(pw)
	if err := atomicWriteFile(path, pw, 0o600); err != nil {
		return "", "", err
	}
	return path, "production_verified", nil
}

func configureSSHKey(configDir, profile string, rec *targetRecord) (string, string, error) {
	slug := profileSlug(profile)
	keyPath := filepath.Join(configDir, sshKeyDir, slug)
	pubPath := keyPath + ".pub"

	if existsRegularSecret(keyPath) {
		switch confirmChoice("SSH key exists. Reuse / Regenerate / Import", "reuse") {
		case "reuse":
			return keyPath, pubPath, nil
		case "import":
			return importSSHKey(keyPath, pubPath)
		case "regenerate":
			// fall through to generation
		}
	} else {
		if confirmChoice("Generate a new ed25519 SSH key or import an existing one?", "generate") == "import" {
			return importSSHKey(keyPath, pubPath)
		}
	}
	return generateEd25519(keyPath, pubPath)
}

func generateEd25519(keyPath, pubPath string) (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("ed25519 generate: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "filterrex-ro")
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(pemBlock)
	if err := atomicWriteFile(keyPath, privPEM, 0o600); err != nil {
		return "", "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	if err := atomicWriteFile(pubPath, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		return "", "", err
	}
	return keyPath, pubPath, nil
}

func importSSHKey(keyPath, pubPath string) (string, string, error) {
	src := prompt("Path to existing private key on the setup host", "")
	if src == "" {
		return "", "", errors.New("import path is required")
	}
	fi, err := os.Lstat(src)
	if err != nil {
		return "", "", fmt.Errorf("import source unreadable")
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return "", "", errors.New("import source is a symlink; refusing")
	}
	if !fi.Mode().IsRegular() {
		return "", "", errors.New("import source is not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("import source permissions %#o are too permissive; use 0600 or 0400", fi.Mode().Perm())
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return "", "", errors.New("import source read failed")
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		zeroBytes(b)
		return "", "", errors.New("import source is not a valid SSH private key")
	}
	if err := atomicWriteFile(keyPath, b, 0o600); err != nil {
		zeroBytes(b)
		return "", "", err
	}
	zeroBytes(b)
	pub := signer.PublicKey()
	if err := atomicWriteFile(pubPath, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		return "", "", err
	}
	return keyPath, pubPath, nil
}

func enrollHostKey(configDir, host string, sshPort int, existing *targetRecord) (string, error) {
	khPath := filepath.Join(configDir, knownHostsFn)

	if hasKnownHostEntry(khPath, host) {
		if confirmChoice("known_hosts already has an entry for "+host+". Reuse or Refresh", "reuse") == "reuse" {
			return khPath, nil
		}
	}

	pub, hostKey, err := fetchHostKey(host, sshPort)
	if err != nil {
		return khPath, err
	}
	sum := sha256.Sum256(pub.Marshal())
	fpRaw := base64.StdEncoding.EncodeToString(sum[:])
	fpNoPad := strings.TrimRight(fpRaw, "=")
	fmt.Printf("\nSwitch presented SSH host key:\n  type:        %s\n  SHA256 fp:   SHA256:%s\n\n", pub.Type(), fpNoPad)
	fmt.Println("This key was received over the network and is NOT yet trusted.")
	fmt.Println("Compare the fingerprint above with the switch console, an existing")
	fmt.Println("trusted SSH session, or an approved inventory record.")

	if !confirmYesNo("I have compared the fingerprint against a trusted source", false) {
		return khPath, errors.New("host key not confirmed out-of-band")
	}
	want := ""
	if len(fpNoPad) >= 12 {
		want = fpNoPad[len(fpNoPad)-12:]
	} else {
		want = fpNoPad
	}
	got := strings.TrimSpace(prompt("Type the final 12 characters of the fingerprint (excluding trailing '=')", ""))
	if got != want {
		return khPath, errors.New("fingerprint challenge failed")
	}

	line := knownHostsLine(host, sshPort, hostKey)
	if err := appendLineAtomic(khPath, line, 0o640); err != nil {
		return khPath, err
	}
	return khPath, nil
}

func fetchHostKey(host string, port int) (ssh.PublicKey, []byte, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "filterrex-hostkey-probe",
		Auth: []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			captured = key
			return errors.New("host-key-only")
		},
		Timeout: 8 * time.Second,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	_, _ = ssh.Dial("tcp", addr, cfg)
	if captured == nil {
		return nil, nil, errors.New("no host key returned (connection failed)")
	}
	return captured, captured.Marshal(), nil
}

func knownHostsLine(host string, port int, wire []byte) string {
	hostPart := host
	if port != 22 {
		hostPart = "[" + host + "]:" + strconv.Itoa(port)
	}
	key, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s %s %s\n", hostPart, key.Type(), base64.StdEncoding.EncodeToString(wire))
}

func hasKnownHostEntry(path, host string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, host+" ") || strings.HasPrefix(line, "["+host+"]:") {
			return true
		}
	}
	return false
}

func probeREST(rec *targetRecord, _ string) (bool, string) {
	cfg := brocaderest.Config{
		TargetProfileID: "wizard-probe",
		Host:            rec.Address,
		Port:            rec.RESTPort,
		TransportMode:   brocaderest.TransportMode(rec.REST.TransportMode),
		Username:        rec.REST.Username,
		PasswordFile:    rec.REST.PasswordFile,
		CAFile:          rec.REST.CAFile,
	}
	client, err := brocaderest.New(cfg)
	if err != nil {
		var e *brocaderest.Error
		if errors.As(err, &e) {
			return false, e.Code
		}
		return false, brocaderest.ErrCodeRESTConnectionFailed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e := client.ProbeSwitchStatus(ctx); e != nil {
		return false, e.Code
	}
	return true, ""
}

func probeSSH(rec *targetRecord) (bool, string) {
	keyBytes, err := os.ReadFile(rec.SSH.KeyPath)
	if err != nil {
		return false, "missing_ssh_key"
	}
	signer, perr := ssh.ParsePrivateKey(keyBytes)
	zeroBytes(keyBytes)
	if perr != nil {
		return false, "missing_ssh_key"
	}
	cb, err := hostKeyCallbackFromFile(rec.SSH.KnownHostsPath)
	if err != nil {
		return false, "known_hosts_missing"
	}
	cfg := &ssh.ClientConfig{
		User:            rec.SSH.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         8 * time.Second,
	}
	addr := net.JoinHostPort(rec.Address, strconv.Itoa(rec.SSHPort))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "unable to authenticate"):
			return false, "ssh_auth_failed"
		case strings.Contains(msg, "host key"):
			return false, "host_key_verification_failed"
		default:
			return false, "ssh_connection_failed"
		}
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return false, "read_only_probe_failed"
	}
	defer sess.Close()
	return true, ""
}

// ─── low-level helpers ──────────────────────────────────────────────────────

func hostKeyCallbackFromFile(path string) (ssh.HostKeyCallback, error) {
	return func(hostname string, remote net.Addr, presented ssh.PublicKey) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return errors.New("known_hosts unreadable")
		}
		presentedMarshal := presented.Marshal()
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 3 {
				continue
			}
			if !strings.HasPrefix(parts[0], strings.SplitN(hostname, ":", 2)[0]) &&
				!strings.Contains(parts[0], hostname) {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				continue
			}
			if bytesEqual(raw, presentedMarshal) {
				return nil
			}
		}
		return errors.New("host key not enrolled")
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadTargets(configDir string) (*targetsDoc, error) {
	p := filepath.Join(configDir, targetsFile)
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return &targetsDoc{Version: 1, Targets: map[string]*targetRecord{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var d targetsDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if d.Targets == nil {
		d.Targets = map[string]*targetRecord{}
	}
	return &d, nil
}

func writeTargets(configDir string, doc *targetsDoc) error {
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if len(buf) == 0 || buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	_ = sort.StringsAreSorted
	return atomicWriteFile(filepath.Join(configDir, targetsFile), buf, 0o600)
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wizard-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	if fi, err := os.Stat(path); err == nil {
		if fi.Mode().Perm()&0o077 != 0 && mode&0o077 == 0 {
			return fmt.Errorf("post-write permissions %#o are too permissive on %s", fi.Mode().Perm(), path)
		}
	}
	return nil
}

func appendLineAtomic(path, line string, mode os.FileMode) error {
	existing, _ := os.ReadFile(path)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		existing = append(existing, '\n')
	}
	existing = append(existing, []byte(line)...)
	return atomicWriteFile(path, existing, mode)
}

func existsRegularSecret(p string) bool {
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular()
}

func profileSlug(id string) string {
	safe := regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(id, "-")
	if safe == "" {
		safe = "target"
	}
	return safe
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

func existingUser(rec *targetRecord, kind string) string {
	if rec == nil {
		return ""
	}
	switch kind {
	case "rest":
		if rec.REST != nil {
			return rec.REST.Username
		}
	case "ssh":
		if rec.SSH != nil {
			return rec.SSH.Username
		}
	}
	return ""
}

// ─── prompt helpers ─────────────────────────────────────────────────────────

func prompt(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		line = ""
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func confirmYesNo(label string, def bool) bool {
	suffix := "[y/N]"
	if def {
		suffix = "[Y/n]"
	}
	fmt.Printf("%s %s: ", label, suffix)
	var line string
	_, _ = fmt.Fscanln(os.Stdin, &line)
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

func confirmChoice(label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	var line string
	_, _ = fmt.Fscanln(os.Stdin, &line)
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line
}

// readSecretNoEcho reads a line from stdin with terminal echo disabled via
// golang.org/x/term, which uses termios ioctls directly and restores state
// even on SIGINT/SIGTERM. We refuse when stdin is not a terminal — a piped
// password on a wizard prompt is almost always a bug (script leaking secrets
// into process listings, shell history, or ~/.*_history).
func readSecretNoEcho(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin is not a terminal; refusing to read secret from a pipe or redirect")
	}
	fmt.Fprint(os.Stderr, label)
	buf, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return buf, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
