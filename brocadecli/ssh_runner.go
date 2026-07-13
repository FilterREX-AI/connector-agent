package brocadecli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHRunnerConfig configures the production SSH command runner.
type SSHRunnerConfig struct {
	// KnownHostsPath is REQUIRED. Host-key verification is mandatory; there is
	// no insecure fallback.
	KnownHostsPath string
	// ConnectTimeout bounds the TCP+handshake time. Default 10s when zero.
	ConnectTimeout time.Duration
	// CommandTimeout bounds a single command's execution. Default 30s when zero.
	CommandTimeout time.Duration
	// Port is the SSH port. Default 22 when zero.
	Port int
}

// sshRunner is the production CommandRunner. It uses non-interactive, key-based
// SSH only — no password or keyboard-interactive auth path exists — and it
// verifies host keys against a known_hosts file. It reuses one connection per
// host across that host's commands; call Close when done.
type sshRunner struct {
	cfg      SSHRunnerConfig
	hostKeyC ssh.HostKeyCallback

	mu      sync.Mutex
	clients map[string]*ssh.Client // keyed by host
}

// NewSSHRunner constructs a production runner. It fails fast if KnownHostsPath
// is missing or unreadable — host-key verification is required.
func NewSSHRunner(cfg SSHRunnerConfig) (CommandRunner, func() error, error) {
	if strings.TrimSpace(cfg.KnownHostsPath) == "" {
		return nil, nil, fmt.Errorf("KnownHostsPath is required for the SSH runner (host-key verification is mandatory)")
	}
	cb, err := knownhosts.New(cfg.KnownHostsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load known_hosts %q: %w", cfg.KnownHostsPath, err)
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	r := &sshRunner{cfg: cfg, hostKeyC: cb, clients: map[string]*ssh.Client{}}
	return r, r.Close, nil
}

// Close tears down all cached connections.
func (r *sshRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for host, c := range r.clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(r.clients, host)
	}
	return firstErr
}

func (r *sshRunner) client(target BrocadeTarget) (*ssh.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[target.Host]; ok {
		return c, nil
	}

	keyBytes, err := os.ReadFile(target.SSHKeyPath)
	if err != nil {
		// Do not include the key path contents; only the (non-secret) path.
		return nil, fmt.Errorf("read ssh key %q: %w", target.SSHKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	// Zero the key material as soon as the signer is built.
	for i := range keyBytes {
		keyBytes[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("parse ssh key for host %s: invalid private key", target.Host)
	}

	cfg := &ssh.ClientConfig{
		User:            target.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)}, // key-based only
		HostKeyCallback: r.hostKeyC,
		Timeout:         r.cfg.ConnectTimeout,
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(r.cfg.Port))
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	r.clients[target.Host] = c
	return c, nil
}

// Run executes one already-resolved, profile-safe command. It is read-only and
// non-interactive: no PTY is requested, and the exec string is passed to
// session.Run without any shell interpolation on our side.
func (r *sshRunner) Run(ctx context.Context, target BrocadeTarget, exec string) CommandResult {
	res := CommandResult{Started: time.Now().UTC()}
	defer func() { res.Elapsed = time.Since(res.Started) }()

	client, err := r.client(target)
	if err != nil {
		res.Err = err
		res.ExitCode = -1
		return res
	}

	session, err := client.NewSession()
	if err != nil {
		res.Err = fmt.Errorf("open ssh session on %s: %w", target.Host, err)
		res.ExitCode = -1
		return res
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	timeout := r.cfg.CommandTimeout
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- session.Run(exec) }()

	select {
	case <-runCtx.Done():
		res.TimedOut = true
		_ = session.Signal(ssh.SIGKILL)
		res.Stdout = stdout.Bytes()
		res.Stderr = append(stderr.Bytes(), []byte("\n[filterrex] command timed out")...)
		res.ExitCode = -1
		return res
	case err := <-done:
		res.Stdout = stdout.Bytes()
		res.Stderr = stderr.Bytes()
		if err == nil {
			res.ExitCode = 0
			return res
		}
		var exitErr *ssh.ExitError
		if ee, ok := err.(*ssh.ExitError); ok {
			exitErr = ee
			res.ExitCode = exitErr.ExitStatus()
		} else {
			res.ExitCode = -1
			res.Err = err
		}
		return res
	}
}
