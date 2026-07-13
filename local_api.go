// ForgeAI Connector Host — Local API Server
//
// Lightweight read-only HTTP server that serves local snapshot data
// over the LAN in Hybrid Mode. Endpoints are authenticated via a
// pre-shared X-Local-Token header (except /v1/health).
//
// TLS: On first start the server generates a self-signed ECDSA P-256
// certificate stored alongside local.db in the config directory.
// Subsequent starts reuse the existing cert. If cert generation fails
// the server falls back to plain HTTP with a warning.
//
// Endpoints:
//   GET  /v1/health              — unauthenticated reachability probe
//   GET  /v1/targets             — list all targets with status
//   GET  /v1/targets/:id/snapshot — latest decrypted snapshot for a target
//   POST /v1/execute             — direct LAN command execution (bypasses cloud relay)

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultLocalAPIBind = "0.0.0.0:7070"
	localAPIVersion     = "v1"
)

// LocalAPIServer serves local snapshot data over the LAN.
// Only started when Hybrid Mode is enabled.
// All endpoints except /v1/health require X-Local-Token.
type LocalAPIServer struct {
	db           *LocalDB
	supervisor   *Supervisor
	relayHandler *RelayHandler
	token        string
	bind         string
	server       *http.Server
	lanURL       string // e.g. "https://192.168.1.50:7070"
	allowedNets  []*net.IPNet // nil = localhost only
	certFile     string
	keyFile      string
}

// NewLocalAPIServer creates and configures the server.
// token is the pre-shared auth token.
// bind is the listen address (e.g. "0.0.0.0:7070").
// certDir is where TLS cert/key files are stored.
// relayHandler enables direct LAN execution via /v1/execute (may be nil).
func NewLocalAPIServer(
	db *LocalDB,
	supervisor *Supervisor,
	token string,
	bind string,
	certDir string,
	relayHandler *RelayHandler,
) *LocalAPIServer {
	if bind == "" {
		bind = defaultLocalAPIBind
	}

	// Parse IP allowlist from env.
	// Default: 127.0.0.1/32 (localhost only).
	// Set FORGEAI_LOCAL_API_ALLOWED_CIDR to expand,
	// e.g. "192.168.0.0/16,10.0.0.0/8"
	allowedNets := parseAllowedCIDRs(
		os.Getenv("FORGEAI_LOCAL_API_ALLOWED_CIDR"))

	certFile := filepath.Join(certDir, "local-api.crt")
	keyFile := filepath.Join(certDir, "local-api.key")

	s := &LocalAPIServer{
		db:           db,
		supervisor:   supervisor,
		relayHandler: relayHandler,
		token:        token,
		bind:         bind,
		allowedNets:  allowedNets,
		certFile:     certFile,
		keyFile:      keyFile,
	lanURL: func() string {
		if v := os.Getenv("FORGEAI_LOCAL_API_URL"); v != "" {
			// Normalise to https since TLS is always attempted
			v = strings.Replace(v, "http://", "https://", 1)
			// Ensure the port is present — if the user provided just an IP,
			// append the port from the bind address so the frontend probes
			// the correct port instead of defaulting to 443.
			if u, err := url.Parse(v); err == nil && u.Port() == "" {
				_, bindPort, _ := net.SplitHostPort(bind)
				if bindPort != "" {
					v = strings.TrimRight(v, "/") + ":" + bindPort
				}
			}
			return v
		}
		return detectLANURL(bind)
	}(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health",
		s.preflightMiddleware(
			s.ipAllowedMiddleware(s.handleHealth)))
	mux.HandleFunc("/v1/targets",
		s.preflightMiddleware(
			s.ipAllowedMiddleware(
				s.authMiddleware(s.handleTargets))))
	mux.HandleFunc("/v1/targets/",
		s.preflightMiddleware(
			s.ipAllowedMiddleware(
				s.authMiddleware(s.handleTargetRoute))))
	mux.HandleFunc("/v1/execute",
		s.preflightMiddleware(
			s.ipAllowedMiddleware(
				s.authMiddleware(s.handleExecute))))

	s.server = &http.Server{
		Addr:         bind,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening. Non-blocking — runs in a goroutine.
// Attempts TLS with self-signed cert; falls back to HTTP on failure.
func (s *LocalAPIServer) Start() {
	// Ensure cert exists — generate if missing
	if err := s.ensureCert(); err != nil {
		audit.Warn("local_api.tls",
			"Failed to init TLS cert — falling back to HTTP",
			Err(err))
		// Fall back to plain HTTP
		go func() {
			cidrs := make([]string, len(s.allowedNets))
			for i, n := range s.allowedNets {
				cidrs[i] = n.String()
			}
			audit.Info("local_api.config",
				"IP allowlist configured",
				F("allowed_cidrs", strings.Join(cidrs, ", ")))
			audit.Info("local_api.start",
				"Local API server listening (HTTP fallback)",
				F("addr", s.bind),
				F("lan_url", s.lanURL))
			if err := s.server.ListenAndServe(); err != nil &&
				err != http.ErrServerClosed {
				audit.Error("local_api.start",
					"Local API server error", Err(err))
			}
		}()
		return
	}

	go func() {
		// Update advertised URL to use https
		if strings.HasPrefix(s.lanURL, "http://") {
			s.lanURL = "https" + s.lanURL[4:]
		}

		cidrs := make([]string, len(s.allowedNets))
		for i, n := range s.allowedNets {
			cidrs[i] = n.String()
		}
		audit.Info("local_api.config",
			"IP allowlist configured",
			F("allowed_cidrs", strings.Join(cidrs, ", ")))
		audit.Info("local_api.start",
			"Local API server listening (HTTPS)",
			F("addr", s.bind),
			F("lan_url", s.lanURL))
		if err := s.server.ListenAndServeTLS(
			s.certFile, s.keyFile); err != nil &&
			err != http.ErrServerClosed {
			audit.Error("local_api.start",
				"Local API server error", Err(err))
		}
	}()
}

// ensureCert generates a self-signed ECDSA cert if
// the cert/key files don't already exist.
// Valid for 10 years, SAN includes the LAN IP.
func (s *LocalAPIServer) ensureCert() error {
	// If both files exist, reuse them
	if _, err := os.Stat(s.certFile); err == nil {
		if _, err := os.Stat(s.keyFile); err == nil {
			audit.Info("local_api.tls",
				"Reusing existing TLS cert",
				F("cert", s.certFile))
			return nil
		}
	}

	audit.Info("local_api.tls",
		"Generating self-signed TLS cert",
		F("cert", s.certFile))

	// Generate ECDSA P-256 key
	priv, err := ecdsa.GenerateKey(
		elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Parse LAN IP for SAN
	var ipAddrs []net.IP
	if s.lanURL != "" {
		host := s.lanURL
		// Strip scheme
		for _, pfx := range []string{
			"https://", "http://"} {
			host = strings.TrimPrefix(host, pfx)
		}
		// Strip port
		if h, _, err :=
			net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		}
	}

	// Always include loopback
	ipAddrs = append(ipAddrs,
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"))

	serial, _ := rand.Int(rand.Reader,
		new(big.Int).Lsh(big.NewInt(1), 128))

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ForgeAI Local Agent"},
			CommonName:   "forgeai-local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ipAddrs,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl,
		&priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	// Write cert PEM
	certOut, err := os.OpenFile(
		s.certFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut,
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// Write key PEM
	keyOut, err := os.OpenFile(
		s.keyFile,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open key file: %w", err)
	}
	defer keyOut.Close()
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := pem.Encode(keyOut,
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privDER,
		}); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	audit.Info("local_api.tls",
		"TLS cert generated",
		F("valid_until",
			tmpl.NotAfter.Format("2006-01-02")),
		F("san_ips", fmt.Sprintf("%v", ipAddrs)))

	return nil
}

// Stop gracefully shuts down the server with a 5s timeout.
func (s *LocalAPIServer) Stop() {
	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		audit.Warn("local_api.stop",
			"Local API shutdown error", Err(err))
	} else {
		audit.Info("local_api.stop", "Local API server stopped")
	}
}

// LANURL returns the advertised LAN address for this server.
func (s *LocalAPIServer) LANURL() string {
	return s.lanURL
}

// authMiddleware enforces X-Local-Token header.
func (s *LocalAPIServer) authMiddleware(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Local-Token")
		if tok != s.token {
			s.writeError(w, http.StatusUnauthorized,
				"invalid or missing X-Local-Token")
			return
		}
		next(w, r)
	}
}

// ipAllowedMiddleware rejects requests from IPs not
// in the allowedNets list. Applied to all endpoints.
func (s *LocalAPIServer) ipAllowedMiddleware(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		if ip == nil {
			s.writeError(w, http.StatusForbidden,
				"could not determine client IP")
			return
		}
		for _, network := range s.allowedNets {
			if network.Contains(ip) {
				next(w, r)
				return
			}
		}
		audit.Warn("local_api.blocked",
			"Request blocked by IP allowlist",
			F("remote_ip", ip.String()),
			F("path", r.URL.Path))
		s.writeError(w, http.StatusForbidden,
			"client IP not in allowed range")
	}
}

// realIP extracts the client IP from RemoteAddr,
// stripping the port.
func realIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

// ── Handlers ──

// GET /v1/health — no auth required, used for reachability probe
func (s *LocalAPIServer) handleHealth(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed,
			"method not allowed")
		return
	}
	state := s.supervisor.GetState()
	label := ""
	if state != nil {
		label = state.Identity.Label
	}

	var dbStats map[string]interface{}
	if s.db != nil {
		dbStats = s.db.Stats()
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"version":      HostVersion,
		"hybrid_mode":  true,
		"label":        label,
		"target_count": s.supervisor.TargetCount(),
		"db_stats":     dbStats,
	})
}

// GET /v1/targets — list all targets with status + summary
func (s *LocalAPIServer) handleTargets(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed,
			"method not allowed")
		return
	}
	state := s.supervisor.GetState()
	if state == nil {
		s.writeJSON(w, http.StatusOK,
			map[string]interface{}{"targets": []interface{}{}})
		return
	}

	targets := make([]map[string]interface{}, 0,
		len(state.Targets))
	for _, t := range state.Targets {
		entry := map[string]interface{}{
			"target_id":   t.TargetID,
			"name":        t.Name,
			"target_type": t.TargetType,
			"enabled":     t.Enabled,
			"status":      string(t.Status),
			"endpoint":    t.Endpoint,
		}
		targets = append(targets, entry)
	}

	s.writeJSON(w, http.StatusOK,
		map[string]interface{}{"targets": targets})
}

// Routes /v1/targets/:id/snapshot and /v1/targets/:id/signals
func (s *LocalAPIServer) handleTargetRoute(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed,
			"method not allowed")
		return
	}
	// Parse: /v1/targets/<id>/<action>
	parts := strings.Split(
		strings.TrimPrefix(r.URL.Path, "/v1/targets/"), "/")
	if len(parts) < 2 {
		s.writeError(w, http.StatusNotFound, "not found")
		return
	}

	targetID := parts[0]
	action := parts[1]

	switch action {
	case "snapshot":
		s.handleSnapshot(w, r, targetID)
	default:
		s.writeError(w, http.StatusNotFound,
			fmt.Sprintf("unknown action: %s", action))
	}
}

// GET /v1/targets/:id/snapshot
func (s *LocalAPIServer) handleSnapshot(
	w http.ResponseWriter, r *http.Request, targetID string,
) {
	if s.db == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"local DB not available")
		return
	}

	payload, collectedAt, err := s.db.LatestSnapshot(targetID)
	if err != nil {
		audit.Warn("local_api.snapshot",
			"Failed to read snapshot", F("target_id", targetID),
			Err(err))
		s.writeError(w, http.StatusInternalServerError,
			"failed to read snapshot")
		return
	}

	if payload == nil {
		s.writeError(w, http.StatusNotFound,
			"no snapshot found for target")
		return
	}

	// Include current worker status so the frontend can detect stale-but-cached scenarios
	resp := map[string]interface{}{
		"ok":           true,
		"target_id":    targetID,
		"collected_at": collectedAt.UTC().Format(time.RFC3339),
		"snapshot":     payload,
	}
	if s.supervisor != nil {
		for _, ws := range s.supervisor.Status() {
			if ws.TargetID == targetID {
				resp["worker_status"] = string(ws.Status)
				if ws.LastError != "" {
					resp["worker_last_error"] = ws.LastError
				}
				break
			}
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// POST /v1/execute — direct browser-to-agent command execution over LAN.
// Bypasses the cloud relay loop entirely. Same execution path as the
// cloud relay but triggered directly by the browser over LAN HTTPS.
func (s *LocalAPIServer) handleExecute(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed,
			"method not allowed")
		return
	}

	if s.relayHandler == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"execution not available")
		return
	}

	var cmd RelayCommand
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		s.writeError(w, http.StatusBadRequest,
			"invalid request body")
		return
	}

	// Require a request ID for tracing
	if cmd.ID == "" {
		cmd.ID = generateID()
	}

	// Validate required fields
	if cmd.Platform == "" ||
		cmd.Method == "" ||
		cmd.Path == "" ||
		cmd.TargetProfileID == "" {
		s.writeError(w, http.StatusBadRequest,
			"platform, method, path, and target_profile_id are required")
		return
	}

	audit.Info("local_api.execute",
		"Direct LAN execute request",
		F("cmd_id", cmd.ID),
		F("platform", cmd.Platform),
		F("method", cmd.Method),
		F("path", cmd.Path),
		F("target_id", cmd.TargetProfileID),
		F("safety", cmd.SafetyLevel))

	result := s.relayHandler.executeCommand(cmd)

	s.writeJSON(w, http.StatusOK,
		map[string]interface{}{
			"ok":              result.ErrorMessage == "",
			"id":              result.ID,
			"response_status": result.ResponseStatus,
			"response_data":   result.ResponseData,
			"error_message":   result.ErrorMessage,
			"duration_ms":     result.DurationMs,
		})
}

// ── Helpers ──

func (s *LocalAPIServer) writeJSON(
	w http.ResponseWriter, status int, v interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *LocalAPIServer) writeError(
	w http.ResponseWriter, status int, msg string,
) {
	s.corsHeaders(w)
	s.writeJSON(w, status,
		map[string]interface{}{"ok": false, "error": msg})
}

// corsHeaders sets all required CORS headers on any response.
func (s *LocalAPIServer) corsHeaders(
	w http.ResponseWriter) {
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	w.Header().Set(
		"Access-Control-Allow-Methods",
		"GET, POST, OPTIONS")
	w.Header().Set(
		"Access-Control-Allow-Headers",
		"X-Local-Token, Content-Type")
	w.Header().Set(
		"Access-Control-Max-Age", "86400")
}

// preflightMiddleware short-circuits OPTIONS requests
// before IP allowlist and auth middleware run.
func (s *LocalAPIServer) preflightMiddleware(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter, r *http.Request) {
		s.corsHeaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// parseAllowedCIDRs parses a comma-separated list of
// CIDR ranges. Falls back to localhost-only if the
// input is empty or entirely invalid.
func parseAllowedCIDRs(raw string) []*net.IPNet {
	// Always include localhost
	_, loopback, _ := net.ParseCIDR("127.0.0.1/32")
	_, loopback6, _ := net.ParseCIDR("::1/128")
	nets := []*net.IPNet{loopback, loopback6}

	if raw == "" {
		return nets
	}

	for _, cidr := range strings.Split(raw, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			audit.Warn("local_api.config",
				"Invalid CIDR in FORGEAI_LOCAL_API_ALLOWED_CIDR",
				F("cidr", cidr), Err(err))
			continue
		}
		nets = append(nets, ipNet)
	}

	return nets
}

// detectLANURL finds the first non-loopback IPv4 address
// and builds the URL using the port from bind.
func detectLANURL(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		port = "7070"
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Sprintf("http://127.0.0.1:%s", port)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() != nil {
				return fmt.Sprintf("http://%s:%s", ip.String(), port)
			}
		}
	}

	return fmt.Sprintf("http://127.0.0.1:%s", port)
}
