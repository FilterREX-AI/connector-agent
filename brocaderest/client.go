package brocaderest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the connector-owned REST binding for one Brocade switch. It is
// derived from the local TargetConfig.REST block; the caller never supplies
// URLs, headers, or credentials.
type Config struct {
	TargetProfileID string        // audit label only
	Host            string        // hostname or IP; no scheme, no path
	Port            int           // 0 → 443 for https-verified, 80 for http-lab-only
	TransportMode   TransportMode // https-verified | http-lab-only
	Username        string
	PasswordFile    string // 0600/0400 file; read on demand
	CAFile          string // optional; extra CA appended to system roots for https-verified
}

// MaxResponseBytes caps every response body before parsing to defend against
// unexpectedly large switch responses.
const MaxResponseBytes = 8 << 20 // 8 MiB

// Response is the sanitized payload returned to callers. RawJSON is decoded
// from the response body when Content-Type is application/*json; otherwise it
// is nil and Text carries the trimmed textual body (capped).
type Response struct {
	HTTPStatus int
	RawJSON    json.RawMessage
	Text       string
	ElapsedMs  int64
	OperationID string
}

// AuditRecord is the credential-free structured audit line for one call. No
// headers, no bodies, no local file paths.
type AuditRecord struct {
	OperationID     string `json:"operation_id"`
	TargetProfileID string `json:"target_profile_id"`
	HTTPStatus      int    `json:"http_status,omitempty"`
	ElapsedMs       int64  `json:"elapsed_ms"`
	ErrorCode       string `json:"error_code,omitempty"`
}

// Client executes allowlisted read-only REST operations against one Brocade
// switch. Construct once per (target, transport policy) and reuse.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a Client honoring the target's transport policy. Returns a
// sanitized *Error on policy violations (unsupported transport, missing lab
// gate, invalid CA file).
func New(cfg Config) (*Client, error) {
	if cfg.Host == "" {
		return nil, newErr(ErrCodeInvalidParameter, "host is required")
	}
	switch cfg.TransportMode {
	case "", TransportHTTPSVerified:
		cfg.TransportMode = TransportHTTPSVerified
	case TransportHTTPLabOnly:
		if os.Getenv("FILTERREX_LAB_MODE") != "1" {
			return nil, newErr(ErrCodeLabModeRequired, "http-lab-only requires FILTERREX_LAB_MODE=1")
		}
	default:
		return nil, newErr(ErrCodeTransportUnsupported, string(cfg.TransportMode))
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// hostname verification is on by default; do NOT set InsecureSkipVerify.
	}
	if cfg.CAFile != "" && cfg.TransportMode == TransportHTTPSVerified {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, newErr(ErrCodeTLSUntrusted, "unable to read ca_file")
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, newErr(ErrCodeTLSUntrusted, "ca_file contains no valid PEM certificates")
		}
		tlsConf.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConf,
		DisableCompression:    true,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
	}

	hc := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		// A switch response must not redirect Basic credentials elsewhere.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{cfg: cfg, http: hc}, nil
}

// Do resolves operationID against the fixed allowlist, validates params,
// authenticates with the on-demand REST password, and returns a sanitized
// Response or *Error. It never accepts a raw URL or path.
func (c *Client) Do(ctx context.Context, operationID string, params map[string]any) (*Response, *AuditRecord, error) {
	start := time.Now()
	audit := &AuditRecord{OperationID: operationID, TargetProfileID: c.cfg.TargetProfileID}

	op, err := Resolve(operationID)
	if err != nil {
		audit.ErrorCode = ErrCodeUnknownOperation
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(ErrCodeUnknownOperation, "")
	}
	if _, verr := validateParams(op, params); verr != nil {
		var e *Error
		if errors.As(verr, &e) {
			audit.ErrorCode = e.Code
		} else {
			audit.ErrorCode = ErrCodeInvalidParameter
		}
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, verr
	}

	u, uerr := c.buildURL(op)
	if uerr != nil {
		audit.ErrorCode = ErrCodeInvalidParameter
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, uerr
	}

	req, rerr := http.NewRequestWithContext(ctx, op.Method, u, nil)
	if rerr != nil {
		audit.ErrorCode = ErrCodeRESTConnectionFailed
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(ErrCodeRESTConnectionFailed, "request build failed")
	}
	req.Header.Set("Accept", "application/yang-data+json, application/json")
	req.Header.Set("User-Agent", "filterrex-connector/brocaderest")

	// On-demand password read + best-effort zeroing.
	pw, perr := readPassword(c.cfg.PasswordFile)
	if perr != nil {
		audit.ErrorCode = ErrCodeMissingPassword
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, perr
	}
	req.SetBasicAuth(c.cfg.Username, string(pw))
	zeroBytes(pw)

	resp, herr := c.http.Do(req)
	if herr != nil {
		code := classifyTransportError(herr)
		audit.ErrorCode = code
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(code, "")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		audit.HTTPStatus = resp.StatusCode
		audit.ErrorCode = ErrCodeRedirectRefused
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(ErrCodeRedirectRefused, "")
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		audit.HTTPStatus = resp.StatusCode
		audit.ErrorCode = ErrCodeRESTAuthFailed
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(ErrCodeRESTAuthFailed, "")
	}

	body, berr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if berr != nil {
		audit.HTTPStatus = resp.StatusCode
		audit.ErrorCode = ErrCodeRESTConnectionFailed
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(ErrCodeRESTConnectionFailed, "response read failed")
	}
	if len(body) > MaxResponseBytes {
		audit.HTTPStatus = resp.StatusCode
		audit.ErrorCode = ErrCodeResponseTooLarge
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(ErrCodeResponseTooLarge, "")
	}

	if resp.StatusCode >= 400 {
		audit.HTTPStatus = resp.StatusCode
		audit.ErrorCode = ErrCodeRESTHTTPError
		audit.ElapsedMs = time.Since(start).Milliseconds()
		return nil, audit, newErr(ErrCodeRESTHTTPError, "http "+strconv.Itoa(resp.StatusCode))
	}

	out := &Response{
		HTTPStatus:  resp.StatusCode,
		ElapsedMs:   time.Since(start).Milliseconds(),
		OperationID: operationID,
	}
	ct := resp.Header.Get("Content-Type")
	if isJSONContentType(ct) {
		out.RawJSON = json.RawMessage(body)
	} else {
		out.Text = string(body)
	}
	audit.HTTPStatus = resp.StatusCode
	audit.ElapsedMs = out.ElapsedMs
	return out, audit, nil
}

func (c *Client) buildURL(op Operation) (string, *Error) {
	scheme := "https"
	defaultPort := 443
	if c.cfg.TransportMode == TransportHTTPLabOnly {
		scheme = "http"
		defaultPort = 80
	}
	port := c.cfg.Port
	if port == 0 {
		port = defaultPort
	}
	// Reject any operator-supplied path contamination — resolver-owned only.
	if !strings.HasPrefix(op.PathTemplate, "/") {
		return "", newErr(ErrCodeInvalidParameter, "operation path template must be absolute")
	}
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(c.cfg.Host, strconv.Itoa(port)),
		Path:   op.PathTemplate,
	}
	return u.String(), nil
}

func classifyTransportError(err error) string {
	msg := err.Error()
	// crypto/tls surfaces verification failures with these substrings.
	if strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "certificate signed by unknown authority") ||
		strings.Contains(msg, "tls: failed to verify") ||
		strings.Contains(msg, "hostname does not match") {
		return ErrCodeTLSUntrusted
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrCodeRESTTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrCodeRESTTimeout
	}
	return ErrCodeRESTConnectionFailed
}

func isJSONContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	return ct == "application/json" ||
		ct == "application/yang-data+json" ||
		strings.HasSuffix(ct, "+json")
}

// ProbeSwitchStatus runs the smallest allowlisted read-only operation and
// returns success or a sanitized error code. Used by the wizard REST probe.
func (c *Client) ProbeSwitchStatus(ctx context.Context) *Error {
	_, _, err := c.Do(ctx, "brocade.switch.status", nil)
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return newErr(ErrCodeReadOnlyProbeFailed, "")
}

func init() {
	// Sanity: the resolver's default op must exist for the probe to work.
	if _, err := Resolve("brocade.switch.status"); err != nil {
		panic(fmt.Sprintf("brocaderest: resolver missing brocade.switch.status: %v", err))
	}
}
