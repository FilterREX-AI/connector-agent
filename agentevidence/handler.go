// Package agentevidence implements the connector-side handler for the
// server-initiated FilterREX Evidence Bundle collection workflow:
//
//	Admin dispatches a job → connector polls /agent-evidence-claim →
//	brocadeexport.RunExport captures a read-only bundle → connector requests
//	an upload intent → PUTs the ZIP to the signed URL → calls
//	/agent-evidence-complete with the server-verified checksum.
//
// This is a THIN glue file. All safety properties (SSH key-only auth, host-key
// verification, read-only command allowlist, shell-metachar rejection, LAN-only
// refusal) live inside brocadecli / brocadeexport and are enforced there.
//
// This handler is deliberately narrow: it only recognizes the typed operation
// "collect_brocade_evidence_bundle_v1". No other commands, no shell exec, no
// user-supplied paths or URLs.
package agentevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// CollectionProfile identifies the embedded read-only Brocade profile.
const CollectionProfile = "brocade-readonly-v1"

// Client talks to the cloud coordination endpoints. It intentionally has NO
// method for arbitrary URLs or shell commands.
//
// Either ConnectorToken (static) or TokenProvider (dynamic, e.g. picks up
// re-enrollment) may be used; TokenProvider wins when both are set.
type Client struct {
	BaseURL        string // e.g. https://<project>.functions.supabase.co
	ConnectorToken string // frc_... — never logged
	TokenProvider  func() string
	AgentVersion   string
	HTTP           *http.Client
}

func (c *Client) token() string {
	if c.TokenProvider != nil {
		if t := c.TokenProvider(); t != "" {
			return t
		}
	}
	return c.ConnectorToken
}


// ClaimedJob is the sanitized payload the cloud returns.
type ClaimedJob struct {
	ID                string    `json:"id"`
	ServiceRequestID  string    `json:"serviceRequestId"`
	TargetProfileID   string    `json:"targetProfileId"`
	CollectionProfile string    `json:"collectionProfile"`
	ExpiresAt         time.Time `json:"expiresAt"`
	LeaseExpiresAt    time.Time `json:"leaseExpiresAt"`
}

// BundleProducer is satisfied by brocadeexport. It receives the target profile
// ID and produces an Evidence Bundle v1.0 ZIP on disk plus its metadata. It
// MUST enforce read-only, host-key verified, key-only SSH, and refuse when
// LAN-only mode is active.
type BundleProducer interface {
	Produce(ctx context.Context, targetProfileID string) (zipPath string, commandProfileVersion string, err error)
}

// LocalReadinessChecker is the second-tier safety gate: the cloud can only
// check reported capability, but the agent must confirm the local
// configuration is actually usable before running SSH.
type LocalReadinessChecker interface {
	Check(targetProfileID string) error // returns non-nil with a code from PublicErrorCodes
}

// Handler wires everything together. Call Run() in a loop from the agent's
// existing outbound-poll scheduler.
type Handler struct {
	Client     *Client
	Producer   BundleProducer
	Readiness  LocalReadinessChecker
	LANOnly    func() bool
	AuditLog   func(event string, fields map[string]any)
	PollEvery  time.Duration
}

// Run polls once. Returns (workDone, error). Safe to call frequently.
func (h *Handler) Run(ctx context.Context) (bool, error) {
	if h.LANOnly != nil && h.LANOnly() {
		// LAN-only mode strictly refuses server-initiated collection.
		return false, nil
	}
	job, err := h.Client.claim(ctx, h.Client.AgentVersion)
	if err != nil {
		return false, err
	}
	if job == nil {
		return false, nil
	}
	h.audit("agent_evidence.claimed", map[string]any{
		"job_id":             job.ID,
		"service_request_id": job.ServiceRequestID,
		"target_profile_id":  job.TargetProfileID,
	})

	if job.CollectionProfile != CollectionProfile {
		_ = h.Client.reportFail(ctx, job.ID, "capability_disabled", "unsupported_profile", job.CollectionProfile)
		h.audit("agent_evidence.failed", map[string]any{"job_id": job.ID, "public_error_code": "capability_disabled"})
		return true, fmt.Errorf("unsupported profile %q", job.CollectionProfile)
	}
	if err := h.Readiness.Check(job.TargetProfileID); err != nil {
		code := errorCode(err, "capability_disabled")
		_ = h.Client.reportFail(ctx, job.ID, code, code, err.Error())
		h.audit("agent_evidence.readiness_failed", map[string]any{
			"job_id":            job.ID,
			"target_profile_id": job.TargetProfileID,
			"public_error_code": code,
		})
		return true, err
	}

	zipPath, profileVer, err := h.Producer.Produce(ctx, job.TargetProfileID)
	if err != nil {
		code := errorCode(err, "bundle_generation_failed")
		_ = h.Client.reportFail(ctx, job.ID, code, code, err.Error())
		h.audit("agent_evidence.failed", map[string]any{"job_id": job.ID, "public_error_code": code})
		return true, err
	}

	f, err := os.Open(zipPath)
	if err != nil {
		_ = h.Client.reportFail(ctx, job.ID, "bundle_generation_failed", "zip_open_failed", err.Error())
		h.audit("agent_evidence.failed", map[string]any{"job_id": job.ID, "public_error_code": "bundle_generation_failed"})
		return true, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		_ = h.Client.reportFail(ctx, job.ID, "bundle_generation_failed", "zip_stat_failed", err.Error())
		h.audit("agent_evidence.failed", map[string]any{"job_id": job.ID, "public_error_code": "bundle_generation_failed"})
		return true, err
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		_ = h.Client.reportFail(ctx, job.ID, "bundle_generation_failed", "hash_failed", err.Error())
		h.audit("agent_evidence.failed", map[string]any{"job_id": job.ID, "public_error_code": "bundle_generation_failed"})
		return true, err
	}
	sum := hex.EncodeToString(hasher.Sum(nil))

	h.audit("agent_evidence.bundle_produced", map[string]any{
		"job_id":                  job.ID,
		"bytes":                   stat.Size(),
		"bundle_sha256":           sum,
		"command_profile_version": profileVer,
	})

	intent, err := h.Client.uploadIntent(ctx, job.ID, stat.Size())
	if err != nil {
		_ = h.Client.reportFail(ctx, job.ID, "upload_url_expired", "intent_failed", err.Error())
		h.audit("agent_evidence.failed", map[string]any{"job_id": job.ID, "public_error_code": "upload_url_expired"})
		return true, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return true, err
	}
	if err := h.Client.putBundle(ctx, intent.UploadURL, f, stat.Size()); err != nil {
		_ = h.Client.reportFail(ctx, job.ID, "upload_failed", "put_failed", err.Error())
		h.audit("agent_evidence.failed", map[string]any{"job_id": job.ID, "public_error_code": "upload_failed"})
		return true, err
	}
	h.audit("agent_evidence.uploaded", map[string]any{"job_id": job.ID, "bytes": stat.Size()})

	if err := h.Client.reportComplete(ctx, job.ID, sum, profileVer); err != nil {
		return true, err
	}
	h.audit("agent_evidence.completed", map[string]any{
		"job_id":                  job.ID,
		"bundle_sha256":           sum,
		"bytes":                   stat.Size(),
		"command_profile_version": profileVer,
	})
	return true, nil
}


func (h *Handler) audit(event string, fields map[string]any) {
	if h.AuditLog != nil {
		h.AuditLog(event, fields)
	}
}

// PublicErrorCodes accepted by agent-evidence-fail.
var PublicErrorCodes = map[string]struct{}{
	"credential_profile_missing":    {},
	"ssh_auth_failed":               {},
	"host_key_failed":               {},
	"host_key_verification_failed":  {},
	"command_profile_failed":        {},
	"bundle_generation_failed":      {},
	"upload_url_expired":            {},
	"upload_failed":                 {},
	"capability_disabled":           {},
	"lan_only_mode":                 {},
	"target_not_found":              {},
	"cancelled":                     {},
	// preview.22 — unified targets.json readiness vocabulary.
	"target_configuration_missing":  {},
	"target_configuration_invalid":  {},
	"target_not_configured":         {},
	"ssh_setup_pending":             {},
	"ssh_probe_stale":               {},
	"ssh_not_ready":                 {},
	"ssh_key_missing":               {},
	"ssh_key_unreadable":            {},
	"known_hosts_missing":           {},
	// preview.23 — artifact directory writability failure surfaced distinctly
	// so the UI can point operators at the read-only /var/lib fix without
	// inspecting nested hints on bundle_generation_failed.
	"artifact_dir_not_writable":     {},
}

type codedError interface{ Code() string }

func errorCode(err error, fallback string) string {
	var ce codedError
	if errors.As(err, &ce) {
		if _, ok := PublicErrorCodes[ce.Code()]; ok {
			return ce.Code()
		}
	}
	return fallback
}

// ── Low-level HTTP client ─────────────────────────────────────────

type intentResp struct {
	UploadURL     string `json:"uploadUrl"`
	StorageBucket string `json:"storageBucket"`
	StoragePath   string `json:"storagePath"`
	ContentType   string `json:"contentType"`
	MaxBytes      int64  `json:"maxBytes"`
}

func (c *Client) doJSON(ctx context.Context, path string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := c.token(); tok != "" {
		req.Header.Set("x-connector-token", tok) // NEVER log
	}
	resp, err := c.http().Do(req)

	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s [%d]: %s", path, resp.StatusCode, string(msg))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) claim(ctx context.Context, agentVersion string) (*ClaimedJob, error) {
	var wrap struct {
		Job *ClaimedJob `json:"job"`
	}
	if err := c.doJSON(ctx, "/functions/v1/agent-evidence-claim",
		map[string]any{"agentVersion": agentVersion}, &wrap); err != nil {
		return nil, err
	}
	return wrap.Job, nil
}

func (c *Client) uploadIntent(ctx context.Context, jobID string, size int64) (*intentResp, error) {
	var out intentResp
	if err := c.doJSON(ctx, "/functions/v1/agent-evidence-upload-intent",
		map[string]any{"jobId": jobID, "sizeBytes": size}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) putBundle(ctx context.Context, url string, body io.Reader, size int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/zip")
	req.ContentLength = size
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload PUT %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

func (c *Client) reportComplete(ctx context.Context, jobID, sha string, profileVer string) error {
	return c.doJSON(ctx, "/functions/v1/agent-evidence-complete",
		map[string]any{
			"jobId":                  jobID,
			"bundleSha256":           sha,
			"commandProfileVersion":  profileVer,
			"agentVersion":           c.AgentVersion,
		}, nil)
}

func (c *Client) reportFail(ctx context.Context, jobID, publicCode, internalCode, msg string) error {
	return c.doJSON(ctx, "/functions/v1/agent-evidence-fail",
		map[string]any{
			"jobId":                 jobID,
			"publicErrorCode":       publicCode,
			"internalErrorCode":     internalCode,
			"internalErrorMessage":  msg,
		}, nil)
}
