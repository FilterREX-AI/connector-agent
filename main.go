// FilterREX Connector Host — Entrypoint
//
// The Connector Host is a long-running supervisor process that manages
// per-target workers. It supports:
//   - Secure host enrollment with bootstrap token
//   - Desired-state sync from FilterREX backend
//   - Multiple concurrent targets (proxmox, truenas, etc.)
//   - Independent worker lifecycle per target
//   - Encrypted local config/secret storage
//   - Legacy single-target env-var mode for backward compatibility
//
// Usage (Enrollment — recommended):
//   FILTERREX_ENROLLMENT_TOKEN=frc_... ./connector-agent
//
// Usage (Legacy mode — single target via env vars):
//   CONNECTOR_TOKEN=frc_... TARGET_TYPE=proxmox PROXMOX_BASE_URL=... ./connector-agent

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/filterrex-ai/connector-agent/targetconfigure"
)

// displayVersion returns the human-facing version string. HostVersion is
// injected by the build via -ldflags; CI historically passes the git tag
// (e.g. "v0.1.0-preview.3"), but a plain "0.1.0-preview.3" is also valid.
// Always render exactly one leading "v" so the startup banner and --version
// output never doubles it. Returns "unknown" when HostVersion is empty.
func displayVersion() string {
	v := strings.TrimSpace(HostVersion)
	if v == "" {
		return "unknown"
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// resolveBrocadeTargetsDir returns the directory the daemon should read
// targets.json from. Precedence: FILTERREX_BROCADE_TARGETS_DIR env override,
// then <configDir>/targets. Whitespace-only env values are treated as unset.
// Kept as a pure function so preview.17's fix has a regression test that
// does not depend on process env or the filesystem.
func resolveBrocadeTargetsDir(envOverride, configDir string) string {
	if v := strings.TrimSpace(envOverride); v != "" {
		return v
	}
	return filepath.Join(configDir, "targets")
}

// targetConfigureRunner matches targetconfigure.Run so main dispatch can be
// unit-tested without invoking the real interactive wizard.
type targetConfigureRunner func(args []string) int

// dispatch handles subcommands that must run WITHOUT starting the supervisor
// (upload queue, relay, local API). Returns (handled, exitCode).
//
// Subcommands here are deliberate local operator actions on the agent host —
// they are NOT reachable over the cloud relay or the local API. When
// `handled` is true the caller must os.Exit(exitCode) immediately; the
// supervisor must not run.
func dispatch(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	runTargetConfigure targetConfigureRunner,
) (handled bool, exitCode int) {
	// --version / -v short-circuit
	for _, arg := range args {
		if arg == "--version" || arg == "-v" {
			fmt.Fprintf(stdout, "FilterREX Connector Host %s\n", displayVersion())
			return true, 0
		}
	}

	if len(args) >= 1 && args[0] == "target" {
		if len(args) >= 2 && args[1] == "configure" {
			return true, runTargetConfigure(args[2:])
		}
		if len(args) >= 2 && args[1] == "probe" {
			return true, targetconfigure.RunProbe(args[2:])
		}
		// Fail-closed: unknown "target" subcommand must not silently boot the daemon.
		sub := ""
		if len(args) >= 2 {
			sub = strings.Join(args[1:], " ")
		}
		fmt.Fprintf(stderr, "unknown target subcommand: %q (supported: configure, probe)\n", sub)
		return true, 2
	}

	return false, 0
}

func main() {
	// Propagate the ldflag-injected host version into the target-configure
	// wizard so its startup banner reflects the actual image tag instead of
	// a stale hardcoded string.
	targetconfigure.WizardVersion = displayVersion()

	if handled, code := dispatch(os.Args[1:], os.Stdout, os.Stderr, targetconfigure.Run); handled {
		os.Exit(code)
	}

	// Handle local, operator-initiated subcommands before starting the
	// supervisor. These are deliberate local actions on the agent host — they
	// are NOT reachable over the cloud relay or the local API.
	if len(os.Args) > 1 && os.Args[1] == "export-brocade-bundle" {
		runExportBrocadeBundleCLI(os.Args[2:])
		return
	}


	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	// Initialize audit logger early — use env LOG_LEVEL or default "info"
	configLevel := os.Getenv("LOG_LEVEL")
	if configLevel == "" {
		configLevel = "info"
	}
	InitAuditLogger(configLevel)

	execPath, _ := os.Executable()
	audit.Info("host.startup", fmt.Sprintf("FilterREX Connector Host %s starting", displayVersion()),
		F("executable", execPath),
		F("pid", os.Getpid()))

	// ── Read remote action opt-in flags from environment ──
	remoteLiveQuery := envBool("FILTERREX_REMOTE_LIVE_QUERY")
	remoteRestart := envBool("FILTERREX_REMOTE_RESTART")
	// Convenience flag: --enable-remote-actions sets both
	if envBool("FILTERREX_REMOTE_ACTIONS") {
		remoteLiveQuery = true
		remoteRestart = true
	}

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = defaultConfigDir
	}

	// Brocade `target configure` / `target probe` write targets.json into a
	// dedicated subdirectory that is bind-mounted read-only into the
	// daemon container at /etc/filterrex/targets (see
	// src/types/connector.ts::getDockerRunCommand). The daemon MUST read
	// its per-target SSH readiness from that same directory — not from the
	// top-level configDir — or the heartbeat will publish REST-only
	// readiness and every "Collect from agent" request will fail the
	// server-side readiness gate with `ssh_not_ready`. Preview.16 and
	// earlier had this mismatch; preview.17 resolves it here.
	brocadeTargetsDir := resolveBrocadeTargetsDir(os.Getenv("FILTERREX_BROCADE_TARGETS_DIR"), configDir)
	audit.Info("host.startup", "Brocade targets directory resolved",
		F("path", brocadeTargetsDir))
	if _, err := os.Stat(filepath.Join(brocadeTargetsDir, "targets.json")); err != nil {
		if os.IsNotExist(err) {
			audit.Warn("host.startup",
				"Brocade targets.json not found — SSH readiness will be empty until `target configure` is run",
				F("path", filepath.Join(brocadeTargetsDir, "targets.json")))
		} else {
			audit.Warn("host.startup",
				"Brocade targets.json stat failed",
				F("path", filepath.Join(brocadeTargetsDir, "targets.json")),
				F("error", err.Error()))
		}
	}

	hybridMode := envBool("FILTERREX_HYBRID_MODE")
	if hybridMode {
		audit.Info("host.startup",
			"Hybrid Mode enabled — local DB will be activated")
	}

	// ── Local API token — stable across restarts ──
	localAPIToken := os.Getenv("FILTERREX_LOCAL_API_TOKEN")
	if localAPIToken == "" && hybridMode {
		// Try to load from persisted file first
		tokenPath := filepath.Join(configDir, "local_api_token")
		if stored, err := os.ReadFile(tokenPath); err == nil && len(stored) > 0 {
			localAPIToken = strings.TrimSpace(string(stored))
			audit.Info("local_api.start",
				"Local API token loaded from disk",
				F("token_prefix", localAPIToken[:8]))
		} else {
			localAPIToken = generateID()
			if err := os.WriteFile(tokenPath, []byte(localAPIToken), 0600); err != nil {
				audit.Warn("local_api.start",
					"Failed to persist local API token", Err(err))
			}
			audit.Info("local_api.start",
				"Local API token generated and persisted",
				F("token_prefix", localAPIToken[:8]))
		}
	}

	// ── Parse change-operation policy from environment ──
	changePolicyConfig := ParseChangePolicyFromEnv()
	changePolicyConfig.LogStartupSummary()

	// ── Check for --force-reset-state flag ──
	forceReset := false
	for _, arg := range os.Args[1:] {
		if arg == "--force-reset-state" {
			forceReset = true
		}
	}

	if forceReset {
		audit.Warn("host.config_loaded", "Force-reset: Clearing persisted enrollment state")
		resetFiles := []string{
			filepath.Join(configDir, stateFileName),
			filepath.Join(configDir, keyFileName),
		}
		for _, f := range resetFiles {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				audit.Error("host.config_loaded", "Failed to remove file", F("path", f), Err(err))
			} else if err == nil {
				audit.Info("host.config_loaded", "Removed file", F("path", f))
			}
		}
		// Remove all secret files
		secretsDir := filepath.Join(configDir, secretsDirName)
		entries, _ := os.ReadDir(secretsDir)
		for _, e := range entries {
			p := filepath.Join(secretsDir, e.Name())
			if err := os.Remove(p); err == nil {
				audit.Info("host.config_loaded", "Removed secret file", F("path", p))
			}
		}
		audit.Info("host.config_loaded", "State reset complete — host will re-enroll on this run")
	}

	// Initialize encrypted store
	store, err := NewStore(configDir, hybridMode)
	if err != nil {
		audit.Critical("host.startup", "Store initialization failed", Err(err))
		os.Exit(1)
	}

	// Determine backend URL (fail closed on empty / decommissioned backends)
	backendURL, err := resolveBackendBase(os.Getenv("BACKEND_URL"))
	if err != nil {
		audit.Critical("host.startup", "Invalid backend configuration", Err(err))
		os.Exit(1)
	}
	backend := NewBackendClient(backendURL)

	// Create supervisor
	supervisor := NewSupervisor(store, backend)
	// Point the supervisor at the Brocade targets subdirectory that the
	// `target configure` / `target probe` wizards write targets.json into.
	// This is /etc/filterrex/targets by default (bind-mounted from the
	// host's /opt/filterrex/secure) — NOT the top-level configDir.
	supervisor.SetTargetConfigDir(brocadeTargetsDir)



	// Register available adapters — built-in only, no dynamic plugins.
	// The concrete set is build-tagged: adapters_full.go (default) registers
	// every vendor adapter; adapters_sanonly.go (SAN-only public build)
	// registers just Brocade.
	registerAdapters(supervisor)

	// ── Enrollment / State Loading ──
	enrollmentToken := os.Getenv("FILTERREX_ENROLLMENT_TOKEN")
	legacyCfg := detectLegacyEnvConfig()

	if enrollmentToken != "" {
		// Enrollment flow
		state, err := MustEnroll(store, backendURL)
		if err != nil {
			audit.Critical("enrollment.failed", "Enrollment failed", Err(err))
			os.Exit(1)
		}
		supervisor.InitializeWithState(state)
		audit.SetHostID(state.Identity.HostID)
		audit.Info("enrollment.success", "Host enrolled",
			F("label", state.Identity.Label), F("host_id_short", state.Identity.HostID[:12]))
	} else {
		// Legacy / existing state flow
		if err := supervisor.Initialize(legacyCfg); err != nil {
			audit.Critical("host.startup", "Supervisor initialization failed", Err(err))
			os.Exit(1)
		}
		// Set host ID if state was loaded
		if state := supervisor.GetState(); state != nil && state.Identity.HostID != "" {
			audit.SetHostID(state.Identity.HostID)
		}
	}

	audit.Info("host.config_loaded", "Targets configured", F("count", supervisor.TargetCount()))

	// Apply remote action flags to host config
	if state := supervisor.GetState(); state != nil {
		if remoteLiveQuery {
			state.Config.RemoteLiveQueryEnabled = true
		}
		if remoteRestart {
			state.Config.RemoteRestartEnabled = true
		}
		if remoteLiveQuery || remoteRestart {
			audit.Info("host.config_loaded", "Remote actions configured",
				F("live_query", state.Config.RemoteLiveQueryEnabled),
				F("restart", state.Config.RemoteRestartEnabled))
		} else {
			audit.Info("host.config_loaded", "Remote actions disabled (set FILTERREX_REMOTE_LIVE_QUERY=true and/or FILTERREX_REMOTE_RESTART=true to enable)")
		}

		// Update audit logger level from persisted config
		audit.SetLevel(parseLogLevel(state.Config.LogLevel))
	}

	// ── Upload Queue ──
	uqCfg := DefaultUploadQueueConfig()
	uqCfg.LocalDB = store.LocalDB()
	uploadQueue := NewUploadQueue(backend, uqCfg)
	// Set connector token so replayed snapshots use valid credentials
	if token := supervisor.GetConnectorToken(); token != "" {
		uploadQueue.connectorToken = token
	}
	uploadQueue.Start()
	supervisor.SetUploadQueue(uploadQueue)

	// Wire reconnect callback: replay unsynced snapshots, broadcast
	// heartbeats, and trigger immediate desired-state refresh on
	// backend recovery.
	var syncMgrPtr *SyncManager
	uploadQueue.SetOnReconnect(func() {
		// Replay snapshots that were deferred
		// during the outage (written to local DB).
		uploadQueue.ReplayUnsynced()

		// Broadcast current worker status to
		// backend so last_worker_status clears
		// the stale "failed" state from before
		// the outage.
		audit.Info("upload.reconnect",
			"Backend connectivity restored — broadcasting "+
				"worker status and triggering desired-state refresh")
		supervisor.BroadcastHeartbeat()

		// Trigger an immediate desired-state sync so the
		// agent picks up any control-plane changes that
		// arrived during the outage.
		if syncMgrPtr != nil {
			syncMgrPtr.TriggerSync()
		}
	})

	// ── Metrics Logger ──
	metricsStopCh := make(chan struct{})
	StartMetricsLogger(5*time.Minute, metricsStopCh)

	// ── Hybrid Mode: local DB retention goroutine ──
	var retentionStopCh chan struct{}
	if ldb := store.LocalDB(); ldb != nil {
		retentionStopCh = make(chan struct{})
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-retentionStopCh:
					return
				case <-ticker.C:
					maxDays := 7
					if st := supervisor.GetState(); st != nil {
						if d := st.Config.LocalRetentionDays; d > 0 {
							maxDays = d
						}
					}
					if _, err := ldb.RunRetention(maxDays); err != nil {
						audit.Error("local_db.retention",
							"Retention run failed", Err(err))
					}
				}
			}
		}()
		audit.Info("local_db.retention",
			"Retention goroutine started",
			F("default_days", 7))
	}

	// ── Local API Server (Hybrid Mode) ──
	// Must be set up BEFORE Reconcile() so workers get the LAN URL/token
	// at creation time and include them in heartbeats.
	// Create a RelayHandler for direct LAN execution via /v1/execute.
	var localAPI *LocalAPIServer
	var localRelayHandler *RelayHandler
	if ldb := store.LocalDB(); ldb != nil {
		localRelayHandler = NewRelayHandler(supervisor, backend, store, changePolicyConfig)

		bind := os.Getenv("FILTERREX_LOCAL_API_BIND")
		if bind == "" {
			bind = defaultLocalAPIBind
		}
		localAPI = NewLocalAPIServer(
			ldb, supervisor, localAPIToken, bind, configDir, localRelayHandler)
		localAPI.Start()

		// Register LAN URL and token on supervisor so workers include
		// them in heartbeat payloads
		supervisor.SetLocalAPIURL(localAPI.LANURL())
		supervisor.SetLocalAPIToken(localAPIToken)

		stats := ldb.Stats()
		audit.Info("local_db.stats", "Local DB ready",
			F("snapshot_count", stats["snapshot_count"]),
			F("unsynced_count", stats["unsynced_count"]))

		// Give TLS init a moment to update the LAN URL
		// then re-register with the https scheme
		go func() {
			time.Sleep(500 * time.Millisecond)
			supervisor.SetLocalAPIURL(localAPI.LANURL())
			audit.Info("local_api.start",
				"LAN URL finalised",
				F("url", localAPI.LANURL()))
		}()
	}

	// Reconcile — starts workers for all enabled targets
	if err := supervisor.Reconcile(); err != nil {
		audit.Critical("host.startup", "Reconciliation failed", Err(err))
		os.Exit(1)
	}

	// Start supervisor-level watchdog.
	// Separate from the per-collection watchdog in worker.run() —
	// handles inter-cycle freeze detection using stage + progress timestamps.
	watchdogCtx, watchdogCancel := context.WithCancel(context.Background())
	defer watchdogCancel()
	go supervisor.RunWatchdog(watchdogCtx)
	audit.Info("watchdog.started", "Supervisor watchdog active", F("scan_interval_secs", 20))

	go supervisor.RunLocalReconcile(watchdogCtx)
	audit.Info("watchdog.started", "Local reconcile loop active", F("interval_secs", 60))

	audit.Info("host.startup", "Active workers started", F("count", supervisor.WorkerCount()))

	// Set up signal channel early for use by update goroutine
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── Desired-State Sync Loop ──
	var syncManager *SyncManager
	if token := supervisor.GetConnectorToken(); token != "" {
		syncInterval := 60 * time.Second
		if state := supervisor.GetState(); state != nil && state.Config.SyncIntervalSecs > 0 {
			syncInterval = time.Duration(state.Config.SyncIntervalSecs) * time.Second
		}

		syncManager = NewSyncManager(backend, store, supervisor, changePolicyConfig)
		syncManager.Start(syncInterval)
		audit.Info("sync.reconciled", "Desired-state sync enabled", F("interval", syncInterval.String()))
		syncMgrPtr = syncManager

		// ── Remote SSH readiness probe wiring (preview.16) ──
		// The RelayHandler embedded in SyncManager and (when hybrid mode
		// is on) the localRelayHandler both execute the `brocade-probe`
		// platform. Give both a config-dir + heartbeat trigger so the
		// probe capability can be advertised.
		syncManager.RelayHandler().SetProbeContext(brocadeTargetsDir, syncManager)
		if localRelayHandler != nil {
			localRelayHandler.SetProbeContext(brocadeTargetsDir, syncManager)
		}
		// Advertise probe_brocade_ssh_readiness_v1 only once we know a
		// probe handler is fully wired. LAN-only is re-checked each
		// heartbeat inside BuildCapabilityManifest.
		supervisor.SetProbeCapabilityReadyFunc(func() bool {
			return syncManager.RelayHandler().ProbeReady()
		})

		// Wire agent-evidence collection into the existing outbound poll.
		// The handler is invoked by SyncManager.commandPollLoop each tick;
		// see tickAgentEvidence. It is single-flight and never blocks.
		initAgentEvidenceRunner(
			backendURL,
			supervisor.GetConnectorToken,
			HostVersion,
			func() bool {
				if st := supervisor.GetState(); st != nil {
					return st.Config.LanOnly
				}
				return false
			},
		)

	} else {
		audit.Warn("sync.error", "No connector token — desired-state sync disabled")
		audit.Info("host.config_loaded", "Enroll the host to enable remote management")
	}


	// ── Update Manager ──
	var updateManager *UpdateManager
	updateMgr, err := NewUpdateManager(store, backend, supervisor, configDir)
	if err != nil {
		audit.Warn("update.check", "Update manager init failed", Err(err))
	} else {
		updateManager = updateMgr

		// Check for pending rollback from a previous failed update
		if updateManager.CheckRollbackNeeded() {
			audit.Warn("update.rollback", "Pending rollback detected — initiating automatic rollback")
			if err := updateManager.Rollback(); err != nil {
				audit.Error("update.rollback", "Rollback failed", Err(err))
			}
		} else {
			// Confirm health if this is a new version that just started
			updateManager.ConfirmHealth()
		}

		// Start periodic update checks if policy allows
		hostState := supervisor.GetState()
		updatePolicy := UpdatePolicy("none")
		if hostState != nil && hostState.Update.UpdatePolicy != "" {
			updatePolicy = UpdatePolicy(hostState.Update.UpdatePolicy)
		}

		if updatePolicy != UpdatePolicyNone {
			updateCtx, updateCancel := context.WithCancel(context.Background())
			defer updateCancel()

			go func() {
				checkInterval := 6 * time.Hour
				ticker := time.NewTicker(checkInterval)
				defer ticker.Stop()

				for {
					select {
					case <-updateCtx.Done():
						return
					case <-ticker.C:
						manifest, err := updateManager.CheckForUpdate(updatePolicy)
						if err != nil {
							audit.Error("update.check", "Update check error", Err(err))
							continue
						}
						if manifest != nil {
							audit.Info("update.available", "Update available",
								F("version", manifest.Version), F("channel", manifest.Channel))
							if err := updateManager.StageUpdate(manifest); err != nil {
								audit.Error("update.staged", "Stage failed", Err(err))
							}
						}
					}
				}
			}()
			audit.Info("update.check", "Update checks enabled", F("policy", string(updatePolicy)))
		} else {
			audit.Info("update.check", "Auto-updates disabled (policy: none)")
		}
	}

	// Wait for shutdown signal
	sig := <-sigCh

	audit.Info("host.shutdown", fmt.Sprintf("Received %v, shutting down gracefully...", sig))

	// Stop metrics logger
	close(metricsStopCh)

	// Final metrics dump
	agentMetrics.DumpToLog()

	if syncManager != nil {
		syncManager.Stop()
	}
	if updateManager != nil {
		updateManager.DrainWorkers(10 * time.Second)
	} else {
		supervisor.Shutdown()
	}

	// Stop upload queue after workers are done
	uploadQueue.Stop()

	if localAPI != nil {
		localAPI.Stop()
	}

	if retentionStopCh != nil {
		close(retentionStopCh)
	}
	if ldb := store.LocalDB(); ldb != nil {
		if err := ldb.Close(); err != nil {
			audit.Warn("local_db.shutdown",
				"Local DB close error", Err(err))
		} else {
			audit.Info("local_db.shutdown",
				"Local DB closed cleanly")
		}
	}

	audit.Info("host.shutdown", "Shutdown complete")
}

// detectLegacyEnvConfig checks for the old single-target environment
// variable configuration and returns a Config if found.
func detectLegacyEnvConfig() *Config {
	token := os.Getenv("CONNECTOR_TOKEN")
	if token == "" {
		return nil
	}

	// If FILTERREX_ENROLLMENT_TOKEN is set, don't treat CONNECTOR_TOKEN as legacy
	if os.Getenv("FILTERREX_ENROLLMENT_TOKEN") != "" {
		return nil
	}

	if !strings.HasPrefix(token, "frc_") {
		audit.Warn("host.config_loaded", "CONNECTOR_TOKEN does not start with frc_")
	}

	targetType := strings.ToLower(os.Getenv("TARGET_TYPE"))
	if targetType == "" {
		// No target type = just a token for enrollment, not legacy mode
		return nil
	}

	c := &Config{
		ConnectorToken:      token,
		BackendURL:          os.Getenv("BACKEND_URL"),
		TargetType:          targetType,
		ProxmoxBaseURL:      strings.TrimRight(os.Getenv("PROXMOX_BASE_URL"), "/"),
		ProxmoxUsername:     os.Getenv("PROXMOX_USERNAME"),
		ProxmoxPassword:    os.Getenv("PROXMOX_PASSWORD"),
		ProxmoxTokenID:     os.Getenv("PROXMOX_TOKEN_ID"),
		ProxmoxTokenSecret: os.Getenv("PROXMOX_TOKEN_SECRET"),
		ProxmoxNode:        os.Getenv("PROXMOX_NODE"),
		TrueNASURL:         strings.TrimRight(os.Getenv("TRUENAS_URL"), "/"),
		TrueNASAPIKey:      os.Getenv("TRUENAS_API_KEY"),
		LogLevel:           os.Getenv("LOG_LEVEL"),
	}

	if base, berr := resolveBackendBase(os.Getenv("BACKEND_URL")); berr != nil {
		audit.Critical("host.config_loaded", "Invalid backend configuration", Err(berr))
		os.Exit(1)
	} else if c.BackendURL == "" {
		c.BackendURL = base + defaultHeartbeatPath
	}

	c.PollIntervalSecs = 30
	if v := os.Getenv("POLL_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 {
			c.PollIntervalSecs = n
		}
	}

	if v := os.Getenv("INSECURE_SKIP_VERIFY"); v == "true" || v == "1" {
		c.InsecureSkipVerify = true
	}

	switch targetType {
	case "proxmox":
		if c.ProxmoxBaseURL == "" {
			audit.Warn("host.config_loaded", "PROXMOX_BASE_URL not set for proxmox target")
			return nil
		}
	case "truenas":
		if c.TrueNASURL == "" || c.TrueNASAPIKey == "" {
			audit.Warn("host.config_loaded", "TRUENAS_URL or TRUENAS_API_KEY not set")
			return nil
		}
	default:
		if !IsValidTargetType(targetType) {
			audit.Warn("host.config_loaded", "Unsupported TARGET_TYPE", F("target_type", targetType))
			return nil
		}
	}

	audit.Info("host.config_loaded", "Legacy env config detected", F("target_type", targetType))

	switch targetType {
	case "proxmox":
		audit.Info("host.config_loaded", "Proxmox endpoint", F("url", c.ProxmoxBaseURL))
		if c.ProxmoxNode != "" {
			audit.Info("host.config_loaded", "Limiting to node", F("node", c.ProxmoxNode))
		}
	case "truenas":
		audit.Info("host.config_loaded", "TrueNAS endpoint", F("url", c.TrueNASURL))
	}

	if c.InsecureSkipVerify {
		audit.Warn("host.config_loaded", "TLS verification DISABLED (self-signed)")
	}

	return c
}

// envBool returns true if the named environment variable is set to "true" or "1".
func envBool(name string) bool {
	v := os.Getenv(name)
	return v == "true" || v == "1"
}
