// ForgeAI Connector Host — System Commands
//
// Handles platform="system" relay commands such as agent-restart
// and agent-version. Extracted from relay.go for clarity.

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"time"
)

// executeSystemCommand handles platform="system" commands (restart, version, etc.).
// Each operation checks its own granular permission flag.
func (rh *RelayHandler) executeSystemCommand(cmd RelayCommand, start time.Time) RelayResult {
	switch cmd.OperationID {
	case "agent-restart":
		// Check granular restart permission
		hostState := rh.supervisor.GetState()
		if hostState == nil || !hostState.Config.RemoteRestartEnabled {
			log.Printf("[system] REJECTED restart cmd=%s: remote restart is disabled (set FORGEAI_REMOTE_RESTART=true to enable)", cmd.ID)
			return RelayResult{
				ID:           cmd.ID,
				ErrorMessage: "Remote restart is disabled on this host. Set FORGEAI_REMOTE_RESTART=true or enable via host config.",
				DurationMs:   time.Since(start).Milliseconds(),
			}
		}
		return rh.handleAgentRestart(cmd, start)
	case "agent-version":
		// Version query is always allowed (informational only)
		return rh.handleAgentVersion(cmd, start)
	default:
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("unknown system operation %q", cmd.OperationID),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}
}

// handleAgentRestart performs a graceful shutdown sequence:
//  1. Log the restart request
//  2. Post acknowledgment result to the cloud
//  3. Signal the supervisor to drain workers (finish in-flight collections)
//  4. Flush the upload queue
//  5. Send SIGTERM so Docker's restart policy brings the container back
func (rh *RelayHandler) handleAgentRestart(cmd RelayCommand, start time.Time) RelayResult {
	log.Printf("[system] ⚡ Restart requested by user (cmd=%s)", cmd.ID)

	result := RelayResult{
		ID:             cmd.ID,
		ResponseStatus: 200,
		ResponseData: map[string]interface{}{
			"message": "Agent restart initiated — graceful shutdown in progress",
			"version": HostVersion,
		},
		DurationMs: time.Since(start).Milliseconds(),
	}

	// Post acknowledgment immediately so the UI knows the command was received
	rh.postResults([]RelayResult{result})
	log.Printf("[system] Restart acknowledgment sent to cloud")

	// Graceful shutdown in a goroutine so ProcessCommands can return
	go func() {
		log.Printf("[system] Starting graceful shutdown sequence...")

		// 1. Drain workers — finish any in-flight snapshot or collection
		log.Printf("[system] Draining workers (waiting up to 15s for in-flight work)...")
		drainDone := make(chan struct{})
		go func() {
			rh.supervisor.Shutdown()
			close(drainDone)
		}()
		select {
		case <-drainDone:
			log.Printf("[system] All workers stopped cleanly")
		case <-time.After(15 * time.Second):
			log.Printf("[system] Worker drain timed out after 15s — proceeding with restart")
		}

		// 2. Allow upload queue to flush remaining snapshots
		log.Printf("[system] Flushing upload queue...")
		time.Sleep(2 * time.Second)

		// 3. Send SIGTERM to trigger the main process shutdown path
		log.Printf("[system] Sending SIGTERM — container will restart via Docker restart policy")
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGTERM)
	}()

	// Return a dummy result — the real one was already posted above
	return RelayResult{ID: cmd.ID, ResponseStatus: 200}
}

// handleAgentVersion returns the current agent version.
func (rh *RelayHandler) handleAgentVersion(cmd RelayCommand, start time.Time) RelayResult {
	return RelayResult{
		ID:             cmd.ID,
		ResponseStatus: 200,
		ResponseData: map[string]interface{}{
			"version": HostVersion,
		},
		DurationMs: time.Since(start).Milliseconds(),
	}
}
