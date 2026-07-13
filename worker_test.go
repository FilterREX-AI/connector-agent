// Regression tests for the supervisor/worker startup deadlock fix.
//
// The original bug: Reconcile() holds s.mu → calls worker.Start() →
// Start() synchronously calls notifyStateChange → callback re-enters
// supervisor and tries to acquire s.mu → deadlock.

package main

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// --- Fake adapter for testing ---

type fakeAdapter struct {
	initErr      error
	initDelay    time.Duration
	collectCount int
	mu           sync.Mutex
	closed       bool
}

func (f *fakeAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	if f.initDelay > 0 {
		time.Sleep(f.initDelay)
	}
	return f.initErr
}

func (f *fakeAdapter) Collect() (map[string]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.collectCount++
	return map[string]interface{}{"ok": true}, nil
}

func (f *fakeAdapter) Capabilities() []string {
	return []string{"test"}
}

func (f *fakeAdapter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeAdapter) HealthCheck() error {
	return nil
}


type fakeBackendPost struct{}

// --- Tests ---

// TestWorkerRunningOnlyAfterInit verifies that Running is emitted only
// after adapter.Init() succeeds, not during Start().
func TestWorkerRunningOnlyAfterInit(t *testing.T) {
	adapter := &fakeAdapter{initDelay: 50 * time.Millisecond}
	var stateChanges []WorkerStatus
	var mu sync.Mutex

	w := NewWorker(WorkerConfig{
		Profile: &TargetProfile{
			TargetID:         "test-1",
			TargetType:       "test",
			Name:             "test-target",
			PollIntervalSecs: 3600, // long interval so it doesn't re-collect
		},
		Adapter: adapter,
		Creds:   map[string]string{},
		Policy:  DefaultRetryPolicy(),
		Backend: &BackendClient{BaseURL: "http://localhost:0"},
		OnStateChange: func(targetID string, status WorkerStatus) {
			mu.Lock()
			stateChanges = append(stateChanges, status)
			mu.Unlock()
		},
	})

	err := w.Start()
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}

	// Immediately after Start(), status should be "starting", not "running"
	state := w.State()
	if state.Status == WorkerStatusRunning {
		t.Fatal("worker reported Running immediately after Start() — before init")
	}

	// Wait for init to complete
	time.Sleep(200 * time.Millisecond)

	state = w.State()
	if state.Status != WorkerStatusRunning {
		t.Fatalf("expected Running after init, got %s", state.Status)
	}

	mu.Lock()
	found := false
	for _, s := range stateChanges {
		if s == WorkerStatusRunning {
			found = true
		}
	}
	mu.Unlock()
	if !found {
		t.Fatal("notifyStateChange(Running) was never called")
	}

	w.Stop()
}

// TestWorkerFailedInitDoesNotEmitRunning verifies that a failed Init
// does not produce a Running notification.
func TestWorkerFailedInitDoesNotEmitRunning(t *testing.T) {
	adapter := &fakeAdapter{initErr: fmt.Errorf("connection refused")}
	var stateChanges []WorkerStatus
	var mu sync.Mutex

	w := NewWorker(WorkerConfig{
		Profile: &TargetProfile{
			TargetID:         "test-fail",
			TargetType:       "test",
			Name:             "fail-target",
			PollIntervalSecs: 3600,
		},
		Adapter: adapter,
		Creds:   map[string]string{},
		Policy:  DefaultRetryPolicy(),
		Backend: &BackendClient{BaseURL: "http://localhost:0"},
		OnStateChange: func(targetID string, status WorkerStatus) {
			mu.Lock()
			stateChanges = append(stateChanges, status)
			mu.Unlock()
		},
	})

	err := w.Start()
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}

	// Wait for the goroutine to fail init
	time.Sleep(200 * time.Millisecond)

	state := w.State()
	if state.Status == WorkerStatusRunning {
		t.Fatal("worker reported Running despite failed init")
	}
	if state.Status != WorkerStatusFailed {
		t.Fatalf("expected Failed after bad init, got %s", state.Status)
	}

	mu.Lock()
	for _, s := range stateChanges {
		if s == WorkerStatusRunning {
			t.Fatal("Running was emitted despite failed init")
		}
	}
	mu.Unlock()
}

// TestSupervisorReconcileDoesNotDeadlock is the core regression test.
// It creates a real supervisor with a fake adapter factory and reconciles
// with a target. If the deadlock is present, this test will hang and
// the test runner will time out.
func TestSupervisorReconcileDoesNotDeadlock(t *testing.T) {
	store, _ := NewStore("/tmp/forgeai-test-deadlock-" + fmt.Sprintf("%d", time.Now().UnixNano()), false)

	backend := &BackendClient{BaseURL: "http://localhost:0"}
	sup := NewSupervisor(store, backend)

	sup.RegisterAdapter("test", func(p *TargetProfile) (TargetAdapter, error) {
		return &fakeAdapter{initDelay: 10 * time.Millisecond}, nil
	})

	sup.InitializeWithState(&HostState{
		Identity: HostIdentity{
			HostID:         "test-host",
			ConnectorToken: "test-token",
			Label:          "test",
		},
		Config: DefaultHostConfig(),
		Targets: []TargetProfile{
			{
				TargetID:         "target-1",
				TargetType:       "test",
				Name:             "Test Target",
				Enabled:          true,
				PollIntervalSecs: 3600,
				Status:           TargetStatusPending,
			},
		},
		Version: 1,
	})

	// This will deadlock (and time out) if the bug is present
	done := make(chan error, 1)
	go func() {
		done <- sup.Reconcile()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Reconcile() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Reconcile() deadlocked — did not complete within 5 seconds")
	}

	// Wait for workers to init
	time.Sleep(200 * time.Millisecond)

	workers := sup.Status()
	if len(workers) == 0 {
		t.Fatal("no workers started after reconcile")
	}
	if workers[0].Status != WorkerStatusRunning {
		t.Fatalf("expected worker Running, got %s", workers[0].Status)
	}

	sup.Shutdown()
}

// TestSupervisorMultipleTargetsNoDeadlock verifies that reconciling
// multiple targets simultaneously does not deadlock.
func TestSupervisorMultipleTargetsNoDeadlock(t *testing.T) {
	store, _ := NewStore("/tmp/forgeai-test-multi-" + fmt.Sprintf("%d", time.Now().UnixNano()), false)
	backend := &BackendClient{BaseURL: "http://localhost:0"}
	sup := NewSupervisor(store, backend)

	sup.RegisterAdapter("test", func(p *TargetProfile) (TargetAdapter, error) {
		return &fakeAdapter{initDelay: 10 * time.Millisecond}, nil
	})

	targets := make([]TargetProfile, 5)
	for i := range targets {
		targets[i] = TargetProfile{
			TargetID:         fmt.Sprintf("target-%d", i),
			TargetType:       "test",
			Name:             fmt.Sprintf("Target %d", i),
			Enabled:          true,
			PollIntervalSecs: 3600,
			Status:           TargetStatusPending,
		}
	}

	sup.InitializeWithState(&HostState{
		Identity: HostIdentity{
			HostID:         "test-host-multi",
			ConnectorToken: "test-token",
			Label:          "test",
		},
		Config:  DefaultHostConfig(),
		Targets: targets,
		Version: 1,
	})

	done := make(chan error, 1)
	go func() {
		done <- sup.Reconcile()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Reconcile() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Reconcile() deadlocked with multiple targets")
	}

	time.Sleep(300 * time.Millisecond)

	workers := sup.Status()
	if len(workers) != 5 {
		t.Fatalf("expected 5 workers, got %d", len(workers))
	}

	for _, ws := range workers {
		if ws.Status != WorkerStatusRunning {
			t.Fatalf("worker %s not Running: %s", ws.TargetID, ws.Status)
		}
	}

	sup.Shutdown()
}

// TestWorkerProfileStableAfterTargetRemoval is the core regression test for
// the slice-pointer aliasing bug. It verifies that after removing targets,
// surviving workers still reference the correct TargetID and TargetType —
// not a shifted slice element.
func TestWorkerProfileStableAfterTargetRemoval(t *testing.T) {
	store, _ := NewStore("/tmp/forgeai-test-alias-"+fmt.Sprintf("%d", time.Now().UnixNano()), false)
	backend := &BackendClient{BaseURL: "http://localhost:0"}
	sup := NewSupervisor(store, backend)

	sup.RegisterAdapter("typeA", func(p *TargetProfile) (TargetAdapter, error) {
		return &fakeAdapter{initDelay: 10 * time.Millisecond}, nil
	})
	sup.RegisterAdapter("typeB", func(p *TargetProfile) (TargetAdapter, error) {
		return &fakeAdapter{initDelay: 10 * time.Millisecond}, nil
	})

	// 5 targets: first 3 are typeA (will be removed), last 2 are typeB (survive)
	targets := []TargetProfile{
		{TargetID: "rm-1", TargetType: "typeA", Name: "Remove 1", Enabled: true, PollIntervalSecs: 3600, Status: TargetStatusPending},
		{TargetID: "rm-2", TargetType: "typeA", Name: "Remove 2", Enabled: true, PollIntervalSecs: 3600, Status: TargetStatusPending},
		{TargetID: "rm-3", TargetType: "typeA", Name: "Remove 3", Enabled: true, PollIntervalSecs: 3600, Status: TargetStatusPending},
		{TargetID: "keep-1", TargetType: "typeB", Name: "Keep 1", Enabled: true, PollIntervalSecs: 3600, Status: TargetStatusPending},
		{TargetID: "keep-2", TargetType: "typeB", Name: "Keep 2", Enabled: true, PollIntervalSecs: 3600, Status: TargetStatusPending},
	}

	sup.InitializeWithState(&HostState{
		Identity: HostIdentity{HostID: "test-alias", ConnectorToken: "test-token", Label: "test"},
		Config:   DefaultHostConfig(),
		Targets:  targets,
		Version:  1,
	})

	// Start all 5 workers
	done := make(chan error, 1)
	go func() { done <- sup.Reconcile() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Reconcile() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Reconcile() deadlocked")
	}

	time.Sleep(200 * time.Millisecond)

	// Verify all 5 running
	workers := sup.Status()
	if len(workers) != 5 {
		t.Fatalf("expected 5 workers, got %d", len(workers))
	}

	// Remove the first 3 targets (simulates desired-state sync after bulk move)
	for _, id := range []string{"rm-1", "rm-2", "rm-3"} {
		if err := sup.RemoveTarget(id); err != nil {
			t.Fatalf("RemoveTarget(%s) error: %v", id, err)
		}
	}

	time.Sleep(200 * time.Millisecond)

	// The 2 surviving workers must still report their original TargetID and type
	workers = sup.Status()
	if len(workers) != 2 {
		t.Fatalf("expected 2 workers after removal, got %d", len(workers))
	}

	foundKeep1, foundKeep2 := false, false
	for _, ws := range workers {
		switch ws.TargetID {
		case "keep-1":
			foundKeep1 = true
		case "keep-2":
			foundKeep2 = true
		default:
			t.Fatalf("unexpected surviving worker: %s", ws.TargetID)
		}
	}
	if !foundKeep1 || !foundKeep2 {
		t.Fatal("not all expected workers survived")
	}

	// Verify FindTarget still returns correct types (not aliased data)
	for _, id := range []string{"keep-1", "keep-2"} {
		tp := sup.FindTarget(id)
		if tp == nil {
			t.Fatalf("FindTarget(%s) returned nil", id)
		}
		if tp.TargetType != "typeB" {
			t.Fatalf("FindTarget(%s) has wrong type: got %s, want typeB", id, tp.TargetType)
		}
		if tp.Name != "Keep 1" && tp.Name != "Keep 2" {
			t.Fatalf("FindTarget(%s) has wrong name: got %s", id, tp.Name)
		}
	}

	sup.Shutdown()
}
