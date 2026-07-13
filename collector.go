// ForgeAI Connector Host — Concurrent Sub-Collection
//
// Provides bounded concurrency helpers for multi-call adapters
// (Nutanix, PowerMax, Proxmox, etc.) to parallelize independent
// API sub-calls within a single collection cycle.

package main

import (
	"sync"
)

// SubCollectionTask represents one independent API call within a collection cycle.
type SubCollectionTask struct {
	Name string
	Fn   func() (map[string]interface{}, error)
}

// RunConcurrentCollection executes multiple sub-collection tasks with bounded concurrency.
// Returns a PartialCollectionResult with timing, status, and data for each section.
func RunConcurrentCollection(tasks []SubCollectionTask, maxConcurrency int) *PartialCollectionResult {
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}
	if maxConcurrency > len(tasks) {
		maxConcurrency = len(tasks)
	}

	result := NewPartialCollectionResult()
	type indexedResult struct {
		index  int
		name   string
		data   map[string]interface{}
		metric SubCallMetric
	}

	results := make([]indexedResult, len(tasks))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, task := range tasks {
		wg.Add(1)
		go func(idx int, t SubCollectionTask) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, metric := TimeSubCall(t.Name, t.Fn)
			results[idx] = indexedResult{
				index:  idx,
				name:   t.Name,
				data:   data,
				metric: metric,
			}
		}(i, task)
	}

	wg.Wait()

	// Collect results in original order for deterministic output
	for _, r := range results {
		result.AddSection(r.name, r.data, r.metric)
	}

	return result
}

// RunSequentialCollection executes sub-collection tasks sequentially.
// Use this when tasks have dependencies or rate-limiting concerns.
func RunSequentialCollection(tasks []SubCollectionTask) *PartialCollectionResult {
	result := NewPartialCollectionResult()

	for _, task := range tasks {
		data, metric := TimeSubCall(task.Name, task.Fn)
		result.AddSection(task.Name, data, metric)
	}

	return result
}
