package anchore

import (
	"fmt"

	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
	log "github.com/sirupsen/logrus"
)

// The result storage system supports an async loading of the merged results of a vuln response and descriptions
// This exists to decouple the construction of a Harbor report request from the set of Anchore API calls needed to populate it.

type ResultStore interface {
	HasResult(
		scanId string,
	) bool // Check if a result is available
	RequestResult(
		scanId string,
		buildFn func() (*harbor.VulnerabilityReport, error),
	) VulnerabilityResult // Request a result to be created
	PopResult(
		scanId string,
	) (VulnerabilityResult, bool) // Returns a result and true if found, false if not (e.g. like hash map interface)
}

type VulnerabilityResult struct {
	ScanId     string
	IsComplete bool
	Result     *harbor.VulnerabilityReport
	Error      error
}

type MemoryResultStore struct {
	Results map[string]VulnerabilityResult
}

var (
	resultChannel = make(chan VulnerabilityResult)
	resultStore   = NewResultStore()
)

func NewResultStore() ResultStore {
	newStore := MemoryResultStore{Results: make(map[string]VulnerabilityResult, 1000)}
	newStore.Start()
	return newStore
}

func (m MemoryResultStore) HasResult(scanId string) bool {
	found, ok := m.Results[scanId]
	log.Debugf("HasResult: %v", found)
	return ok && found.IsComplete
}

func (m MemoryResultStore) PopResult(scanId string) (VulnerabilityResult, bool) {
	found, ok := m.Results[scanId]
	if found.IsComplete {
		delete(m.Results, scanId)
	}
	return found, ok
}

func (m MemoryResultStore) RequestResult(
	scanId string,
	buildFn func() (*harbor.VulnerabilityReport, error),
) VulnerabilityResult {
	existing, ok := m.PopResult(scanId)

	if !ok {
		// Result not found so begin the async fetch
		go func() {
			result, err := buildFn()
			if err != nil {
				log.Debugf("error building result for %v: %v", scanId, err)
				resultChannel <- VulnerabilityResult{scanId, true, nil, err}
			} else {
				log.Debugf("result built for %v", scanId)
				resultChannel <- VulnerabilityResult{scanId, true, result, nil}
			}
		}()
		existing = VulnerabilityResult{ScanId: scanId, IsComplete: false, Result: nil, Error: fmt.Errorf("result not ready")}
		m.Results[scanId] = existing
	}
	return existing
}

func (m MemoryResultStore) resultRetriever() {
	log.Info("starting result fetch loop")
	for true {
		report := <-resultChannel
		m.Results[report.ScanId] = report
	}
}

func (m MemoryResultStore) Start() {
	// Start the retreiver loop
	go m.resultRetriever()
}
