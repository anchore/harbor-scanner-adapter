package anchore

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
)

// The result storage system supports an async loading of the merged results of a vuln response and descriptions
// This exists to decouple the construction of a Harbor report request from the set of Anchore API calls needed to populate it.

type ResultStore interface {
	HasResult(
		scanID string,
	) bool // Check if a result is available
	RequestResult(
		scanID string,
		buildFn func() (*harbor.VulnerabilityReport, error),
	) VulnerabilityResult // Request a result to be created
	PopResult(
		scanID string,
	) (VulnerabilityResult, bool) // Returns a result and true if found, false if not (e.g. like hash map interface)
}

type VulnerabilityResult struct {
	ScanID     string
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

func (m MemoryResultStore) HasResult(scanID string) bool {
	found, ok := m.Results[scanID]
	log.Debugf("HasResult: %v", found)
	return ok && found.IsComplete
}

func (m MemoryResultStore) PopResult(scanID string) (VulnerabilityResult, bool) {
	found, ok := m.Results[scanID]
	if found.IsComplete {
		log.WithField("scanId", scanID).Debug("found completed result and removing from store to return to caller")
		delete(m.Results, scanID)
	} else {
		log.WithField("scanId", scanID).Debug("found result in store, but not complete, so not removing from store")
	}

	return found, ok
}

func (m MemoryResultStore) RequestResult(
	scanID string,
	buildFn func() (*harbor.VulnerabilityReport, error),
) VulnerabilityResult {
	existing, ok := m.PopResult(scanID)

	if !ok {
		// Result not found so begin the async fetch
		go func() {
			result, err := buildFn()
			if err != nil {
				log.Debugf("error building result for %v: %v", scanID, err)
				resultChannel <- VulnerabilityResult{scanID, true, nil, err}
			} else {
				log.Debugf("result built for %v", scanID)
				resultChannel <- VulnerabilityResult{scanID, true, result, nil}
			}
		}()
		existing = VulnerabilityResult{ScanID: scanID, IsComplete: false, Result: nil, Error: fmt.Errorf("result not ready")}
		m.Results[scanID] = existing
	}
	return existing
}

func (m MemoryResultStore) resultRetriever() {
	for {
		report := <-resultChannel
		log.WithFields(log.Fields{"scanId": report.ScanID, "isComplete": report.IsComplete, "reportError": report.Error}).
			Debug("scan result added to result store")
		m.Results[report.ScanID] = report
	}
}

func (m MemoryResultStore) Start() {
	log.Info("starting result fetch loop")
	go m.resultRetriever()
}
