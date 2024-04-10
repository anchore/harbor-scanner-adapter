package anchore

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
)

// The result storage system supports an async loading of the merged results of a vuln response and descriptions
// This exists to decouple the construction of a Harbor report request from the set of Anchore API calls needed to populate it.

type ResultStore interface {
	HasResult(
		scanID string,
	) bool // Check if a result is available
	RequestCreateScan(
		scanID string,
		buildFn func() (bool, error),
	) VulnerabilityResult // Request a result to be created and add image for analysis
	RequestAnalysisStatus(
		scanID string,
		buildFn func() (bool, error),
	) VulnerabilityResult // Request a result to be created and add image for analysis
	RequestResult(
		scanID string,
		buildFn func() (*harbor.VulnerabilityReport, error),
	) VulnerabilityResult // Request a result to be created
	RequestRawResult(
		scanID string,
		buildFn func() (*anchore.ImageVulnerabilityReport, error),
	) VulnerabilityResult
	SafeUpdateResult(
		scanID string,
		result VulnerabilityResult,
	) // Update a result in the store
	GetResult(
		scanID string,
	) (VulnerabilityResult, bool) // Get a result if it exists
	PopResult(
		scanID string,
	) (VulnerabilityResult, bool) // Returns a result and true if found, false if not (e.g. like hash map interface)
}

type VulnerabilityResult struct {
	ScanID                string
	ScanCreated           bool
	AnalysisComplete      bool
	ReportBuildInProgress bool
	IsComplete            bool
	Result                *harbor.VulnerabilityReport
	RawResult             *anchore.ImageVulnerabilityReport
	Error                 error
}

type MemoryResultStore struct {
	Results map[string]VulnerabilityResult
	mu      sync.Mutex
}

var (
	resultChannel = make(chan VulnerabilityResult)
	resultStore   = NewResultStore()
)

func NewResultStore() ResultStore {
	newStore := MemoryResultStore{Results: make(map[string]VulnerabilityResult, 1000)}
	newStore.Start()
	return &newStore
}

func (m *MemoryResultStore) HasResult(scanID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	found, ok := m.Results[scanID]
	log.Debugf("HasResult: %v", found)
	return ok && found.IsComplete
}

func (m *MemoryResultStore) GetResult(scanID string) (VulnerabilityResult, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	found, ok := m.Results[scanID]
	return found, ok
}

func (m *MemoryResultStore) PopResult(scanID string) (VulnerabilityResult, bool) {
	m.mu.Lock()
	defer func() {
		m.mu.Unlock()
		log.WithField("CacheSize", len(m.Results)).Debug("Cache size - after pop")
	}()

	log.WithField("CacheSize", len(m.Results)).Debug("Cache size - before pop")

	found, ok := m.Results[scanID]
	if found.IsComplete {
		log.WithField("scanId", scanID).Debug("found completed result and removing from store to return to caller")
		delete(m.Results, scanID)
	} else {
		log.WithField("scanId", scanID).Debug("found result in store, but not complete, so not removing from store")
	}

	return found, ok
}

func (m *MemoryResultStore) SafeUpdateResult(scanID string, result VulnerabilityResult) {
	log.WithField("scanId", scanID).Debug("updating result in store")
	m.mu.Lock()
	m.Results[scanID] = result
	m.mu.Unlock()
}

func (m *MemoryResultStore) RequestCreateScan(
	scanID string,
	buildFn func() (bool, error),
) VulnerabilityResult {
	existing, ok := m.PopResult(scanID)

	if !ok {
		// Result not found so begin the async fetch
		go func() {
			imageAdded, err := buildFn()
			if err != nil {
				log.Debugf("error creating scan for %v: %v", scanID, err)
				// Set IsComplete to true to remove the scan from the store if the create scan fails so that it can be retried without using the cache.
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           false,
					AnalysisComplete:      false,
					ReportBuildInProgress: false,
					IsComplete:            true,
					Result:                nil,
					Error:                 err,
				}
			} else {
				log.Debugf("create scan finished for %v", scanID)
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           imageAdded,
					AnalysisComplete:      false,
					ReportBuildInProgress: false,
					IsComplete:            false,
					Result:                nil,
					Error:                 nil,
				}
			}
		}()
		newScan := VulnerabilityResult{
			ScanID:                scanID,
			ScanCreated:           false,
			AnalysisComplete:      false,
			ReportBuildInProgress: false,
			IsComplete:            false,
			Result:                nil,
			Error:                 fmt.Errorf("create scan not ready"),
		}
		m.SafeUpdateResult(scanID, newScan)
	}
	return existing
}

func (m *MemoryResultStore) RequestAnalysisStatus(
	scanID string,
	buildFn func() (bool, error),
) VulnerabilityResult {
	existing, ok := m.PopResult(scanID)
	if (!ok || existing.ScanCreated) && !existing.AnalysisComplete {
		// Result not found so begin the async fetch
		go func() {
			complete, err := buildFn()
			currentState, _ := m.GetResult(scanID)
			if err != nil {
				log.Debugf("error checking analysis state for %v: %v", scanID, err)
				// Set IsComplete to true to remove the scan from the store if the create scan fails so that it can be retried without using the cache.
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           true,
					AnalysisComplete:      false,
					ReportBuildInProgress: currentState.ReportBuildInProgress,
					IsComplete:            true,
					Result:                nil,
					Error:                 err,
				}
			} else {
				log.Debugf("checking analysis state complete for %v", scanID)
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           true,
					AnalysisComplete:      complete,
					ReportBuildInProgress: currentState.ReportBuildInProgress,
					IsComplete:            currentState.IsComplete,
					Result:                currentState.Result,
					Error:                 nil,
				}
			}
		}()
		existing.ScanID = scanID
		existing.ScanCreated = true
		existing.Error = fmt.Errorf("image analysis not ready")
		m.SafeUpdateResult(scanID, existing)
	}
	return existing
}

func (m *MemoryResultStore) RequestResult(
	scanID string,
	buildFn func() (*harbor.VulnerabilityReport, error),
) VulnerabilityResult {
	existing, _ := m.PopResult(scanID)
	if !existing.ReportBuildInProgress && existing.ScanCreated && existing.AnalysisComplete {
		log.WithField("scanID", scanID).Debug("Scan created, beginning report build")
		// Result not found so begin the async fetch
		go func() {
			result, err := buildFn()
			if err != nil {
				log.Debugf("error building result for %v: %v", scanID, err)
				// Set IsComplete to true to remove the scan from the store so that it can be retried without using the cache.
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           true,
					AnalysisComplete:      true,
					ReportBuildInProgress: true,
					IsComplete:            true,
					Result:                nil,
					Error:                 err,
				}
			} else {
				log.Debugf("result built for %v", scanID)
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           true,
					AnalysisComplete:      true,
					ReportBuildInProgress: true,
					IsComplete:            true,
					Result:                result,
					Error:                 nil,
				}
			}
		}()
		existing.ReportBuildInProgress = true
		existing.Error = fmt.Errorf("result not ready")
		m.SafeUpdateResult(scanID, existing)
	}
	return existing
}

func (m *MemoryResultStore) RequestRawResult(
	scanID string,
	buildFn func() (*anchore.ImageVulnerabilityReport, error),
) VulnerabilityResult {
	existing, _ := m.PopResult(scanID)

	if !existing.ReportBuildInProgress && existing.ScanCreated && existing.AnalysisComplete {
		log.Debug("Scan created, beginning raw report build")
		// Result not found so begin the async fetch
		go func() {
			result, err := buildFn()
			if err != nil {
				log.Debugf("error building raw result for %v: %v", scanID, err)
				// Set IsComplete to true to remove the scan from the store so that it can be retried without using the cache.
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           true,
					AnalysisComplete:      true,
					ReportBuildInProgress: true,
					IsComplete:            true,
					Result:                nil,
					Error:                 err,
				}
			} else {
				log.Debugf("raw result built for %v", scanID)
				resultChannel <- VulnerabilityResult{
					ScanID:                scanID,
					ScanCreated:           true,
					AnalysisComplete:      true,
					ReportBuildInProgress: true,
					IsComplete:            true,
					Result:                nil,
					RawResult:             result,
					Error:                 nil,
				}
			}
		}()
		existing.ReportBuildInProgress = true
		existing.Error = fmt.Errorf("result not ready")
		m.SafeUpdateResult(scanID, existing)
	}
	return existing
}

func (m *MemoryResultStore) resultRetriever() {
	for {
		report := <-resultChannel
		log.WithFields(log.Fields{"scanId": report.ScanID, "imageAdded": report.ScanCreated, "isComplete": report.IsComplete, "reportError": report.Error}).
			Debug("scan result added to result store")
		m.SafeUpdateResult(report.ScanID, report)
	}
}

func (m *MemoryResultStore) Start() {
	log.Info("starting result fetch loop")
	go m.resultRetriever()
}
