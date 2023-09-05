// Models for the harbor adapter API, defined by the API spec

package harbor

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	_ Severity = iota
	SevNone
	SevUnknown
	SevNegligible
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var SeverityNames = [...]string{
	"None",
	"Unknown",
	"Negligible",
	"Low",
	"Medium",
	"High",
	"Critical",
}

func (sev Severity) String() string {
	if sev < SevNone || sev > SevCritical {
		return "Unknown"
	}

	return SeverityNames[sev-1]
}

func ToHarborSeverity(severity string) Severity {
	severity = strings.ToLower(severity)

	switch severity {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low":
		return SevLow
	case "unknown":
		return SevUnknown
	case "negligible":
		return SevNegligible
	default:
		log.Printf("Encountered unknown severity string: %s", severity)
		return SevUnknown
	}
}

// Marshalling for JSON stuff
func (sev Severity) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(fmt.Sprintf(`"%v"`, sev.String()))
	return buffer.Bytes(), nil
}

// Severity for a vulnerability found in an artifact
type Severity int64

// The source to retrieve an artifact, including authc
type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

// Artifact is a scannable object in a Registry (e.g. docker image)
type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag"`
}

type ScanRequest struct {
	Registry Registry `json:"registry"`
	Artifact Artifact `json:"artifact"`
}

// Response is an id generated by the adapter to lookup the scan result when complete
type ScanResponse struct {
	ID string `json:"id"`
}

type RawReport interface{}

// The vulnerability report for a docker image
type VulnerabilityReport struct {
	GeneratedAt     time.Time        `json:"generated_at"`
	Artifact        Artifact         `json:"artifact"`
	Scanner         Scanner          `json:"scanner"`
	Severity        Severity         `json:"severity"`
	Vulnerabilities []VulnerableItem `json:"vulnerabilities"`
}

// A vulnerable item in the image. Maps a package to a vulnerability and vulnerability metadata
type VulnerableItem struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Pkg         string   `json:"package"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Links       []string `json:"links"`
	Fixed       string   `json:"fixed_version,omitempty"`
}

// Metadata about the adapter itself
type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	ConsumesMIMETypes []string `json:"consumes_mime_types"`
	ProducesMIMETypes []string `json:"produces_mime_types"`
}

// Error holds the information about an error, including metadata about its JSON structure.
type Error struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error Error `json:"error"`
}
