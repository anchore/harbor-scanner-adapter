package harbor

import (
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"
)

func TestMarshalJSON(t *testing.T) {
	report := VulnerabilityReport{
		GeneratedAt:     time.Now(),
		Artifact:        Artifact{},
		Scanner:         Scanner{},
		Severity:        SevHigh,
		Vulnerabilities: nil,
	}

	s, err := json.Marshal(&report)
	if err != nil {
		log.Printf("could not marshal %v", err)
		t.Fail()
	}

	if !strings.Contains(string(s), "High") {
		log.Printf("Incorrect marshalling: %v", string(s))
		t.Fail()
	}
}

func TestSeverity_String(t *testing.T) {
	if SevHigh.String() != "High" {
		t.Fail()
	}
	if SevUnknown.String() != "Unknown" {
		t.Fail()
	}
}
