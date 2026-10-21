package anchore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/client"
)

// The raw-report path must wire FilterVendorIgnoredVulns — not
// FullVulnerabilityDescriptions — into Anchore's vendor_only query param,
// exactly like the Harbor-format path does. The two config booleans are set
// to opposite values so an argument swap cannot pass.
func TestRawReportUsesVendorIgnoredFilterFlag(t *testing.T) {
	vendorOnly := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/vuln/all") {
			select {
			case vendorOnly <- r.URL.Query().Get("vendor_only"):
			default:
			}
			_, _ = w.Write([]byte(`{"image_digest":"sha256:x","vulnerabilities":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	scanID, err := GenerateScanID(
		"project1/repo1",
		"sha256:4214707ec3ec157f9566258710e274824a0b6a8e34051bd081d9192900d06647",
	)
	if err != nil {
		t.Fatalf("could not generate scan id: %v", err)
	}

	// Seed the store as if the scan was created and analysis finished, so
	// GetRawVulnerabilityReport proceeds straight to the report build.
	resultStore.SafeUpdateResult(scanID+"-raw", VulnerabilityResult{
		ScanID:           scanID + "-raw",
		ScanCreated:      true,
		AnalysisComplete: true,
	})

	adapter, err := NewScannerAdapter(&AdapterConfig{
		AnchoreClientConfig: client.Config{
			Endpoint:       srv.URL,
			Username:       "user",
			Password:       "pass",
			TimeoutSeconds: 5,
		},
		FullVulnerabilityDescriptions: true,
		FilterVendorIgnoredVulns:      false,
	})
	if err != nil {
		t.Fatalf("could not build adapter: %v", err)
	}

	// Kicks off the async report build; "result not ready" is expected here.
	_, _ = adapter.GetRawVulnerabilityReport(scanID)

	select {
	case got := <-vendorOnly:
		if got != "false" {
			t.Errorf("raw report sent vendor_only=%s; want false (FilterVendorIgnoredVulns), "+
				"got the value of FullVulnerabilityDescriptions instead", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("adapter never called the Anchore vulnerabilities API")
	}
}
