package v1

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/anchore/harbor-scanner-adapter/pkg/adapter"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
)

const (
	TestRegistry = "http://harbor.domain:8443"
	TestRepo1    = "library/image1/image"
	TestDigest1  = "sha256:4214707ec3ec157f9566258710e274824a0b6a8e34051bd081d9192900d06647" // #nosec G101
	TestTag1     = "latest"
)

var okConfig = anchore.AdapterConfig{
	ListenAddr:                    ":8080",
	APIKey:                        "apikey123",
	LogFormat:                     "",
	LogLevel:                      logrus.InfoLevel,
	FullVulnerabilityDescriptions: false,
}

type MockAdapter struct{}

func (m *MockAdapter) GetMetadata() (harbor.ScannerAdapterMetadata, error) {
	return harbor.ScannerAdapterMetadata{
		Scanner: harbor.Scanner{},
		Capabilities: []harbor.Capability{
			{
				ConsumesMIMETypes: nil,
				ProducesMIMETypes: nil,
			},
		},
		Properties: nil,
	}, nil
}

func (m *MockAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	id, err := anchore.GenerateScanID(req.Artifact.Repository, req.Artifact.Digest)
	if err != nil {
		return harbor.ScanResponse{}, err
	}
	return harbor.ScanResponse{ID: id}, nil
}

func (m *MockAdapter) GetHarborVulnerabilityReport(_ string, _ bool) (*harbor.VulnerabilityReport, error) {
	return &harbor.VulnerabilityReport{}, nil
}

func (m *MockAdapter) GetRawVulnerabilityReport(_ string) (harbor.RawReport, error) {
	return `{"image": "sha256:test123"}`, nil
}

func NewMockAdapter() adapter.ScannerAdapter {
	return &MockAdapter{}
}

func NewMockHandler() APIHandler {
	return APIHandler{
		scanner: NewMockAdapter(),
		config:  okConfig,
	}
}

func TestCreateScan(t *testing.T) {
	handler := NewMockHandler()

	okRequests := [][]string{
		{
			fmt.Sprintf(
				`{"registry": {"url": "%v"}, "artifact": {"repository": "%v", "digest": "%v", "tag": "%v"}}`,
				TestRegistry,
				TestRepo1,
				TestDigest1,
				TestTag1,
			),
			`{"id":"bGlicmFyeS9pbWFnZTEvaW1hZ2VAc2hhMjU2OjQyMTQ3MDdlYzNlYzE1N2Y5NTY2MjU4NzEwZTI3NDgyNGEwYjZhOGUzNDA1MWJkMDgxZDkxOTI5MDBkMDY2NDc="}`,
		},
		{
			fmt.Sprintf(
				`{"registry": {"url": "%v"}, "artifact": {"repository": "%v", "digest": "%v", "tag": "%v"}}`,
				TestRegistry,
				TestRepo1,
				TestDigest1,
				"",
			),
			`{"id":"bGlicmFyeS9pbWFnZTEvaW1hZ2VAc2hhMjU2OjQyMTQ3MDdlYzNlYzE1N2Y5NTY2MjU4NzEwZTI3NDgyNGEwYjZhOGUzNDA1MWJkMDgxZDkxOTI5MDBkMDY2NDc="}`,
		},
	}

	for _, input := range okRequests {
		reqBody := strings.NewReader(input[0])
		req, err := http.NewRequest("POST", "/api/v1/scan", reqBody)
		if err != nil {
			t.Fatal(err)
		}
		if req == nil {
			t.Fatal("nil request obj")
		}

		req.Header.Set("Content-Type", ScanRequestMimeType)
		req.Header.Set(AcceptHeader, ScanResponseMimeType)

		rr := httptest.NewRecorder()
		handlerFn := http.HandlerFunc(handler.CreateScan)
		handlerFn.ServeHTTP(rr, req)

		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusAccepted {
			t.Errorf("handler returned wrong status code: got %v want %v. Body: %v",
				status, http.StatusOK, rr.Body)
		}

		// Check the response body is what we expect.
		expected := input[1]
		if strings.TrimSpace(rr.Body.String()) != strings.TrimSpace(expected) {
			t.Errorf("handler returned unexpected body: got %v want %v",
				rr.Body.String(), expected)
		}
	}
}

func TestGetMetadata(t *testing.T) {
	t.Skip()
}

func TestGetRawScanReport(t *testing.T) {
	t.Skip()
}

func TestGetScanReport(t *testing.T) {
	t.Skip()
}

func TestAuthenticationMiddleware(t *testing.T) {
	t.Skip()
}

func TestGetHarborVulnerabilityReport(t *testing.T) {
	t.Skip()
}
