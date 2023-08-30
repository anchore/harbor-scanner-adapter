package adapter

import (
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
)

const (
	HarborVulnReportv1MimeType    = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	RawVulnReportMimeType         = "application/vnd.scanner.adapter.vuln.report.raw+json"
	DockerImageMimeType           = "application/vnd.docker.distribution.manifest.v2+json"
	OciImageMimeType              = "application/vnd.oci.image.manifest.v1+json"
	HarborMetadataVulnDbUpdateKey = "harbor.scanner-adapter/vulnerability-database-updated-at"
	HarborMetadataScannerTypeKey  = "harbor.scanner-adapter/scanner-type"
	AdapterType                   = "os-package-vulnerability"
	AdapterVersion                = "1.0.0"
	AdapterVendor                 = "Anchore Inc."
	AdapterName                   = "Anchore"
)

var AdapterMetadata = harbor.ScannerAdapterMetadata{
	Scanner: harbor.Scanner{
		Name:    AdapterName,
		Version: AdapterVersion,
		Vendor:  AdapterVendor,
	},
	Capabilities: []harbor.Capability{
		{
			ConsumesMIMETypes: []string{
				DockerImageMimeType,
				OciImageMimeType,
			},
			ProducesMIMETypes: []string{
				HarborVulnReportv1MimeType,
				RawVulnReportMimeType,
			},
		},
	},
	Properties: map[string]string{
		HarborMetadataVulnDbUpdateKey: "", // This gets updated in response to requests from Harbor
		HarborMetadataScannerTypeKey:  AdapterType,
	},
}

// ScannerAdapter defines methods for scanning container images.
type ScannerAdapter interface {
	GetMetadata() (harbor.ScannerAdapterMetadata, error)
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetHarborVulnerabilityReport(scanId string, includeDescriptions bool) (*harbor.VulnerabilityReport, error)
	GetRawVulnerabilityReport(scanId string) (harbor.RawReport, error)
}
