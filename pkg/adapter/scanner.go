package adapter

import (
	"fmt"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	HarborVulnReportv1MimeType    = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	RawVulnReportMimeType         = "application/vnd.scanner.adapter.vuln.report.raw+json"
	DockerImageMimeType           = "application/vnd.oci.image.manifest.v1+json"
	OciImageMimeType              = "application/vnd.docker.distribution.manifest.v2+json"
	HarborMetadataVulnDbUpdateKey = "harbor.scanner-adapter/vulnerability-database-updated-at"
	HarborMetadataScannerTypeKey  = "harbor.scanner-adapter/scanner-type"
	AdapterType                   = "os-application-package-vulnerability"
	DefaultListenAddr             = ":8080"
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

type ServiceConfig struct {
	ListenAddr string // Address to listen on, e.g ":8080" or "127.0.0.1:80"
	ApiKey     string // Key for auth, used as a Bearer token
}

// ScannerAdapter defines methods for scanning container images.
type ScannerAdapter interface {
	GetMetadata() (harbor.ScannerAdapterMetadata, error)
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetHarborVulnerabilityReport(scanId string) (harbor.VulnerabilityReport, error)
	GetRawVulnerabilityReport(scanId string) (harbor.RawReport, error)
}

// Load the service configuration, from environment variables since there are no secrets here. If not set, uses default listen addr :8080
func GetConfig() (ServiceConfig, error) {
	cfg := ServiceConfig{}
	var ok bool

	if cfg.ListenAddr, ok = os.LookupEnv("SCANNER_ADAPTER_LISTEN_ADDR"); ok {
		// Verify the format as valid
		comps := strings.Split(cfg.ListenAddr, ":")
		if len(comps) == 2 {
			if len(comps[0]) == 0 {
				//Ok, like ":8080"
			} else {
				if net.ParseIP(comps[0]) == nil {
					return cfg, fmt.Errorf("invalid IP component of listen address %s", cfg.ListenAddr)
				}
			}

			if _, err := strconv.Atoi(comps[1]); err != nil {
				return cfg, fmt.Errorf("invalid port format in listen address %s", cfg.ListenAddr)
			}
		} else {
			return cfg, fmt.Errorf("invalid listen addr format %s", cfg.ListenAddr)
		}
	} else {
		cfg.ListenAddr = DefaultListenAddr
	}

	if cfg.ApiKey, ok = os.LookupEnv("SCANNER_ADAPTER_APIKEY"); ok {
		log.Printf("Detected api key in configuration")
	} else {
		log.Printf("No api key detected in configuration")
	}

	return cfg, nil
}
