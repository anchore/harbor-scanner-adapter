package adapter

import (
	"fmt"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
	log "github.com/sirupsen/logrus"
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
	AdapterType                   = "os-package-vulnerability"
	DefaultListenAddr             = ":8080"
	AdapterVersion                = "1.0.0-alpha"
	AdapterVendor                 = "Anchore Inc."
	AdapterName                   = "Anchore"
	DefaultLogLevel               = log.InfoLevel
	ScanRequestMimeType           = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
	ScanResponseMimeType          = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	ErrorResponseMimeType         = "application/vnd.scanner.adapter.error+json; version=1.0"
	ListenAddrEnvVar              = "SCANNER_ADAPTER_LISTEN_ADDR"
	LogLevelEnvVar                = "SCANNER_ADAPTER_LOG_LEVEL"
	LogFormatEnvVar               = "SCANNER_ADAPTER_LOG_FORMAT"
	ApiKeyEnvVar                  = "SCANNER_ADAPTER_APIKEY"
	FullVulnDescriptionsEnvVar    = "SCANNER_ADAPTER_FULL_VULN_DESCRIPTIONS"
	TlsKeyEnvVar                  = "SCANNER_ADAPTER_TLS_KEY_FILE"
	TlsCertEnvVar                 = "SCANNER_ADAPTER_TLS_CERT_FILE"
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
	ListenAddr                    string // Address to listen on, e.g ":8080" or "127.0.0.1:80"
	ApiKey                        string // Key for auth, used as a Bearer token
	LogFormat                     string
	LogLevel                      log.Level
	FullVulnerabilityDescriptions bool //If true, the scanner adapter will query anchore to get vuln descriptions, else will use cvss string and defer to the link url
	TLSKeyFile                    string // Path to key file
	TLSCertFile                   string // Path to cert file
}

// ScannerAdapter defines methods for scanning container images.
type ScannerAdapter interface {
	GetMetadata() (harbor.ScannerAdapterMetadata, error)
	Scan(req harbor.ScanRequest) (harbor.ScanResponse, error)
	GetHarborVulnerabilityReport(scanId string, includeDescriptions bool) (harbor.VulnerabilityReport, error)
	GetRawVulnerabilityReport(scanId string) (harbor.RawReport, error)
}

// Load the service configuration, from environment variables since there are no secrets here. If not set, uses default listen addr :8080
func GetConfig() (ServiceConfig, error) {
	cfg := ServiceConfig{}
	var ok bool
	var level string

	if cfg.ListenAddr, ok = os.LookupEnv(ListenAddrEnvVar); ok {
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

	if cfg.ApiKey, ok = os.LookupEnv(ApiKeyEnvVar); ok {
		log.Info("Detected api key in configuration")
	} else {
		log.Info("No api key detected in configuration")
	}

	cfg.LogFormat = ""
	if cfg.LogFormat, ok = os.LookupEnv(LogFormatEnvVar); ok {
		cfg.LogFormat = strings.ToLower(cfg.LogFormat)
	}

	cfg.LogLevel = log.InfoLevel
	if level, ok = os.LookupEnv(LogLevelEnvVar); ok {
		var err error
		cfg.LogLevel, err = log.ParseLevel(level)
		if err != nil {
			log.Errorf("invalid log level specified %v. defaulting to info level", level)
		}
	}

	var useVulnDescription string
	if useVulnDescription, ok = os.LookupEnv(FullVulnDescriptionsEnvVar); ok {
		log.Info("Full vuln description value detected in configuration")
		cfg.FullVulnerabilityDescriptions = "false" != strings.ToLower(useVulnDescription)
	} else {
		log.Info("No full vulnerability description value found in env, defaulting to 'true'")
		cfg.FullVulnerabilityDescriptions = true
	}

	if cfg.TLSCertFile, ok = os.LookupEnv(TlsCertEnvVar); ! ok {
		cfg.TLSCertFile = ""
	}

	if cfg.TLSKeyFile, ok = os.LookupEnv(TlsKeyEnvVar); ! ok {
		cfg.TLSKeyFile = ""
	}

	return cfg, nil
}
