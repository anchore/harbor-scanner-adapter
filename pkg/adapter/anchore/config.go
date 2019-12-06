package anchore

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/client"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
)

type AdapterConfig struct {
	ListenAddr                    string // Address to listen on, e.g ":8080" or "127.0.0.1:80"
	ApiKey                        string // Key for auth, used as a Bearer token
	LogFormat                     string
	LogLevel                      log.Level
	FullVulnerabilityDescriptions bool   //If true, the scanner adapter will query anchore to get vuln descriptions, else will use cvss string and defer to the link url
	TLSKeyFile                    string // Path to key file
	TLSCertFile                   string // Path to cert file
	FilterVendorIgnoredVulns      bool
	TLSVerify                     bool                // Enable TLS verification on api calls to the adapter
	RegistryTLSVerify             bool                // Enable TLS verification on Anchore's calls to the registry on the data path
	RegistryValidateCreds         bool                // Validate registry credentials when adding them to Anchore via the Anchore API
	AnchoreClientConfig           client.ClientConfig //Credentials and client configuration
	CacheConfig                   CacheConfiguration
	UseAnchoreConfiguredCreds     bool // If true, the adapter will ignore the dynamic credentials that are provided by harbor for each scan and will instead expect that the admin has configured Anchore with credentials out-of-band. Default is False.
}

const (
	DefaultTimeoutSeconds             = 60
	DefaultListenAddr                 = ":8080"
	DefaultLogLevel                   = log.InfoLevel
	ListenAddrEnvVar                  = "SCANNER_ADAPTER_LISTEN_ADDR"
	LogLevelEnvVar                    = "SCANNER_ADAPTER_LOG_LEVEL"
	LogFormatEnvVar                   = "SCANNER_ADAPTER_LOG_FORMAT"
	ApiKeyEnvVar                      = "SCANNER_ADAPTER_APIKEY"
	FullVulnDescriptionsEnvVar        = "SCANNER_ADAPTER_FULL_VULN_DESCRIPTIONS"
	TlsKeyEnvVar                      = "SCANNER_ADAPTER_TLS_KEY_FILE"
	TlsCertEnvVar                     = "SCANNER_ADAPTER_TLS_CERT_FILE"
	FilterVendorIgnoredVulns          = "SCANNER_ADAPTER_FILTER_VENDOR_IGNORED"
	TLSVerifyEnvVarName               = "SCANNER_ADAPTER_TLS_VERIFY"
	RegistryValidateCredsEnvVarName   = "SCANNER_ADAPTER_REGISTRY_VALIDATE_CREDS"
	RegistryTLSVerifyEnvVarName       = "SCANNER_ADAPTER_REGISTRY_TLS_VERIFY"
	EndpointEnvVarName                = "ANCHORE_ENDPOINT"
	UsernameEnvVarName                = "ANCHORE_USERNAME"
	PasswordEnvVarName                = "ANCHORE_PASSWORD"
	AuthConfigFile                    = "ANCHORE_AUTHFILE_PATH"
	TimeoutEnvVarName                 = "ANCHORE_CLIENT_TIMEOUT_SECONDS"
	DescriptionCacheEnabledEnvVarName = "SCANNER_ADAPTER_DESCRIPTION_CACHE_ENABLED"
	DescriptionCacheItemCount         = "SCANNER_ADAPTER_DESCRIPTION_CACHE_COUNT"
	DescriptionCacheTtl               = "SCANNER_ADAPTER_DESCRIPTION_CACHE_TTL"
	DefaultDescriptionCacheEnabled    = true
	DefaultDescriptionCacheTTL        = 60 * 60 * 24
	DefaultDescriptionCacheItemCount  = 10000
	ReportCacheEnabledEnvVarName      = "SCANNER_ADAPTER_REPORT_CACHE_ENABLED"
	ReportCacheItemCount              = "SCANNER_ADAPTER_REPORT_CACHE_COUNT"
	ReportCacheTtl                    = "SCANNER_ADAPTER_REPORT_CACHE_TTL"
	DefaultReportCacheEnabled         = true
	DefaultReportCacheTTL             = 180
	DefaultReportCacheItemCount       = 100
	DbUpdateCacheEnabledEnvVarName    = "SCANNER_ADAPTER_DB_UPDATE_CACHE_ENABLED"
	DbUpdateCacheTtl                  = "SCANNER_ADAPTER_DB_UPDATE_CACHE_TTL"
	DefaultDbUpdateCacheEnabled       = true
	DefaultDbUpdateCacheTTL           = 60
	UseAnchoreConfigCredsEnvVarName   = "SCANNER_ADAPTER_IGNORE_HARBOR_CREDS"
	UseAnchoreConfigCredsDefault      = false
)

// Initialized to defaults
var DefaultCacheConfig = CacheConfiguration{
	VulnDescriptionCacheEnabled:  DefaultDescriptionCacheEnabled,
	VulnDescriptionCacheMaxCount: DefaultDescriptionCacheItemCount,
	VulnDescriptionCacheTTL:      DefaultDescriptionCacheTTL,
	DbUpdateCacheEnabled:         DefaultDbUpdateCacheEnabled,
	DbUpdatedCacheTTL:            DefaultDbUpdateCacheTTL,
	VulnReportCacheEnabled:       DefaultReportCacheEnabled,
	VulnReportCacheMaxCount:      DefaultReportCacheItemCount,
	VulnReportCacheTTL:           DefaultReportCacheTTL,
}

// Simple env var handler to ensure consistent behavior for booleans
func GetEnvBoolean(varName string, defaultValue bool) (bool, error) {
	if varName == "" {
		return false, fmt.Errorf("empty environment vaiable name, cannot get value")
	}

	if value, ok := os.LookupEnv(varName); ok {
		value = strings.ToLower(value) // Normalize

		if value == "true" || value == "y" || value == "yes" {
			return true, nil
		} else if value == "false" || value == "n" || value == "no" {
			return false, nil
		} else {
			log.WithFields(log.Fields{"value": value, "key": varName, "type": "bool"}).Error("invalid format for environment variable value")
			return false, fmt.Errorf("value %v cannot be parsed as a bool", value)
		}
	}

	return defaultValue, nil
}

// Load the service configuration, from environment variables since there are no secrets here. If not set, uses default listen addr :8080
func GetConfig() (AdapterConfig, error) {
	cfg := AdapterConfig{}
	var ok bool
	var level string
	var err error

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

	cfg.LogLevel = DefaultLogLevel
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

	if cfg.TLSCertFile, ok = os.LookupEnv(TlsCertEnvVar); !ok {
		cfg.TLSCertFile = ""
	}

	if cfg.TLSKeyFile, ok = os.LookupEnv(TlsKeyEnvVar); !ok {
		cfg.TLSKeyFile = ""
	}

	cfg.AnchoreClientConfig = client.ClientConfig{}

	if path, ok := os.LookupEnv(AuthConfigFile); ok {
		log.Printf("Using config file at %v", path)
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Error("error reading config file")
			return cfg, err
		}

		err = json.Unmarshal(content, &cfg.AnchoreClientConfig)
		if err != nil {
			log.Error("error unmarshalling json config file")
			return cfg, err
		}
	}

	// Process additional env var overrides. If set in env, will override any value found in the config file
	if addr, ok := os.LookupEnv(EndpointEnvVarName); ok {
		cfg.AnchoreClientConfig.Endpoint = addr
	} else if cfg.AnchoreClientConfig.Endpoint == "" {
		err := fmt.Errorf("no endpoint for Anchore found in env under key %s", EndpointEnvVarName)
		return cfg, err
	}

	if username, ok := os.LookupEnv(UsernameEnvVarName); ok {
		cfg.AnchoreClientConfig.Username = username
	} else if cfg.AnchoreClientConfig.Username == "" {
		err := fmt.Errorf("no username for Anchore found in env under key %s", EndpointEnvVarName)
		return cfg, err
	}

	if pwd, ok := os.LookupEnv(PasswordEnvVarName); ok {
		cfg.AnchoreClientConfig.Password = pwd
	} else if cfg.AnchoreClientConfig.Password == "" {
		err := fmt.Errorf("no password for Anchore found in env under key %s", EndpointEnvVarName)
		return cfg, err
	}

	if timeout, ok := os.LookupEnv(TimeoutEnvVarName); ok {
		var err error
		if cfg.AnchoreClientConfig.TimeoutSeconds, err = strconv.Atoi(timeout); err != nil {
			return cfg, fmt.Errorf("timeout value %s could not be converted to int seconds", timeout)
		}
	}

	// Set default if timeout is uninitialized or zero. A timeout > 0 is required
	if cfg.AnchoreClientConfig.TimeoutSeconds <= 0 {
		cfg.AnchoreClientConfig.TimeoutSeconds = DefaultTimeoutSeconds
		log.Printf("Using default client call timeout: %v", cfg.AnchoreClientConfig.TimeoutSeconds)
	}

	cfg.FilterVendorIgnoredVulns, err = GetEnvBoolean(FilterVendorIgnoredVulns, false)
	if err != nil {
		return cfg, err
	}

	cfg.AnchoreClientConfig.TLSVerify, err = GetEnvBoolean(TLSVerifyEnvVarName, true)
	if err != nil {
		return cfg, err
	}

	cfg.RegistryTLSVerify, err = GetEnvBoolean(RegistryTLSVerifyEnvVarName, true)
	if err != nil {
		return cfg, err
	}

	cfg.RegistryValidateCreds, err = GetEnvBoolean(RegistryValidateCredsEnvVarName, true)
	if err != nil {
		return cfg, err
	}

	cfg.CacheConfig = DefaultCacheConfig

	cfg.CacheConfig.VulnDescriptionCacheEnabled, err = GetEnvBoolean(DescriptionCacheEnabledEnvVarName, DefaultDescriptionCacheEnabled)

	if count, ok := os.LookupEnv(DescriptionCacheItemCount); ok {
		cfg.CacheConfig.VulnDescriptionCacheMaxCount, err = strconv.Atoi(count)
		if err != nil {
			log.WithFields(log.Fields{"value": count, "key": DescriptionCacheItemCount, "type": "int"}).Error("invalid format for environment variable value")
			return cfg, err
		}
	}

	if ttl, ok := os.LookupEnv(DescriptionCacheTtl); ok {
		cfg.CacheConfig.VulnDescriptionCacheMaxCount, err = strconv.Atoi(ttl)
		if err != nil {
			log.WithFields(log.Fields{"value": ttl, "key": DescriptionCacheTtl, "type": "int"}).Error("invalid format for environment variable value")
			return cfg, err
		}
	}

	cfg.CacheConfig.VulnReportCacheEnabled, err = GetEnvBoolean(ReportCacheEnabledEnvVarName, DefaultReportCacheEnabled)

	if count, ok := os.LookupEnv(ReportCacheItemCount); ok {
		cfg.CacheConfig.VulnReportCacheMaxCount, err = strconv.Atoi(count)
		if err != nil {
			log.WithFields(log.Fields{"value": count, "key": ReportCacheItemCount, "type": "int"}).Error("invalid format for environment variable value")
			return cfg, err
		}
	}

	if ttl, ok := os.LookupEnv(ReportCacheTtl); ok {
		cfg.CacheConfig.VulnReportCacheMaxCount, err = strconv.Atoi(ttl)
		if err != nil {
			log.WithFields(log.Fields{"value": ttl, "key": ReportCacheTtl, "type": "int"}).Error("invalid format for environment variable value")
			return cfg, err
		}
	}

	cfg.CacheConfig.DbUpdateCacheEnabled, err = GetEnvBoolean(DbUpdateCacheEnabledEnvVarName, DefaultDbUpdateCacheEnabled)

	if ttl, ok := os.LookupEnv(DbUpdateCacheTtl); ok {
		cfg.CacheConfig.DbUpdatedCacheTTL, err = strconv.Atoi(ttl)
		if err != nil {
			log.WithFields(log.Fields{"value": ttl, "key": DbUpdateCacheTtl, "type": "int"}).Error("invalid format for environment variable value")
			return cfg, err
		}
	}

	cfg.UseAnchoreConfiguredCreds, err = GetEnvBoolean(UseAnchoreConfigCredsEnvVarName, UseAnchoreConfigCredsDefault)

	return cfg, nil
}
