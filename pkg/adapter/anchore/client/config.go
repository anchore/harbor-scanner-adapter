/*
Configuration types and loaders for the Anchore client
*/

package client

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

type ClientConfig struct {
	Endpoint                 string `json:"endpoint"`
	Username                 string `json:"username"`
	Password                 string `json:"password"`
	TimeoutSeconds           int    `json:"timeoutSeconds"`
	FilterVendorIgnoredVulns bool   `json:"filterVendorIgnoredVulns"`
	SkipTLSVerify            bool   `json:"skipTlSVerify"`
}

const (
	DefaultTimeoutSeconds    = 60
	EndpointEnvVarName       = "ANCHORE_ENDPOINT"
	UsernameEnvVarName       = "ANCHORE_USERNAME"
	PasswordEnvVarName       = "ANCHORE_PASSWORD"
	AuthConfigFile           = "ANCHORE_AUTHFILE_PATH"
	TimeoutEnvVarName        = "ANCHORE_CLIENT_TIMEOUT_SECONDS"
	FilterVendorIgnoredVulns = "ANCHORE_FILTER_VENDOR_IGNORED"
	SkipTLSVerifyEnvVarName  = "ANCHORE_SKIP_TLS_VERIFY"
)

func GetConfig() (*ClientConfig, error) {
	cfg := &ClientConfig{}

	if path, ok := os.LookupEnv(AuthConfigFile); ok {
		log.Printf("Using config file at %v", path)
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(content, cfg)
		if err != nil {
			return nil, err
		}

	}

	// Process additional env var overrides. If set in env, will override any value found in the config file
	if addr, ok := os.LookupEnv(EndpointEnvVarName); ok {
		cfg.Endpoint = addr
	} else if cfg.Endpoint == "" {
		err := fmt.Errorf("no endpoint for Anchore found in env under key %s", EndpointEnvVarName)
		return nil, err
	}

	if username, ok := os.LookupEnv(UsernameEnvVarName); ok {
		cfg.Username = username
	} else if cfg.Username == "" {
		err := fmt.Errorf("no username for Anchore found in env under key %s", EndpointEnvVarName)
		return nil, err
	}

	if pwd, ok := os.LookupEnv(PasswordEnvVarName); ok {
		cfg.Password = pwd
	} else if cfg.Password == "" {
		err := fmt.Errorf("no password for Anchore found in env under key %s", EndpointEnvVarName)
		return nil, err
	}

	if filterVendorIgnored, ok := os.LookupEnv(FilterVendorIgnoredVulns); ok {
		cfg.FilterVendorIgnoredVulns = strings.ToLower(filterVendorIgnored) == "true"
	}

	if timeout, ok := os.LookupEnv(TimeoutEnvVarName); ok {
		var err error
		if cfg.TimeoutSeconds, err = strconv.Atoi(timeout); err != nil {
			return nil, fmt.Errorf("timeout value %s could not be converted to int seconds", timeout)
		}
	}

	// Set default if timeout is uninitialized or zero. A timeout > 0 is required
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = DefaultTimeoutSeconds
		log.Printf("Using default client call timeout: %v", cfg.TimeoutSeconds)
	}

	if tlsVerify, ok := os.LookupEnv(SkipTLSVerifyEnvVarName); ok {
		cfg.SkipTLSVerify = strings.ToLower(tlsVerify) == "true"
	} else {
		// False by default
		cfg.SkipTLSVerify = false
	}

	return cfg, nil
}
