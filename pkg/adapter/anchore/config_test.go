package anchore

import (
	"log"
	"os"
	"testing"
)

// Test loading the config from a file
func TestFileConfigLoad(t *testing.T) {
	// Set this as its required for config load to succeed.
	if os.Setenv(EndpointEnvVarName, "https://somehost:8228") != nil {
		t.Fatal("Could not set env endpoint")
	}

	if os.Setenv(AuthConfigFile, "fixtures/config_test.json") != nil {
		t.Fatal("Could not set env for path")
	}

	cfg, err := GetConfig()
	if err != nil || (cfg == AdapterConfig{}) {
		log.Printf("Could not load config from file: %v", err)
		t.Fail()
	}

	if cfg.AnchoreClientConfig.Username != "harbortester" {
		t.Errorf("wrong username")
	}

	if cfg.AnchoreClientConfig.Password != "harbortesterpasser" {
		t.Errorf("wrong password")
	}
}

// Test loading config from env
func TestEnvConfig(t *testing.T) {
	var err error

	_ = os.Setenv(EndpointEnvVarName, "https://somehost:8228")
	_ = os.Setenv(UsernameEnvVarName, "harboruser")
	_ = os.Setenv(PasswordEnvVarName, "harboruserpassword")

	conf, err := GetConfig()
	if err != nil {
		log.Printf("Error loading config")
		t.Fail()
	}
	if conf == (AdapterConfig{}) {
		log.Printf("Config is nil")
		t.Fail()
	}
}
