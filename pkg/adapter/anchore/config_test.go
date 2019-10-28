package anchore

import (
	"log"
	"os"
	"testing"
)

// Test loading the config from a file
func TestFileConfigLoad(t *testing.T) {
	if os.Setenv(AuthConfigFile, "fixtures/config_test.json") != nil {
		log.Printf("Could not set env for path")
		t.Fail()
	}

	cfg, err := GetConfig()
	if err != nil || (cfg == AdapterConfig{}) {
		log.Printf("Could not load config from file: %v", err)
		t.Fail()
	}

	if cfg.AnchoreClientConfig.Endpoint != "https://someserver.somewhere:8228" {
		t.Errorf("wrong endpoint")
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

	err = os.Setenv(EndpointEnvVarName, "https://somehost:8228")
	err = os.Setenv(UsernameEnvVarName, "harboruser")
	err = os.Setenv(PasswordEnvVarName, "harboruserpassword")

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

// Test both in place, ensure file has precedence
func TestFileOverride(t *testing.T) {

}
