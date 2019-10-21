package client

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
	if err != nil || cfg == nil {
		log.Printf("Could not load config from file: %v", err)
		t.Fail()
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
	if conf == nil {
		log.Printf("Config is nil")
		t.Fail()
	}
}

// Test both in place, ensure file has precedence
func TestFileOverride(t *testing.T) {

}
