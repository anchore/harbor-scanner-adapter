package credential

import (
	"strings"
)

type CredentialLoader interface {
	LoadFromCredentialStore(passwordConfig string) string
}

func CreateCredentialLoader(passwordConfig string) CredentialLoader {
	if strings.HasPrefix(passwordConfig, "aws:secretmanager") {
		return &AWSCredenitalLoader{}
	}
	return &DefaultCredenitalLoader{}
}
