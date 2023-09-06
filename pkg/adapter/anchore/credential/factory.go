package credential

import (
	"strings"
)

type Loader interface {
	LoadFromCredentialStore(passwordConfig string) string
}

func CreateCredentialLoader(passwordConfig string) Loader {
	if strings.HasPrefix(passwordConfig, "aws:secretmanager") {
		return &AWSCredenitalLoader{}
	}
	return &DefaultCredenitalLoader{}
}
