package credential

import (
	"strings"
)

type CredentialLoader interface {
	load(string) string
}

func CreateCredentialLoader(key string) CredentialLoader {
	if strings.HasPrefix(key, "aws:secretmanager") {
		return &AWSCredenitalLoader{}
	}
	return &DefaultCredenitalLoader{}
}
