package credential

import (
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/client"
	"strings"
)

type CredentialLoader interface {
	load(client.ClientConfig)
}

func CreateCredentialLoader(clientConfiguration client.ClientConfig) CredentialLoader {
	if strings.HasPrefix(clientConfiguration.Password, "aws:secretmanager") {
		return &AWSCredenitalLoader{}
	}
	return &DefaultCredenitalLoader
}
