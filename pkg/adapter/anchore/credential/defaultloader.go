package credential

import "github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/client"

type DefaultCredenitalLoader struct{}

func (c *DefaultCredenitalLoader) load(key string) {
	return key
}
