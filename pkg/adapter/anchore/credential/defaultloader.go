package credential

type DefaultCredenitalLoader struct{}

func (c *DefaultCredenitalLoader) LoadFromCredentialStore(passwordConfig string) string {
	return passwordConfig
}
