package credential

type DefaultCredenitalLoader struct{}

func (c *DefaultCredenitalLoader) load(key string) {
	return key
}
