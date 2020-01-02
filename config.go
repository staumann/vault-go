package vault

type Config struct {
	VaultAddress   string
	AuthToken      string
	PassPhrasePath string
	RetryLimit     int
	RetryTimeout   string
	AppToken       struct {
		CreateAppToken bool
		Path           string
	}
}
