package vault

//Config this struct is the main object for initializing the vault plugin
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
