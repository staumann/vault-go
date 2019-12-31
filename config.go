package vault

type Config struct {
	GenerateToken  bool
	VaultAddress   string
	AuthToken      string
	PassPhrasePath string
	RetryLimit     int
	RetryTimeout   string
	AppToken       struct {
		Enabled bool
		Path    string
	}
}
