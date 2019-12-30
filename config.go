package vault

type Config struct {
	GenerateToken  bool
	VaultAddress   string
	AuthToken      string
	PassPhrasePath string
	AppToken       struct {
		Enabled bool
		Path    string
	}
}
