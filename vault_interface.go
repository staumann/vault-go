package vault

import "github.com/hashicorp/vault/api"

type LayerInterface interface {
	GetValueFromVault(string) map[string]interface{}
	WriteSecretToVault(string, map[string]interface{}) error
	GetCredentialsJson() []byte
	GetPassPhrase() string
}

type logicalInterface interface {
	Read(string) (*api.Secret, error)
	Write(string, map[string]interface{}) (*api.Secret, error)
}
