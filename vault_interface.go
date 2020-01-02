package vault

import "github.com/hashicorp/vault/api"

type logicalInterface interface {
	Read(string) (*api.Secret, error)
	Write(string, map[string]interface{}) (*api.Secret, error)
}
