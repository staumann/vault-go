package vault

import (
	"encoding/json"
	"errors"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"testing"
)

type MockVaultLogical struct {
	SavedPassPhrase string
	WriteHandler    func(string, map[string]interface{}, *MockVaultLogical) (*api.Secret, error)
	ReadHandler     func(string, *MockVaultLogical) (*api.Secret, error)
}

func (mvl *MockVaultLogical) Read(path string) (*api.Secret, error) {
	if mvl.ReadHandler != nil {
		return mvl.ReadHandler(path, mvl)
	}
	return nil, nil
}

func (mvl *MockVaultLogical) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	if mvl.WriteHandler != nil {
		return mvl.WriteHandler(path, data, mvl)
	}
	return nil, nil
}

func TestGetVaultClient(t *testing.T) {
	authStruct := Config{
		VaultAddress: "localhost:8888",
		AuthToken:    "123456789",
	}
	config = authStruct
	c := getVaultClient()

	if c == nil {
		t.Error("Error the returned client is nil")
		t.FailNow()
	}

	if c.Address() != authStruct.VaultAddress {
		t.Errorf("Error the adress is not the expected: %s. But got: %s", authStruct.VaultAddress, c.Address())
		t.Fail()
	}
}

func TestGetVaultClientWithExistingClient(t *testing.T) {
	config = Config{
		VaultAddress: "localhost:8888",
		AuthToken:    "123456789",
	}

	c := getVaultClient()

	config.VaultAddress = "https://irgendwo.wo.nur:12465"
	config.AuthToken = "TokenShit"

	c = getVaultClient()

	if c.Address() != "localhost:8888" {
		t.Error("Client is created everyTime the method is called. Expected: Client is only created once")
		t.Fail()
	}
}

func TestLayer_GetValueFromVault(t *testing.T) {
	layer := Layer{&MockVaultLogical{
		ReadHandler: func(s string, mvl *MockVaultLogical) (secret *api.Secret, e error) {
			assert.Equal(t, "test/path", s)
			sc := &api.Secret{
				Data: map[string]interface{}{"data": "testData"},
			}
			return sc, nil
		},
	}}

	d := layer.getValueFromVault("test/path")

	assert.Equal(t, "testData", d["data"])
}

func TestLayer_WriteSecretToVault(t *testing.T) {
	layer := Layer{&MockVaultLogical{
		WriteHandler: func(s string, i map[string]interface{}, mvl *MockVaultLogical) (secret *api.Secret, e error) {
			assert.Equal(t, "test/path", s)
			assert.Equal(t, "data", i["data"].(map[string]interface{})["testData"])

			sc := &api.Secret{
				Data: i,
			}

			return sc, nil
		},
	}}
	dMap := map[string]interface{}{"testData": "data", "pass": "testPass"}
	e := layer.writeSecretToVault("test/path", dMap)

	assert.Nil(t, e)
}

func TestLayer_WriteSecretToVaultError(t *testing.T) {
	layer := Layer{&MockVaultLogical{
		WriteHandler: func(s string, i map[string]interface{}, mvl *MockVaultLogical) (secret *api.Secret, e error) {
			return nil, errors.New("testError")
		},
	}}

	e := layer.writeSecretToVault("/test", make(map[string]interface{}))
	assert.Equal(t, "testError", e.Error())
}

func TestLayer_GetCredentialsJson(t *testing.T) {
	layer := Layer{&MockVaultLogical{
		ReadHandler: func(s string, mvl *MockVaultLogical) (secret *api.Secret, e error) {
			assert.Equal(t, "test/path", s)

			data := map[string]interface{}{"data": map[string]string{"testKey": "testValue"}}

			sc := &api.Secret{Data: data}

			return sc, nil
		},
	}}
	b := layer.getJsonBytes("test/path")
	result := make(map[string]interface{})
	_ = json.Unmarshal(b, &result)
	assert.Equal(t, "testValue", result["testKey"])
}

func TestLayer_GetPassPhraseAlreadyRecieved(t *testing.T) {
	layer := Layer{&MockVaultLogical{
		ReadHandler: func(s string, mvl *MockVaultLogical) (secret *api.Secret, e error) {
			return nil, nil
		},
	}}
	phraseData = map[string]interface{}{"pass": "testPhrase"}

	assert.Equal(t, "testPhrase", layer.getPassPhrase())
}

func TestLayer_GetPassPhrase(t *testing.T) {
	config.PassPhrasePath = "/test/passphrase"
	phraseData = map[string]interface{}{}
	mvl := &MockVaultLogical{
		ReadHandler: func(s string, mvl *MockVaultLogical) (secret *api.Secret, e error) {
			return nil, nil
		},
		WriteHandler: func(s string, i map[string]interface{}, mvl *MockVaultLogical) (secret *api.Secret, e error) {
			assert.Equal(t, "/test/passphrase", s)
			passphrase := i["data"].(map[string]interface{})["pass"].(string)
			assert.Equal(t, 32, len(passphrase))
			mvl.SavedPassPhrase = passphrase

			return nil, nil
		},
	}
	layer := Layer{mvl}

	pass := layer.getPassPhrase()

	assert.Equal(t, mvl.SavedPassPhrase, pass)
	assert.NotEqual(t, "", pass)
}

func TestEncrypt(t *testing.T) {
	value := "testString"
	passPhrase := "testPassphrase"

	returnValue := Encrypt([]byte(value), passPhrase)

	assert.NotNil(t, string(returnValue))
	d := Decrypt(returnValue, passPhrase)
	assert.Equal(t, value, string(d))
}
