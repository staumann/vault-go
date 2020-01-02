package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/hashicorp/vault/api"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"
)

var accesslayer layer
var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))
var phraseData map[string]interface{}
var applicationToken string
var client *api.Client
var config Config

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const tokenName = "token"
const dataName = "data"

func init() {
	phraseData = make(map[string]interface{})
}

type layer struct {
	logical logicalInterface
}

//Init the function to initialize the vault plugin. Pass the configuration Object to use.
func Init(cfg Config) {
	config = cfg
	getVaultClient()
}

func getAccessLayer() layer {
	if accesslayer == (layer{}) {
		c := getVaultClient()
		accesslayer = layer{logical: c.Logical()}
		if config.AppToken.CreateAppToken {
			applicationToken = createAppToken()
			if err := accesslayer.writeSecretToVault(config.AppToken.Path, map[string]interface{}{"token": applicationToken}); err != nil {
				log.Fatalf("Error storing appToken in vault: %s", err.Error())
			}
		}
	}

	return accesslayer
}

func createAppToken() string {
	return stringWithCharset(32, charset)
}

func (l layer) getValueFromVault(path string) map[string]interface{} {

	s, e := l.logical.Read(path)
	if e != nil {
		log.Fatalf("Error getting vault value: %s", e.Error())
	}
	if s != nil {
		return s.Data
	}
	return nil
}

func (l layer) writeSecretToVault(path string, data map[string]interface{}) error {
	_, e := l.logical.Write(path, map[string]interface{}{dataName: data})
	return e
}

func (l layer) getJSONBytes(path string) []byte {
	data := l.getValueFromVault(path)
	if len(data) == 0 {
		log.Fatalf("Error nothing found under vault path %s", path)
	} else {
		cred, e := json.Marshal(data[dataName])
		if e != nil {
			log.Print(e.Error())
		}
		return cred
	}

	return nil
}

func (l layer) getPassPhrase() string {
	if config.PassPhrasePath == "" {
		return ""
	}
	if _, ok := phraseData["pass"]; !ok {
		result := l.getValueFromVault(config.PassPhrasePath)

		if result != nil {
			phraseData = result[dataName].(map[string]interface{})
		}
		if _, ok := phraseData["pass"]; !ok {
			log.Printf("Writing new passphrase to vault")
			phraseData["pass"] = stringWithCharset(32, charset)
			err := l.writeSecretToVault(config.PassPhrasePath, phraseData)
			if err != nil {
				panic(err)
			}
		}
	}
	return phraseData["pass"].(string)
}

func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	cLen := len(charset)
	for i := range b {
		b[i] = charset[seededRand.Intn(cLen)]
	}
	return string(b)
}

func getVaultClient() *api.Client {
	if client == nil {
		log.Printf("Connection to vault under %s", config.VaultAddress)
		if checkAndWaitForVault() {
			c, err := api.NewClient(&api.Config{
				Address: config.VaultAddress,
				HttpClient: &http.Client{
					Timeout: 5 * time.Second,
				},
			})

			if err != nil {
				panic(err)
			}
			c.SetToken(config.AuthToken)
			client = c
		} else {
			panic("No retries left. It was not possible to get a connection to vault.")
		}

	}

	return client
}

//EncryptString uses Encrypt and just converts the given string to a byte array. As PassPhrase this method uses a generated passphrase stored in vault.
func EncryptString(dataString string) []byte {
	return Encrypt([]byte(dataString), getAccessLayer().getPassPhrase())
}

//EncryptBytes see Encrypt. The PassPhrase is randomly generated and stored in vault
func EncryptBytes(data []byte) []byte {
	return Encrypt(data, getAccessLayer().getPassPhrase())
}

//DecryptBytes see Decrypt. The PassPhrase is randomly generated and stored in vault
func DecryptBytes(data []byte) []byte {
	return Decrypt(data, getAccessLayer().getPassPhrase())
}

//DecryptString uses Decrypt and just converts the given string to a byte array. As PassPhrase this method uses a generated passphrase stored in vault.
func DecryptString(dataString string) []byte {
	return Decrypt([]byte(dataString), getAccessLayer().getPassPhrase())
}

//Decrypt decrypt the given byte array using the passed passPhrase. If the decryption was successful the decrypted bytes are returned.
func Decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("error decrypting byte array: %s", err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("error decrypting byte array: %s", err.Error())
	}
	return plaintext
}

//Encrypt encrypts the given byte array with the given passphrase and returns the encrypted byte array.
func Encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("error encrypting byte array: %s", err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		log.Printf("error encrypting byte array: %s", err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

//GetJSONBytes retrieves the stored json under the given path. The expected strcture of the secret:
//	{
//		"data": {
//			"jsonKey1": "value",
//			"jsonKey2": [
//				"test1",
//				"test2"
//			]
//		}
//	}
func GetJSONBytes(path string) []byte {
	return getAccessLayer().getJSONBytes(path)
}

//GetValue retrieves the generic data from a vault secret using the given path
func GetValue(path string) map[string]interface{} {
	return getAccessLayer().getValueFromVault(path)
}

//GetPassPhrase this method retrieves the current passPhrase from vault. If no passPhrase exists a new one is randomly created.
//If you plan to use this method you need to pass the "PassPhrasePath" in the configuration object
func GetPassPhrase() string {
	return getAccessLayer().getPassPhrase()
}

func checkAndWaitForVault() bool {
	log.Printf("checking if vault is reachable under: %s", config.VaultAddress)
	resp, err := http.Get(config.VaultAddress)
	timeout, parseError := time.ParseDuration(config.RetryTimeout)
	if parseError != nil {
		timeout = 1 * time.Second
	}
	retries := config.RetryLimit
	for {
		if resp != nil && err == nil && resp.StatusCode != 502 {
			log.Printf("vault is accessible: last request status code %d", resp.StatusCode)
			return true
		}
		retries = retries - 1
		log.Printf("error connecting to vault. %d retries left", retries)
		if retries <= 0 {
			return false
		}
		time.Sleep(timeout)
		resp, err = http.Get(config.VaultAddress)
	}
}

func refreshAppToken() {
	data := GetValue(config.AppToken.Path)
	applicationToken = GetStringFromSecret(data, tokenName)
}

//GetStringFromSecret is a helper method to retrieve the stored data from the given secret data as an string
func GetStringFromSecret(sData map[string]interface{}, key string) string {
	dataMap := sData[dataName].(map[string]interface{})
	var v interface{}
	var ok bool
	if v, ok = dataMap[key]; !ok {
		return ""
	}
	return v.(string)

}

//GetAppToken retrieves the current AppToken from vault using the current config.
//forceRefresh triggers a refresh of the appToken. After the refresh is completed the new token is returned.
func GetAppToken(forceRefresh bool) string {
	if applicationToken == "" || forceRefresh {
		refreshAppToken()
	}

	return applicationToken
}
