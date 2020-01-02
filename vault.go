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

var accessLayer Layer
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

type Layer struct {
	logical logicalInterface
}

func Init(cfg Config) {
	config = cfg
	getVaultClient()
}

func getAccessLayer() Layer {
	if accessLayer == (Layer{}) {
		c := getVaultClient()
		accessLayer = Layer{logical: c.Logical()}
		if config.AppToken.CreateAppToken {
			applicationToken = createAppToken()
			if err := accessLayer.writeSecretToVault(config.AppToken.Path, map[string]interface{}{"token": applicationToken}); err != nil {
				log.Fatalf("Error storing appToken in vault: %s", err.Error())
			}
		}
	}

	return accessLayer
}

func createAppToken() string {
	return stringWithCharset(32, charset)
}

func (l Layer) getValueFromVault(path string) map[string]interface{} {

	s, e := l.logical.Read(path)
	if e != nil {
		log.Fatalf("Error getting vault value: %s", e.Error())
	}
	if s != nil {
		return s.Data
	}
	return nil
}

func (l Layer) writeSecretToVault(path string, data map[string]interface{}) error {
	_, e := l.logical.Write(path, map[string]interface{}{dataName: data})
	return e
}

func (l Layer) getJsonBytes(path string) []byte {
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

func (l Layer) getPassPhrase() string {
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

func EncryptString(dataString string) []byte {
	return Encrypt([]byte(dataString), getAccessLayer().getPassPhrase())
}
func EncryptBytes(data []byte) []byte {
	return Encrypt(data, getAccessLayer().getPassPhrase())
}
func DecryptBytes(data []byte) []byte {
	return Decrypt(data, getAccessLayer().getPassPhrase())
}
func DecryptString(dataString string) []byte {
	return Decrypt([]byte(dataString), getAccessLayer().getPassPhrase())
}

func Decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func Encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func GetJsonBytes(path string) []byte {
	return getAccessLayer().getJsonBytes(path)
}

func GetValue(path string) map[string]interface{} {
	return getAccessLayer().getValueFromVault(path)
}

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
		} else {
			retries = retries - 1
			log.Printf("error connecting to vault. %d retries left", retries)
			if retries <= 0 {
				return false
			}
			time.Sleep(timeout)
			resp, err = http.Get(config.VaultAddress)

		}

	}
}

func refreshAppToken() {
	data := GetValue(config.AppToken.Path)
	applicationToken = GetStringFromSecret(data, tokenName)
}

//getDataFromSecret is a helper method to retrieve the stored data from the given secret data
func GetStringFromSecret(sData map[string]interface{}, key string) string {
	dataMap := sData[dataName].(map[string]interface{})

	if v, ok := dataMap[key]; !ok {
		return ""
	} else {
		return v.(string)
	}
}

func GetAppToken(forceRefresh bool) string {
	if applicationToken == "" || forceRefresh {
		refreshAppToken()
	}

	return applicationToken
}
