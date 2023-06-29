package weaveapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strings"

	publicKey "github.com/ecies/go/v2"
	"gitlab.com/c0b/go-ordered-json"
)

func SharedSecret(privateKey *publicKey.PrivateKey, serverPublicKey *publicKey.PublicKey) []byte {
	sharedSecret, error := privateKey.ECDH(serverPublicKey)
	if error != nil {
		panic(error)
	}
	return sharedSecret
}

func SignHttp(secret []byte, url string, apiKey string, nonce string, data string) string {
	if data == "" {
		data = "{}"
	}
	toSign := url + "\n" + apiKey + "\n" + nonce + "\n" + data
	
	return SignRequest(secret, toSign)
}

func SignWs(secret []byte, data ordered.OrderedMap) string {
	apiKey, exists := data.GetValue("x-api-key")
	if !exists {
		apiKey = "null"
	}
	nonce, exists := data.GetValue("nonce")
	if !exists {
		nonce = "null"
	}
	signature, exists := data.GetValue("signature")
	if !exists {
		signature = "null"
	}
	organization, exists := data.GetValue("organization")
	if !exists {
		organization = "null"
	}
	account, exists := data.GetValue("account")
	if !exists {
		account = "null"
	}
	scope, exists := data.GetValue("scope")
	if !exists {
		scope = "null"
	}
	table, exists := data.GetValue("table")
	if !exists {
		table = "null"
	}

	toSign := string(apiKey.(string)) +
		"\n" + string(nonce.(string)) +
		"\n" + string(signature.(string)) +
		"\n" + string(organization.(string)) +
		"\n" + string(account.(string)) +
		"\n" + string(scope.(string)) +
		"\n" + string(table.(string))
	
	return SignRequest(secret, toSign)
}

func SignRequest(secret []byte, toSign string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(toSign))

	result := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return result
}

func ReadKey(keyProperty string, keyFileProperty string) string {
    if keyProperty != "" {
        return keyProperty
	} else {
    	file, error := os.Open(keyFileProperty)
		if error != nil {
			panic(error)
		}
		stat, error := file.Stat()
		if error != nil {
			panic(error)
		}
		fileBytes := make([]byte, stat.Size())
		file.Read(fileBytes)
		fileString := string(fileBytes)
		var response string
		response = strings.Replace(fileString, "\r", "", -1)
		response = strings.Replace(response, "\n", "", -1)
		response = strings.Replace(response, "\t", "", -1)
		response = strings.Replace(response, " ", "", -1)
		return response
	}
}

func AESEncrypt(data string, key []byte, seed []byte, iv string) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		HandleError(err)
	}
	
	ecb := cipher.NewCBCEncrypter(block, xorWithSeed(seed, iv))
	content := []byte(data)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted
}

func AESDecrypt(data []byte, key []byte, seed []byte, iv string) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		HandleError(err)
	}
	
	ecb := cipher.NewCBCDecrypter(block, xorWithSeed(seed, iv))
	decrypted := make([]byte, len(data))
	ecb.CryptBlocks(decrypted, data)

	return PKCS5Trimming(decrypted)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func xorWithSeed(seed []byte, iv string) []byte {
	s := make([]byte, len(iv))
	for i := 0; i < len(iv); i++ {
		s[i] = iv[i] ^ seed[i % len(seed)]
	}
	return s
}