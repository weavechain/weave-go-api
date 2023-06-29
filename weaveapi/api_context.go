package weaveapi

import (
	"crypto/ed25519"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	eciesgo "github.com/ecies/go/v2"
)

type ApiContext struct {
	Seed 				[]byte
	SeedHex 			string
	PublicKey 			string
	ServerPubKey 		*eciesgo.PublicKey
	ServerSigKey 		*eciesgo.PublicKey
	ClientPublicKey 	*eciesgo.PublicKey
	ClientPrivateKey 	*eciesgo.PrivateKey
	SigKeys				*ed25519.PrivateKey
	SigKey				string
}

func NewApiContext(Seed []byte, SeedHex string, ServerPublicKey string, ServerSigKey string, ClientPublicKey string, ClientPrivateKey string) ApiContext {
	serverPubKey, _ := DeserializePublic(ServerPublicKey)
	serverSigKey, _ := DeserializePublic(ServerSigKey)
	clientPublicKey, _ := DeserializePublic(ClientPublicKey)
	clientPrivateKey := DeserializePrivate(ClientPrivateKey, "")
	apiContext := ApiContext{
		Seed: Seed,
		SeedHex: SeedHex,
		PublicKey: ClientPublicKey, 
		ServerPubKey: serverPubKey, 
		ServerSigKey: serverSigKey,
		ClientPublicKey: clientPublicKey,
		ClientPrivateKey: clientPrivateKey}
	
	apiContext.deriveSigKeys()
	return apiContext
}

func GenerateKeys() (string, string) {
	pk, error := eciesgo.GenerateKey()
	HandleError(error)

	pub := pk.PublicKey

	publicKey := "weave" + string(base58.Encode(pub.Bytes(true)))
	privateKey := string(base58.Encode(pk.Bytes()))

	return publicKey, privateKey
}

func DeserializePublic(key string) (*eciesgo.PublicKey, error) {
	if strings.HasPrefix(key, "weave") {
		key = key[5:]
	}
	decodedKey := base58.Decode(key)
	return eciesgo.NewPublicKeyFromBytes(decodedKey)
}

func DeserializePrivate(PrivateKey string, Password string) *eciesgo.PrivateKey {
	decodedKey := base58.Decode(PrivateKey)
	return eciesgo.NewPrivateKeyFromBytes(decodedKey)
}

func (context *ApiContext) deriveSigKeys() {
	pvk := context.ClientPrivateKey.D.Bytes()

	seed := byteArrayToLong(pvk, 6)
	rng := NewRandom(seed)
	var b [32]int64
	s := make([]byte, 32)
	rng.NextBytes(&b)
	for i := 0; i < 32; i++ {
		b[i] ^= int64(pvk[i])
		if b[i] < 0 {
			b[i] = 256 + b[i]
		}
		s[i] = byte(b[i] & 0xff)
	}

	keys := ed25519.NewKeyFromSeed(s)
	
	context.SigKeys = &keys
	context.SigKey = base58.Encode([]byte(keys)[32:])
}

func (context *ApiContext) CreateEd25519Signature(message string) string {
	privKey := *context.SigKeys
	signature := ed25519.Sign(privKey, []byte(message))
	b64Sig := base58.Encode(signature)
	return b64Sig
}

func (context *ApiContext) VerifyEd25519Signature(publicKey ed25519.PublicKey, signature []byte, message string) bool {
	return ed25519.Verify(publicKey, []byte(message), signature)
}

func (context *ApiContext) Verify(publicKey eciesgo.PublicKey, signature []byte, message string) bool {
	b := publicKey.Bytes(true)
	var pub ed25519.PublicKey
	pub = b
	return context.VerifyEd25519Signature(pub, signature, message)
}

func byteArrayToLong(byteArray []byte, size int) int64 {
	value := int64(0)
	for i := 0; i < size; i++ {
		value = value * 256 + int64(byteArray[i])
	}
	return value
}