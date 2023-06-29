package weaveapi

import (
	"encoding/base64"
	"strconv"
	"time"

	"gitlab.com/c0b/go-ordered-json"
)

type Session struct {
	Organization		string
	Account				string	
	PublicKey			string
	Scopes				string
	ApiKey				string
	Secret				[]byte
	SecretExpireUTC		time.Time
	IntegrityChecks 	bool
	Nonce				uint64
	TableLayoutCache	ordered.OrderedMap
	PrevRecordsData		ordered.OrderedMap
	ExpiryCUshionSec	uint32
}

func NewSession(data ordered.OrderedMap, decryptedSecret string) Session {
	secret, _ := base64.StdEncoding.DecodeString(decryptedSecret)

	return Session{
		Organization: data.Get("organization").(string),
		Account: data.Get("account").(string),
		PublicKey: data.Get("publicKey").(string),
		Scopes: data.Get("scopes").(string),
		ApiKey: data.Get("apiKey").(string),
		Secret: secret,
		SecretExpireUTC: convertTimestamp(data.Get("secretExpireUTC").(string)),
		IntegrityChecks: data.Get("integrityChecks").(bool),
		Nonce: 0,
		TableLayoutCache: *ordered.NewOrderedMap(),
		PrevRecordsData: *ordered.NewOrderedMap(),
		ExpiryCUshionSec: 10,
	}
}

func (session *Session) GetNonce() uint64 {
	session.Nonce++
	return session.Nonce
}

func (session *Session) nearExpiry() bool {
	return time.Now().Add(10 * time.Second).After(session.SecretExpireUTC)
}

func convertTimestamp(timestamp string) time.Time {
    i, err := strconv.ParseInt(timestamp, 10, 64)
    if err != nil {
        panic(err)
    }
    return time.Unix(i, 0)
}