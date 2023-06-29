package weaveapi

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"gitlab.com/c0b/go-ordered-json"
)

func NodeApiGenerateKeys() (string, string) {
	nodeApi := NewNodeApi(ChainClientConfig{})
	return nodeApi.GenerateKeys()
}

func WeaveClientConfig(pub string, pvk string, node string, organization string) ordered.OrderedMap {
	s := strings.Split(node, "/")
	seed := s[len(s) - 1]


	config := ordered.NewOrderedMap()
	config.Set("organization", organization)
	config.Set("account", pub)
	config.Set("scope", "*")

	chainClientConfig := ordered.NewOrderedMap()
	chainClientConfig.Set("apiVersion", 1)
	chainClientConfig.Set("seed", seed)
	chainClientConfig.Set("privateKey", pvk)
	chainClientConfig.Set("publicKey", pub)

	if strings.HasPrefix(node, "http") {
		idx := s[len(s) - 2]
		items := strings.Split(idx, ":")
		http := ordered.NewOrderedMap()

		http.Set("host", items[0])
		http.Set("port", items[1])
		http.Set("useHttps", strings.HasPrefix(node, "https"))
		chainClientConfig.Set("http", http)
		chainClientConfig.Set("ws", WsConfig{})
	} else if strings.HasPrefix(node, "ws") {
		idx := s[len(s) - 2]
		items := strings.Split(idx, ":")
		ws := ordered.NewOrderedMap()

		ws.Set("host", items[0])
		ws.Set("port", items[1])
		ws.Set("useWss", strings.HasPrefix(node, "wss"))
		chainClientConfig.Set("ws", ws)
		chainClientConfig.Set("http", HttpConfig{})
	}
	config.Set("chainClientConfig", chainClientConfig)

	return *config

}

func ConnectWeaveApi(configFile string, credentials string) (NodeApi, Session) {

	var config ClientConfig
	if IsJson(configFile) {
		config = ClientConfig{}

		_ = json.Unmarshal([]byte(configFile), &config)
	} else {
		file, error := ioutil.ReadFile(configFile)
		HandleError(error)

		config = ClientConfig{}

		_ = json.Unmarshal([]byte(file), &config)
	}

	organization := config.Organization
	account := config.Account
	scope := config.Scope

	nodeApi := NewNodeApi(config.ChainClientConfig)
	nodeApi.Init()

	loginFuture := nodeApi.Login(organization, account, scope, credentials)
	session, error := loginFuture.Await()
	HandleError(error)

	return nodeApi, session.(Session)
}

func IsJson(s string) bool {
	var js map[string]interface{}
    return json.Unmarshal([]byte(s), &js) == nil
}