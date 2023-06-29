package weaveapi

type ClientConfig struct {
	Organization 		string 				`json:"organization"`
	Account 			string				`json:"account"`
	Scope 				string				`json:"scope"`
	ChainClientConfig 	ChainClientConfig 	`json:"chainClientConfig"`
}

type ChainClientConfig struct {
	ApiVersion 			string		`json:"apiVersion";default:""`
	HttpConfig 			HttpConfig	`json:"http"`
	WsConfig			WsConfig	`json:"ws"`
	Seed 				string 		`json:"seed";default:""`
	ClientPubKey 		string 		`json:"publicKey";default:""`
	ClientPubKeyFile 	string 		`json:"publicKeyFile";default:""`
	ClientPrivKey		string 		`json:"privateKey";default:""`
	ClientPrivKeyFile	string 		`json:"privateKeyFile";default:""`
	encryption 			bool		`json:"encryption"`
}

type HttpConfig struct {
	UseHttps 	bool 	`json:"useHttps"`
	Host 		string 	`json:"host"`
	Port 		string	`json:"port"`
}

type WsConfig struct {
	UseWss	bool	`json:"useWss"`
	Host 	string 	`json:"host"`
	Port 	string	`json:"port"`
}