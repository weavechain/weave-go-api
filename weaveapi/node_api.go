package weaveapi

import (
	"crypto/ed25519"
	"math/big"

	"github.com/Allan-Jacobs/go-futures"
	"github.com/btcsuite/btcutil/base58"
	"gitlab.com/c0b/go-ordered-json"
)


type AbstractClient interface {
	Init()
	ApiContext()																													*ApiContext
	Login(organization string, account string, scopes string, credentials string) 													futures.Future[interface{}] 
	CreateTable(session Session, scope string, table string, createOptions CreateOptions) 											futures.Future[interface{}]
	DropTable(session Session, scope string, table string) 																			futures.Future[interface{}]
	Write(session Session, scope string, records Records, writeOptions WriteOptions)												futures.Future[interface{}]
	Read(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) 									futures.Future[interface{}]
	GetTableDefinition(session Session, scope string, table string)																	futures.Future[interface{}]
	Logout(session Session) 																										futures.Future[interface{}]
	Status(session Session) 																										futures.Future[interface{}]
	Terms(session Session, scope string, table string, options CreateOptions) 														futures.Future[interface{}]
	UpdateLayout(session Session, scope string, table string, layout interface{}) 													futures.Future[interface{}]
	UpdateConfig(session Session, path string, values interface{}) 																	futures.Future[interface{}]
	GrantRole(session Session, account string, roles interface{}) 																	futures.Future[interface{}]
	Count(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) 								futures.Future[interface{}]
	Delete(session Session, scope string, table string, filter interface{}, deleteOptions DeleteOptions) 							futures.Future[interface{}]
	DownloadTable(session Session, scope string, table string, filter interface{}, format string, readOptions ReadOptions) 			futures.Future[interface{}]
	Hashes(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) 								futures.Future[interface{}]
	HashCheckpoint(session Session, enable bool) 																					futures.Future[interface{}]
	PublishDataset(session Session, did string, name string, description string, license string,	
		metadata string, weave string, fullDescription string, logo string, category string, scope string, table string,	
		filter interface{}, format string, price int64, token string, pageorder uint64, publishOptions PublishOptions)				futures.Future[interface{}]
	EnableProduct(session Session, did string, productType string, active bool) 													futures.Future[interface{}]
	DownloadDataset(session Session, did string, readOptions ReadOptions) 															futures.Future[interface{}]
	PublishTask(session Session, did string, name string, description string, license string, metadata string, 	
		weave string, fullDescription string, logo string, category string, task string, price int64, 
		token string, pageorder int64, publishOptions PublishOptions)																futures.Future[interface{}]
	RunTask(session Session, did string, computeOptions ComputeOptions) 															futures.Future[interface{}]
	Subscribe(session Session, scope string, table string, filter interface{}, 	
		subscribeOptions SubscribeOptions, updateHandler interface{})																futures.Future[interface{}]
	Unsubscribe(session Session, subscriptionId string) 																			futures.Future[interface{}]
	Compute(session Session, image string, computeOptions ComputeOptions) 															futures.Future[interface{}]
	GetImage(session Session, image string, localOutputFolder string, computeOptions ComputeOptions) 								futures.Future[interface{}]
	Flearn(session Session, image string, flOptions FLOptions) 																		futures.Future[interface{}]
	SplitLearn(session Session, image string, slOptions SLOptions) 																	futures.Future[interface{}]
	ForwardApi(session Session, feedId string, params ordered.OrderedMap) 															futures.Future[interface{}]
	UploadApi(session Session, params ordered.OrderedMap) 																			futures.Future[interface{}]
	HeGetInputs(session Session, datasources []interface{}, args []interface{}) 													futures.Future[interface{}]
	HeGetOutputs(session Session, encoded string, args []interface{}) 																futures.Future[interface{}]
	HeEncode(session Session, items []interface{}) 																					futures.Future[interface{}]
	Mpc(session Session, scope string, table string, algo string, fields []string, filter interface{}, mpcOptions MPCOptions) 		futures.Future[interface{}]
	StorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) 			futures.Future[interface{}]
	ZkStorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) 			futures.Future[interface{}]
	MerkleTree(session Session, scope string, table string, filter interface{}, salt string, digest string, options ReadOptions) 	futures.Future[interface{}]
	MerkleProof(session Session, scope string, table string, hash string) 															futures.Future[interface{}]
	RootHash(session Session, scope string, table string) 																			futures.Future[interface{}]
	ZkMerkleTree(session Session, scope string, table string, filter interface{}, salt string,
		digest string, rounds int, seed int, options ZKOptions) 																	futures.Future[interface{}]
	MimcHash(session Session, data string, rounds int, seed int)																	futures.Future[interface{}]
	ProofsLastHash(session Session, scope string, table string)																		futures.Future[interface{}]
	UpdateProofs(session Session, scope string, table string)																		futures.Future[interface{}]
	VerifyMerkleHash(session Session, tree string, hash string, digest string)														futures.Future[interface{}]
	ZkProof(session Session, scope string, table string, gadget string, params string, 
		fields []string, filter interface{}, zkOptions ZKOptions) 																	futures.Future[interface{}]
	ZkDataProof(session Session, gadget string, params string, values []interface{}, zkOptions ZKOptions)							futures.Future[interface{}]
	VerifyZkProof(session Session, proof string, gadget string, params string, commitment string, nGenerators int) 					futures.Future[interface{}]
	TaskLineage(session Session, taskId string) 																					futures.Future[interface{}]
	VerifyTaskLineage(session Session, lineageData ordered.OrderedMap) 																futures.Future[interface{}]
	TaskOutputData(session Session, taskId string, options OutputOptions) 															futures.Future[interface{}]
	History(session Session, scope string, table string, filter interface{}, historyOptions HistoryOptions) 						futures.Future[interface{}]
	Writers(session Session, scope string, table string, filter interface{}) 														futures.Future[interface{}]
	Tasks(session Session, scope string, table string, filter interface{}) 															futures.Future[interface{}]
	Lineage(session Session, scope string, table string, filter interface{}) 														futures.Future[interface{}]
	DeployOracle(session Session, oracleType string, targetBlockchain string, source string, deployOptions DeployOptions)			futures.Future[interface{}]
	DeployFeed(session Session, image string, options DeployOptions) 																futures.Future[interface{}]
	RemoveFeed(session Session, feedId string) 																						futures.Future[interface{}]
	StartFeed(session Session, feedId string, options ComputeOptions)																futures.Future[interface{}]
	StopFeed(session Session, feedId string) 																						futures.Future[interface{}]
	IssueCredentials(session Session, issuer string, holder string, credentials ordered.OrderedMap, options CredentialsOptions) 	futures.Future[interface{}]
	VerifyCredentials(session Session, credentials ordered.OrderedMap, options CredentialsOptions) 									futures.Future[interface{}]
	CreatePresentation(session Session, credentials ordered.OrderedMap, subject string, options CredentialsOptions)					futures.Future[interface{}]
	SignPresentation(session Session, presentation ordered.OrderedMap, domain string, challenge string, options CredentialsOptions) futures.Future[interface{}]
	VerifyDataSignature(session Session, signer string, signature string, toSign string) 											futures.Future[interface{}]
	VerifyPresentation(session Session, presentation ordered.OrderedMap, domain string,
		challenge string, options CredentialsOptions) 																				futures.Future[interface{}]
	PostMessage(session Session, targetInboxKey string, message string, options MessageOptions) 									futures.Future[interface{}]
	PollMessages(session Session, inboxKey string, options MessageOptions) 															futures.Future[interface{}]
	GetSidechainDetails(session Session) 																							futures.Future[interface{}]
	GetUserDetails(session Session, publicKey string)																				futures.Future[interface{}]
	GetNodes(session Session)																										futures.Future[interface{}]
	GetScopes(session Session) 																										futures.Future[interface{}]
	GetTables(session Session, scope string) 																						futures.Future[interface{}]
	GetNodeConfig(session Session, nodePublicKey string) 																			futures.Future[interface{}]
	GetAccountNotifications(session Session) 																						futures.Future[interface{}]
	Balance(session Session, accountAddress string, scope string, token string)														futures.Future[interface{}]
	Transfer(session Session, accountAddress string, scope string, token string, amount big.Int) 									futures.Future[interface{}]
	Call(session Session, contractAddress string, scope string, fn string, data []byte) 											futures.Future[interface{}]
	UpdateFees(session Session, scope string, fees string)																			futures.Future[interface{}]
	ContractState(session Session, contractAddress string, scope string) 															futures.Future[interface{}]
	CreateUserAccount(session Session, organization string, account string, publicKey string, roles []string) 						futures.Future[interface{}]
	ResetConfig(session Session) 																									futures.Future[interface{}]
	Withdraw(session Session, token string, amount big.Int) 																		futures.Future[interface{}]
}

type NodeApi struct {
	Config			ChainClientConfig
	ClientPublicKey	string
	Client			AbstractClient
}

func NewNodeApi(ChainClientConfig ChainClientConfig) NodeApi {
	return NodeApi{Config: ChainClientConfig}
}

func (nodeApi *NodeApi) Init() {
	nodeApi.ClientPublicKey = ReadKey(nodeApi.Config.ClientPubKey, nodeApi.Config.ClientPubKeyFile)

	isHttp := nodeApi.Config.HttpConfig != HttpConfig{}
	isWs := nodeApi.Config.WsConfig != WsConfig{}
	if isHttp {
		httpClient := NewHttpClient(nodeApi.Config)
		nodeApi.Client = &httpClient
	} else if isWs {
		wsClient := NewWsClient(nodeApi.Config)
		nodeApi.Client = &wsClient
	}
	nodeApi.Client.Init()
}

func (NodeApi *NodeApi) GenerateKeys() (string, string) {
	return GenerateKeys()
}

func (nodeApi *NodeApi) Login(organization string, account string, scopes string, credentials string) futures.Future[interface{}] {
	return nodeApi.Client.Login(organization, account, scopes, credentials)
}

func (nodeApi *NodeApi) CreateTable(session Session, scope string, table string, createOptions CreateOptions) futures.Future[interface{}] {
	return nodeApi.Client.CreateTable(session, scope, table, createOptions)
}

func (nodeApi *NodeApi) DropTable(session Session, scope string, table string) futures.Future[interface{}] {
	return nodeApi.Client.DropTable(session, scope, table)
} 

func (nodeApi *NodeApi) Read(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.Read(session, scope, table, filter, readOptions)
}

func (nodeApi *NodeApi) GetTableDefinition(session Session, scope string, table string) futures.Future[interface{}] {
	return nodeApi.Client.GetTableDefinition(session, scope, table)
}

func (nodeApi *NodeApi) Logout(session Session) futures.Future[interface{}] {
	return nodeApi.Client.Logout(session)
}

func (nodeApi *NodeApi) Status(session Session) futures.Future[interface{}] {
	return nodeApi.Client.Status(session)
}

func (nodeApi *NodeApi) Terms(session Session, scope string, table string, options CreateOptions) futures.Future[interface{}] {
	return nodeApi.Client.Terms(session, scope, table, options)
}

func (nodeApi *NodeApi) UpdateLayout(session Session, scope string, table string, layout interface{}) futures.Future[interface{}] {
	return nodeApi.UpdateLayout(session, scope, table, layout)
}

func (nodeApi *NodeApi) UpdateConfig(session Session, path string, values interface{}) futures.Future[interface{}] {
	return nodeApi.UpdateConfig(session, path, values)
}

func (nodeApi *NodeApi) GrantRole(session Session, account string, roles interface{}) futures.Future[interface{}] {
	return nodeApi.GrantRole(session, account, roles)
}

func (nodeApi *NodeApi) Count(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.Count(session, scope, table, filter, readOptions)
}

func (nodeApi *NodeApi) Delete(session Session, scope string, table string, filter interface{}, deleteOptions DeleteOptions) futures.Future[interface{}] {
	return nodeApi.Client.Delete(session, scope, table, filter, deleteOptions)
}

func (nodeApi *NodeApi) DownloadTable(session Session, scope string, table string, filter interface{}, format string, readOptions ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.DownloadTable(session, scope, table, filter, format, readOptions)
}

func (nodeApi *NodeApi) HashRecord(row []interface{}, salt string, digest string) string {
	return base58.Encode([]byte(SignRequest([]byte(salt), ToJson(row))))
}

func (nodeApi *NodeApi) Sign(data string) string {
	return nodeApi.Client.ApiContext().CreateEd25519Signature(data)
}

func (nodeApi *NodeApi) VerifyKeySignature(publicKey ed25519.PublicKey, signature []byte, data string) bool {
	return nodeApi.Client.ApiContext().VerifyEd25519Signature(publicKey, signature, data)
}

func (nodeApi *NodeApi) VerifyLineageSignature(signature string, inputHash string, computeHash string, paramsHash string, data string) bool {
	pubKey := nodeApi.Client.ApiContext().ServerSigKey
	if &inputHash == nil {
		inputHash = ""
	}

	if &computeHash == nil {
		inputHash = ""
	}

	if &paramsHash == nil {
		inputHash = ""
	}
	toSign := inputHash + "\n" + computeHash + "\n" + paramsHash + "\n" + data

	sig := base58.Decode(signature)
	return nodeApi.Client.ApiContext().Verify(*pubKey, sig, toSign)
}

func (nodeApi *NodeApi) VerifySignature(signature string, data string) bool {
	pubKey := nodeApi.Client.ApiContext().ServerSigKey
	sig := base58.Decode(signature)
	return nodeApi.Client.ApiContext().Verify(*pubKey, sig, data)
}

func (nodeApi *NodeApi) Hashes(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.Hashes(session, scope, table, filter, readOptions)
}

func (nodeApi *NodeApi) HashCheckpoint(session Session, enable bool) futures.Future[interface{}] {
	return nodeApi.Client.HashCheckpoint(session, enable)
}

func (nodeApi *NodeApi) PublishDataset(session Session, did string, name string, description string, license string, metadata string, weave string, fullDescription string, logo string, category string, scope string, table string, filter interface{}, format string, price int64, token string, pageorder uint64, publishOptions PublishOptions) futures.Future[interface{}] {
	return nodeApi.Client.PublishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, publishOptions)
}

func (nodeApi *NodeApi) EnableProduct(session Session, did string, productType string, active bool) futures.Future[interface{}] {
	return nodeApi.Client.EnableProduct(session, did, productType, active)
}

func (nodeApi *NodeApi) DownloadDataset(session Session, did string, readOptions ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.DownloadDataset(session, did, readOptions)
}

func (nodeApi *NodeApi) PublishTask(session Session, did string, name string, description string, license string, metadata string, weave string, fullDescription string, logo string, category string, task string, price int64, token string, pageorder int64, publishOptions PublishOptions) futures.Future[interface{}] {
	return nodeApi.Client.PublishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, publishOptions)
}

func (nodeApi *NodeApi) RunTask(session Session, did string, computeOptions ComputeOptions) futures.Future[interface{}] {
	return nodeApi.Client.RunTask(session, did, computeOptions)
}

func (nodeApi *NodeApi) Subscribe(session Session, scope string, table string, filter interface{}, subscribeOptions SubscribeOptions, updateHandler interface{}) futures.Future[interface{}] {
	return nodeApi.Client.Subscribe(session, scope, table, filter, subscribeOptions, updateHandler)
}

func (nodeApi *NodeApi) Unsubscribe(session Session, subscriptionId string) futures.Future[interface{}] {
	return nodeApi.Client.Unsubscribe(session, subscriptionId)
}

func (nodeApi *NodeApi) Compute(session Session, image string, computeOptions ComputeOptions) futures.Future[interface{}] {
	return nodeApi.Client.Compute(session, image, computeOptions)
}

func (nodeApi *NodeApi) GetImage(session Session, image string, localOutputFolder string, computeOptions ComputeOptions) futures.Future[interface{}] {
	return nodeApi.Client.GetImage(session, image, localOutputFolder, computeOptions)
}

func (nodeApi *NodeApi) Flearn(session Session, image string, flOptions FLOptions) futures.Future[interface{}] {
	return nodeApi.Client.Flearn(session, image, flOptions)
}

func (nodeApi *NodeApi) SplitLearn(session Session, image string, slOptions SLOptions) futures.Future[interface{}] {
	return nodeApi.Client.SplitLearn(session, image, slOptions)
}

func (nodeApi *NodeApi) ForwardApi(session Session, feedId string, params ordered.OrderedMap) futures.Future[interface{}] {
	return nodeApi.Client.ForwardApi(session, feedId, params)
}

func (nodeApi *NodeApi) UploadApi(session Session, params ordered.OrderedMap) futures.Future[interface{}] {
	return nodeApi.Client.UploadApi(session, params)
}

func (nodeApi *NodeApi) HeGetInputs(session Session, datasources []interface{}, args []interface{}) futures.Future[interface{}] {
	return nodeApi.Client.HeGetInputs(session, datasources, args)
}

func (nodeApi *NodeApi) HeGetOutputs(session Session, encoded string, args []interface{}) futures.Future[interface{}] {
	return nodeApi.Client.HeGetOutputs(session, encoded, args)
}

func (nodeApi *NodeApi) HeEncode(session Session, items []interface{}) futures.Future[interface{}] {
	return nodeApi.Client.HeEncode(session, items)
}

func (nodeApi *NodeApi) Mpc(session Session, scope string, table string, algo string, fields []string, filter interface{}, mpcOptions MPCOptions) futures.Future[interface{}] {
	return nodeApi.Client.Mpc(session, scope, table, algo, fields, filter, mpcOptions)
}

func (nodeApi *NodeApi) StorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.StorageProof(session, scope, table, filter, challenge, options)
}

func (nodeApi *NodeApi) ZkStorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.ZkStorageProof(session, scope, table, filter, challenge, options)
}

func (nodeApi *NodeApi) MerkleTree(session Session, scope string, table string, filter interface{}, salt string, digest string, options ReadOptions) futures.Future[interface{}] {
	return nodeApi.Client.MerkleTree(session, scope, table, filter, salt, digest, options)
}

func (nodeApi *NodeApi) MerkleProof(session Session, scope string, table string, hash string) futures.Future[interface{}] {
	return nodeApi.Client.MerkleProof(session, scope, table, hash)
}

func (nodeApi *NodeApi) RootHash(session Session, scope string, table string) futures.Future[interface{}] {
	return nodeApi.Client.RootHash(session, scope, table)
}

func (nodeApi *NodeApi) ZkMerkleTree(session Session, scope string, table string, filter interface{}, salt string, digest string, rounds int, seed int, options ZKOptions) futures.Future[interface{}] {
	return nodeApi.Client.ZkMerkleTree(session, scope, table, filter, salt, digest, rounds, seed, options)
}

func (nodeApi *NodeApi) MimcHash(session Session, data string, rounds int, seed int) futures.Future[interface{}] {
	return nodeApi.Client.MimcHash(session, data, rounds, seed)
}

func (nodeApi *NodeApi) ProofsLastHash(session Session, scope string, table string) futures.Future[interface{}] {
	return nodeApi.Client.ProofsLastHash(session, scope, table)
}

func (nodeApi *NodeApi) UpdateProofs(session Session, scope string, table string) futures.Future[interface{}] {
	return nodeApi.Client.UpdateProofs(session, scope, table)
}

func (nodeApi *NodeApi) VerifyMerkleHash(session Session, tree string, hash string, digest string) futures.Future[interface{}] {
	return nodeApi.Client.VerifyMerkleHash(session, tree, hash, digest)
}

func (nodeApi *NodeApi) ZkProof(session Session, scope string, table string, gadget string, params string, fields []string, filter interface{}, zkOptions ZKOptions) futures.Future[interface{}] {
	return nodeApi.Client.ZkProof(session, scope, table, gadget, params, fields, filter, zkOptions)
}

func (nodeApi *NodeApi) ZkDataProof(session Session, gadget string, params string, values []interface{}, zkOptions ZKOptions) futures.Future[interface{}] {
	return nodeApi.Client.ZkDataProof(session, gadget, params, values, zkOptions)
}

func (nodeApi *NodeApi) VerifyZkProof(session Session, proof string, gadget string, params string, commitment string, nGenerators int) futures.Future[interface{}] {
	return nodeApi.Client.VerifyZkProof(session, proof, gadget, params, commitment, nGenerators)
}

func (nodeApi *NodeApi) TaskLineage(session Session, taskId string) futures.Future[interface{}] {
	return nodeApi.Client.TaskLineage(session, taskId)
}

func (nodeApi *NodeApi) VerifyTaskLineage(session Session, lineageData ordered.OrderedMap) futures.Future[interface{}] {
	return nodeApi.Client.VerifyTaskLineage(session, lineageData)
}

func (nodeApi *NodeApi) TaskOutputData(session Session, taskId string, options OutputOptions) futures.Future[interface{}] {
	return nodeApi.Client.TaskOutputData(session, taskId, options)
}

func (nodeApi *NodeApi) History(session Session, scope string, table string, filter interface{}, historyOptions HistoryOptions) futures.Future[interface{}] {
	return nodeApi.Client.History(session, scope, table, filter, historyOptions)
}

func (nodeApi *NodeApi) Writers(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	return nodeApi.Client.Writers(session, scope, table, filter)
}

func (nodeApi *NodeApi) Tasks(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	return nodeApi.Client.Tasks(session, scope, table, filter)
}

func (nodeApi *NodeApi) Lineage(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	return nodeApi.Client.Lineage(session, scope, table, filter)
}

func (nodeApi *NodeApi) DeployOracle(session Session, oracleType string, targetBlockchain string, source string, deployOptions DeployOptions) futures.Future[interface{}] {
	return nodeApi.Client.DeployOracle(session, oracleType, targetBlockchain, source, deployOptions)
}

func (nodeApi *NodeApi) DeployFeed(session Session, image string, options DeployOptions) futures.Future[interface{}] {
	return nodeApi.Client.DeployFeed(session, image, options)
}

func (nodeApi *NodeApi) RemoveFeed(session Session, feedId string) futures.Future[interface{}] {
	return nodeApi.Client.RemoveFeed(session, feedId)
}

func (nodeApi *NodeApi) StartFeed(session Session, feedId string, options ComputeOptions) futures.Future[interface{}] {
	return nodeApi.Client.StartFeed(session, feedId, options)
}

func (nodeApi *NodeApi) StopFeed(session Session, feedId string) futures.Future[interface{}] {
	return nodeApi.Client.StopFeed(session, feedId)
}

func (nodeApi *NodeApi) IssueCredentials(session Session, issuer string, holder string, credentials ordered.OrderedMap, options CredentialsOptions) futures.Future[interface{}] {
	return nodeApi.Client.IssueCredentials(session, issuer, holder, credentials, options)
}

func (nodeApi *NodeApi) VerifyCredentials(session Session, credentials ordered.OrderedMap, options CredentialsOptions) futures.Future[interface{}] {
	return nodeApi.Client.VerifyCredentials(session, credentials, options)
}

func (nodeApi *NodeApi) CreatePresentation(session Session, credentials ordered.OrderedMap, subject string, options CredentialsOptions) futures.Future[interface{}] {
	return nodeApi.Client.CreatePresentation(session, credentials, subject, options)
}

func (nodeApi *NodeApi) SignPresentation(session Session, presentation ordered.OrderedMap, domain string, challenge string, options CredentialsOptions) futures.Future[interface{}] {
	return nodeApi.Client.SignPresentation(session, presentation, domain, challenge, options)
}

func (nodeApi *NodeApi) VerifyDataSignature(session Session, signer string, signature string, toSign string) futures.Future[interface{}] {
	return nodeApi.Client.VerifyDataSignature(session, signer, signature, toSign)
}

func (nodeApi *NodeApi) VerifyPresentation(session Session, presentation ordered.OrderedMap, domain string, challenge string, options CredentialsOptions) futures.Future[interface{}] {
	return nodeApi.Client.VerifyPresentation(session, presentation, domain, challenge, options)
}

func (nodeApi *NodeApi) PostMessage(session Session, targetInboxKey string, message string, options MessageOptions) futures.Future[interface{}] {
	return nodeApi.Client.PostMessage(session, targetInboxKey, message, options)
}

func (nodeApi *NodeApi) PollMessages(session Session, inboxKey string, options MessageOptions) futures.Future[interface{}] {
	return nodeApi.Client.PollMessages(session, inboxKey, options)
}

func (nodeApi *NodeApi) GetSidechainDetails(session Session) futures.Future[interface{}] {
	return nodeApi.Client.GetSidechainDetails(session)
}

func (nodeApi *NodeApi) GetUserDetails(session Session, publicKey string) futures.Future[interface{}] {
	return nodeApi.Client.GetUserDetails(session, publicKey)
}

func (nodeApi *NodeApi) GetNodes(session Session) futures.Future[interface{}] {
	return nodeApi.Client.GetNodes(session)
}

func (nodeApi *NodeApi) GetScopes(session Session) futures.Future[interface{}] {
	return nodeApi.Client.GetScopes(session)
}

func (nodeApi *NodeApi) GetTables(session Session, scope string) futures.Future[interface{}] {
	return nodeApi.Client.GetTables(session, scope)
}

func (nodeApi *NodeApi) GetNodeConfig(session Session, nodePublicKey string) futures.Future[interface{}] {
	return nodeApi.Client.GetNodeConfig(session, nodePublicKey)
}

func (nodeApi *NodeApi) GetAccountNotifications(session Session) futures.Future[interface{}] {
	return nodeApi.Client.GetAccountNotifications(session)
}

func (nodeApi *NodeApi) Balance(session Session, accountAddress string, scope string, token string) futures.Future[interface{}] {
	return nodeApi.Client.Balance(session, accountAddress, scope, token)
}

func (nodeApi *NodeApi) Transfer(session Session, accountAddress string, scope string, token string, amount big.Int) futures.Future[interface{}] {
	return nodeApi.Client.Transfer(session, accountAddress, scope, token, amount)
}

func (nodeApi *NodeApi) Call(session Session, contractAddress string, scope string, fn string, data []byte) futures.Future[interface{}] {
	return nodeApi.Client.Call(session, contractAddress, scope, fn, data)
}

func (nodeApi *NodeApi) UpdateFees(session Session, scope string, fees string) futures.Future[interface{}] {
	return nodeApi.Client.UpdateFees(session, scope, fees)
}

func (nodeApi *NodeApi) ContractState(session Session, contractAddress string, scope string) futures.Future[interface{}] {
	return nodeApi.Client.ContractState(session, contractAddress, scope)
}

func (nodeApi *NodeApi) CreateUserAccount(session Session, organization string, account string, publicKey string, roles []string) futures.Future[interface{}] {
	return nodeApi.Client.CreateUserAccount(session, organization, account, publicKey, roles)
}

func (nodeApi *NodeApi) ResetConfig(session Session) futures.Future[interface{}] {
	return nodeApi.Client.ResetConfig(session)
}

func (nodeApi *NodeApi) Withdraw(session Session, token string, amount big.Int) futures.Future[interface{}] {
	return nodeApi.Client.Withdraw(session, token, amount)
}