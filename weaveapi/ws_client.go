package weaveapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/Allan-Jacobs/go-futures"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"gitlab.com/c0b/go-ordered-json"
)

const WS_CONN_TIMEOUT = 100

type WsClient struct {
	ChainClientConfig 	ChainClientConfig
	ClientPublicKey		string
	ClientPrivateKey	string
	ServerSigKey		string
	SecretKey			[]byte
	websocket			websocket.Conn
	wsOpen				bool
	context				context.Context
	apiContext			ApiContext
	clientVersion 		string
	apiUrl 				string
	version 			string
	encryption 			bool
	pendingRequests		ordered.OrderedMap
	pendingReplies		ordered.OrderedMap
}

func NewWsClient(ChainClientConfig ChainClientConfig) WsClient {
	version := "v1"
	encryption := ChainClientConfig.encryption
	
	return WsClient{ChainClientConfig: ChainClientConfig, clientVersion: "v1", version: version, encryption: encryption}
}

func (client WsClient) Client() WsClient {
	return client
}

func (client *WsClient) ApiContext() *ApiContext {
	return &client.apiContext
}

func (client *WsClient) Init() {

	client.pendingRequests = *ordered.NewOrderedMap()
	client.pendingReplies = *ordered.NewOrderedMap()

	var protocol string
	if client.ChainClientConfig.WsConfig.UseWss {
		protocol = "wss"
	} else {
		protocol = "ws"
	}
	port, _ := strconv.Atoi(client.ChainClientConfig.WsConfig.Port)
	client.apiUrl = fmt.Sprintf("%s://%s:%d", protocol, ParseHost(client.ChainClientConfig.WsConfig.Host), port)

	client.startDaemon()

	serverPublicKeyMap, error := client.PublicKey().Await()
	HandleError(error)
	serverPublicKey := serverPublicKeyMap.(*ordered.OrderedMap).Get("data")

	serverSigKeyMap, error := client.SigKey().Await()
	HandleError(error)
	serverSigKey := serverSigKeyMap.(*ordered.OrderedMap).Get("data")
	client.ServerSigKey = serverSigKey.(string)

	client.ClientPublicKey = ReadKey(client.ChainClientConfig.ClientPubKey, client.ChainClientConfig.ClientPubKeyFile)
	client.ClientPrivateKey = ReadKey(client.ChainClientConfig.ClientPrivKey, client.ChainClientConfig.ClientPrivKeyFile)
	
	decodedSeed, _ :=  hex.DecodeString(client.ChainClientConfig.Seed)
	apiContext := NewApiContext(
		decodedSeed,
		client.ChainClientConfig.Seed,
		serverPublicKey.(string),
		client.ServerSigKey,
		client.ClientPublicKey,
		client.ClientPrivateKey)
	
	client.apiContext = apiContext
	client.SecretKey = SharedSecret(client.apiContext.ClientPrivateKey, client.apiContext.ServerPubKey)[1:]
}

func (client *WsClient) startDaemon() {
	ws, _, err := websocket.DefaultDialer.Dial(client.apiUrl, nil)

	HandleError(err)

	client.websocket = *ws
	
	go client.startWsLoop()
}

func (client *WsClient) startWsLoop() {
	client.websocket.SetReadLimit(2048)
	client.websocket.SetReadDeadline(time.Now().Add(60 * time.Second))
	client.websocket.SetPongHandler(func(string) error { client.websocket.SetReadDeadline(time.Now().Add(60 * time.Second)); return nil })
	for {
		_, message, err := client.websocket.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				HandleError(err)
			}
			break
		}
		message = bytes.TrimSpace(bytes.Replace(message, []byte{'\n'}, []byte{' '}, -1))
		client.onMessage(message)
	}
}

func (client *WsClient) wsLoop() {
	for {
		msgType, msg, error := client.websocket.ReadMessage()
		HandleError(error)

		if msgType == 1 {
			client.onMessage(msg)
		}
	}	
}

func (client *WsClient) onMessage(msg []byte) {
	data := ordered.NewOrderedMap()

	error := data.UnmarshalJSON(msg)
	HandleError(error)

	id := data.Get("id")
 
	if id != nil {
		reply := data.Get("reply").(*ordered.OrderedMap)

		if reply.Get("res") == "fwd" {
			r := reply.Get("data").(ordered.OrderedMap)
			var b64DecodedMsg []byte
			base64.StdEncoding.Decode(b64DecodedMsg, r.Get("msg").([]byte))
			decrypted := AESDecrypt(b64DecodedMsg, client.SecretKey, client.apiContext.Seed, string(FromHex(r.Get("x-iv").(string))))
			error = reply.UnmarshalJSON(decrypted)
			HandleError(error)
		}
		
		if reply.Has("target") && reply.Get("target").(*ordered.OrderedMap).Has("operationType") && strings.ToLower(reply.Get("target").(*ordered.OrderedMap).Get("operationType").(string)) == "login" {
			sdataStr := reply.Get("data").(string)
			sdata := ordered.NewOrderedMap()
			error := sdata.UnmarshalJSON([]byte(sdataStr))
			HandleError(error)

			secret := FromHex(sdata.Get("secret").(string))
			iv := FromHex(sdata.Get("x-iv").(string))
			decryptedSecret := AESDecrypt(secret, client.SecretKey, client.apiContext.Seed, string(iv))
			sdata.Delete("secret")
			
			client.pendingReplies.Set(id.(string), NewSession(*sdata, string(decryptedSecret)))
		} else {
			client.pendingReplies.Set(id.(string), reply)
		}
	}
}

func (client *WsClient) request(data ordered.OrderedMap, isAuth bool) futures.Future[interface{}] {
	id := uuid.New().String()
	id = strings.ReplaceAll(id, "-", "")

	data.Set("id", id)
	future := futures.PromiseLikeFuture(func(resolve futures.Resolver[interface{}], reject futures.Rejector) {
		for {
			if client.pendingReplies.Has(id) {
				break
			}
			time.Sleep(time.Millisecond * 10)
		}
		resolve(client.pendingReplies.Get(id))
	})

	msg, err := data.MarshalJSON()
	HandleError(err)

	if isAuth && client.encryption {
		iv := generateIv()
		encrypted := AESEncrypt(string(msg), client.SecretKey, client.apiContext.Seed, iv)

		request := ordered.NewOrderedMap()
		request.Set("id", id)
		request.Set("type", "enc")
		request.Set("x-enc", base64.StdEncoding.EncodeToString(encrypted))
		request.Set("x-iv", hex.EncodeToString([]byte(iv)))
		request.Set("x-key", client.apiContext.PublicKey)

		requestJson, err := request.MarshalJSON()
		HandleError(err)
		error := client.websocket.WriteMessage(1, requestJson)
		HandleError(error)
	} else {
		error := client.websocket.WriteMessage(1, msg)
		HandleError(error)
	}
	return future
}

func (client *WsClient) Version() futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "version")
	return client.request(*data, false)
}

func (client *WsClient) Ping() futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "ping")
	return client.request(*data, false)
}

func (client *WsClient) PublicKey() futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "public_key")
	return client.request(*data, false)
}

func (client *WsClient) SigKey() futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "sig_key")
	return client.request(*data, false)
}

func (client *WsClient) Login(organization string, account string, scopes string, credentials string) futures.Future[interface{}] {
	toSign := organization + "\n" + client.ClientPublicKey + "\n" + scopes
	iv := generateIv()
	signature := client.signString(toSign, iv)

	if len(account) <= 0 || account == "" {
		account = client.ClientPublicKey
	}
	
	data := ordered.NewOrderedMap()
	data.Set("type", "login")
	data.Set("organization", organization)
	data.Set("account", account)
	data.Set("scopes", scopes)
	data.Set("signature", signature)
	if credentials == "" {
		data.Set("credentials", nil)
	} else {
		data.Set("credentials", credentials)
	}
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))
	data.Set("x-key", client.apiContext.PublicKey)
	data.Set("x-sig-key", client.apiContext.SigKey)
	data.Set("x-dlg-sig", client.apiContext.CreateEd25519Signature(string(client.apiContext.ServerPubKey.Bytes(true))))
	data.Set("x-own-sig", client.apiContext.CreateEd25519Signature(string(client.apiContext.PublicKey)))

	return client.request(*data, true)
}

func (client *WsClient) authPost(session Session, data ordered.OrderedMap) futures.Future[interface{}] {
	data.Set("x-api-key", session.ApiKey)
	data.Set("x-nonce", session.GetNonce())

	signature := SignWs(session.Secret, data)
	data.Set("x-sig", signature)

	return client.request(data, true)
}

func (client *WsClient) Logout(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "logout")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)

	return client.authPost(session, *data)
}

func (client *WsClient) Status(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "status")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)

	return client.authPost(session, *data)
}

func (client *WsClient) Terms(session Session, scope string, table string, options CreateOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "terms")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) CreateTable(session Session, scope string, table string, createOptions CreateOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "create")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", createOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) DropTable(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "drop")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)

	return client.authPost(session, *data)
}

func (client *WsClient) UpdateLayout(session Session, scope string, table string, layout interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "update_layout")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("layout", layout)

	return client.authPost(session, *data)
}

func (client *WsClient) UpdateConfig(session Session, path string, values interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "update_config")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("path", path)
	data.Set("values", values)

	return client.authPost(session, *data)
}

func (client *WsClient) GrantRole(session Session, account string, roles interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "grant_role")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("targetAccount", account)
	data.Set("layout", roles)

	return client.authPost(session, *data)
}

func (client *WsClient) Write(session Session, scope string, records Records, writeOptions WriteOptions) futures.Future[interface{}] {
	if session.IntegrityChecks {
		layout := client.getLayout(session, scope, records.Table)
		integritySig := IntegritySignature(client.ClientPublicKey, session, scope, records, layout, client.apiContext.SeedHex, client.apiContext.CreateEd25519Signature)

		records.Integrity = append(records.Integrity, integritySig)
	}

	data := ordered.NewOrderedMap()
	data.Set("type", "write")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", records.Table)
	data.Set("enc", "json")
	data.Set("records", records.ToJson())
	data.Set("options", ToJson(writeOptions))

	return client.authPost(session, *data)
}

func (client *WsClient) Read(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "read")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("options", readOptions)
	data.Set("scope", scope)
	data.Set("table", table)
	
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) signString(toSign string, iv string) string {
	return hex.EncodeToString(AESEncrypt(toSign, client.SecretKey, client.apiContext.Seed, iv))
}

func (client *WsClient) getLayout(session Session, scope string, table string) ordered.OrderedMap {
	key := scope + ":" + table
	layout := session.TableLayoutCache.Get(key)
	if layout == nil {
		layoutMap := ordered.NewOrderedMap()
	
		result := ordered.NewOrderedMap()
		c := client.GetTableDefinition(session, scope, table)
		response, error := c.Await()
		if error != nil {
			panic(error)
		}
		result.UnmarshalJSON([]byte(response.(string)))
		data := result.Get("data")
		dataString := string(data.(string))
		layoutMap.UnmarshalJSON([]byte(dataString))
		session.TableLayoutCache.Set(key, layoutMap)

		layoutResult := layoutMap.Get("layout")
		layoutResultMap := layoutResult.(*ordered.OrderedMap)
		return *layoutResultMap
	}

	return *ordered.NewOrderedMap()
}

func (client *WsClient) GetTableDefinition(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_table_definition")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
		
	return client.authPost(session, *data)
}

func (client *WsClient) Count(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "count")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", readOptions)

	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) Delete(session Session, scope string, table string, filter interface{}, deleteOptions DeleteOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "delete")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", deleteOptions)

	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) DownloadTable(session Session, scope string, table string, filter interface{}, format string, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "download_table")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("format", format)
	data.Set("options", readOptions)

	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) Hashes(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "hashes")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", readOptions)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) HashCheckpoint(session Session, enable bool) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "hash_checkpoint")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("options", enable)

	return client.authPost(session, *data)
}

func (client *WsClient) PublishDataset(session Session, did string, name string, description string, license string, metadata string, weave string, fullDescription string, logo string, category string, scope string, table string, filter interface{}, format string, price int64, token string, pageorder uint64, publishOptions PublishOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "publish_dataset")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("did", did)
	data.Set("name", name)
	data.Set("description", description)
	data.Set("license", license)
	data.Set("metadata", metadata)
	data.Set("weave", weave)
	data.Set("full_description", fullDescription)
	data.Set("logo", logo)
	data.Set("category", category)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("format", format)
	data.Set("price", price)
	data.Set("token", token)
	data.Set("pageorder", pageorder)
	data.Set("options", publishOptions)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) EnableProduct(session Session, did string, productType string, active bool) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "enable_product")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("did", did)
	data.Set("productType", productType)
	data.Set("active", active)

	return client.authPost(session, *data)
}

func (client *WsClient) DownloadDataset(session Session, did string, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "download_dataset")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("did", did)
	data.Set("options", readOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) PublishTask(session Session, did string, name string, description string, license string, metadata string, weave string, fullDescription string, logo string, category string, task string, price int64, token string, pageorder int64, publishOptions PublishOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "publish_task")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("did", did)
	data.Set("name", name)
	data.Set("description", description)
	data.Set("license", license)
	data.Set("metadata", metadata)
	data.Set("weave", weave)
	data.Set("full_description", fullDescription)
	data.Set("logo", logo)
	data.Set("category", category)
	data.Set("task", task)
	data.Set("price", price)
	data.Set("token", token)
	data.Set("pageorder", pageorder)
	data.Set("options", publishOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) RunTask(session Session, did string, computeOptions ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "run_task")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("did", did)
	data.Set("options", computeOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) Subscribe(session Session, scope string, table string, filter interface{}, subscribeOptions SubscribeOptions, updateHandler interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "subscribe")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", subscribeOptions)
	data.Set("updateHandler", updateHandler)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) Unsubscribe(session Session, subscriptionId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "unsubscribe")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("subscriptionId", subscriptionId)

	return client.authPost(session, *data)
}

func (client *WsClient) Compute(session Session, image string, computeOptions ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "compute")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("image", image)
	data.Set("options", computeOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) GetImage(session Session, image string, localOutputFolder string, computeOptions ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_image")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("image", image)
	data.Set("localOutputFolder", localOutputFolder)
	data.Set("options", computeOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) Flearn(session Session, image string, flOptions FLOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "f_learn")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("image", image)
	data.Set("options", flOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) SplitLearn(session Session, image string, slOptions SLOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "split_learn")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("image", image)
	data.Set("options", slOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) ForwardApi(session Session, feedId string, params ordered.OrderedMap) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "forward_api")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("feedId", feedId)
	data.Set("params", params)

	return client.authPost(session, *data)
}

func (client *WsClient) UploadApi(session Session, params ordered.OrderedMap) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "upload_api")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("params", params)

	return client.authPost(session, *data)
}

func (client *WsClient) HeGetInputs(session Session, datasources []interface{}, args []interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "he_get_inputs")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("datasources", datasources)
	data.Set("args", args)

	return client.authPost(session, *data)
}

func (client *WsClient) HeGetOutputs(session Session, encoded string, args []interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "he_get_outputs")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("encoded", encoded)
	data.Set("args", args)

	return client.authPost(session, *data)
}

func (client *WsClient) HeEncode(session Session, items []interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "he_encode")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("args", items)

	return client.authPost(session, *data)
}

func (client *WsClient) Mpc(session Session, scope string, table string, algo string, fields []string, filter interface{}, mpcOptions MPCOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "mpc")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("algo", algo)
	data.Set("fields", fields)
	data.Set("options", mpcOptions)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) StorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "storage_proof")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("challenge", challenge)
	data.Set("options", options)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) ZkStorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "zk_storage_proof")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("challenge", challenge)
	data.Set("options", options)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) MerkleTree(session Session, scope string, table string, filter interface{}, salt string, digest string, options ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "merkle_tree")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("salt", salt)
	data.Set("digest", digest)
	data.Set("options", options)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) MerkleProof(session Session, scope string, table string, hash string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "merkle_proof")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("hash", hash)

	return client.authPost(session, *data)
}

func (client *WsClient) RootHash(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "root_hash")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)

	return client.authPost(session, *data)
}

func (client *WsClient) ZkMerkleTree(session Session, scope string, table string, filter interface{}, salt string, digest string, rounds int, seed int, options ZKOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "zk_merkle_tree")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("salt", salt)
	data.Set("digest", digest)
	data.Set("rounds", rounds)
	data.Set("seed", seed)
	data.Set("options", options)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) MimcHash(session Session, data string, rounds int, seed int) futures.Future[interface{}] {
	dataMap := ordered.NewOrderedMap()
	dataMap.Set("type", "mimc_hash")
	dataMap.Set("organization", session.Organization)
	dataMap.Set("account", session.Account)
	dataMap.Set("data", data)
	dataMap.Set("rounds", rounds)
	dataMap.Set("seed", seed)

	return client.authPost(session, *dataMap)
}

func (client *WsClient) ProofsLastHash(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "proofs_last_hash")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)

	return client.authPost(session, *data)
}

func (client *WsClient) UpdateProofs(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "update_proofs")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)

	return client.authPost(session, *data)
}

func (client *WsClient) VerifyMerkleHash(session Session, tree string, hash string, digest string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "verify_merkle_hash")
	data.Set("tree", tree)
	data.Set("hash", hash)
	data.Set("digest", digest)

	return client.authPost(session, *data)
}

func (client *WsClient) ZkProof(session Session, scope string, table string, gadget string, params string, fields []string, filter interface{}, zkOptions ZKOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "zk_proof")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("gadget", gadget)
	data.Set("params", params)
	data.Set("fields", fields)
	data.Set("options", zkOptions)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) ZkDataProof(session Session, gadget string, params string, values []interface{}, zkOptions ZKOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "zk_data_proof")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("gadget", gadget)
	data.Set("params", params)
	data.Set("values", values)
	data.Set("options", zkOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) VerifyZkProof(session Session, proof string, gadget string, params string, commitment string, nGenerators int) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "zk_proof")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("proof", proof)
	data.Set("gadget", gadget)
	data.Set("params", params)
	data.Set("commitment", commitment)
	data.Set("nGenerators", nGenerators)

	return client.authPost(session, *data)
}

func (client *WsClient) TaskLineage(session Session, taskId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "task_lineage")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("taskId", taskId)

	return client.authPost(session, *data)
}

func (client *WsClient) VerifyTaskLineage(session Session, lineageData ordered.OrderedMap) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "verify_task_lineage")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("lineageData", lineageData)

	return client.authPost(session, *data)
}

func (client *WsClient) TaskOutputData(session Session, taskId string, options OutputOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "task_output_data")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("taskId", taskId)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) History(session Session, scope string, table string, filter interface{}, historyOptions HistoryOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "history")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", historyOptions)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) Writers(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "writers")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) Tasks(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "tasks")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) Lineage(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "lineage")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("table", table)
	if filter != nil {
		data.Set("filter", filter)
	}

	return client.authPost(session, *data)
}

func (client *WsClient) DeployOracle(session Session, oracleType string, targetBlockchain string, source string, deployOptions DeployOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "deploy_oracle")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("oracleType", oracleType)
	data.Set("targetBlockchain", targetBlockchain)
	data.Set("source", source)
	data.Set("options", deployOptions)

	return client.authPost(session, *data)
}

func (client *WsClient) DeployFeed(session Session, image string, options DeployOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "deploy_feed")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("image", image)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) RemoveFeed(session Session, feedId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "remove_feed")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("feedId", feedId)

	return client.authPost(session, *data)
}

func (client *WsClient) StartFeed(session Session, feedId string, options ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "start_feed")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("feedId", feedId)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) StopFeed(session Session, feedId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "stop_feed")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("feedId", feedId)

	return client.authPost(session, *data)
}

func (client *WsClient) IssueCredentials(session Session, issuer string, holder string, credentials ordered.OrderedMap, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "issue_credentials")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("issuer", issuer)
	data.Set("holder", holder)
	data.Set("credentials", credentials)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) VerifyCredentials(session Session, credentials ordered.OrderedMap, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "verify_credentials")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("credentials", credentials)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) CreatePresentation(session Session, credentials ordered.OrderedMap, subject string, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "create_presentation")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("credentials", credentials)
	data.Set("subject", subject)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) SignPresentation(session Session, presentation ordered.OrderedMap, domain string, challenge string, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "sign_presentation")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("presentation", presentation)
	data.Set("domain", domain)
	data.Set("challenge", challenge)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) VerifyDataSignature(session Session, signer string, signature string, toSign string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "verify_data_signature")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("signer", signer)
	data.Set("signature", signature)
	data.Set("data", toSign)

	return client.authPost(session, *data)
}

func (client *WsClient) VerifyPresentation(session Session, presentation ordered.OrderedMap, domain string, challenge string, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "verify_presentation")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("presentation", presentation)
	data.Set("domain", domain)
	data.Set("challenge", challenge)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) PostMessage(session Session, targetInboxKey string, message string, options MessageOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "post_message")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("targetInboxKey", targetInboxKey)
	data.Set("message", message)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) PollMessages(session Session, inboxKey string, options MessageOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "poll_messages")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("inboxKey", inboxKey)
	data.Set("options", options)

	return client.authPost(session, *data)
}

func (client *WsClient) GetSidechainDetails(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_sidechain_details")

	return client.authPost(session, *data)
}

func (client *WsClient) GetUserDetails(session Session, publicKey string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_user_details")
	data.Set("publicKey", publicKey)

	return client.authPost(session, *data)
}

func (client *WsClient) GetNodes(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_nodes")

	return client.authPost(session, *data)
}

func (client *WsClient) GetScopes(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_scopes")

	return client.authPost(session, *data)
}

func (client *WsClient) GetTables(session Session, scope string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_tables")
	data.Set("scope", scope)

	return client.authPost(session, *data)
}

func (client *WsClient) GetNodeConfig(session Session, nodePublicKey string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_node_config")
	data.Set("nodePublicKey", nodePublicKey)

	return client.authPost(session, *data)
}

func (client *WsClient) GetAccountNotifications(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "get_account_notifications")

	return client.authPost(session, *data)
}

func (client *WsClient) Balance(session Session, accountAddress string, scope string, token string) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token
	
	iv := generateIv()
	signature := client.signString(toSign, iv)

	data := ordered.NewOrderedMap()
	data.Set("type", "balance")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("accountAddress", accountAddress)
	data.Set("scope", scope)
	data.Set("token", token)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	return client.authPost(session, *data)
}

func (client *WsClient) Transfer(session Session, accountAddress string, scope string, token string, amount big.Int) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token + "\n" + amount.String()
	
	iv := generateIv()
	signature := client.signString(toSign, iv)

	data := ordered.NewOrderedMap()
	data.Set("type", "transfer")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("accountAddress", accountAddress)
	data.Set("scope", scope)
	data.Set("token", token)
	data.Set("amount", amount)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	return client.authPost(session, *data)
}

func (client *WsClient) Call(session Session, contractAddress string, scope string, fn string, data []byte) futures.Future[interface{}] {
	var serialized []byte
	base64.StdEncoding.Encode(serialized, data)
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + contractAddress + "\n" + scope + "\n" + fn + "\n" + string(serialized)

	iv := generateIv()
	signature := client.signString(toSign, iv)

	dataMap := ordered.NewOrderedMap()
	dataMap.Set("type", "call")
	dataMap.Set("organization", session.Organization)
	dataMap.Set("account", session.Account)
	dataMap.Set("contractAddress", contractAddress)
	dataMap.Set("scope", scope)
	dataMap.Set("function", fn)
	dataMap.Set("data", data)
	dataMap.Set("signature", signature)
	dataMap.Set("x-iv", hex.EncodeToString([]byte(iv)))

	return client.authPost(session, *dataMap)
}

func (client *WsClient) UpdateFees(session Session, scope string, fees string) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + scope + "\n" + fees

	iv := generateIv()
	signature := client.signString(toSign, iv)

	data := ordered.NewOrderedMap()
	data.Set("type", "update_fees")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("scope", scope)
	data.Set("fees", fees)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	return client.authPost(session, *data)
}

func (client *WsClient) ContractState(session Session, contractAddress string, scope string) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + contractAddress + "\n" + scope

	iv := generateIv()
	signature := client.signString(toSign, iv)

	data := ordered.NewOrderedMap()
	data.Set("type", "contract_state")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("contractAddress", contractAddress)
	data.Set("scope", scope)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	return client.authPost(session, *data)
}

func (client *WsClient) CreateUserAccount(session Session, organization string, account string, publicKey string, roles []string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "create_user_account")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("targetOrganization", organization)
	data.Set("targetAccount", account)
	data.Set("publicKey", publicKey)
	data.Set("roles", roles)

	return client.authPost(session, *data)
}

func (client *WsClient) ResetConfig(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "reset_config")

	return client.authPost(session, *data)
}

func (client *WsClient) Withdraw(session Session, token string, amount big.Int) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("type", "withdraw")
	data.Set("organization", session.Organization)
	data.Set("account", session.Account)
	data.Set("token", token)
	data.Set("amount", amount)

	return client.authPost(session, *data)
}