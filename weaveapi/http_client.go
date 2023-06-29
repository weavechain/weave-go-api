package weaveapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/Allan-Jacobs/go-futures"
	"gitlab.com/c0b/go-ordered-json"
)

type HttpClient struct {
	ChainClientConfig 	ChainClientConfig
	ClientPublicKey		string
	ClientPrivateKey	string
	ServerSigKey		string
	SecretKey			[]byte
	apiContext			ApiContext
	clientVersion 		string
	apiUrl 				string
	version 			string
	encryption 			bool
}

type headers struct {
	apiKey		string `json:"x-api-key"`
	nonce		string `json:"x-nonce"`
	signature 	string `json:"x-sig"`
}

type message struct {
	call	string	`json:"call"`
	body	string	`json:"body"`
	headers	string	`json:"headers"`
}

type encMessage struct {
	result			string				`json:"res"`
	data			ordered.OrderedMap	`json:"data`
}

func NewHttpClient(ChainClientConfig ChainClientConfig) HttpClient {
	version := "v1"
	encryption := ChainClientConfig.encryption
	
	return HttpClient{ChainClientConfig: ChainClientConfig, clientVersion: "v1", version: version, encryption: encryption}
}

func (client *HttpClient) Init() {
	var protocol string
	if client.ChainClientConfig.HttpConfig.UseHttps {
		protocol = "https"
	} else {
		protocol = "http"
	}

	port, _ := strconv.Atoi(client.ChainClientConfig.HttpConfig.Port)
	client.apiUrl = fmt.Sprintf("%s://%s:%d", protocol, ParseHost(client.ChainClientConfig.HttpConfig.Host), port)
	serverPublicKey := client.PublicKey().Data
	client.ServerSigKey = client.SigKey().Data
	client.ClientPublicKey = ReadKey(client.ChainClientConfig.ClientPubKey, client.ChainClientConfig.ClientPubKeyFile)
	client.ClientPrivateKey = ReadKey(client.ChainClientConfig.ClientPrivKey, client.ChainClientConfig.ClientPrivKeyFile)

	decodedSeed, _ :=  hex.DecodeString(client.ChainClientConfig.Seed)
	apiContext := NewApiContext(
		decodedSeed,
		client.ChainClientConfig.Seed,
		serverPublicKey,
		client.ServerSigKey,
		client.ClientPublicKey,
		client.ClientPrivateKey)
	
	client.apiContext = apiContext
	client.SecretKey = SharedSecret(client.apiContext.ClientPrivateKey, client.apiContext.ServerPubKey)[1:]
}

func (client *HttpClient) ApiContext() *ApiContext {
	return &client.apiContext
}

func (client *HttpClient) post(call string, data string, headers string) string {
	if client.encryption {
		url := client.apiUrl + "/" + client.version + "/enc"

		request := client.encrypt(call, data, headers)
		response, error := http.Post(url, "application/json", bytes.NewBuffer([]byte(request)))
		if error != nil {
			panic(error)
		}

		var output encMessage
		outputJson := readResponse(response)
		json.Unmarshal([]byte(outputJson), &output)
		outputStr := client.decrypt(output)

		return outputStr
	} else {
		url := client.apiUrl + "/" + client.version + "/" + call
		request, error := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))

		headersMap := ordered.NewOrderedMap()
		error = headersMap.UnmarshalJSON([]byte(headers))
		iterator := headersMap.EntriesIter()
		for {
			pair, ok := iterator()
			if !ok {
				break
			}
			request.Header.Add(pair.Key, string(pair.Value.(string)))
		}
		
		httpClient := &http.Client{}
		response, error := httpClient.Do(request)
		if error != nil {
			panic(error)
		}
		return readResponse(response)
	}
}

func (client *HttpClient) encrypt(call string, data string, headers string) string {
	toSend := message{call: call, body: data, headers: headers}
	toSendJson := ToJson(toSend)
	
	rand.Seed(time.Now().UnixNano())
  
	iv := generateIv()
	
	encrypted := AESEncrypt(toSendJson, client.SecretKey, client.apiContext.Seed, iv)


	request := ordered.NewOrderedMap()
	request.Set("x-enc", base64.StdEncoding.EncodeToString(encrypted))
	request.Set("x-iv", hex.EncodeToString([]byte(iv)))
	request.Set("x-key", client.apiContext.PublicKey)

	requestJson, error := request.MarshalJSON()
	HandleError(error)
	return string(requestJson)
}

func (client *HttpClient) decrypt(output encMessage) string {
	reply := output.data
	msg := reply.Get("msg")
	data, error := base64.StdEncoding.DecodeString(string(msg.(string)))
	if error != nil {
		panic(error)
	}
	iv := reply.Get("x-iv")
	decrypted := AESDecrypt(data, client.SecretKey, client.apiContext.Seed, string(iv.(string)))
	return ToJson(decrypted)
}

func (client *HttpClient) get(call string) (string, error) {
	url := client.apiUrl + "/" + client.version + "/" + call
	response, error := http.Get(url)
	return readResponse(response), error
}

func (client *HttpClient) PublicKey() Record {
	future := futures.PromiseLikeFuture(func(resolve futures.Resolver[string], reject futures.Rejector) {
		publicKey, error := client.get("public_key")
		if error != nil {
			reject(error)
		}
		resolve(publicKey)
	})
	
	var result Record
	response, error := future.Await()
	if error != nil {
		panic(error)
	}
	json.Unmarshal([]byte(response), &result)
	return result
}

func (client *HttpClient) SigKey() Record {
	future := futures.PromiseLikeFuture(func(resolve futures.Resolver[string], reject futures.Rejector) {
		sigKey, error := client.get("sig_key")
		if error != nil {
			reject(error)
		}
		resolve(sigKey)
	})

	var result Record
	response, error := future.Await()
	if error != nil {
		panic(error)
	}
	json.Unmarshal([]byte(response), &result)
	return result
}

func readResponse(response *http.Response) string {
	buf := new(bytes.Buffer)
    buf.ReadFrom(response.Body)
    return buf.String()
}

func generateIv() string {
	b := make([]byte, 16)
	charset := "abcdefghijklmnopqrstuvwxyz"
	for i := range b {
	  b[i] = charset[rand.Intn(16)]
	}
	return string(b)
}

func (client *HttpClient) Login(organization string, account string, scopes string, credentials string) futures.Future[interface{}] {
	toSign := organization + "\n" + client.ClientPublicKey + "\n" + scopes
	iv := generateIv()
	signature := client.signString(toSign, iv)

	if len(account) <= 0 || account == "" {
		account = client.ClientPublicKey
	}
	
	request := ordered.NewOrderedMap()
	request.Set("organization", organization)
	request.Set("account", account)
	request.Set("scopes", scopes)
	request.Set("signature", signature)
	if credentials == "" {
		request.Set("credentials", nil)
	} else {
		request.Set("credentials", credentials)
	}
	request.Set("x-iv", hex.EncodeToString([]byte(iv)))
	request.Set("x-key", client.apiContext.PublicKey)
	request.Set("x-sig-key", client.apiContext.SigKey)
	request.Set("x-dlg-sig", client.apiContext.CreateEd25519Signature(string(client.apiContext.ServerPubKey.Bytes(true))))
	request.Set("x-own-sig", client.apiContext.CreateEd25519Signature(string(client.apiContext.PublicKey)))

	requestJson, _ := request.MarshalJSON()

	reply := client.post("login", string(requestJson), "")
	replyJson := ordered.NewOrderedMap()
	replyJson.UnmarshalJSON([]byte(reply))

	dataJson := replyJson.Get("data")
	
	data := ordered.NewOrderedMap()
	dataString := string(dataJson.(string))
	data.UnmarshalJSON([]byte(dataString))
	
	encodedSecret := data.Get("secret")

	secret := FromHex(encodedSecret.(string))
	
	encodedIvHex := data.Get("x-iv")
	
	decodedIv := FromHex(encodedIvHex.(string))

	decryptedSecret := AESDecrypt(secret, client.SecretKey, client.apiContext.Seed, string(decodedIv))
	data.Delete("secret")

	future := futures.PromiseLikeFuture(func(resolve futures.Resolver[interface{}], reject futures.Rejector) {
		resolve(NewSession(*data, string(decryptedSecret)))
	})

	return future
}

func (client *HttpClient) signString(toSign string, iv string) string {
	return hex.EncodeToString(AESEncrypt(toSign, client.SecretKey, client.apiContext.Seed, iv))
}

func (client *HttpClient) buildHeaders(session Session, call string, data string) string {
	dataMap := ordered.NewOrderedMap()
	dataMap.UnmarshalJSON([]byte(data))

	body, error := dataMap.MarshalJSON()
	if error != nil {
		HandleError(error)
	}
	
	nonce := strconv.FormatFloat(float64(session.GetNonce()), 'f', 1, 64)
	url := "/" + client.version + "/" + call
	signature := SignHttp(session.Secret, url, session.ApiKey, nonce, string(body))

	headers := ordered.NewOrderedMap()
	headers.Set("x-api-key", session.ApiKey)
	headers.Set("x-nonce", nonce)
	headers.Set("x-sig", signature)
		
	headersJson, error := headers.MarshalJSON()
	if error != nil {
		HandleError(error)
	}
	return string(headersJson)
}

func (client *HttpClient) authPost(session Session, call string, data string) futures.Future[interface{}] {
	headers := client.buildHeaders(session, call, data)
	future := futures.PromiseLikeFuture(func(resolve futures.Resolver[interface{}], reject futures.Rejector) {
		resolve(client.post(call, data, headers))
	})
	return future
}

func (client *HttpClient) CreateTable(session Session, scope string, table string, createOptions CreateOptions) futures.Future[interface{}] {
	
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", createOptions.ToJson())
		
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}
	return client.authPost(session, "create", string(dataJson))
}

func (client *HttpClient) DropTable(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
		
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}
	return client.authPost(session, "drop", string(dataJson))
}

func (client *HttpClient) Write(session Session, scope string, records Records, writeOptions WriteOptions) futures.Future[interface{}] {
	if session.IntegrityChecks {
		layout := client.getLayout(session, scope, records.Table)
		integritySig := IntegritySignature(client.ClientPublicKey, session, scope, records, layout, client.apiContext.SeedHex, client.apiContext.CreateEd25519Signature)

		records.Integrity = append(records.Integrity, integritySig)
	}

	message := ordered.NewOrderedMap()
	message.Set("scope", scope)
	message.Set("table", records.Table)
	message.Set("enc", "json")
	message.Set("records", records.ToJson())
	message.Set("options", ToJson(writeOptions))

	messageJson, _ := message.MarshalJSON()

	return client.authPost(session, "write", string(messageJson))
}

func (client *HttpClient) Read(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("options", readOptions)
	data.Set("scope", scope)
	data.Set("table", table)
	
	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "read", string(dataJson))
}

func (client *HttpClient) GetTableDefinition(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
		
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_table_definition", string(dataJson))
}

func (client *HttpClient) getLayout(session Session, scope string, table string) ordered.OrderedMap {
	key := scope + ":" + table
	layout := session.TableLayoutCache.Get(key)
	if layout == nil {
		layoutMap := ordered.NewOrderedMap()
	
		result := ordered.NewOrderedMap()
		completableFuture := client.GetTableDefinition(session, scope, table)
		response, error := completableFuture.Await()
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

func (client *HttpClient) Logout(session Session) futures.Future[interface{}] {
	return client.authPost(session, "logout", "")
}

func (client *HttpClient) Status(session Session) futures.Future[interface{}] {
	return client.authPost(session, "status", "")
}

func (client *HttpClient) Terms(session Session, scope string, table string, options CreateOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", options)
		
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "terms", string(dataJson))
}

func (client *HttpClient) UpdateLayout(session Session, scope string, table string, layout interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("layout", layout)
		
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "update_layout", string(dataJson))
}

func (client *HttpClient) UpdateConfig(session Session, path string, values interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("path", path)
	data.Set("values", values)
		
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "update_config", string(dataJson))
}

func (client *HttpClient) GrantRole(session Session, account string, roles interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("targetAccount", account)
	data.Set("roles", roles)
		
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "grant_role", string(dataJson))
}

func (client *HttpClient) Count(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", readOptions)
	
	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "count", string(dataJson))
}

func (client *HttpClient) Delete(session Session, scope string, table string, filter interface{}, deleteOptions DeleteOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", deleteOptions)
	
	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "delete", string(dataJson))
}

func (client *HttpClient) DownloadTable(session Session, scope string, table string, filter interface{}, format string, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("format", format)
	data.Set("options", readOptions)
	
	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "download_table", string(dataJson))
}

func (client *HttpClient) Hashes(session Session, scope string, table string, filter interface{}, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", readOptions)

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "hashes", string(dataJson))
}

func (client *HttpClient) HashCheckpoint(session Session, enable bool) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("enable", enable)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "hash_checkpoint", string(dataJson))
}

func (client *HttpClient) PublishDataset(session Session, did string, name string, description string, license string, metadata string, weave string, fullDescription string, logo string, category string, scope string, table string,	filter interface{}, format string, price int64, token string, pageorder uint64, publishOptions PublishOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
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
	data.Set("options", ToJson(publishOptions))

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "publish_dataset", string(dataJson))
}

func (client *HttpClient) EnableProduct(session Session, did string, productType string, active bool) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("did", did)
	data.Set("productType", productType)
	data.Set("active", active)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "enable_product", string(dataJson))
}

func (client *HttpClient) DownloadDataset(session Session, did string, readOptions ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("did", did)
	data.Set("options", ToJson(readOptions))

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "download_dataset", string(dataJson))
}

func (client *HttpClient) PublishTask(session Session, did string, name string, description string, license string, metadata string, weave string, fullDescription string, logo string, category string, task string, price int64, token string, pageorder int64, publishOptions PublishOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
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
	data.Set("options", ToJson(publishOptions))

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "publish_task", string(dataJson))
}

func (client *HttpClient) RunTask(session Session, did string, computeOptions ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("did", did)
	data.Set("options", ToJson(computeOptions))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "run_task", string(dataJson))
}

func (client *HttpClient) Subscribe(session Session, scope string, table string, filter interface{}, subscribeOptions SubscribeOptions, updateHandler interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", ToJson(subscribeOptions))

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "subscribe", string(dataJson))
}

func (client *HttpClient) Unsubscribe(session Session, subscriptionId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("subscriptionId", subscriptionId)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "unsubscribe", string(dataJson))
}

func (client *HttpClient) Compute(session Session, image string, computeOptions ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("image", image)
	data.Set("options", ToJson(computeOptions))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "compute", string(dataJson))
}

func (client *HttpClient) GetImage(session Session, image string, localOutputFolder string, computeOptions ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("imageName", image)
	data.Set("image", base64.StdEncoding.EncodeToString([]byte(image)))
	data.Set("localOutputFolder", localOutputFolder)
	data.Set("options", ToJson(computeOptions))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_image", string(dataJson))
}

func (client *HttpClient) Flearn(session Session, image string, flOptions FLOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("image", image)
	data.Set("options", ToJson(flOptions))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "f_learn", string(dataJson))
}

func (client *HttpClient) SplitLearn(session Session, image string, slOptions SLOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("image", image)
	data.Set("options", ToJson(slOptions))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "split_learn", string(dataJson))
}

func (client *HttpClient) ForwardApi(session Session, feedId string, params ordered.OrderedMap) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("feedId", feedId)
	data.Set("params", params)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "forward_api", string(dataJson))
}

func (client *HttpClient) UploadApi(session Session, params ordered.OrderedMap) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("params", params)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "upload_api", string(dataJson))
}

func (client *HttpClient) HeGetInputs(session Session, datasources []interface{}, args []interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("datasources", datasources)
	data.Set("args", args)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "he_get_inputs", string(dataJson))
}

func (client *HttpClient) HeGetOutputs(session Session, encoded string, args []interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("encoded", encoded)
	data.Set("args", args)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "he_get_outputs", string(dataJson))
}

func (client *HttpClient) HeEncode(session Session, items []interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("items", items)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "he_encode", string(dataJson))
}

func (client *HttpClient) Mpc(session Session, scope string, table string, algo string, fields []string, filter interface{}, mpcOptions MPCOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("algo", algo)
	data.Set("fields", fields)
	data.Set("options", ToJson(mpcOptions))

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "mpc", string(dataJson))
}

func (client *HttpClient) StorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("challenge", challenge)
	data.Set("options", ToJson(options))
	

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "storage_proof", string(dataJson))
}

func (client *HttpClient) ZkStorageProof(session Session, scope string, table string, filter interface{}, challenge string, options ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("challenge", challenge)
	data.Set("options", ToJson(options))

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "zk_storage_proof", string(dataJson))
}

func (client *HttpClient) MerkleTree(session Session, scope string, table string, filter interface{}, salt string, digest string, options ReadOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("salt", salt)
	data.Set("digest", digest)
	data.Set("options", ToJson(options))


	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "merkle_tree", string(dataJson))
}

func (client *HttpClient) MerkleProof(session Session, scope string, table string, hash string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("hash", hash)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "merkle_proof", string(dataJson))
}

func (client *HttpClient) RootHash(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "root_hash", string(dataJson))
}

func (client *HttpClient) ZkMerkleTree(session Session, scope string, table string, filter interface{}, salt string, digest string, rounds int, seed int, options ZKOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("salt", salt)
	data.Set("digest", digest)
	data.Set("rounds", rounds)
	data.Set("seed", seed)
	data.Set("options", ToJson(options))


	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "zk_merkle_tree", string(dataJson))
}

func (client *HttpClient) MimcHash(session Session, data string, rounds int, seed int) futures.Future[interface{}] {
	dataMap := ordered.NewOrderedMap()
	dataMap.Set("data", data)
	dataMap.Set("rounds", rounds)
	dataMap.Set("seed", seed)
			
	dataJson, error := dataMap.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "mimc_hash", string(dataJson))
}

func (client *HttpClient) ProofsLastHash(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "proofs_last_hash", string(dataJson))
}

func (client *HttpClient) UpdateProofs(session Session, scope string, table string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "update_proofs", string(dataJson))
}

func (client *HttpClient) VerifyMerkleHash(session Session, tree string, hash string, digest string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("tree", tree)
	data.Set("hash", hash)
	data.Set("digest", digest)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "verify_merkle_hash", string(dataJson))
}

func (client *HttpClient) ZkProof(session Session, scope string, table string, gadget string, params string, fields []string, filter interface{}, zkOptions ZKOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("gadget", gadget)
	data.Set("params", params)
	data.Set("fields", fields)
	data.Set("options", ToJson(zkOptions))

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "zk_proof", string(dataJson))
}

func (client *HttpClient) ZkDataProof(session Session, gadget string, params string, values []interface{}, zkOptions ZKOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("gadget", gadget)
	data.Set("params", params)
	data.Set("values", values)
	data.Set("options", ToJson(zkOptions))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "zk_data_proof", string(dataJson))
}

func (client *HttpClient) VerifyZkProof(session Session, proof string, gadget string, params string, commitment string, nGenerators int) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("proof", proof)
	data.Set("gadget", gadget)
	data.Set("params", params)
	data.Set("commitment", commitment)
	data.Set("nGenerators", nGenerators)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "verify_zk_proof", string(dataJson))
}

func (client *HttpClient) TaskLineage(session Session, taskId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("taskId", taskId)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "task_lineage", string(dataJson))
}

func (client *HttpClient) VerifyTaskLineage(session Session, lineageData ordered.OrderedMap) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("task_lineage", lineageData)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "verify_task_lineage", string(dataJson))
}

func (client *HttpClient) TaskOutputData(session Session, taskId string, options OutputOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("taskId", taskId)
	data.Set("options", ToJson(options))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "task_output_data", string(dataJson))
}

func (client *HttpClient) History(session Session, scope string, table string, filter interface{}, historyOptions HistoryOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)
	data.Set("options", ToJson(historyOptions))

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "history", string(dataJson))
}

func (client *HttpClient) Writers(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "writers", string(dataJson))
}

func (client *HttpClient) Tasks(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "tasks", string(dataJson))
}

func (client *HttpClient) Lineage(session Session, scope string, table string, filter interface{}) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("table", table)

	if filter != nil {
		data.Set("filter", filter)
	}
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "lineage", string(dataJson))
}

func (client *HttpClient) DeployOracle(session Session, oracleType string, targetBlockchain string, source string, deployOptions DeployOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("oracleType", oracleType)
	data.Set("targetBlockchain", targetBlockchain)
	data.Set("source", source)
	data.Set("options", ToJson(deployOptions))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "deploy_oracle", string(dataJson))
}

func (client *HttpClient) DeployFeed(session Session, image string, options DeployOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("image", image)
	data.Set("options", ToJson(options))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "deploy_feed", string(dataJson))
}

func (client *HttpClient) RemoveFeed(session Session, feedId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("feedId", feedId)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "remove_feed", string(dataJson))
}

func (client *HttpClient) StartFeed(session Session, feedId string, options ComputeOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("feedId", feedId)
	data.Set("options", ToJson(options))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "start_feed", string(dataJson))
}

func (client *HttpClient) StopFeed(session Session, feedId string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("feedId", feedId)
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "stop_feed", string(dataJson))
}

func (client *HttpClient) IssueCredentials(session Session, issuer string, holder string, credentials ordered.OrderedMap, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("issuer", issuer)
	data.Set("holder", holder)
	data.Set("credentials", credentials)
	data.Set("options", ToJson(options))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "issue_credentials", string(dataJson))
}

func (client *HttpClient) VerifyCredentials(session Session, credentials ordered.OrderedMap, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("credentials", credentials)
	data.Set("options", ToJson(options))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "verify_credentials", string(dataJson))
}

func (client *HttpClient) CreatePresentation(session Session, credentials ordered.OrderedMap, subject string, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("credentials", credentials)
	data.Set("subject", subject)
	data.Set("options", ToJson(options))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "create_presentation", string(dataJson))
}

func (client *HttpClient) SignPresentation(session Session, presentation ordered.OrderedMap, domain string, challenge string, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("presentation", presentation)
	data.Set("domain", domain)
	data.Set("challenge", challenge)
	data.Set("options", ToJson(options))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "sign_presentation", string(dataJson))
}

func (client *HttpClient) VerifyDataSignature(session Session, signer string, signature string, toSign string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("signer", signer)
	data.Set("signature", signature)
	data.Set("data", ToJson(toSign))
			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "verify_data_signature", string(dataJson))
}

func (client *HttpClient) VerifyPresentation(session Session, presentation ordered.OrderedMap, domain string, challenge string, options CredentialsOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("presentation", presentation)
	data.Set("domain", domain)
	data.Set("challenge", challenge)

			
	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "verify_presentation", string(dataJson))
}

func (client *HttpClient) PostMessage(session Session, targetInboxKey string, message string, options MessageOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("targetInboxKey", targetInboxKey)
	data.Set("message", message)
	data.Set("options", options)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "post_message", string(dataJson))
}

func (client *HttpClient) PollMessages(session Session, inboxKey string, options MessageOptions) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("inboxKey", inboxKey)
	data.Set("options", options)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "poll_message", string(dataJson))
}

func (client *HttpClient) GetSidechainDetails(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_sidechain_details", string(dataJson))
}

func (client *HttpClient) GetUserDetails(session Session, publicKey string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("publicKey", publicKey)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_user_details", string(dataJson))
}

func (client *HttpClient) GetNodes(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_nodes", string(dataJson))
}

func (client *HttpClient) GetScopes(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_scopes", string(dataJson))
}

func (client *HttpClient) GetTables(session Session, scope string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("scope", scope)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_tables", string(dataJson))
}

func (client *HttpClient) GetNodeConfig(session Session, nodePublicKey string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("nodePublicKey", nodePublicKey)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "get_node_config", string(dataJson))
}

func (client *HttpClient) GetAccountNotifications(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "account_notifications", string(dataJson))
}

func (client *HttpClient) Balance(session Session, accountAddress string, scope string, token string) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token
	
	iv := generateIv()
	signature := client.signString(toSign, iv)
	
	data := ordered.NewOrderedMap()
	data.Set("accountAddress", accountAddress)
	data.Set("scope", scope)
	data.Set("token", token)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "balance", string(dataJson))
}

func (client *HttpClient) Transfer(session Session, accountAddress string, scope string, token string, amount big.Int) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token + "\n" + amount.String()
	
	iv := generateIv()
	signature := client.signString(toSign, iv)
	
	data := ordered.NewOrderedMap()
	data.Set("accountAddress", accountAddress)
	data.Set("scope", scope)
	data.Set("token", token)
	data.Set("amount", amount)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "transfer", string(dataJson))
}

func (client *HttpClient) Call(session Session, contractAddress string, scope string, fn string, data []byte) futures.Future[interface{}] {
	var serialized []byte
	base64.StdEncoding.Encode(serialized, data)
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + contractAddress + "\n" + scope + "\n" + fn + "\n" + string(serialized)

	iv := generateIv()
	signature := client.signString(toSign, iv)

	dataMap := ordered.NewOrderedMap()
	dataMap.Set("contractAddress", contractAddress)
	dataMap.Set("scope", scope)
	dataMap.Set("function", fn)
	dataMap.Set("data", data)
	dataMap.Set("signature", signature)
	dataMap.Set("x-iv", hex.EncodeToString([]byte(iv)))

	dataJson, error := dataMap.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "call", string(dataJson))
}

func (client *HttpClient) UpdateFees(session Session, scope string, fees string) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + scope + "\n" + fees

	iv := generateIv()
	signature := client.signString(toSign, iv)

	data := ordered.NewOrderedMap()
	data.Set("scope", scope)
	data.Set("fees", fees)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "update_fees", string(dataJson))
}

func (client *HttpClient) ContractState(session Session, contractAddress string, scope string) futures.Future[interface{}] {
	toSign := session.Organization + "\n" + client.ClientPublicKey + "\n" + contractAddress + "\n" + scope

	iv := generateIv()
	signature := client.signString(toSign, iv)

	data := ordered.NewOrderedMap()
	data.Set("contractAddress", contractAddress)
	data.Set("scope", scope)
	data.Set("signature", signature)
	data.Set("x-iv", hex.EncodeToString([]byte(iv)))

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "contract_state", string(dataJson))
}

func (client *HttpClient) CreateUserAccount(session Session, organization string, account string, publicKey string, roles []string) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("targetOrganization", organization)
	data.Set("targetAccount", account)
	data.Set("publicKey", publicKey)
	data.Set("roles", roles)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "create_user_account", string(dataJson))
}

func (client *HttpClient) ResetConfig(session Session) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "reset_config", string(dataJson))
}

func (client *HttpClient) Withdraw(session Session, token string, amount big.Int) futures.Future[interface{}] {
	data := ordered.NewOrderedMap()
	data.Set("token", token)
	data.Set("amount", amount)

	dataJson, error := data.MarshalJSON()
	if error != nil {
		HandleError(error)
	}

	return client.authPost(session, "withdraw", string(dataJson))
}

