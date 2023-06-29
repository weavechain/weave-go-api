package weaveapi

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"gitlab.com/c0b/go-ordered-json"
)

func ToJson(obj interface{}) string {
	optMarshalled, error := json.Marshal(obj)
	if error != nil {
		panic(error)
	}
	return string(optMarshalled)
}

func converRecordFields(field interface{}, fieldType string) interface{} {
	if field == nil {
		return nil
	} else if fieldType == "LONG" || fieldType == "TIMESTAMP" {
		return int(field.(int))
	} else if fieldType == "DOUBLE" {
		return float64(field.(float64))
	} else {
		return string(field.(string))
	}
}

func standardizeRecord(record []interface{}, layout []*ordered.OrderedMap) []interface{} {
	if layout != nil {
		for i := 0; i < len(layout); i++ {
			if i < len(record) {
				layoutMap := layout[i]
				converted := converRecordFields(record[i], layoutMap.Get("type").(string))
				if converted != nil && reflect.TypeOf(converted).String() == "float64" {
					convString := fmt.Sprintf("%f", converted)
					if len(convString) > 2 && convString[len(convString)-2:] == ".0" {
						converted = int(converted.(int))
					}
				}
				record[i] = converted
			} else {
				record[i] = nil
			}
		i++
		}
	}
	return record
}

func IntegritySignature(clientPublicKey string, session Session, scope string, records Records, tableDefinition ordered.OrderedMap, seedHex string, signFn func(message string) string) ordered.OrderedMap {
	var idColumn interface{}
	layout := []*ordered.OrderedMap{}
	tableDefinitionJson, _ := tableDefinition.MarshalJSON()
	print("TableDefinition in integrity: ", string(tableDefinitionJson))
	if tableDefinition.Has("idColumnIndex") || tableDefinition.Has("columns") {
		idColIndex := tableDefinition.Get("idColumnIndex")
		idColumn, _ = idColIndex.(json.Number).Int64()
		columns := tableDefinition.Get("columns").([]interface{})
		for i := 0; i < len(columns); i++ {
			layout = append(layout, columns[i].(*ordered.OrderedMap))
		}
	} else {
		idColumn = ""
	}
	
	salt := []byte(seedHex)

	idBuffer := ""
	hashBuffer := ""
	first := true
	for i := 0; i < len(records.Records); i++ {
		record := standardizeRecord(records.Records[i], layout)
		data := ToJson(records.Records[i])
		hash := SignRequest(salt, data)

		if first {
			first = false
		} else {
			idBuffer += " "
			hashBuffer += "\n"
		}
		if idColumn == nil || record[i] == nil {
			idBuffer += "null"
		} else {
			idBuffer += strconv.Itoa(record[i].(int))
		}
		hashBuffer += hash
	}

	toSign := idBuffer + "\n" + hashBuffer
	recordHash := SignRequest(salt, toSign)

	key := scope + ":" + records.Table
	var count int
	hash := ""
	prevRecordsData := session.PrevRecordsData.Get(key)
	if prevRecordsData == nil {
		count = 1
	} else {
		prevRecordsDataMap := ordered.OrderedMap(prevRecordsData.(ordered.OrderedMap))
		countFromMap := prevRecordsDataMap.Get("count")
		count = int(countFromMap.(int))
		hash = prevRecordsDataMap.Get("hash").(string)
	}
	
	integrityCheck := ordered.NewOrderedMap()
	integrityCheck.Set("count", strconv.Itoa(count))
	integrityCheck.Set("pubKey", clientPublicKey)
	integrityCheck.Set("recordsHash", recordHash)
	if hash != "" {
		integrityCheck.Set("prevRecordsHash", hash)
	}

	sessionPrevRecords := ordered.NewOrderedMap()
	sessionPrevRecords.Set("hash", recordHash)
	sessionPrevRecords.Set("count", count + 1)
	
	session.PrevRecordsData.Set(key, sessionPrevRecords)
	
	serialization, error := integrityCheck.MarshalJSON()
	HandleError(error)
	integrityCheck.Set("sig", signFn(string(serialization)))

	result := ordered.NewOrderedMap()
	result.Set("sig", integrityCheck)
	return *result
}

func HandleError(error error) {
	if error != nil {
		panic(error)
	}
}

func FromHex(encoded string) []byte {
	res, err := hex.DecodeString(encoded)
	HandleError(err)

	return res
}

func GetDefaultGateway() string {
	weaveHost := os.Getenv("WEAVE_HOST")
	if len(weaveHost) > 0 {
		return weaveHost
	}
	
	weaveHostOs := os.Getenv("WEAVE_HOST_OS")
	if len(weaveHostOs) > 0 && weaveHostOs == "win" {
		return "host.docker.internal"
	}
	
	readFile, err := os.Open("/proc/net/route")
  
    if err == nil {
		fileScanner := bufio.NewScanner(readFile)
	
		fileScanner.Split(bufio.ScanLines)
	
		for fileScanner.Scan() {
			fields := strings.Fields(strings.TrimSpace(fileScanner.Text()))
			value, error := strconv.ParseInt(fields[3], 16, 64)
			if error != nil || fields[1] != "00000000" || value & 2 == 0 {
				continue;
			}

			value, error = strconv.ParseInt(fields[2], 16, 64)
			HandleError(error)
			return int2ip(uint32(value)).String()
		}
		readFile.Close()
	}

	hostname, error := os.Hostname()
	HandleError(error)
	ips, error := net.LookupHost(hostname)
	HandleError(error)

	ip := ips[0]
	idx := strings.LastIndex(ip, ".")
	if strings.HasPrefix(ip, "172.") {
		return ip[0:idx + 1] + "1"
	}
	return "172.17.0.1"
}

func isDocker() bool {
	path := "/proc/self/cgroup"

	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	
	readFile, err := os.Open(path)
	HandleError(err)
	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	docker := false
	for fileScanner.Scan() {
		if fileScanner.Text() == "docker" {
			docker = true
		}
	}
	return !fileInfo.IsDir() && docker
}

func ParseHost(host string) string {
	if host != "gw" || !isDocker() {
		return host
	} else {
		return GetDefaultGateway()
	}
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}
