package weaveapi

import (
	"gitlab.com/c0b/go-ordered-json"
)

type Records struct {
	Table		string					`json:"table"`
	Records		[][]interface{}			`json:"items"`
	Integrity	[]ordered.OrderedMap	`json:"integrity"`
}

func NewRecords(table string, records [][]interface{}, integrity []ordered.OrderedMap) Records {
	return Records{Table: table, Records: records, Integrity: integrity}
}

func (records *Records) ToJson() string {
	result := ordered.NewOrderedMap()
	result.Set("table", records.Table)
	result.Set("items", records.Records)
	
	result.Set("integrity", &records.Integrity)

	resultJson, _ := result.MarshalJSON()
	return string(resultJson)
}

type Record struct {
	Id			string	`json:"id"`
	Data 		string	`json:"data"`
	Metadata	string	`json:"metadata"`
}

func NewRecord(id string, data string, metadata string) Record {
	return Record{Id: id, Data: data, Metadata: metadata}
}