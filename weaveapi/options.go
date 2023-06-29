package weaveapi

import (
	"gitlab.com/c0b/go-ordered-json"
)

type CreateOptions struct {
	FailIfExists		bool					`json:"failIfExists"`
	Replicate			bool					`json:"replicate"`
	Layout 				ordered.OrderedMap		`json:"layout"`
	CreateTimeoutSec	int						`json:"createTimeoutSec"`
}

const DEFAULT_CREATE_TIMEOUT_SEC = 300

func NewCreateOptions(failIfExists bool, replicate bool, layout ordered.OrderedMap, createTimeoutSec int) CreateOptions {
	return CreateOptions{FailIfExists: failIfExists, Replicate: replicate, Layout: layout, CreateTimeoutSec: createTimeoutSec}
}

func (createOptions *CreateOptions) ToJson() string {
	result := ordered.NewOrderedMap()
	result.Set("failIfExists", createOptions.FailIfExists)
	result.Set("replicate", createOptions.Replicate)

	layoutJson, _ := createOptions.Layout.MarshalJSON()
	result.Set("layout", string(layoutJson))
	result.Set("createTimeoutSec", createOptions.CreateTimeoutSec)
	
	resultJson, _ := result.MarshalJSON()
	return string(resultJson)
}

func CREATE_DEFAULT() CreateOptions {
	return NewCreateOptions(true, true, *&ordered.OrderedMap{}, DEFAULT_CREATE_TIMEOUT_SEC)
}

func CREATE_FAILSAFE() CreateOptions {
	return NewCreateOptions(false, true, *&ordered.OrderedMap{}, DEFAULT_CREATE_TIMEOUT_SEC)
}

type DropOptions struct {
	FailIfExists		bool	`json:"failIfNotExists"`
	Replicate			bool	`json:"replicate"`
	DropTimeoutSec		int		`json:"dropTimeoutSec"`
}

const DEFAULT_DROP_TIMEOUT_SEC = 300

func NewDropOptions(failIfExists bool, replicate bool, DropTimeoutSec int) DropOptions {
	return DropOptions{FailIfExists: failIfExists, Replicate: replicate, DropTimeoutSec: DropTimeoutSec}
}

func DROP_DEFAULT() DropOptions {
	return NewDropOptions(true, true, DEFAULT_DROP_TIMEOUT_SEC)
}

func DROP_FAILSAFE() DropOptions {
	return NewDropOptions(false, true, DEFAULT_DROP_TIMEOUT_SEC)
}

type DeleteOptions struct {
	AllowDistribute				bool	`json:"allowDistribute"`
	CorrelationUuid				string	`json:"correlationUuid"`
	ThresholdMultisigContext	string	`json:"thresholdMultisigContext"`
}

func NewDeleteOptions(allowDistribute bool, correlationUuid string, thresholdMultisigContext string) DeleteOptions {
	return DeleteOptions{AllowDistribute: allowDistribute, CorrelationUuid: correlationUuid, ThresholdMultisigContext: thresholdMultisigContext}
}

func DELETE_DEFAULT() DeleteOptions {
	return NewDeleteOptions(true, "", "")
}

type HistoryOptions struct {
	OperationTypes []string
}

func NewHistoryOptions(operationTypes []string) HistoryOptions {
	return HistoryOptions{OperationTypes: operationTypes}
}

func HISTORY_DEFAULT() HistoryOptions {
	return NewHistoryOptions([]string{"read, delete, write"})
}

const DEFAULT_READ_TIMEOUT_SEC = 300

type ReadOptions struct {
	VerifyHash		bool	`json:"verifyHash"`
	ReadTimeoutSec	int		`json:"readTimeoutSec"`
	PeersConsesus	int		`json:"peersConsensus"`
	EnableMux		bool	`json:"enableMux"`
	GetBatchHashes	bool	`json:"getBatchHashes"`
}

func NewReadOptions(verifyHash bool, readTimeoutSec int, peersConsesus int, enableMux bool, getBatchHashes bool) ReadOptions {
	return ReadOptions{VerifyHash: verifyHash, ReadTimeoutSec: readTimeoutSec, PeersConsesus: peersConsesus, EnableMux: enableMux, GetBatchHashes: getBatchHashes}
}

func READ_DEFAULT() ReadOptions {
	return NewReadOptions(true, DEFAULT_READ_TIMEOUT_SEC, 0, false, false)
}

func READ_DEFAULT_NO_CHAIN() ReadOptions {
	return NewReadOptions(false, DEFAULT_READ_TIMEOUT_SEC, 0, false, false)
}

const ALL_ACTIVE = 2147483647

func READ_DEFAULT_MUX() ReadOptions {
	return NewReadOptions(true, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE, true, false)
}

func READ_DEFAULT_MUX_NO_CHAIN() ReadOptions {
	return NewReadOptions(false, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE, true, false)
}


var ALL_ACTIVE_NODES = []string {"*"}

type MPCOptions struct {
	VerifyHash		bool
	ReadTimeoutSec	int
	Sources			[]string
}

func NewMPCOPtions(verifyHash bool, readTimeoutSec int, sources []string) MPCOptions {
	return MPCOptions{VerifyHash: verifyHash, ReadTimeoutSec: readTimeoutSec, Sources: sources}
}

func MPC_DEFAULT() MPCOptions {
	return NewMPCOPtions(true, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES)
}

func MPC_DEFAULT_NO_CHAIN() MPCOptions {
	return NewMPCOPtions(false, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES)
}


const DEFAULT_GENERATORS = 128
const DEFAULT_COMMITMENT = "GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3"

type ZKOptions struct {
	VerifyHash		bool
	ReadTimeoutSec	int
	Sources			[]string
	Generators		int
	Commitment		string
}

func NewZKOptions(verifyHash bool, readTimeoutSec int, sources []string, generators int, commitment string) ZKOptions {
	return ZKOptions{VerifyHash: verifyHash, ReadTimeoutSec: readTimeoutSec, Sources: sources, Generators: generators, Commitment: commitment}
}

func ZK_DEFAULT() ZKOptions {
	return NewZKOptions(true, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES, DEFAULT_GENERATORS, DEFAULT_COMMITMENT)
}

func ZK_DEFAULT_NO_CHAIN() ZKOptions {
	return NewZKOptions(false, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES, DEFAULT_GENERATORS, DEFAULT_COMMITMENT)
}

type SubscribeOptions struct {
	VerifyHash		bool
	InitialSnapshot	bool
	ReadTimeoutSec	int
	ExternalUpdates	bool
	BatchingOptions	interface{}
}

func NewSubscribeOptions(verifyHash bool, initialSnapshot bool, readTimeoutSec int, externalUpdates bool, batchingOptions interface{}) SubscribeOptions {
	return SubscribeOptions{VerifyHash: verifyHash, InitialSnapshot: initialSnapshot, ReadTimeoutSec: readTimeoutSec, ExternalUpdates: externalUpdates, BatchingOptions: batchingOptions}
}

func SUBSCRIBE_DEFAULT() SubscribeOptions {
	return NewSubscribeOptions(true, true, DEFAULT_READ_TIMEOUT_SEC, false, nil)
}


const DEFAULT_GUARANTEED_DELIVERY = true
const DEFAULT_MIN_ACKS = 1
const DEFAULT_MEMORY_ACKS = false
const DEFAULT_HASH_ACKS = 1
const DEFAULT_WRITE_TIMEOUT_SEC = 300

type WriteOptions struct {
	Guaranteed		bool	`json:"guaranteed"`
	MinAcks			int		`json:"minAcks"`
	InMemoryAcks	bool	`json:"inMemoryAcks"`
	MinHashAcks		int		`json:"minHashAcks"`
	WriteTimeoutSec	int		`json:"writeTimeoutSec"`
	AllowDistribute	bool	`json:"allowDistribute"`
	SignOnChain		bool	`json:"signOnChain"`
	SyncSigning		bool	`json:"syncSigning"`
}

func NewWriteOptions(guaranteed bool, minAcks int, inMemoryAcks bool, minHashAcks int, writeTimeoutSec int, allowDistribute bool, signOnChain bool, syncSigning bool) WriteOptions {
	return WriteOptions{Guaranteed: guaranteed, MinAcks: minAcks, InMemoryAcks: inMemoryAcks, MinHashAcks: minHashAcks, WriteTimeoutSec: writeTimeoutSec, AllowDistribute: allowDistribute, SignOnChain: signOnChain, SyncSigning: syncSigning}
}

func WRITE_DEFAULT() WriteOptions {
	return NewWriteOptions(
        DEFAULT_GUARANTEED_DELIVERY,
        DEFAULT_MIN_ACKS,
        DEFAULT_MEMORY_ACKS,
        DEFAULT_HASH_ACKS,
        DEFAULT_WRITE_TIMEOUT_SEC,
        true,
        true,
        false)
}

func WRITE_DEFAULT_ASYNC() WriteOptions {
	return NewWriteOptions(
        false,
        DEFAULT_MIN_ACKS,
        true,
        0,
        DEFAULT_WRITE_TIMEOUT_SEC,
        true,
        true,
        false)
}

func WRITE_DEFAULT_NO_CHAIN() WriteOptions {
	return NewWriteOptions(
        DEFAULT_GUARANTEED_DELIVERY,
        DEFAULT_MIN_ACKS,
        DEFAULT_MEMORY_ACKS,
        0,
        DEFAULT_WRITE_TIMEOUT_SEC,
        true,
        false,
        false)
}

const DEFAULT_COMPUTE_TIMEOUT_SEC = 300

type ComputeOptions struct {
	Sync			bool
	TimeoutSec		int
	PeersConsensus	int
	Scopes			string
	Params			ordered.OrderedMap
}

func NewComputeOptions(sync bool, timeoutSec int, peersConsensus int, scopes string, params ordered.OrderedMap) ComputeOptions {
	return ComputeOptions{Sync: sync, TimeoutSec: timeoutSec, PeersConsensus: peersConsensus, Scopes: scopes, Params: params}
}

func COMPUTE_DEFAULT() ComputeOptions {
	return NewComputeOptions(
		true,
		DEFAULT_COMPUTE_TIMEOUT_SEC,
		0,
		"",
		ordered.OrderedMap{})
}


type FLOptions struct {
	Sync			bool
	TimeoutSec		int
	PeersConsensus	int
	Scopes			string
	Params			ordered.OrderedMap
}

func NewFLOptions(sync bool, timeoutSec int, peersConsensus int, scopes string, params ordered.OrderedMap) FLOptions {
	return FLOptions{Sync: sync, TimeoutSec: timeoutSec, PeersConsensus: peersConsensus, Scopes: scopes, Params: params}
}

func FL_DEFAULT() FLOptions {
	return NewFLOptions(
		true,
		DEFAULT_COMPUTE_TIMEOUT_SEC,
		0,
		"",
		ordered.OrderedMap{})
}

type SLOptions struct {
	Sync			bool
	TimeoutSec		int
	MinParticipants	int
	Scopes			string
	Sources			[]string
	Params			ordered.OrderedMap
}

func NewSLOptions(sync bool, timeoutSec int, minParticipants int, scopes string, sources []string, params ordered.OrderedMap) SLOptions {
	return SLOptions{Sync: sync, TimeoutSec: timeoutSec, MinParticipants: minParticipants, Sources: sources, Scopes: scopes, Params: params}
}

func SL_DEFAULT() SLOptions {
	return NewSLOptions(
		true,
		DEFAULT_COMPUTE_TIMEOUT_SEC,
		0,
		"",
		nil,
		ordered.OrderedMap{})
}

type CredentialsOptions struct {
	OpTimeoutSec			int
	ProofType				string
	ExpirationTimestampGMT	interface{}
}

func NewCredentialsOptions(opTimeoutSec int, proofType string, expirationTimestampGMT interface{}) CredentialsOptions {
	return CredentialsOptions{OpTimeoutSec: opTimeoutSec, ProofType: proofType, ExpirationTimestampGMT: expirationTimestampGMT}
}

func VS_DEFAULT() CredentialsOptions {
	return NewCredentialsOptions(DEFAULT_READ_TIMEOUT_SEC, "json-ld", nil)
}

const DEFAULT_PUBLISH_TIMEOUT_SEC = 300

type PublishOptions struct {
	OptionType		string
	RollingUnit		string
	RollingCount	int
	VerifyHash		bool
	ReadTimeoutSec	int
	PeersConsensus	int
	EnableMux		bool
}

func NewPublishOptions(optionType string, rollingUnit string, rollingCount int, verifyHash bool, readTimeoutSec int, peersConsensus int, enableMux bool) PublishOptions {
	return PublishOptions{OptionType: optionType, RollingUnit: rollingUnit, RollingCount: rollingCount, VerifyHash: verifyHash, ReadTimeoutSec: readTimeoutSec, PeersConsensus: peersConsensus, EnableMux: enableMux}
}

func PUBLISH_DEFAULT() PublishOptions {
	return NewPublishOptions(
        "snapshot",
        "",
        0,
        true,
        DEFAULT_CREATE_TIMEOUT_SEC,
        0,
        false)
}

type PublishTaskOptions struct {
	ComputeTimeoutSec	int
	Params				ordered.OrderedMap
	AllowCustomParams	bool
}

func NewPublishTaskOptions(computeTimeoutSec int, params ordered.OrderedMap, allowCustomParams bool) PublishTaskOptions {
	return PublishTaskOptions{ComputeTimeoutSec: computeTimeoutSec, Params: params, AllowCustomParams: allowCustomParams}
}

func PUBLISH_TASK_DEFAULT() PublishTaskOptions {
	return NewPublishTaskOptions(
		DEFAULT_COMPUTE_TIMEOUT_SEC,
		ordered.OrderedMap{},
		false)
}

type OutputOptions struct {
	OutputType string
}

func NewOutputOptions(outputType string) OutputOptions {
	return OutputOptions{OutputType: outputType}
}

func DEFAULT_OUTPUT() OutputOptions {
	return NewOutputOptions("csv")
}

type DeployOptions struct {
	Sync 		bool
	TimeoutSec 	int
	Params		ordered.OrderedMap
}

func NewDeployOptions(sync bool, timeoutSec int, params ordered.OrderedMap) DeployOptions {
	return DeployOptions{Sync: sync, TimeoutSec: timeoutSec, Params: params}
}

func DEFAULT_DEPLOY() DeployOptions {
	return NewDeployOptions(false, DEFAULT_COMPUTE_TIMEOUT_SEC, ordered.OrderedMap{})
}

const DEFAULT_OP_TIMEOUT_SEC = 300
const DEFAULT_TIME_TO_LIVE_SEC = 300

type MessageOptions struct {
	OpTimeoutSec	int
	TtlSec			int
}

func NewMessageOptions(opTimeoutSec int, ttlSec int) MessageOptions {
	return MessageOptions{OpTimeoutSec: opTimeoutSec, TtlSec: ttlSec}
}

func DEFAULT_MESSAGE() MessageOptions {
	return NewMessageOptions(DEFAULT_OP_TIMEOUT_SEC, DEFAULT_TIME_TO_LIVE_SEC)
}