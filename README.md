## Weavechain Go API

[https://weavechain.com](https://weavechain.com): Layer-0 For Data

#### Data read sample

```Go
import (
	"fmt"
	"goapi/weaveapi"

	"gitlab.com/c0b/go-ordered-json"
)

pub, pvk := weaveapi.NodeApiGenerateKeys()

fmt.Println("Public key: ", pub)
fmt.Println("Private key: ", pvk)

node := "https://public.weavechain.com:443/92f30f0b6be2732cb817c19839b0940c"
organization := "weavedemo"
scope := "shared"
table := "directory"

cfg := weaveapi.WeaveClientConfig(pub, pvk, node, organization)

cfgJson, error := cfg.MarshalJSON()
weaveapi.HandleError(error)

nodeApi, session := weaveapi.ConnectWeaveApi(string(cfgJson), "")

reply, error := nodeApi.Read(session, scope, table, nil, weaveapi.READ_DEFAULT_NO_CHAIN()).Await()
weaveapi.HandleError(error)

fmt.Println(reply)
```

#### Docs

[https://docs.weavechain.com](https://docs.weavechain.com)