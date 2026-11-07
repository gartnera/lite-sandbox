module github.com/gartnera/lite-sandbox

go 1.26.0

require (
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.32.7
	github.com/aws/aws-sdk-go-v2/credentials v1.19.7
	github.com/aws/smithy-go v1.24.0
	github.com/benhoyt/goawk v1.31.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/fugue-labs/monty-go v0.2.0
	github.com/jellydator/ttlcache/v3 v3.4.0
	github.com/jonathonwebb/getopt v1.0.2
	github.com/mark3labs/mcp-go v1.5.0
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/peterh/liner v1.2.3
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f
	golang.org/x/sync v0.17.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.45.0
	gopkg.in/yaml.v3 v3.0.1
	mvdan.cc/sh/v3 v3.14.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-runewidth v0.0.31 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/fugue-labs/monty-go => github.com/gartnera/monty-go v0.0.0-20261104045841-c72915f64e61

// TODO: drop this fork once a mcp-go release supports the SEP-2663 tasks
// extension (io.modelcontextprotocol/tasks, mark3labs/mcp-go#987) and
// per-request task decisions (server.WithTaskDecision). The fork's main is
// upstream main + #987 + WithTaskDecision.
replace github.com/mark3labs/mcp-go => github.com/gartnera/mcp-go v0.0.0-20261106234818-8999d8155119
