module github.com/tinfoilsh/confidential-agent-monitor/dev/manual_tests

go 1.27.3

require (
	code.dny.dev/ssrf v0.3.0
	github.com/tinfoilsh/confidential-agent-monitor v0.0.0
	github.com/tinfoilsh/confidential-agent-monitor/connector/credential v0.0.0
	github.com/tinfoilsh/confidential-agent-monitor/connector/slots v0.0.0
	github.com/tinfoilsh/confidential-agent-monitor/connector/web v0.0.0
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.47.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.1 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.3.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/jwx/v3 v3.2.0 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/modelcontextprotocol/go-sdk v1.8.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/vektah/gqlparser/v2 v2.5.58 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace (
	github.com/tinfoilsh/confidential-agent-monitor => ../..
	github.com/tinfoilsh/confidential-agent-monitor/connector/credential => ../../connector/credential
	github.com/tinfoilsh/confidential-agent-monitor/connector/slots => ../../connector/slots
	github.com/tinfoilsh/confidential-agent-monitor/connector/web => ../../connector/web
)
