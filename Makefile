digicert-mpki:
	go build -o digicert-mpki ./cmd/cli

mpki.json:
	curl -o mpki.json https://pki-ws-rest.symauth.com/mpki/api/v1/docs
	# TODO: add steps to set schemes, securityDefinitions and tweak tag/operation names

swagger: mpki.json
	swagger generate cli -f mpki.json -A digicert-mpki
	git restore cli/cli.go
