module hello-world

go 1.24.1

replace github.com/alibaba/higress/plugins/wasm-go => ../..

require (
	github.com/alibaba/higress/plugins/wasm-go v0.0.0
	github.com/higress-group/proxy-wasm-go-sdk v0.0.0-20250402062734-d50d98c305f0
)

require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/resp v0.1.1 // indirect
)
