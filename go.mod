module github.com/felix-homelab/rpmgr

go 1.26.0

toolchain go1.27.1

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
)

require google.golang.org/protobuf v1.36.12

require (
	connectrpc.com/connect v1.21.0 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.6.2 // indirect
)
