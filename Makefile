# Makefile
.PHONY: build-linux-amd64 build-linux-arm64 build-windows-amd64 build-windows-arm64 build

build-linux-amd64:
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-o bin/golinhound-linux-amd64 \
	./cmd/golinhound

build-linux-arm64:
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
	-o bin/golinhound-linux-arm64 \
	./cmd/golinhound

build-windows-amd64:
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
	-o bin/golinhound-windows-amd64.exe \
	./cmd/golinhound

build-windows-arm64:
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build \
	-o bin/golinhound-windows-arm64.exe \
	./cmd/golinhound

build: build-linux-amd64 build-linux-arm64 build-windows-amd64 build-windows-arm64
