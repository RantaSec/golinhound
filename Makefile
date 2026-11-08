# Makefile
.PHONY: build build-linux-amd64 build-linux-arm64 extension clean

# Pull schema.name and schema.version from the extension manifest so the ZIP
# filename always tracks the JSON source of truth.
#
# extension/saved_queries.json is stored as a bare array so the file can be
# loaded directly by queries.specterops.io; the BloodHound extension API
# wants a {"queries": [...]} envelope, so we wrap it on the fly at ZIP time.
SCHEMA_NAME    := $(shell jq -r .schema.name    extension/schema.json)
SCHEMA_VERSION := $(shell jq -r .schema.version extension/schema.json)
EXTENSION_ZIP  := $(SCHEMA_NAME)-Community-$(SCHEMA_VERSION).zip

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

extension:
	jq '{queries: .}' extension/saved_queries.json > extension/saved_queries.json.tmp
	mv extension/saved_queries.json.tmp extension/saved_queries.json
	cd extension && zip -q -j $(EXTENSION_ZIP) schema.json saved_queries.json

build: build-linux-amd64 build-linux-arm64 extension

clean:
	rm -rf bin/
	rm -f extension/*.zip
