# Makefile
.PHONY: build-linux-amd64 build-linux-arm64 build clean \
        lssudo-linux-amd64 lssudo-linux-arm64

LSSUDO_DIR    := tools/lssudo
LSSUDO_BINDIR := $(LSSUDO_DIR)/bin
EMBED_DIR     := internal/collect/embedded_binaries

lssudo-linux-amd64:
	$(MAKE) -C $(LSSUDO_DIR) build-linux-amd64
	@install -D $(LSSUDO_BINDIR)/lssudo-linux-amd64 $(EMBED_DIR)/lssudo-linux-amd64

lssudo-linux-arm64:
	$(MAKE) -C $(LSSUDO_DIR) build-linux-arm64
	@install -D $(LSSUDO_BINDIR)/lssudo-linux-arm64 $(EMBED_DIR)/lssudo-linux-arm64

build-linux-amd64: lssudo-linux-amd64
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-o bin/golinhound-linux-amd64 \
	./cmd/golinhound

build-linux-arm64: lssudo-linux-arm64
	@mkdir -p "bin/"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
	-o bin/golinhound-linux-arm64 \
	./cmd/golinhound

build: build-linux-amd64 build-linux-arm64

clean:
	rm -rf bin/
	rm -f $(EMBED_DIR)/lssudo-linux-*
	$(MAKE) -C $(LSSUDO_DIR) clean
