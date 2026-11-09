SUDO_RS_REPO := https://github.com/trifectatechfoundation/sudo-rs.git
SUDO_RS_REF  := v0.2.15

BUILD_DIR    := .build
VENDOR_DIR   := $(BUILD_DIR)/sudo-rs
PATCH        := sudo-rs.patch

BIN_DIR      := bin
AMD64_TRIPLE := x86_64-unknown-linux-musl
ARM64_TRIPLE := aarch64-unknown-linux-musl
AMD64_BIN    := $(BIN_DIR)/lssudo-linux-amd64
ARM64_BIN    := $(BIN_DIR)/lssudo-linux-arm64

.PHONY: all build build-linux-amd64 build-linux-arm64 vendor clean distclean distclean-vendor

all: build

build: build-linux-amd64 build-linux-arm64
	@$(MAKE) --no-print-directory distclean-vendor

build-linux-amd64: $(AMD64_BIN)

build-linux-arm64: $(ARM64_BIN)

$(AMD64_BIN): vendor | $(BIN_DIR)
	cargo build --release --target $(AMD64_TRIPLE)
	install -m 0755 target/$(AMD64_TRIPLE)/release/lssudo $@
	@ldd $@ 2>&1 | grep -q 'statically linked\|not a dynamic executable' \
		|| (echo "error: $@ is dynamically linked:" >&2; ldd $@ >&2; exit 1)
	@echo "built: $@"

$(ARM64_BIN): vendor | $(BIN_DIR)
	cargo build --release --target $(ARM64_TRIPLE)
	install -m 0755 target/$(ARM64_TRIPLE)/release/lssudo $@
	@echo "built: $@ (cross-arch; static link enforced by +crt-static rustflag)"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

vendor: $(VENDOR_DIR)/.patched

$(VENDOR_DIR)/.patched: $(PATCH)
	rm -rf $(VENDOR_DIR)
	mkdir -p $(BUILD_DIR)
	git clone --quiet --depth 1 --branch $(SUDO_RS_REF) $(SUDO_RS_REPO) $(VENDOR_DIR)
	git -C $(VENDOR_DIR) apply --check $(abspath $(PATCH))
	git -C $(VENDOR_DIR) apply $(abspath $(PATCH))
	touch $@

distclean-vendor:
	rm -rf $(BUILD_DIR)

clean:
	cargo clean
	rm -rf $(BIN_DIR)
	$(MAKE) --no-print-directory distclean-vendor

distclean: clean
