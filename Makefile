# Specter-rs - top-level Makefile
# Phase 0 toolchain spike: Rust no_std beacon -> static COFF archive ->
# rust-lld (lld-link flavor) single-.text PE -> raw PIC blob.
#
# Outputs:
#   build/beacon.x64.bin          - release PIC blob (single .text)
#
# Usage:
#   make                - build the blob
#   make pic-check      - link twice at different image bases; identical
#                         .text bytes prove position independence
#   make clean

TARGET      := x86_64-pc-windows-gnu
OUT_DIR     := build
LIB         := target/$(TARGET)/release/libspecter_beacon.a
EXE         := $(OUT_DIR)/beacon.exe
BLOB        := $(OUT_DIR)/beacon.x64.bin
RUST_LLD_BIN := $(shell rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld
# rust-lld is a multi-call binary: invoked as `lld-link` it drives COFF linking.
LLD         := $(OUT_DIR)/lld-link

# Link the ARCHIVE, never the extracted objects: the linker then pulls only
# the referenced members (compiler_builtins otherwise lands in the blob whole).
#
# Flags:
#   everything merges into a single .text (no .rdata),
#   entry symbol SptEntry, no CRT, dead code elimination.
LDFLAGS := /entry:SptEntry \
	/subsystem:native \
	/machine:x64 \
	/merge:.rdata=.text \
	/merge:.sptend=.text \
	/opt:ref,icf \
	/nodefaultlib \
	/nologo

.PHONY: all blob check test pic-check clean

all: blob

$(LIB):
	cargo build --release -Z build-std=core

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

$(LLD): | $(OUT_DIR)
	@ln -sf $(RUST_LLD_BIN) $(LLD)

$(EXE): $(LIB) tools/pe_blob.py $(LLD)
	$(LLD) $(LDFLAGS) $(LIB) /out:$(EXE)

blob: $(EXE)
	python3 tools/pe_blob.py $(EXE) $(BLOB)
	@printf '[+] size: %s bytes\n' "$$(wc -c < $(BLOB))"

# Position-independence proof: link at two different image bases; identical
# .text bytes mean the beacon contains no absolute addresses.
pic-check: $(LLD) $(LIB)
	$(LLD) $(LDFLAGS) /base:0x10000000 $(LIB) /out:$(OUT_DIR)/base_a.exe
	$(LLD) $(LDFLAGS) /base:0x40000000 $(LIB) /out:$(OUT_DIR)/base_b.exe
	python3 tools/pe_blob.py $(OUT_DIR)/base_a.exe $(OUT_DIR)/blob_a.bin >/dev/null
	python3 tools/pe_blob.py $(OUT_DIR)/base_b.exe $(OUT_DIR)/blob_b.bin >/dev/null
	cmp $(OUT_DIR)/blob_a.bin $(OUT_DIR)/blob_b.bin \
		&& echo "[+] PIC: .text identical at both image bases" \
		|| (echo "[-] NOT position-independent (bytes differ between bases)"; exit 1)

# Blob guardrails: no text strings, size budget (see tools/check_blob.py).
check: blob
	python3 tools/check_blob.py $(BLOB)
	$(MAKE) pic-check

# Full local gate: everything CI runs. The Rust unit tests run on the host
# target (std test harness); the beacon itself is checked for its own target.
test:
	cargo fmt --all --check
	cargo clippy --release -Z build-std=core -- -D warnings
	cargo check --release -Z build-std=core
	cargo test --target x86_64-unknown-linux-gnu -p specter-core --lib
	python3 tools/test_pe_blob.py
	$(MAKE) check

clean:
	rm -rf $(OUT_DIR) target
