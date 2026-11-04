#!/usr/bin/env bash
# install.sh — prerequisites to build specter-rs on a fresh teamserver or
# dev box (phase 4 of docs/ETUDE-DE-FAISABILITE.md): rustup + the pinned
# nightly + its components/targets, then a full verification build.
set -euo pipefail
cd "$(dirname "$0")"

PIN=$(awk -F'"' '/^[[:space:]]*channel[[:space:]]*=/{print $2; exit}' rust-toolchain.toml)
if [ -z "$PIN" ]; then
    echo "[install] cannot read the pinned channel from rust-toolchain.toml" >&2
    exit 1
fi
echo "[install] pinned toolchain: $PIN"

if ! command -v rustup >/dev/null 2>&1; then
    echo "[install] rustup is required (https://rustup.rs) — install it first" >&2
    exit 1
fi

rustup toolchain install "$PIN" --profile minimal \
    --component rust-src --component rustfmt --component clippy
rustup target add x86_64-pc-windows-gnu x86_64-unknown-linux-gnu --toolchain "$PIN"
rustup default "$PIN"

echo "[install] verifying: make test"
make test

echo "[install] OK — blob at build/beacon.x64.bin"
