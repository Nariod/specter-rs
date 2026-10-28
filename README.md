# Specter-rs

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows_x64-0078D4?style=for-the-badge" alt="platform"/>
  <img src="https://img.shields.io/badge/C2-AdaptixC2_1.2-006400?style=for-the-badge" alt="C2"/>
  <img src="https://img.shields.io/badge/Lang-Rust_2021-DEA584?style=for-the-badge" alt="lang"/>
  <img src="https://github.com/Nariod/specter-rs/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

> [!WARNING]
> **Work in progress.** Specter-rs is a Rust rewrite of
> [Specter](https://github.com/0xC9H/specter). The core loop — check-in,
> task execution, results — is functional and validated against a real
> AdaptixC2 server on a live Windows implant, but the project is still
> short of full feature parity with the original (see
> [PARITE.md](docs/PARITE.md)).

A Rust rewrite of the Specter beacon: an [AdaptixC2](https://github.com/nicecatch-cyber/AdaptixC2)
Windows x64 agent focused on **EDR evasion**, preserving the original project's
philosophy. The original project is **[Specter](https://github.com/0xC9H/specter)
by 0xC9H** — this rewrite exists on top of its ideas, architecture, and
research; all credit for the original design and evasion research belongs
to its author.

The server-side integration targets the **AdaptixC2 v1.2 plugin ABI** (the
installed server; the original project targets 2.0) — specter-rs conforms to
AdaptixC2, never the other way around.

## What works (validated live, Windows 11 VM against a real AdaptixC2 v1.2 server)

- **Full check-in loop** — WinHTTP (resolved by FNV-64 hash, no import
  table), 19-field beat, RC4 session, malleable HTTP transaction
  (template split, base64 beat header), task pack parsing, encrypted
  results frame (16 KiB per cycle, atomic records).
- **Evasion core** — indirect syscalls with gadget rotation (Hell's Gate /
  Tartarus' Gate / Hell's Hall), hardware-breakpoint hooks (Dr0-Dr3 + VEH)
  blinding ETW and AMSI, return-address spoofing, **encrypted sleep mask**
  (flips `NtProtectVirtualMemory` on RX images + RWX probe, validated
  over 15+ cycles on the real implant).
- **Operator commands** — `sleep`, `terminate` (thread/process), file set
  (`pwd`, `cd`, `ls`, `cat`, `mkdir`, `rm`, `cp`, `mv`), `upload` /
  `download` (streamed, 48 KiB / 8 KiB per cycle) with `exfil`
  start/stop/cancel, `ps` (tree, arch/context per process), `getuid`,
  `ps kill`, **`ps run`** (hidden window, stdout captured through an
  anonymous pipe, output streamed across cycles), **`jobs list` /
  `jobs kill`**, `disks`, and the **COFF/BOF loader** (`execute bof`,
  full relocation set, subset of the Beacon API, `.pdata` registration,
  variadic `BeaconPrintf`) — BOFs compile with plain `rustc` or MSVC C.
- **Server plugin (Go, ABI v1.2)** — real agent generation dialog driving
  the beacon's own cargo pipeline, RC4 Encrypt/Decrypt, PackTasks /
  ProcessData for every command above, native-style task rendering.

Position-independent, single `.text` section, no CRT, no globals (the
instance lives in `TEB->NtTib.ArbitraryUserPointer`), per-build
encryption and build-time injected configuration, malleable profiles
(`profiles/`). Blob currently ~34 KiB (budget 40 KiB, see guardrails).

## Documentation

- **[Feasibility study](docs/ETUDE-DE-FAISABILITE.md)** (french) — architecture,
  per-invariant analysis, risks, phased roadmap, build pipeline rules (§8bis).
- **[Parity tracking](docs/PARITE.md)** (french) — feature-by-feature mapping
  between specter and this rewrite, updated at every iteration.
- **[Wire contract](docs/WIRE.md)** (french) — the byte-level protocol with
  the AdaptixC2 v1.2 native beacon: HTTP transaction, packer endianness,
  beat, RC4 session, every task and result record format.

## Layout

```
crates/beacon/          PIC beacon (Rust no_std) — check-in loop, task handlers
crates/core/            Pure no_std logic: wire, rc4, transport, config
                        (host-tested under the std harness)
src_server/agent_specter_rs/  AdaptixC2 v1.2 agent plugin (Go)
docs/                   Feasibility study, parity tracking, wire contract
profiles/               Malleable C2 profile definitions (JSON, format v2)
tools/                  Blob pipeline (pe_blob.py, check_blob.py), test
                        harness (server.py / agent.ps1 / queue_job.py),
                        reference BOFs
```

## Build

```bash
make            # build/beacon.x64.bin — raw PIC blob (single .text)
make test       # everything CI runs: fmt, clippy, host tests, guardrails
make pic-check  # position-independence proof (double image base)
```

Toolchain: Rust nightly pinned in `rust-toolchain.toml` (build-std=core),
target `x86_64-pc-windows-gnu`, final link with the Rust-bundled `rust-lld`.
No MinGW, no NASM required.

Generation through the server: the plugin's agent dialog (listener
`specter-http`, agent `specter-rs`) drives the same pipeline with the
listener's keys/URIs/profile injected at build time.

## Quality guardrails

CI (`.github/workflows/ci.yml`) gates every push and PR through layers:

1. **Source discipline** — `rustfmt --check` and `clippy -D warnings`
   (both part of the pinned toolchain, so a dev machine without them
   cannot exist).
2. **Host unit tests** — pure logic lives in `specter-core` (no_std,
   no panic handler, no host API): it is linked into the PIC beacon and
   unit-tested under the std harness on the host.
3. **Blob invariants** — the blob must build, pass layout verification
   (`tools/pe_blob.py`: entry prologue at offset 0, call target in range,
   `SPT_END` marker last), contain **no text strings** and stay under the
   **size budget** (`tools/check_blob.py`, 40 KiB — raise it deliberately,
   in its own commit), and prove **position independence** by byte-identical
   double-base linking (`make pic-check`).
4. **Tooling tests** — the Python verification pipeline is itself tested
   (`tools/test_pe_blob.py`, synthetic PEs, all failure modes).

## Status

Phases 0-3 **done**: PIC pipeline with a proven position-independence
check, syscall engine, HWBP hooks, sleep mask, HTTP check-in, wire
contract, operator commands listed above, and the Go plugin — all
validated against a live AdaptixC2 v1.2 server on a real Windows 11
implant. Remaining for parity (see [PARITE.md](docs/PARITE.md)):
interactive `shell`, token operations (`tkn`), `screenshot`, SOCKS5 and
port forwarding, PPID spoofing, the extended Beacon API and async BOF
pool.

---

## Acknowledgments

This project is a Rust rewrite of **[Specter](https://github.com/0xC9H/specter)**
by **0xC9H**, and would not exist without the original project — its design,
philosophy, and evasion research. The original project's own acknowledgments
carry over in full, as the techniques are the same:

| Project | Author | Reference |
|---------|--------|-----------|
| **Specter** (original project) | 0xC9H | [0xC9H/specter](https://github.com/0xC9H/specter) |
| **NaX** (NoNameAx AdaptixC2 agent) | MaorSabag | [NaX](https://github.com/MaorSabag/NaX) |
| **Stardust** (PIC implant template behind NaX) | C5pider | [Stardust](https://github.com/Cracked5pider/Stardust) |
| **Ekko** (RC4 sleep obfuscation) | C5pider | [Ekko](https://github.com/Cracked5pider/Ekko) |
| **Astral Projection** (module-stomped sleep) | KuwaitiSt | [Astral_Projection](https://github.com/KuwaitiSt/Astral_Projection) |
| **Hell's Gate** (direct SSN extraction) | am0nsec & smelly__vx | [HellsGate](https://github.com/am0nsec/HellsGate) |
| **ThreadStackSpoofer** (TIB stack spoofing) | mgeeky | [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) |

---

> [!IMPORTANT]
> **Authorized use only.** Red team engagements, security research, and
> adversary emulation against systems you are authorized to target. Anything
> else is illegal.
