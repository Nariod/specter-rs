# Specter-rs

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows_x64-0078D4?style=for-the-badge" alt="platform"/>
  <img src="https://img.shields.io/badge/C2-AdaptixC2_1.2-006400?style=for-the-badge" alt="C2"/>
  <img src="https://img.shields.io/badge/Lang-Rust_2021-DEA584?style=for-the-badge" alt="lang"/>
  <img src="https://github.com/Nariod/specter-rs/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

> [!NOTE]
> **Release candidate RC1 — validated live.** The full C2 loop and every
> operator command below were re-run green on a real Windows 11 implant
> against a real AdaptixC2 v1.2 server (session r03, 2026-11-05): files,
> ps/jobs, transfers (md5-verified), exfil, screenshot, BOF, tkn, shell,
> tunnels byte-exact, sleep, terminate, and the threadpool+TIB encrypted
> sleep for 1790 cycles without a fault. Hostile-pack hardening, full
> Astral Projection and the SMB named-pipe pivot are in (iterations
> 21-31, see [PARITE.md](docs/PARITE.md)).

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
  over 15+ cycles on the real implant), and **threadpool sleep with TIB
  stack spoofing** — the beacon thread parks in `WaitForSingleObject`
  while a threadpool worker runs the mask stub with the parked thread's
  TEB bounds and saved Rsp lent from a donor thread (CFG-whitelisted
  through `NtSetInformationVirtualMemory`, validated 43 cycles live).
- **Operator commands** — `sleep`, `terminate` (thread/process), file set
  (`pwd`, `cd`, `ls`, `cat`, `mkdir`, `rm`, `cp`, `mv`), `upload` /
  `download` (streamed, 48 KiB / 8 KiB per cycle) with `exfil`
  start/stop/cancel, `ps` (tree, arch/context per process), `getuid`,
  `ps kill`, **`ps run`** (hidden window, stdout captured through an
  anonymous pipe, output streamed across cycles), **`jobs list` /
  `jobs kill`**, `disks`, **`screenshot`** (GDI capture by hash, BMP
  streamed across cycles and reassembled server-side), **`tkn`**
  (steal/make/impersonate/revert/list/remove/getuid/privs — token
  store in the instance, thread-level impersonation), the
  **interactive shell** (Remote Shell terminal, cmd.exe/PowerShell
  with input echo and line-echo filtering), the
  **COFF/BOF loader** (`execute bof`,
  full relocation set, subset of the Beacon API, `.pdata` registration,
  variadic `BeaconPrintf`) — BOFs compile with plain `rustc` or MSVC C,
  and **tunnels** — `socks` (SOCKS5), `lportfwd`, `rportfwd`, all
  relayed through the check-in cycle and validated byte-exact against
  a live implant.
- **SMB named-pipe pivot** — `link \\host\pipe\name` / `unlink`: while a
  pivot is active the whole check-in transport runs over the pipe
  (frame `u32 LE len || payload` each way, same RC4 body as HTTP).
- **Resilience** — hostile task-pack hardening (fuzzed parsers, bounded
  COFF loader, 64-bit layout with a 64 MiB cap), check-in watchdog (silent
  exit after 30 consecutive failures), `ps run -ppid <pid>` parent spoofing,
  dll-notify (foreign loader-notification callbacks unhooked, ours kept),
  async BOFs on a dedicated thread, extended Beacon API (`BeaconFormat*`,
  `BeaconUseToken`/`BeaconRevertToken`).
- **Response page buffer** — 256 KiB heap buffer (64 KiB stack fallback);
  the server caps task packs at 192 KiB and re-queues the overflow, so big
  uploads/BOFs no longer truncate the page.
- **Server plugin (Go, ABI v1.2)** — real agent generation dialog driving
  the beacon's own cargo pipeline, RC4 Encrypt/Decrypt, PackTasks /
  ProcessData for every command above (pack capped + re-queued),
  native-style task rendering and session menu (all commands, incl.
  `link`/`unlink` and `ps run -ppid`).

Position-independent, single `.text` section, no CRT, no globals (the
instance lives in `TEB->NtTib.ArbitraryUserPointer`), per-build
encryption and build-time injected configuration, malleable profiles
(`profiles/`). Blob currently ~57 KiB — 58,128 bytes (budget 60 KiB, see
guardrails).

## Quick start — using specter-rs from AdaptixC2

1. **Prerequisites + build** (once, on the teamserver):
   ```bash
   ./install.sh                 # pins the Rust nightly + targets, then make test
   make                         # build/beacon.x64.bin (raw PIC blob)
   cd src_server/agent_specter_rs && make    # agent_specter_rs.so (ABI v1.2 plugin)
   make test                               # plugin integration harness, no UI needed
   ```
   `install.sh` reads the pinned toolchain from `rust-toolchain.toml` — no
   MinGW/NASM needed. The plugin Makefile uses the same Go version and
   `GOEXPERIMENT` as the `adaptixserver` binary (see its header comment).
   The beacon checkout path is configurable via `SPECTER_RS_DIR`
   (default `~/Documents/specter-rs`).
2. **Install the plugin**: copy the whole `src_server/agent_specter_rs/`
   directory (`agent_specter_rs.so`, `ax_config.axs`, `config.yaml`) into
   the server's `extenders/agent_specter_rs/` folder and restart the
   server — it logs a load error if the `.so` is missing.
3. **Create a listener**: type `specter-http`, set host/port and the
   malleable profile (`profiles/default.json`, or your own — format v2
   unchanged; the listener's profile overrides the embedded one).
4. **Generate an agent**: agent type `specter-rs`, fill the dialog (sleep,
   jitter, killdate, watermark, sleep-mask, and the `debug` checkbox —
   it makes the payload emit `specter.log` next to it; the listener key
   and URIs are injected at build time), payload format `Bin`. The
   dialog drives the same cargo pipeline as `make`.
5. **Run the blob** on the target with any injection method — it is
   position-independent, single `.text`, no import table, per-build
   encrypted by the server wrapper. The session shows up in the client.
6. **Operate**: session menu / console — `sleep`, `terminate`,
   `pwd cd ls cat mkdir rm cp mv`, `upload`/`download`/`exfil`,
   `ps list|kill|run` (optional `-ppid`), `jobs list|kill`, `disks`,
   `screenshot`, `tkn ...`, interactive shell, `execute bof` (BOFs compile
   with plain `rustc` or MSVC C — see `tools/bof/`), `socks` /
   `lportfwd` / `rportfwd`, `link`/`unlink` (SMB pivot).

### Running BOFs (`execute bof`)

Any x64 COFF object with a `go(args, len)` entry works. Reference BOFs live
in `tools/bof/` (`hello`, `args`, `imports`, `format`, `dump_entry`):

```bash
rustc --target x86_64-pc-windows-gnu --emit=obj -C opt-level=z \
    -C panic=abort my_bof.rs -o my_bof.o
```

Call convention (see `docs/WIRE.md` §BOF): never call a Beacon API or a
`__imp_MODULE$Func` import directly — in Rust use an `extern *static*`
(LLVM emits a `refptr`, the call goes through the `mapFuncs` slot); in C use
`DECLSPEC_IMPORT`. Supported Beacon API: `BeaconOutput`, `BeaconPrintf`
(C-variadic, `%s %d %u %x %X %c %p`), `BeaconDataParse/Int/Short/Length/
Extract/Ptr`, and `BeaconFormatAlloc/Free/Reset/Append/Printf/ToString`,
`BeaconUseToken`, `BeaconRevertToken`. Compatibility of third-party `.o`
files can be checked on the host before a session:
`SPT_BOF_DIR=/path/to/objs cargo test -p specter-core --lib external_bofs`.

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
install.sh              One-shot prerequisites + verification (rustup pin,
                        targets, make test)
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
   **size budget** (`tools/check_blob.py`, 60 KiB — every raise is its own
   dedicated commit), and prove **position independence** by byte-identical
   double-base linking (`make pic-check`).
4. **Tooling tests** — the Python verification pipeline is itself tested
   (`tools/test_pe_blob.py`, synthetic PEs, all failure modes).

## Status

**Release candidate RC1** — everything above is implemented and was
validated against a live AdaptixC2 v1.2 server on a real Windows 11
implant (session r03, 2026-11-05, incl. 1790 clean threadpool-sleep
cycles). Iterations 21-31 landed the hostile-pack hardening, full Astral
Projection (private-heap mask + image backup/unmap/remap during sleep),
the SMB named-pipe pivot, watchdog, `install.sh`, PPID spoofing, the
extended Beacon API, dll-notify, the async BOF pool, and the sleep stub
moved to the end of the image. The parity table in
[PARITE.md](docs/PARITE.md) is the source of truth (41 done / 5 partial /
0 todo / 6 out of scope by design — the server side stays in Go).

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
