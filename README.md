# Specter-rs

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows_x64-0078D4?style=for-the-badge" alt="platform"/>
  <img src="https://img.shields.io/badge/C2-AdaptixC2_2.0-006400?style=for-the-badge" alt="C2"/>
  <img src="https://img.shields.io/badge/Lang-Rust_2021-DEA584?style=for-the-badge" alt="lang"/>
</p>

> [!WARNING]
> **Work in progress.** Specter-rs is the early-stage Rust rewrite of
> [Specter](https://github.com/0xC9H/specter). Nothing is functional yet.
> This repository currently contains the feasibility study and the project
> scaffold.

A Rust rewrite of the Specter beacon: an [AdaptixC2](https://github.com/nicecatch-cyber/AdaptixC2)
Windows x64 agent focused on **EDR evasion**, preserving the original project's
philosophy. The original project is **[Specter](https://github.com/0xC9H/specter)
by 0xC9H** — this rewrite exists on top of its ideas, architecture, and
research; all credit for the original design and evasion research belongs
to its author.

- Position-independent, single `.text` section, no CRT, no import table
- No globals: the instance lives in `TEB->NtTib.ArbitraryUserPointer`, fully reentrant
- Indirect syscalls with gadget rotation (Hell's Gate / Tartarus' Gate / Hell's Hall)
- Hardware-breakpoint hooking (Dr0-Dr3 + VEH), return-address spoofing, Ekko/Astral sleep obfuscation
- Per-build encryption and build-time injected configuration
- Malleable C2 profiles (see `profiles/`)

The server-side plugins (`agent_specter`, listeners, refs) are **not** rewritten:
the AdaptixC2 plugin ABI is Go, so they stay in Go. The rewrite targets the
beacon (`src_beacon` in the original).

## Documentation

- **[Feasibility study](docs/ETUDE-DE-FAISABILITE.md)** (french) — architecture,
  per-invariant analysis, risks, phased roadmap. Verdict: **GO conditionnel**,
  pending a phase 0 toolchain spike.

## Layout

```
crates/beacon/        PIC beacon (Rust no_std) — scaffold
docs/                 Feasibility study
profiles/             Malleable C2 profile definitions (JSON, format v2, unchanged)
```

## Build

```bash
make            # build/beacon.x64.bin — raw PIC blob (single .text)
make pic-check  # position-independence proof (double image base)
```

Toolchain: Rust nightly pinned in `rust-toolchain.toml` (build-std=core),
target `x86_64-pc-windows-gnu`, final link with the Rust-bundled `rust-lld`.
No MinGW, no NASM required.

## Status

Phase 0 (toolchain spike) — **done**: 23-byte PIC blob, entry `#[naked]` at
offset 0, `SPT_END` marker last, PIC proven. Phase 1 (runtime: allocator,
FNV API hashing, TEB instance, build.rs config) in progress. See the
[feasibility study](docs/ETUDE-DE-FAISABILITE.md), section 8.

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
