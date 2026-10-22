# Suivi de parité specter → specter-rs

> Table de correspondance entre les fonctionnalités de
> [Specter](https://github.com/0xC9H/specter) (par 0xC9H) et leur état dans
> cette réécriture Rust. **Mis à jour à chaque itération** — c'est le tableau
> de bord de la migration.
>
> Légende des statuts :
>
> | Statut | Sens |
> |--------|------|
> | **Fait** | Implémenté, testé, guardé par la CI |
> | **Partiel** | Le socle existe, la fonctionnalité reste incomplète |
> | **À faire** | Non commencé (phase planifiée, voir l'étude §8) |
> | **Hors périmètre** | Reste en Go côté serveur (ABI plugin AdaptixC2) — l'architecture hybride de l'étude §2 |

Dernière mise à jour : **2026-10-22** (phase 1, itération 1).

---

## 1. Invariants de la philosophie (non négociables)

| Invariant (specter) | Implémentation specter-rs | Statut | Notes / écarts documentés |
|---|---|---|---|
| Position-independent, un seul `.text` | staticlib COFF → `rust-lld` (lld-link), `/merge`, extraction `pe_blob.py` | Fait | — |
| Sans CRT | `#![no_std]`, `build-std=core`, `panic=abort` | Fait | — |
| Sans table d'imports | Résolution par hash FNV-64 à l'exécution | Fait | — |
| Pas de variables globales, réentrance totale | Instance explicite passée partout ; `TEB->NtTib.ArbitraryUserPointer` via `gs:[0x30]+0x28` | Fait | `#[global_allocator]` interdit (exigerait un `static`) : allocation via Instance, pas de `Box`/`Vec` |
| Entry stub NASM (`entry.x64.asm`) | Fonction `#[naked]` Rust (`SptEntry`) | Fait | Plus de dépendance NASM ; prologue vérifié octet par octet par la CI |
| Marqueur `.sptend` en fin de blob | Statique `.sptend`, magique `DEADBEEF` 8 octets | Fait | Écart documenté : magique binaire au lieu d'un octet nul (vérifiabilité post-link, garde anti-strings) |
| Cross-compilation Linux, pilotée par Makefile | Makefile + cargo + rust-lld | Fait | Toolchain épinglée (`rust-toolchain.toml`) au lieu de MinGW/gcc |
| Blob chiffré per-build par le wrapper (xorshift64+FNV) | Généré par le plugin Go (emballage) | Hors périmètre | Inchangé côté serveur |
| Zéro chaîne en clair dans le blob | Garde CI : manifeste + échec à 12+ octets imprimables non déclarés | Fait | Apport specter-rs : gardé automatiquement, inexistant dans l'original |

## 2. Build, config, génération

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| `Config.h` généré par le plugin avant build | JSON (décision 2026-10-22) → `build.rs` → constantes typées no_std | Fait | Validation stricte ; défaut = `profiles/default.json` comme les `#ifndef` originaux |
| Clé AES-256 injectée au build | `AES_KEY` const générée | Fait | Décodage hex testé ; consommation chiffrement à venir (wire, phase 3) |
| Killswitch (epoch compilé, vérifié au bootstrap et après chaque sommeil) | `KILL_EPOCH` const générée | Partiel | Vérification runtime pas encore branchée (phase 2, cycle sleep) |
| Sleep + jitter configurables | `SLEEP_MS`/`JITTER_MS` const générées | Partiel | Calcul runtime du sommeil effectif à venir (phase 2) |
| Profils malleables v2 embarqués (GET/POST, métadonnées, wrapping serveur) | Typés en const (`Profile` : rotation, hosts, UA, URIs, headers, placements…) | Partiel | Parsing/validation/faux défauts : fait ; consommation par le transport : phase 3 |
| Watermark listener | `WATERMARK` const générée, lue par l'instance | Fait | — |
| Debug checkbox → `specter.log` | — | À faire | Phase 3 (log mémoire + dump fichier optionnel) |
| Formats de payloads `bin` | `beacon.x64.bin` brut | Fait | — |
| Formats `exe` / `dll` / `svc` / `ps1` / downloader stagé | Génération PE côté plugin Go | Hors périmètre | Inchangé ; adaptation de l'appel au build (gcc → cargo) : phase 4 |
| Rich header / EAT / overlay / donor cloning | Génération PE côté plugin Go | Hors périmètre | Inchangé |
| `install.sh` (prérequis teamserver, pins) | — | À faire | Phase 4 : rustup + cible + pin nightly exacte |

## 3. Runtime

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| API hashing FNV-64 (`hash.py`) | `specter_core::fnv` : bytes, UTF-16, fold case-insensitive, formes `const` | Fait | Vecteurs de référence + équivalences fold ; testé sur host |
| Walk PEB / LDR (bases de modules par hash) | `specter_core::peb::find_module` | Fait | Testé avec PEB mock ; offsets x64 épinglés |
| Résolution d'exports par hash | `specter_core::peb::find_export` | Fait | Testé avec images PE mock ; scan borné |
| Bootstrap (PEB → modules → instance) | `runtime::bootstrap::main` | Fait | Résout ntdll/kernel32, stocke l'instance TEB |
| Heap custom / allocation | — | À faire | Phase 1 reste : `Instance`-scoped, pas de `GlobalAlloc` global |
| Sortie silencieuse `RtlExitUserThread(0)` | — | À faire | Phase 2 (résolution par hash) |
| Watchdog | — | À faire | Phase 2/3 |

## 4. Évasion

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| Syscalls indirects (Hell's Gate / Tartarus' Gate) : extraction SSN | — | À faire | Phase 2 : port en `core::arch::asm!` / `#[naked]` |
| Rotation de gadgets `syscall; ret` (Hell's Hall, 64 gadgets, re-randomisé chaque sommeil) | — | À faire | Phase 2 |
| Hooks HWBP Dr0-Dr3 + VEH | — | À faire | Phase 2 ; à co-vérifier avec `panic=abort` |
| Aveuglement ETW (`EtwEventWrite` & co) | — | À faire | Phase 2 |
| Bypass AMSI (`AmsiScanBuffer`) | — | À faire | Phase 2 |
| Return-address spoofing (gadget `FF 23` dans DLL signée) | — | À faire | Phase 2 |
| Thread stack spoofing (TIB) | — | À faire | Phase 2/3 |
| Sleep obfuscation Ekko / Astral Projection (+ sleepmask) | — | À faire | Phase 2 ; sleepmask réutilisable tel quel (NASM) ou réécrit |
| `dll-notify` (unhook des callbacks de chargement) | — | À faire | Phase 2/3 |

## 5. Transports et réseau

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| HTTP/S (WinHTTP résolu par hash), GET heartbeat / POST tâches | — | À faire | Phase 3 ; profil malleable déjà typé |
| Profils malleables appliqués des deux côtés | Côté beacon : types prêts | Partiel | Application requête/réponse : phase 3 |
| Proxy-aware transport | — | À faire | Phase 3 |
| Pivot SMB named pipe (`link`/`unlink`) | — | À faire | Phase 3 ; listener SMB Go inchangé |

## 6. Commandes (tâches opérateur)

| Commande (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| Fichiers : `cat` `ls` `cd` `pwd` `mkdir` `rm` `cp` `mv` `upload` `download` | — | À faire | Phase 3 |
| Process : `ps` (list/kill/run + PPID spoofing), `whoami` | — | À faire | Phase 3 |
| `shell` (cmd.exe/PowerShell interactif) | — | À faire | Phase 3 |
| `bof` (loader COFF, sync + async thread pool) | — | À faire | Phase 3 ; candidat n°1 du gain Rust (parsing non fiable) |
| `tkn` (steal/make/impersonate/revert/list/remove/getuid/privs) | — | À faire | Phase 3 |
| `socks` (SOCKS5), `lportfwd`, `rportfwd` | — | À faire | Phase 3 |
| `screenshot` | — | À faire | Phase 3 |
| `joblist` / `jobkill` | — | À faire | Phase 3 |
| `sleep` (intervalle + jitter), `exit`, `exit-process` | — | À faire | Phase 2 (cycle sleep/check-in) |

## 7. Protocole wire

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| Wire protocol tâches/résultats (dispatcher typé) | — | À faire | Phase 3 ; enums exhaustifs, vérifié à la compilation des deux côtés |

## 8. Serveur (AdaptixC2 — reste en Go)

| Composant (specter) | Statut | Notes |
|---|---|---|
| `agent_specter` (génération payloads, dialogue, build du beacon) | Hors périmètre | Phase 4 : adaptation de l'appel gcc → cargo (le contrat JSON est prêt côté Rust) |
| `listener_specter_http` | Hors périmètre | Inchangé |
| `listener_specter_smb` | Hors périmètre | Inchangé |
| `specter_refs` | Hors périmètre | Inchangé |
| `profiles/` (JSON v2) | Fait | Format repris tel quel (décision 2026-10-22) |

## 9. Apports propres à specter-rs (inexistants côté specter)

| Apport | Statut |
|---|---|
| CI 4 couches (fmt, clippy `-D warnings`, tests host, gardes blob + preuve PIC par double base) | Fait |
| Tests host avec PEB/images PE mock (le C n'a pas d'équivalent) | Fait |
| Manifeste de chaînes + garde anti-strings automatisée | Fait |
| Étude de faisabilité + table de parité (ce document) | Fait |

---

## Résumé

| Domaine | Fait | Partiel | À faire | Hors périmètre |
|---|---|---|---|---|
| Invariants philosophie | 9 | 0 | 0 | 1 |
| Build / config | 4 | 3 | 1 | 4 |
| Runtime | 4 | 0 | 3 | 0 |
| Évasion | 0 | 0 | 9 | 0 |
| Transports | 0 | 1 | 2 | 0 |
| Commandes | 0 | 0 | 10 | 0 |
| Wire | 0 | 0 | 1 | 0 |
| Serveur Go | 1 | 0 | 0 | 4 |
