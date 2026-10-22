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

Dernière mise à jour : **2026-10-22** (phase 3, itération 7 : rejeu du check-in contre le listener réel).

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
| Killswitch (epoch compilé, vérifié au bootstrap et après chaque sommeil) | `KILL_EPOCH` const + conversion FILETIME→epoch testée + contrôle dans le cycle | Fait | Sortie = boucle silencieuse (placeholder) ; `RtlExitUserThread(0)` en phase 2 |
| Sleep + jitter configurables | Cycle runtime : `sleep_with_jitter(SLEEP_MS, JITTER_MS, rng)` → `NtDelayExecution` **indirect** (gadget ntdll tournant) | Fait | Hypothèse documentée : jitter symétrique ± ms, à réconcilier avec le dialogue du plugin en phase 4 ; le masque de sommeil chiffré (Ekko/Astral) reste à faire |
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
| Heap custom / allocation | `specter_core::heap::Heap` (handle + pointeurs résolus), méthodes Instance-scoped | Fait | Pas de `GlobalAlloc` global (philosophie no-globals) ; testé avec mocks WinAPI |
| Sortie silencieuse `RtlExitUserThread(0)` | Résolu par hash depuis ntdll, appelé au killswitch et en échec de bootstrap | Fait | Résolu en premier au bootstrap : toute défaillance ultérieure doit pouvoir partir sans trace |
| Watchdog | — | À faire | Phase 2/3 |

## 4. Évasion

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| Syscalls indirects (Hell's Gate / Tartarus' Gate) : extraction SSN | `syscalls.rs` : extraction depuis le stub (`mov eax,<SSN>`), détection de hook (`E9`), interpolation depuis les voisins non hookés (SSN séquentiels) | Fait | Testé sur mock ntdll (stubs hookés/non hookés, bords, tout-hooké) ; l'appel lui-même est en `asm!` dans le beacon (`mov r10,rcx ; mov eax,SSN ; call gadget`) |
| Rotation de gadgets `syscall; ret` (Hell's Hall, 64 gadgets, re-randomisé chaque sommeil) | Scan `.text` de ntdll pour `0F 05 C3`, cap 64, gadget re-tiré du RNG à chaque cycle de sommeil | Fait | Le `syscall` ne s'exécute jamais depuis la mémoire du beacon |
| Hooks HWBP Dr0-Dr3 + VEH | `specter_core::hwbp` : CONTEXT x64 épinglé (offsets `offset_of!`), bits Dr7, neutralisation par réécriture du contexte (retour propre synthétisé, zéro octet modifié) ; beacon : VEH `extern "system"`, armement via `NtGet/NtSetContextThread` **indirects** (pseudo-handle thread courant) | Fait | Armé sur le thread du beacon ; le ré-armement des threads du pool async attend la phase 3 (BOFs) ; cible inconnue → hooks désactivés sans échec |
| Aveuglement ETW (`EtwEventWrite` & co) | Hooks HWBP sur `EtwEventWrite`, `EtwEventWriteFull`, `NtTraceEvent` (Dr0-Dr2, Dr3 libre pour AMSI) | Fait | Variante HWBP par défaut (modules byte-clean) ; la variante patch `ret` (sans HWBP) n'est pas portée — documented |
| Bypass AMSI (`AmsiScanBuffer`) | Dr3 (laissé libre par ETW) : hook immédiat si amsi.dll est mappé, sinon différé par `LdrRegisterDllNotification` ; retour synthétisé `E_INVALIDARG`, zéro octet modifié | Fait | Test de décision host (notification mock, casse insensible, raisons/absence) ; la callback ignore les threads étrangers (instance via `gs`) |
| Return-address spoofing (gadget `FF 23` dans DLL signée) | Scan `FF 23` pur testé (core) + harness naked `spt_spoof_call2` : gadget poussé comme fausse adresse de retour, continuation via `jmp [rbx]` (RBX callee-saved survit à l'appel), alignement win64 respecté ; premier consommateur : lecture horloge du killswitch | Partiel | Le fallback `ADD RSP, imm8; RET` et le scan étendu aux 7 modules signés de l'original restent à faire ; l'asm est revu instruction par instruction mais non exécutable en test host |
| Thread stack spoofing (TIB) | — | À faire | Phase 2/3 |
| Sleep obfuscation Ekko / Astral Projection (+ sleepmask) | Masque de sommeil chiffré : stub naked auto-suffisant (xorshift64 byte-stream, image chiffrée hormis la fenêtre du stub, sleep `NtDelayExecution` indirect sur gadget Hell's Hall, déchiffrement par flux identique) ; bornes découvertes au bootstrap par fonctions pures testées (prologue d'entrée, magiques de fin d'image et de stub) | Partiel | Écart vs Ekko original : chiffrement par le même thread (propriété équivalente : l'image est illisible pendant tout le sommeil, le thread est dans le syscall) ; le spoofing pile/tas pendant le sommeil (ThreadStackSpoofer) reste à faire ; fenêtre d'exposition VEH identique à l'original |
| `dll-notify` (unhook des callbacks de chargement) | — | À faire | Phase 2/3 |

## 5. Transports et réseau

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| HTTP/S (WinHTTP résolu par hash), GET heartbeat / POST tâches | `runtime::winhttp` : winhttp.dll chargé à la demande (`LoadLibraryA` par hash), 9 exports résolus par FNV-64, transaction POST complète (session/connect/request/send/read/close) par cycle ; échec = sommeil + retry, jamais fatal | Partiel | Itérations 6-7 : les octets exacts du beacon sont acceptés par le listener réel — rejeu host via le harnais `core::replay` (session créée, tâche sleep reçue/accusée) ; l'exécution WinHTTP sur l'implant Windows reste à démontrer en démo ; HTTPS automatique sur port 443, non testé en labo |
| Profils malleables appliqués des deux côtés | Côté beacon : façonnage consommé (`core::transport`) — en-tête beat RC4+base64 (clé listener), headers/UA/URI du profil, gabarit de page en réponse ; côté plugin : le profil du listener override le profil malleable au build (le listener est l'autorité) | Partiel | Le placement/format/mask du profil (cookies specter v2) restent non consommés : le listener BeaconHTTP n'en a pas |
| Proxy-aware transport | `WinHttpOpen(ACCESS_DEFAULT_PROXY)` | Partiel | Comportement système par défaut, non testé |
| Pivot SMB named pipe (`link`/`unlink`) | — | À faire | Phase 3 ; listener SMB Go inchangé |

## 6. Commandes (tâches opérateur)

| Commande (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| `sleep` — le **cycle** est fait (voir §2) ; la **commande opérateur** (changement à runtime) | Beacon : `COMMAND_PROFILE` subop 1 parsé, profil runtime mis à jour, accusé renvoyé au cycle suivant ; plugin Go : `ProcessData` gère l'accusé (`TsAgentUpdateData`) ; dialogue opérateur déclaré (ax_config.axs : `sleep`, `terminate`) et `CreateCommand` porté | Fait* | Itération 7 : round-trip complet vérifié contre le serveur réel (rejeu) — tâche `sleep 45 5` créée par l'API opérateur, reçue par les octets du beacon, accusée, marquée complétée (« Sleep time has been changed »), profil session mis à jour. *L'exécution sur l'implant Windows réel reste la démonstration du MVP |
| Fichiers : `cat` `ls` `cd` `pwd` `mkdir` `rm` `cp` `mv` `upload` `download` | — | À faire | Phase 3 |
| Process : `ps` (list/kill/run + PPID spoofing), `whoami` | — | À faire | Phase 3 |
| `shell` (cmd.exe/PowerShell interactif) | — | À faire | Phase 3 |
| `bof` (loader COFF, sync + async thread pool) | — | À faire | Phase 3 ; candidat n°1 du gain Rust (parsing non fiable) |
| `tkn` (steal/make/impersonate/revert/list/remove/getuid/privs) | — | À faire | Phase 3 |
| `socks` (SOCKS5), `lportfwd`, `rportfwd` | — | À faire | Phase 3 |
| `screenshot` | — | À faire | Phase 3 |
| `joblist` / `jobkill` | — | À faire | Phase 3 |

## 7. Protocole wire

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| Wire protocol tâches/résultats (dispatcher typé) | `core::transport` + `core::wire` : enveloppe beat (RC4+base64, préfixe type/id), extraction du gabarit de page, pack de tâches `[data\|u32 LE taskId]`, cadre des résultats (flags 0 + u32 LE + u32 BE size) — tout épinglé par des vecteurs générés par la sémantique Go exacte (crypto/rc4, base64, PackArray, PackTasks) | Partiel | Itération 6 ; contrat complet pinné dans docs/WIRE.md ; commandes supportées : sleep, terminate (les autres restent à faire) |

## 8. Serveur (AdaptixC2 — reste en Go)

| Composant (specter) | Statut | Notes |
|---|---|---|
| `agent_specter` (génération payloads, dialogue, build du beacon) | `src_server/agent_specter_rs` (Go, ABI AdaptixC2 **v1.2** — le serveur installé ; l'original vise 2.0) : dialogue de génération, `BuildPayload` pilotant le pipeline cargo via `SPT_CONFIG` (avec `listener_key` + override du profil par le listener réel), `CreateAgent`/`Encrypt`/`Decrypt`/`PackTasks`/`ProcessData` portés du natif (RC4 session, packer,COMMAND_PROFILE/TERMINATE), chargé et vérifié sur le serveur réel (test négatif : le serveur logge l'échec si le .so manque) | Partiel | Itération 7 : rejeu du check-in contre le listener réel vérifié — session `specter-rs` créée sur le serveur (identité complète), tâche `sleep` round-trip complet via l'API opérateur (harnais `core::replay`, `#[ignore]`, piloté par env) ; `CreateCommand` + dialogues ax (`sleep`, `terminate`) livrés ; reste : commandes fichiers/process/shell, pivots (`PivotPackData` stub explicite) |
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
| Build / config | 6 | 1 | 1 | 4 |
| Runtime | 6 | 0 | 1 | 0 |
| Évasion | 5 | 2 | 2 | 0 |
| Transports | 0 | 3 | 1 | 0 |
| Commandes | 1 | 0 | 9 | 0 |
| Wire | 0 | 1 | 0 | 0 |
| Serveur Go | 0 | 2 | 0 | 3 |
