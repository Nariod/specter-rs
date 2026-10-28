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

Dernière mise à jour : **2026-10-28** (phase 3, itération 19 : tunnels socks/lportfwd/rportfwd validés byte-exact sur l'implant réel).

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
| Résolution d'exports par hash | `specter_core::peb::find_export` | Fait | **Exports forwardés résolus** (itération 16, port de `resolver.c` `SptGetProcEx`/`SptResolveForwarder`) : chaînes avec cap de profondeur (cycles api-set), fallback kernelbase pour les contrats `api-`/`ext-` (byte-wise, pas de littéral dans l'image), forward par ordinal et par nom, `LoadLibraryA` pour les cibles absentes du PEB (`current_peb` : `gs:[0x60]` sous Windows, mock PEB en tests) ; testé avec images PE mock (forwarder par nom/ordinal, cible absente, cycle borné). Le crash sysinfo de l'itération 15 venait d'un export forwardé appelé comme du code |
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
| Return-address spoofing (gadget `FF 23` dans DLL signée) | Scan des 6 modules signés de l'original (kernel32, kernelbase, bcrypt, advapi32, user32, iphlpapi — lookups PEB, absents = sautés) : `FF 23` d'abord, puis **fallback `ADD RSP, imm8; RET`** (`48 83 C4 xx C3`, imm ≡ 8 mod 16 — contrainte d'alignement structurelle : le slot d'atterrissage est l'adresse de retour originale, l'asm natif ne sert réellement que ce cas aussi) ; harness naked `spt_spoof_call2` (JMP [RBX] + continuation) et `spt_spoof_call2_addrsp` (`sub rsp, imm; push gadget` — RET chain directement vers l'appelant réel, pile restaurée à l'état post-call normal, zéro continuation) ; knob de génération `retspoof_force_addrsp` (case diagnostic du dialogue) force le harnais ADD RSP pour la validation ; log debug du type résolu (`bs: gadget ff23/addrsp/none`) ; consommateur : lecture horloge du killswitch à chaque cycle | Fait | Itération 17 : **validé sur l'implant réel en mode forcé** — session ADD RSP de 87 check-ins propres (175 s à sleep 2s) + cycle complet de tâche (pwd rendu), zéro crash — ~87 retours de l'harnais addrsp par le gadget. Confirmé par specter.log en mode forcé : `bs: gadget addrsp` (le gadget ADD RSP est résolu, le harnais tourne à chaque lecture d'horloge — zéro crash sur ~90 cycles cumulés). L'asm est revu instruction par instruction, non exécutable en test host |
| Thread stack spoofing (TIB) | — | À faire | Phase 2/3 |
| Sleep obfuscation Ekko / Astral Projection (+ sleepmask) | Masque de sommeil chiffré : stub naked auto-suffisant (xorshift64 byte-stream, plages chiffrées hormis la page du stub, sleep `NtDelayExecution` indirect sur gadget Hell's Hall, déchiffrement par flux identique) ; bornes découvertes au bootstrap (prologue d'entrée, magiques de fin d'image et de stub) ; **plages chiffrées clampées aux frontières de pages excluant la page du stub** (NtProtectVirtualMemory agit par pages — le stub vit à l'offset 0x60, un flip naïf rendait sa page non-exécutive en pleine exécution) ; flips `NtProtectVirtualMemory` (SSN Hell's Gate) RW avant le flux et restauration de la protection d'origine après le déchiffrement (images RX des packers), statuts capturés, dégradation propre (sommeil clair) si un flip échoue ; graine chargée après tous les syscalls de flip (ils clobbent RAX, qui porte l'état du keystream) | Partiel | **Validé sur l'implant réel (itération 16)** : RustPacker ntapc (image PAGE_EXECUTE_READ), masque seul puis masque+hooks ETW/AMSI ensemble — 15 check-ins, image chiffrée pendant chaque sommeil, protections restaurées, hooks interceptant les événements de l'hôte pendant les fenêtres chiffrées, zéro crash. Écarts : chiffrement par le même thread (l'image est illisible pendant tout le sommeil) ; la première page (stub d'entree + fenêtre du masque) reste en clair pendant le sommeil — exposition documentée, à réduire en déplaçant le stub en fin d'image ; spoofing pile/tas (ThreadStackSpoofer) à faire ; fenêtre d'exposition VEH identique à l'original |
| `dll-notify` (unhook des callbacks de chargement) | — | À faire | Phase 2/3 |

## 5. Transports et réseau

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| HTTP/S (WinHTTP résolu par hash), GET heartbeat / POST tâches | `runtime::winhttp` : winhttp.dll chargé à la demande (`LoadLibraryA` par hash), 9 exports résolus par FNV-64, transaction POST complète (session/connect/request/send/read/close) par cycle ; échec = sommeil + retry, jamais fatal | Fait | Itérations 6-7 (rejeu) + **16 : validation sur l'implant Windows réel** (VM sur tailnet, listener BeaconHTTP réel) — session créée (identité complète), beats acceptés, cycle complet `check-in: ok` y compris le cas « pack de tâches vide » (le serveur n'écrit rien quand aucune tâche n'est hébergée). HTTPS automatique sur port 443, non testé en labo |
| Profils malleables appliqués des deux côtés | Côté beacon : façonnage consommé (`core::transport`) — en-tête beat RC4+base64 (clé listener), headers/UA/URI du profil, gabarit de page en réponse ; côté plugin : le profil du listener override le profil malleable au build (le listener est l'autorité) | Partiel | Le placement/format/mask du profil (cookies specter v2) restent non consommés : le listener BeaconHTTP n'en a pas |
| Proxy-aware transport | `WinHttpOpen(ACCESS_DEFAULT_PROXY)` | Partiel | Comportement système par défaut, non testé |
| Pivot SMB named pipe (`link`/`unlink`) | — | À faire | Phase 3 ; listener SMB Go inchangé |

## 6. Commandes (tâches opérateur)

| Commande (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| `sleep` — le **cycle** est fait (voir §2) ; la **commande opérateur** (changement à runtime) | Beacon : `COMMAND_PROFILE` subop 1 parsé, profil runtime mis à jour, accusé renvoyé au cycle suivant ; plugin Go : `ProcessData` gère l'accusé (`TsAgentUpdateData`) ; dialogue opérateur déclaré (ax_config.axs : `sleep`, `terminate`) et `CreateCommand` porté | Fait | Itération 7 (rejeu) + **16 : validés sur l'implant Windows réel** — `sleep 5s` appliqué en live (beats à 5 s) ; `terminate` (thread) : session morte proprement au cycle de réception (RtlExitUserThread, zéro tick après, processus l'ayant survécu) |
| Fichiers : `cat` `ls` `cd` `pwd` | Beacon : handlers `runtime::tasks` (APIs par hash : GetCurrentDirectoryA, SetCurrentDirectoryA, FindFirstFileA/Next/Close, CreateFileA/ReadFile/CloseHandle ; échec Win32 → record COMMAND_ERROR avec GetLastError) ; plugin Go : CreateCommand + ProcessData portés du natif (rendu listing + synchro navigateur fichiers), dialogues ax déclarés | Fait* | Itération 10 (rejeu) + **16 : validées sur l'implant Windows réel** — pwd, ls (listing complet avec types/tailles/dates), cat (contenu binaire) rendus à l'opérateur |
| Fichiers : `mkdir` `rm` `cp` `mv` | Beacon : `CreateDirectoryA`, `GetFileAttributesA`+`RemoveDirectoryA`/`DeleteFileA` (le byte de résultat dit fichier/répertoire), `CopyFileA` (écrasement), `MoveFileA` ; plugin Go : CreateCommand + ProcessData portés, dialogues ax | Fait* | Itération 11 (rejeu) + **16 : validées sur l'implant réel** — mkdir (ALREADY_EXISTS correct), cp (« File copied successfully »), mv, rm (DIR_NOT_EMPTY correct). Correctif au passage : `Task::path()` couvrait mal les nouveaux variants (test épinglé) |
| Fichiers : `upload` `download` + contrôle `exfil` (start/stop/cancel) | Beacon : download en streaming (handle ouvert à travers les cycles, un chunk 48 KiB par POST (itération 16 : 64 → 48, la file de résultats de cycle est passée à 16 KiB et les deux doivent tenir dans le cadre body de 0x12000), records START/CONTINUE/FINISH avec fileId RNG), upload par accumulation heap des chunks SAVEMEMORY puis écriture (cap 8 Mo), exfil stop/cancel ferme le handle + accuse ; plugin Go : `createTaskCommandSaveMemory` (chunks 8 KiB — notre contrat, le natif utilise 1 MiB, format wire identique), ProcessData DOWNLOAD/EXFIL/UPLOAD portés (TsDownloadAdd/Update/Close, navigateur fichiers rafraîchi) | Fait* | **16 : tout validé sur l'implant réel** — download (fid, « File download complete », 262 959 o sauvés côté serveur), upload (round-trip octet pour octet vérifié par cat), exfil stop à mi-transfert (correctif au passage : le beacon lisait l'état exfil comme u8 alors que le serveur l'écrit en u32 — désynchronisation de 3 octets, le stop ne matchait jamais le fid). Débits : download 48 KiB/cycle, upload 8 KiB/cycle (borne par le sleep) |
| Process : `ps` (list/kill), `getuid` (whoami) | Beacon : Toolhelp32 snapshot + ProcessIdToSessionId + IsWow64Process + token (élévation, LookupAccountSidA pour domaine/user — au mieux par processus, accès refusé = champs neutres), `TerminateProcess` pour kill ; plugin Go : rendu arborescent natif porté + synchro navigateur processus | Fait* | **16 : `ps` validé sur l'implant réel** (arborescence complète, arch/context par processus). Correctifs au passage (offsets épinglés par le BOF de dump tools/bof/dump_entry.rs : `szExeFile` à **+0x2C** — lu à +0x30, chaque nom perdait 2 wchars ; `LookupAccountSidA` : les tampons Name/ReferencedDomainName étaient inversés — le contexte affichait user\machine). `ps kill` validé en live (processus tué, disparition vérifiée au listing suivant) |
| Process : `ps run` (lancement + sortie capturée ; PPID spoofing à part) | Beacon : CreatePipe (SECURITY_ATTRIBUTES x64 — **bInheritHandle à +0x10**, le correctif clé : il était écrit à +4 dans le padding, l'extrémité d'écriture n'était jamais héritable, l'enfant n'écrivait jamais dans le pipe) + STARTUPINFOA x64 aligné (hStdOutput/hStdError à +0x58/+0x60, STARTF_USESTDHANDLES|USESHOWWINDOW, SW_HIDE) + CreateProcessA (bInheritHandles, CREATE_NO_WINDOW) ; tableau de 8 jobs dans l'instance, `jobs_tick` à chaque cycle : PeekNamedPipe → ReadFile (drain cap 8 KiB) → records COMMAND_JOB RUNNING avec la sortie, GetExitCodeProcess → FINISHED puis récolte ; plugin Go : CreateCommand `ps run` (-o, -i, -s), ProcessData COMMAND_PS_RUN/COMMAND_JOB portés | Fait* | **16 : validé sur l'implant réel** — `ps run -o cmd.exe /c echo` (sortie rendue à l'opérateur), `ping -n 100` (sortie streamée sur plusieurs cycles, sortie complète agrégée sur la tâche), fin détectée + job récolté (« No active jobs » ensuite). PPID spoofing non couvert (APIs father/ppid à suivre) |
| Jobs : `jobs list` `jobs kill` | Beacon : parcours du tableau de jobs (réponse : entête n/m + type/pid/état par job), TerminateProcess sur le handle du job tué + record KILLED ; plugin Go : CreateCommand `jobs list`/`jobs kill` (task_id hex), ProcessData portés (rendu tableau natif, message d'état hex `%08x` — correctif : le job id s'affichait en décimal) | Fait* | **16 : validés en live** — `jobs list` (tableau JobID/PID/Type, « No active jobs » à vide), `jobs kill` sur job vivant (« mark as Killed », sortie flushée, tâche close) ; kill d'un job déjà récolté → « not found » correct |
| `disks` (lecteurs montés) | Beacon : `GetLogicalDrives` + `GetDriveTypeA` ; plugin Go : rendu + synchro GUI lecteurs | Fait* | Itération 12 (rejeu) + **16 : validé sur l'implant réel** (C: Hard Drive, D: CD-ROM) |
| `shell` (cmd.exe/PowerShell interactif) | Beacon : le shell vit dans la table jobs (type 4), pipes stdin+stdout héritables + STARTUPINFOA x64 (hStdInput +0x50), CreateProcessA CREATE_NO_WINDOW ; écho de l'entrée tapée pour cmd.exe (mode pipe : pas d'écho conhost), filtrage de l'écho de ligne de cmd en tête de sortie (port SptShellFilterEcho), détection PowerShell (pas d'écho) ; records COMMAND_JOB STARTING/RUNNING/KILLED/FINISHED(+exitCode) ; plugin : TerminalCallbacks conformes au natif (Start/Write/Close via jobs kill), routage vers le canal terminal avec repli console si le terminal n'existe plus ; menu session « Remote Shell » (axs) | Fait* | **18bis : validé sur l'implant réel** (via commandes shelltest API) : banner cmd, écho, sortie `whoami` + prompt, exit (FINISHED, job récolté), jobs kill (KILLED). Subtilité découverte : cmd.exe en mode pipe exige un CRLF (un CR isolé ne déclenche pas la ligne — le client natif convertit). Le canal terminal GUI (client connecté) suit le même contrat que le natif v1.2, non testé faute de GUI |
| `bof` (loader COFF) — l'intérêt central du C2 | Beacon : `core::coff` (parse COFF x64 pur, borné — 512 symboles, relocations 10 octets) + chargeur `beacon::coff` (port de runner.c : layout data→mapFuncs→code, `VirtualAlloc` RWX, relocations additives ADDR64/ADDR32NB/REL32..REL32_5 exactes, ADDR32 non patché comme l'original, imports `__imp_MODULE$Func` par hash via PEB puis LoadLibraryA, table Beacon API par hash — Output/Printf/DataParse/Int/Short/Length/Extract/Ptr, `BeaconPrintf` C-variadic natif → formateur pur borné `%s %d %u %x %X %c %p` sans flottants, .pdata enregistré via RtlAddFunctionTable pour les BOFs SEH, erreur SYMBOL = nom du symbole) ; records : lifecycle EXEC_BOF (état 1/2) dans la file de cycle, outputs EXEC_BOF_OUT dans une file heap drainée au POST par records entiers (fin en dernier — l'ordre natif) ; plugin Go : CreateCommand `execute bof` (base64 + fallback brut+NUL), ProcessData EXEC_BOF/EXEC_BOF_OUT portés (map bof_output), dialogues ax natifs | Fait | Itération 14 (loader+parsing pinnés par tests host, COFF synthétique) + **16 : validé sur l'implant Windows réel** — `execute bof` (BOF Rust `tools/bof/hello.rs`, 858 o) sur session vivante : `bof: exec`/`bof: done`, sortie « hello from the specter-rs bof » rendue à l'opérateur, beacon stable ensuite. Convention d'appel indirecte documentée (WIRE.md §BOF : extern static/refptr — un `jmp rel32` direct saute dans le slot mapFuncs, comportement identique à l'original). Écarts documentés : async séquentiel (state 1 puis exécution inline — pas de pool de threads), une région RWX au lieu du split data/code RX, sous-ensemble de l'API Beacon (tokens/format/KV à suivre), pas de wrapper CreateThread pour les BOFs qui spawnent leurs threads |
| `tkn` (steal/make/impersonate/revert/list/remove/getuid/privs) | Beacon : port complet de token.c — advapi32 par hash (PEB puis LoadLibraryA), 8 tokens stockés dans l'instance (tableau, pattern jobs), steal = OpenProcess/OpenProcessToken/DuplicateTokenEx + GetTokenInformation(TokenUser)+LookupAccountSidA, make = LogonUserA (mot de passe zéroïté), impersonate = ImpersonateLoggedOnUser, getuid = token de thread d'abord (contraire du getuid process), privs = TokenPrivileges + LookupPrivilegeNameA, remove ferme + revert auto si actif ; plugin Go : dialogue tkn 8 sous-commandes + rendus (tableau list/privs, messages d'état) ; wire 52-59 (ids libres natifs) | Fait* | **18 : validé sur l'implant réel** — steal depuis explorer.exe, list, impersonate, getuid à travers le token de thread, revert, privs (5 avec états), remove + « not found » sur id inexistant. `tkn make` non testé en live (pas de second compte sur la VM) ; les opérations suivantes (fichiers, ps run) hériteront du token impersoné puisque l'impersonation est au niveau thread |
| `socks` (SOCKS5), `lportfwd`, `rportfwd` | Beacon : module tunnels `beacon::tasks` (table `Tunnel[16]`, WSAStartup différé par tunnel_surface, socket/connect/select/recv/ioctl par hash ws2_32, inet_addr + repli gethostbyname, non-bloquant, select timeout 0 par tick — 4 Ko lu/cycle/socket, listener 127.0.0.1 pour rportfwd, pause/resume de flux, parse WRITE en ligne par emprunt) ; plugin Go : `TunnelMessage*` (ConnectTCP/Write/Close/Pause/Resume/Reverse → proxy tasks), ProcessData start/write/accept/close/reverse (resume sur result 0, halt mappé WSA→SOCKS5), CreateCommand socks/lportfwd/rportfwd en **tâches serveur TASK_TYPE_TUNNEL** ; contract WIRE.md §Tunnels | Fait | **19 : validés sur l'implant réel** — socks (SOCKS5, curl `--socks5-hostname`), lportfwd (listener serveur → egress beacon), rportfwd (listener beacon, fetch depuis la VM) : 20 Ko **byte-exact** (md5) à travers le cycle check-in ; stops propres. Bugs racine corrigés en cours : (1) `TASK_TYPE_TASK` vide des commandes tunnel empoisonnait le parse du pack beacon → `TASK_TYPE_TUNNEL` comme le référence ; (2) `parse_tunnel_write` ne consommait ni le commandId ni le taskId → désync du pack ; (3) la file de résultats différés n'était pas consommée au POST réussi → records renvoyés (start record dupliqué → double resume → réponse SOCKS5 en double) |
| `screenshot` | Beacon : capture GDI par hash (user32/gdi32 résolus PEB puis `LoadLibraryA`, tiering 24bpp/8bpp du natif contre la borne heap 8 MiB), BMP complet en heap puis **streamé comme un download** (START/CONTINUE/FINISH, 48 KiB par cycle — le corps POST est borné à 0x12000, un BMP plein écran fait ~6 Mo) ; échec de capture = record COMMAND_ERROR ; plugin Go : CreateCommand `screenshot`, ProcessData réassemblage par task id (map mutex) → `TsScreenshotAdd`, dialogue ax déclaré | Fait* | **17 : validé sur l'implant réel** — 1920x1122 24bpp, 6 462 774 o streamés en 276 s (sleep 2s), « Screenshot captured », BMP valide stocké côté serveur (DB + disque). Écarts : le fallback 8bpp n'est pas déclenché par la VM de test (écran 24bpp sous la borne) ; une capture à la fois |
| `joblist` / `jobkill` | Couvert par l'infrastructure jobs (ligne `Jobs` ci-dessus) : tableau de jobs de l'instance, list/kill par ID | Fait* | **16 : validés en live** (voir ligne Jobs) |

## 7. Protocole wire

| Fonctionnalité (specter) | Implémentation specter-rs | Statut | Notes |
|---|---|---|---|
| Wire protocol tâches/résultats (dispatcher typé) | `core::transport` + `core::wire` : enveloppe beat (RC4+base64, préfixe type/id), extraction du gabarit de page, pack de tâches `[data\|u32 LE taskId]`, cadre des résultats (flags 0 + u32 LE + u32 BE size) — tout épinglé par des vecteurs générés par la sémantique Go exacte (crypto/rc4, base64, PackArray, PackTasks) | Fait | Itération 6 (vecteurs) + **16 : validé en VM réelle contre le serveur réel** (beat 19 champs accepté — username collecté via `GetUserNameW` après correction des recettes sysinfo, domaine vide en workgroup, Win 11 x64, IP interne) ; pack vide = zéro tâche géré |

## 8. Serveur (AdaptixC2 — reste en Go)

| Composant (specter) | Statut | Notes |
|---|---|---|
| `agent_specter` (génération payloads, dialogue, build du beacon) | `src_server/agent_specter_rs` (Go, ABI AdaptixC2 **v1.2** — le serveur installé ; l'original vise 2.0) : dialogue de génération, `BuildPayload` pilotant le pipeline cargo via `SPT_CONFIG` (avec `listener_key` + override du profil par le listener réel), `CreateAgent`/`Encrypt`/`Decrypt`/`PackTasks`/`ProcessData` portés du natif (RC4 session, packer,COMMAND_PROFILE/TERMINATE), chargé et vérifié sur le serveur réel (test négatif : le serveur logge l'échec si le .so manque) | Partiel | Itération 7 (rejeu complet via `core::replay`) + **16 : boucle réelle complète** — blob généré par le plugin (API opérateur), exécuté sur la VM Windows (RustPacker ntapc, harnais `tools/harness`), session vivante : `sleep` + `execute bof` rendus à l'opérateur ; reste : commandes fichiers/process en démo réelle, pivots (`PivotPackData` stub explicite) |
| `listener_specter_http` | Hors périmètre | Inchangé |
| `listener_specter_smb` | Hors périmètre | Inchangé |
| `specter_refs` | Hors périmètre | Inchangé |
| `profiles/` (JSON v2) | Fait | Format repris tel quel (décision 2026-10-22) |

## 9. Apports propres à specter-rs (inexistants côté specter)

| Apport | Statut |
|---|---|
| Canal debug à la génération (case `debug` → `specter.log` : bootstrap, check-in begin/ok, bof exec/done/error ; replié hors du blob par -Oz quand désactivé) | Fait (itération 14) |
| VEH diagnostique (builds DEBUG seulement) : capture code/RIP/ExceptionAddress de toute exception anormale avant de la laisser suivre (ferme la fenêtre de diagnostic là où le WER n'arrive jamais dans le harnais) — il a localisé le bug du masque (violation d'exécution à RIP=stub+0x63, l'instruction suivant le flip de la page du stub). Muet sur les exceptions HWBP normales des hooks (SINGLE_STEP/BREAKPOINT) | Fait (itération 16) |

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
| Runtime | 7 | 0 | 1 | 0 |
| Évasion | 6 | 1 | 2 | 0 |
| Transports | 1 | 2 | 1 | 0 |
| Commandes | 12 | 0 | 1 | 0 |
| Wire | 1 | 0 | 0 | 0 |
| Serveur Go | 0 | 2 | 0 | 3 |
