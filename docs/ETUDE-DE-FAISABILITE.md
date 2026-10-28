# specter-rs — Étude de faisabilité

> Réécriture de [Specter](https://github.com/0xC9H/specter) par **0xC9H**
> (beacon Windows x64, C + NASM) en Rust, en conservant la philosophie
> initiale du projet. Tous les crédits du projet original et de la recherche
> d'évasion qu'il met en œuvre reviennent à son auteur — voir les
> remerciements dans le README.
>
> Étude réalisée à partir de l'analyse du code source original (README,
> `Makefile`, `Linker.ld`, en-têtes `src_beacon/include/`, structure
> `src_server/`, profils).

---

## 0. Résumé exécutif

| Question | Réponse |
|----------|---------|
| La réécriture Rust est-elle **techniquement** faisable ? | **Oui.** Chaque invariant du beacon C a un équivalent Rust `no_std` éprouvé. |
| La philosophie est-elle **conservable** ? | **Oui, en totalité.** PIC, `.text` unique, pas de CRT, pas d'imports, pas de globaux, instance dans le TEB : tous transposables. |
| Le périmètre optimal ? | **Hybride** : réécrire `src_beacon` en Rust, **garder les plugins serveur en Go** (ABI AdaptixC2). |
| Le gain réel ? | Élimination de la classe entière des bugs mémoire (COFF loader, wire, parsing FS/PS) — là où un crash coûte un beacon en pleine mission. **Pas** un gain d'évasion. |
| Le risque principal ? | Le pipeline de build (Rust `no_std` + linker script + blob PIC) et la discipline d'empreinte binaire. Se lève par une **phase 0 de 2-3 jours** avant tout engagement. |
| Verdict | **GO conditionnel** — engager la phase 0, décider les phases suivantes sur ses résultats. |

---

## 1. Ce que « conserver la philosophie » impose

Invariants extraits du projet original. Chacun est une contrainte **non négociable**
de la réécriture :

1. **Position-independent** : un seul `.text`, pas de `.data`/`.bss`/`.rdata`/`.reloc`
   (`Linker.ld` fusionne tout et `/DISCARD` le reste). L'artefact est un blob brut
   extrait par `objcopy -O binary`.
2. **Sans CRT, sans table d'imports** : toute API est résolue à l'exécution par
   hash FNV-64. Aucune dépendance à `msvcrt` ni IAT.
3. **Aucune variable globale** : l'instance (`SPT_INSTANCE`) vit dans
   `TEB->NtTib.ArbitraryUserPointer`, récupérée par la macro `G_INSTANCE`.
   Réentrance totale (threads pool, BOFs async).
4. **Syscalls indirects uniquement** : SSN extrait par Hell's Gate / Tartarus'
   Gate, l'instruction `syscall` exécutée depuis un gadget `0F 05 C3` de ntdll,
   gadget re-randomisé à chaque cycle de sommeil (Hell's Hall). Jamais de
   `syscall` depuis la mémoire du beacon.
5. **Hooks HWBP** (Dr0-Dr3 + VEH) plutôt que patch d'octets — modules byte-clean.
6. **Sleep obfuscation** : Ekko / Astral Projection avec sleepmask NASM embarqué
   en blob, spoofing de pile et de tas pendant le sommeil.
7. **Config générée par build** : le plugin Go écrit `Config.h` (clé AES-256,
   sleep/jitter, watermark, URL C2, profil malleable) avant chaque compilation.
   Kill epoch compilé dans le binaire.
8. **Chiffrement per-build** : xorshift64 + FNV-64 sur clé aléatoire de 16 octets
   générée à la build — casse le hashage statique inter-builds.
9. **Cross-compilation depuis Linux** (MinGW + NASM), build piloté par le
   teamserver via le plugin `agent_specter`.
10. **Intégration AdaptixC2 2.0** : plugins Go compilés sur le teamserver
    (version Go et `GOEXPERIMENT` pinnés par `install.sh`).

---

## 2. Périmètre : que réécrire, que garder

| Composant | Verdict | Justification |
|-----------|---------|---------------|
| `src_beacon/` (C) | **Réécrire en Rust** | Cœur de la demande ; là où Rust apporte un gain mesurable (voir §5). |
| `src_beacon/asm/` (NASM) | **Garder d'abord, migrer au cas par cas** | `sleepmask`, `retspoof`, `entry` restent en NASM assemblés et liés au binaire Rust (interopérabilité triviale). `syscall.x64.asm` est un bon candidat à une migration vers des fonctions `#[naked]` (phase 2), mais rien n'y oblige. |
| `src_server/agent_specter` (Go) | **Garder en Go** | ABI plugin AdaptixC2 = Go. `pl_main.go` (162 KoC) = génération de payloads (PE templates, Rich header, EAT, overlay, donor cloning), dialogue de génération. Le réécrire en Rust = coût très élevé, bénéfice nul (code sûr côté serveur, pas exposé à des données adversariales). |
| `src_server/listener_*`, `specter_refs` (Go) | **Garder en Go** | Même raison d'ABI. |
| `profiles/` (JSON v2) | **Inchangé** | Format consommé des deux côtés ; la parité du format fait partie de la parité du projet. |
| `install.sh`, `Makefile` racine | **Adapter** | Ajout de la toolchain Rust sur le teamserver, pin de version (comme Go l'est déjà). |

Le seul changement d'interface : `agent_specter` n'écrit plus `Config.h` mais
un fichier de config lisible par `build.rs` (env var ou chemin fixe) — le
contrat fonctionnel « le plugin écrit la config puis invoque le build » reste
identique, seul le format d'échange change (JSON au lieu de C `#define`).

---

## 3. Faisabilité technique, invariant par invariant

| Invariant C | Équivalent Rust | Statut | Points d'attention |
|---|---|---|---|
| Sans CRT | `#![no_std]`, `panic = "abort"`, `panic_handler` custom | Éprouvé | Voir §4 pour les chaînes de panic. |
| `.text` unique, `/DISCARD` | `rust-lld` + `Linker.ld` adapté ; fusionner `.rdata*`/`.rodata*` dans `.text` dans le script | Éprouvé | rustc émet des sections propres (`.rodata.cst16`, etc.) — toutes à fusionner explicitement. |
| PIC strict, pas de `.reloc` | Cible `x86_64-pc-windows-gnu`, `-C relocation-model=pic` ; rustc inlie les `const` (pas de pointeurs relocalisés si discipline « const-only ») | Éprouvé, à valider en phase 0 | Toute structure contenant un pointeur de fonction ne doit pas finir en `static` relocalisé. |
| Pas de globaux / TEB | Tout passe un `&mut Instance` ; lecture `gs:[0x30]` en `unsafe` minime | OK | Interdire `static mut`, `OnceCell`, lazy-init. Rust rend cette discipline *vérifiable* (le compilateur refuse les `static mut` sûrs). |
| Allocateur | `GlobalAlloc` implémenté au-dessus du heap du runtime porté (`RtlAllocateHeap` résolu par hash) | Éprouvé | Réimplémenter le heap custom du runtime C tel quel, en dessous de `GlobalAlloc`. |
| Syscalls indirects | `core::arch::asm!` pour la lecture de SSN et l'appel via gadget ; fonctions `#[naked]` (stables depuis Rust 1.82) | Direct | Le code existant se traduit presque ligne à ligne : c'est de l'asm inline, pas du C. |
| AES-256 + FNV + xorshift64 | Crates `no_std` (`aes`/`cipher` de RustCrypto, implémentation aesni) ou port direct du C | OK | Auditer le coût binaire de la crate ; le port direct du C existant est l'option la plus prévisible. |
| HTTP / SMB | Inchangé : WinHTTP résolu par hash (le downloader CRT-free le fait déjà), pipes nommées SMB | Direct | Port mécanique. |
| COFF loader (BOF) | **Candidat n°1 de la réécriture** : parsing de données non fiables, aujourd'hui en C pur, dans un process où un segfault = perte du beacon | Fort gain | Slices bornés, `zerocopy`-style, erreurs typées. |
| Wire protocol | Types Rust + enums exhaustifs côté dispatcher | Fort gain | La structure des messages devient vérifiée à la compilation des deux côtés. |
| HWBP + VEH | Indépendant du langage (Dr0-Dr3, gestionnaire d'exceptions) | Direct | Le VEH doit rester fonctionnel avec `panic=abort` — à confirmer en phase 2 (point ouvert). |
| Sleep obfuscation | Mécanismes pilotés par syscalls + sleepmask NASM inchangé, blob embarqué via `include_bytes!` (équivalent de `gen_blob.py`) | Direct | Le sleepmask reste du NASM pur. |
| Kill epoch / jitter / watchdog | Logique pure | Trivial | — |
| `.pdata`/`.xdata` | `panic = "abort"` supprime l'unwinding Rust | À trancher en phase 0 | Le Makefile original extrait pdata/xdata ; vérifier si le VEH/exceptions C en dépendent réellement. Si besoin, `-C panic-unwind` + script adapté, mais l'objectif est de s'en passer. |

---

## 4. Empreinte binaire et détection

- **Taille** : budget à mesurer. Discipline : `opt-level = "z"`, LTO, `codegen-units = 1`,
  aucun `core::fmt`, pas de formatage de panic. Surcoût attendu de Rust vs C :
  modéré (quelques KiB), à valider en phase 0 par comparaison directe des blobs.
- **Chaînes de panic** : Rust embarque les messages de panic dans le binaire.
  Solution propre : **nightly piné + `-Zbuild-std=core` +
  `-Zpanic-abort-tests`/`panic_immediate_abort`** → aucune chaîne embarquée,
  abort immédiat. Le pin d'une version nightly exacte par `install.sh` est le
  même mécanisme que le pin Go/GOEXPERIMENT déjà en place. Alternative stable :
  zéro panique « par construction » (le compilateur liste les chemins restants).
- **Empreinte compilateur** : `--remap-path-prefix` pour retirer les chemins de
  build ; `.comment`/`.note*` déjà `/DISCARD`és par le linker script ; `strip`
  complet. Les métadonnées Rust n'ont aucune raison de survivre au blob.
- **Signatures statiques** : le C MinGW a les siennes, Rust les siennes — mais
  le beacon final est chiffré per-build, PIC, sans imports : la surface statique
  est minime par construction. À valider par A/B en labo (critère de sortie
  phase 4).

**Point important** : Rust n'améliore pas l'évasion — les techniques (syscalls
indirects, HWBP, Ekko, spoofing) sont orthogonales au langage. specter-rs doit
être positionné comme « la même furtivité, plus de fiabilité », pas « plus furtif ».

---

## 5. Gains attendus

1. **Classe de bugs mémoire éliminée** dans les zones qui manipulent des données
   non fiables : COFF loader, wire, `ls`/`cat` (FS), `ps` (énumération process),
   headers HTTP. Aujourd'hui, un overflow ou UAF dans le beacon C se traduit par
   un crash silencieux ou une corruption à distance — le pire scénario en
   engagement. Rust rend cette classe impossible par construction.
2. **Sûreté de la concurrence** vérifiée à la compilation : thread pool async
   BOF, jobs, tunnels — le borrow checker couvre exactement les cas que le C
   doit gérer à la main sans filet.
3. **Testabilité** : la logique pure (wire, profils malleables, crypto, COFF sur
   fichiers de test) devient testable par `cargo test` sur la machine de dev,
   sans Windows ni cible.
4. **Dispatcher typé** : enums exhaustifs ; une commande ajoutée côté serveur
   sans traitement beacon devient une erreur de compilation, pas un `default:` muet.

---

## 6. Coûts et difficultés

- **Toolchain sur le teamserver** : le plugin compile le beacon côté serveur →
  `rustup` + composants (`rust-src` si build-std, cible `x86_64-pc-windows-gnu`)
  à ajouter à `install.sh`, avec pin de version exacte. Coût ops modéré mais réel.
- **Prévisibilité du code généré** : rustc est moins docile que `gcc -O2` pour
  l'asm fin (clobbers, stack probes). Mitigation : `no_std`, `#[naked]`, et
  conservation des modules NASM critiques tels quels.
- **Stack probes** : rustc peut insérer des probes de pile — impact sur le blob
  PIC à vérifier en phase 0 (point ouvert).
- **Effort** (ordre de grandeur, un développeur maîtrisant les deux langages et
  le code original) :

| Phase | Contenu | Estimation |
|-------|---------|------------|
| 0 | Spike toolchain (voir §8) | 2-3 jours |
| 1 | Runtime (alloc, hashing, TEB, config build.rs) | 2-3 semaines |
| 2 | Syscalls + evasion core | 2-3 semaines |
| 3 | Wire, net, tasks, COFF | 3-5 semaines |
| 4 | Intégration AdaptixC2, parité, labo détection | 2-4 semaines |
| **Total** | | **≈ 2 à 3 mois ETP** |

- **Décalage avec le projet actif** : Specter évolue en continu ; la réécriture
  doit cibler un tag figé de l'original puis rattraper les évolutions, ou
  geler les fonctionnalités côté C pendant la migration.

---

## 7. Risques

| # | Risque | Probabilité | Impact | Mitigation |
|---|--------|-------------|--------|------------|
| 1 | rustc émet des sections/relocations incompatibles avec le `.text` unique PIC | Moyenne | Bloquant | Phase 0 dédiée **avant toute autre dépense** ; linker script Rust validé sur un hello-world first. |
| 2 | Chaînes de panic / empreinte Rust dégradant la discrétion | Moyenne | Moyen | Nightly piné + `panic_immediate_abort` + `remap-path-prefix`. |
| 3 | Régression de furtivité vs original (signatures Rust) | Faible | Élevé | A/B labo, chiffrement per-build inchangé. |
| 4 | Build teamserver fragile (nightly) | Moyenne | Moyen | Pin exact comme pour Go ; option de build offline des blobs. |
| 5 | Régression fonctionnelle en cours de migration (projet actif) | Moyenne | Élevé | Parité par commande + tests wire ; tag figé de l'original. |
| 6 | Non-achèvement (montée en charge) | Moyenne | Élevé | Migration par modules avec double-run A/B : le même plugin produit le bin C *et* le bin Rust pendant la transition, bascule par checkbox de génération. |

---

## 8. Feuille de route recommandée

**Phase 0 — Spike toolchain** : ✅ **terminée, tous les critères de sortie atteints.**

Résultats (2026-10-22, `make blob` / `make pic-check`) :

| Critère de sortie | Résultat |
|---|---|
| Blob PIC Rust minimal (entry naked → fn Rust → boucle) | 23 octets : `sub rsp,8` / `call spt_main` / `ud2` + boucle + marqueur |
| `.text` unique | Oui — `.rdata` et `.sptend` fusionnés via lld-link, rien d'autre |
| Zéro reloc / zéro adresse absolue | Oui — preuve par double base d'image (`pic-check` : octets identiques à `0x10000000` et `0x40000000`) |
| Zéro chaîne | Oui — aucun `panic!` de formatage, handler muet |
| Décision stable vs nightly | **Nightly** (`nightly-2026-10-21`, épinglé dans `rust-toolchain.toml`) : `build-std=core` est requis, la std précompilée traîne des références à `rust_eh_personality` incompatibles avec `panic=abort` |
| `.pdata`/`.xdata` | Non émis par le crate beacon sous `build-std` + `panic=abort` ; à revoir quand le VEH/HWBP existera |
| Stack probes | Absents du spike ; à re-surveiller quand du vrai code existera |

Découvertes de pipeline (points durs, à conserver comme règles du projet) :

1. **Lier l'archive, jamais les objets extraits** — le linker fait alors la
   sélection paresseuse des membres ; autrement tout `compiler_builtins`
   atterrit dans le blob (mesuré : 54 Ko au lieu de 23 octets).
2. `rust-lld` est multi-call : invoqué sous le nom `lld-link` (symlink), il
   pilote le lien COFF — **aucun besoin de MinGW**, contrairement au C
   original (NASM reste également absent du pipeline : l'entry est une
   fonction `#[naked]` Rust).
3. Le PE final n'a **pas de table de symboles** : la vérification du blob se
   fait par patterns d'octets (prologue d'entrée, cible du `call`, magique
   de fin) dans `tools/pe_blob.py`.
4. Le marqueur `.sptend` porte un magique 8 octets (`SPT_END\0`) au lieu
   d'un octet nul : seule déviation documentée par rapport au C, motivée
   par le point 3 (vérifiabilité post-link).
5. `lld-link` fusionne les sections par ordre alphabétique — le marqueur de
   fin reste dernier tant qu'aucune section au nom postérieur n'est fusionnée
   dans `.text` (le `.xdata` doit rester hors du blob, comme dans l'original
   qui livre pdata/xdata en artefacts séparés).

**Phase 1 — Runtime** : **terminée.** Livré : contrat de config JSON plugin →
`build.rs` → module généré (types no_std, validation stricte, manifeste de
chaînes), FNV-64 (variantes ASCII/UTF-16, case-insensitive pour les noms de
modules), PEB walk + résolution d'exports (testés sur host avec PEB/images
mock), bootstrap du beacon (résolution par hash, instance dans le TEB), heap
Instance-scoped (mocks WinAPI), RNG xorshift64 (seedé par
`QueryPerformanceCounter`), cycle sleep+jitter, killswitch FILETIME→epoch
vérifié au bootstrap et après chaque sommeil. Blob : 936 octets, toutes les
gardes tiennent. La sortie silencieuse (`RtlExitUserThread`) et le masque de
sommeil obfusqué passent en phase 2.

## 8bis. Guardrails qualité (mis en place dès la phase 0/1)

CI (`.github/workflows/ci.yml`) — 4 couches, toutes exécutables localement
via `make test` :

1. **Discipline source** : rustfmt + clippy `-D warnings`, composants de la
   toolchain épinglée.
2. **Tests unitaires host** (`specter-core`) : la logique pure est dans un
   crate dédié, testable sous harnais std ; le beacon consomme le même code
   en dépendance no_std.
3. **Invariants du blob** : layout vérifié par patterns d'octets, **aucune
   chaîne ASCII** (le marqueur de fin est passé en magique binaire
   `DEADBEEF`), **budget de taille** 4 KiB (`tools/check_blob.py`),
   preuve PIC par double base.
4. **Tests du pipeline Python** : PEs synthétiques, tous les modes d'échec
   (`tools/test_pe_blob.py`).

Règles d'architecture découvertes en cours de route (à respecter pour
garder le pipeline vert) :

| Règle | Pourquoi |
|---|---|
| `specter-core` : logique pure, sans handler de panic | le handler de panic vit dans `specter-core` (gated `#[cfg(not(test))]`) : présent dans le graphe du beacon, absent quand le harnais std teste le crate |
| `#[panic_handler]` jamais dans le crate beacon | empêche tout lien du beacon dans un binaire std (doublon de lang item) — le beacon n'est testable que via le pipeline blob |
| Pas de `crate-type = "rlib"` sur le beacon | rustc émet des thunks `__imp_` dllimport dans `.data`, cassant l'invariant `.text` unique |
| `doctest = false` sur `specter-core` | les doctests compilent la lib sans `cfg(test)` sous `panic=unwind`, interdit en no_std |
| `build-std=core` **par flag** (Makefile), pas en config globale | la config globale reconstruirait aussi std et casse les tests host |
| `.xdata` fusionné vers `.pdata`, jamais vers `.text` | lld-link fusionne par ordre alphabétique : `xdata` viendrait après `sptend` et le marqueur de fin ne serait plus le dernier octet du blob |
| Le seuil anti-strings échoue à 12+ octets imprimables | le code exécutable produit naturellement des runs imprimables (`41 57 41 56...` = prologues) mesurés jusqu'à ~10 ; les runs plus courts sont affichés en revue, pas fatals |
| Pas d'allocateur global (`#[global_allocator]`) | un allocateur global exige un `static` — interdit par la philosophie no-globals ; l'allocation passe par l'instance TEB (APIs explicites, pas de `Box`/`Vec` dans le beacon) |
| `panic = "immediate-abort"` (feature cargo `panic-immediate-abort`) | sans lui, une seule borne de slice liée entraîne `core::panicking` + la machinerie de formatage (chaînes, libm tirée par les builtins) dans le blob |
| Zéro référence à `compiler_builtins` depuis le code du blob | l'archive est un objet LTO-fusionné : une référence (`___chkstk_ms`, `memcpy`, `memset`) tire ~50 KiB ; le beacon embarque son propre `___chkstk_ms` naked et copie/init manuellement |

**Phase 2 — Evasion core** : en cours — itérations 1 et 2 livrées :
moteur de syscalls indirects complet (extraction SSN Hell's Gate, détection
de hooks, interpolation Tartarus' Gate, scan de gadgets `0F 05 C3` cap 64,
rotation Hell's Hall par cycle, tout testé sur mock ntdll), sommeil via
`NtDelayExecution` indirect, sortie silencieuse `RtlExitUserThread(0)`,
hooks HWBP Dr0-Dr3 + VEH (CONTEXT x64 épinglé, neutralisation par contexte
testée sur host, armement via NtGet/NtSetContextThread indirects),
aveuglement ETW (EtwEventWrite, EtwEventWriteFull, NtTraceEvent) et bypass
AMSI (Dr3, hook immédiat si amsi.dll est mappé, sinon différé par
`LdrRegisterDllNotification`, retour `E_INVALIDARG` synthétisé).
Itérations 4-5 : return-address spoofing (harness naked `JMP [RBX]`,
continuation en paramètre — l'opérande `sym` a été attrapé par la preuve
PIC : il émettait une adresse absolue) et masque de sommeil chiffré
(stub naked auto-suffisant : xorshift64 byte-stream sur l'image entière
hormis sa fenêtre, `NtDelayExecution` indirect, déchiffrement par flux
identique ; bornes découvertes par fonctions pures testées). Blob :
5 018 octets, **zéro compiler_builtins lié**, gardes vertes, PIC prouvé.
Reste phase 2 : spoofing pile/tas pendant le sommeil
(ThreadStackSpoofer), fallback retspoof `ADD RSP`, ré-armement HWBP
multi-threads.

Nouvelles règles de pipeline découvertes en phase 2 (ajoutées à la liste
ci-dessus) :

- **`panic = "immediate-abort"`** : les bornes de slices et les panics
  deviennent des pièges `ud2` inline — sinon `core::panicking` + 4 Ko de
  chaînes et la machinerie de formatage entrent dans le blob.
- **Zéro référence à `compiler_builtins`** : une seule référence
  (`___chkstk_ms` des grandes frames, `memcpy` des copies) tire l'objet
  LTO-fusionné entier (~50 KiB) — le beacon embarque son propre
  `___chkstk_ms` (naked asm) et toutes les copies/init sont manuelles.
- Les hashes de noms sont des `const` de crate (pliés) ; les littéraux
  runtime légitimes (ex. `.text`, l'alphabet base64, les noms de modules
  `amsi.dll`/`ntdll.dll`/`winhttp.dll`) sont déclarés dans le manifeste
  de chaînes du build script.

Nouvelles règles de pipeline découvertes en phase 3 (itération 6) :

- **Les listes de `&str` de la config sont rendues en données compactées
  + tableau d'offsets** (`packed_list`, build/render.rs) : une constante
  `[&str; N]` — ou une struct avec champ `&str` — référencée par le code
  émet des pointeurs gras absolus en statique, que la preuve PIC attrape ;
  les chaînes compactées restent adressées rip-relative.
- **Tampons de pile ≥ 512 octets : non initialisés (`MaybeUninit`)** —
  chaque octet lu est écrit d'abord (packeur, API, lectures bornées) ;
  une init `[0; N]` de grande taille émet un appel `memset` → tire
  compiler_builtins. Le lint `uninit_assumed_init` est autorisé par site,
  invariant documentée.
- **La garde anti-strings décompose les runs** en chaînes déclarées +
  colles < 5 octets : les constantes rdata adjacentes se concatètent dans
  le `.text` fusionné ; une run n'est une fuite que si elle ne se
  décompose pas (tests épinglés des deux côtés).

**Phase 3 — Fonctionnel** : wire typé, HTTP (WinHTTP par hash), SMB pipe,
tasks (fs, ps, tokens, socks, portfwd), COFF loader — les tests unitaires
tournent sur la machine de dev.

Itération 6 (2026-10-22) — transport HTTP + check-in câblé : contrat wire
re-pinné contre la source du listener v1.2 (docs/WIRE.md : header beat
`hb_header` = base64(RC4(clé listener, watermark || agentId || beat19)),
réponse dans le gabarit de page, cadre 5 octets des résultats, pack de
tâches préfixé u32 LE) ; `core::transport` pur, épinglé par des vecteurs
générés par la sémantique Go exacte (crypto/rc4, base64, PackArray,
PackTasks) ; `runtime::winhttp` (chargement à la demande, 9 exports par
hash, transaction POST par cycle, échec non fatal) ; cycle de check-in
dans `bootstrap::main` (clé de session 32 octets, agentId RNG, beat
sysinfo, tâches sleep/terminate, accusés différés d'un cycle) ; plugin
Go : `CreateAgent`/`Encrypt`/`Decrypt`/`PackTasks`/`ProcessData` portés
du natif + `listener_key` et override du profil par le listener réel au
build. Budget blob relevé 8192 → 12288 (commit dédié).

Itération 7 (2026-10-22) — check-in prouvé contre le serveur réel : un
listener `BeaconHTTP` est créé par l'API teamserver (login, listener/create,
agent/command/execute — le protocole opérateur est scriptable) ; le harnais
`core::replay` (test `#[ignore]` piloté par variables d'environnement,
`SPT_REPLAY_*`) rejoue les octets exacts du beacon à travers le même code
pur que l'implant. Résultat : la session `specter-rs` apparaît côté serveur
(identité complète, OS « Win 11 x64 » via la table native), une tâche
`sleep 45 5` créée par l'API opérateur traverse le cycle complet —
`CreateCommand` (dialogues ax `sleep`/`terminate` livrés) → `PackTasks` →
parse beacon → accusé → `ProcessData` → tâche complétée, profil de session
mis à jour. Correctif au passage : le parse beacon de `COMMAND_TERMINATE`
consomme l'exit method (1 thread / 2 process) avant le taskId, comme le
natif. Reste : exécution de l'implant Windows (démo MVP), commandes
fichiers/process/shell, IP interne, élévation, domaine, SMB.

Itération 8 (2026-10-22) — génération vérifiée bout en bout + bug
critique attrapé : la génération par le flux opérateur réel
(`/agent/generate` → plugin → cargo → blob) livrait un blob dont TOUTE la
transaction HTTP avait été éliminée par `-Oz` (tampon du verbe HTTP trop
court — échec de capacité prouvable au compile-time ⇒ le code aval est
mort et supprimé, voir les règles ci-dessus). Corrigé (`[u16; 5]`) ;
l'extraction du gabarit passe en boucles manuelles (`memcmp` interdit) ;
le blob opérateur régénéré embarque et prouve toutes les chaînes du
listener (clé 16 o, hosts, URIs, hb_header, gabarit de page, alphabet
base64) — 11 796/12 288 octets, PIC prouvé.

Itération 9 (2026-10-22) — garde anti-blob-mort + identité complète :
le plugin vérifie à la génération que le blob embarque chaque paramètre
du listener (clé, hosts, URIs, hb_header, gabarit) — le détecteur fiable
de la classe de bug de l'itération 8 ; le beat collecte désormais l'IP
interne (GetIpAddrTable via iphlpapi chargé à la demande), le domaine
rejoint (NetGetJoinInformation via netapi32, converti ACP) et l'élévation
(OpenProcessToken/GetTokenInformation via advapi32) — restent workingtime
et le bit server. Budget relevé 12 288 → 16 384 (commit dédié) : blob à
12 660 octets, PIC prouvé ; flux opérateur réel re-vérifié de bout en
bout (génération 12 692 octets, tous paramètres présents).

Itération 10 (2026-10-22) — premières commandes opérateur : `pwd`, `cd`,
`ls`, `cat` de bout en bout. Côté beacon : dispatch typé (`core::transport`
parse, `beacon::tasks` exécute via APIs résolues par hash, les résultats
sont mis en file pour le POST suivant) ; échecs Win32 → record
`COMMAND_ERROR` avec `GetLastError`. Côté plugin : `CreateCommand` et les
cas `ProcessData` correspondants portés du natif (y compris le rendu du
listing et la synchro du navigateur de fichiers), dialogues ax déclarés.
Le harnais de rejeu fabrique les résultats comme le fait l'implant :
`pwd`/`ls`/`cat` émis par l'API opérateur, reçus, accusés, et rendus
correctement par le serveur réel (tâches complétées, texte affiché).
Formats épinglés par vecteurs Go (PackArray int/string pour les tâches,
enregistrements BE pour les résultats). Blob : 15 388/16 384 — la marge
est quasi consommée, la prochaine commande demandera une relance.

Itération 11 (2026-10-22) — suite fichiers : `mkdir`, `rm`, `cp`, `mv`
de bout en bout (même gabarit que l'itération 10 : CreateCommand/ProcessData
portés, handlers par hash, échecs en COMMAND_ERROR). Budget relevé
16 384 → 20 480 en commit dédié (blob à 16 780). Correctif attrapé par
le test réel : `Task::path()` ne couvrait pas les nouveaux variants —
le rejeu fabriquait des résultats à chemin vide (`Directory '' created`)
et les handlers beacon auraient appelé les APIs avec des chaînes vides ;
test de couverture des accesseurs épinglé (tout variant doit exposer son
argument). Round-trip réel re-vérifié (`mkdir` → `Directory 'C:\vm-demo'
created successfully`).

Itération 12 (2026-10-22) — commandes système : `getuid`, `disks`,
`ps list`, `ps kill` de bout en bout. Beacon : Toolhelp32 snapshot
(Process32W, pids/ppid), ProcessIdToSessionId, IsWow64Process (arch),
token + LookupAccountSidA par processus (élévation, domaine/utilisateur —
best effort, accès refusé = champs neutres), GetLogicalDrives/GetDriveTypeA,
OpenProcess+TerminateProcess. Plugin Go : les cas ProcessData portés du
natif — y compris le rendu arborescent du `ps list` (boîtes dessinées,
tri par pid) et les synchronisations GUI (processus, lecteurs). Rejeu réel
: les quatre commandes rendues correctement par le serveur (« You are
'MEGACORP\nariod' », table des lecteurs, arborescence, « Process 4321
killed »). Blob : 19 244/20 480.

Itération 13 (2026-10-27) — transferts : `download`, `upload`, `exfil`
de bout en bout. Download en streaming : handle ouvert à travers les
cycles (état dans l'instance), un chunk 64 KiB par POST, records
START/CONTINUE/FINISH avec fileId RNG (server-side : TsDownloadAdd/
Update/Close, la tâche reste ouverte jusqu'au FINISH). Upload par
chunks SAVEMEMORY (le plugin découpe en 8 KiB — notre contrat beacon,
le natif utilise 1 MiB mais le format wire est identique), accumulation
dans un buffer heap (cap 8 Mo, HEAP_ZERO_MEMORY) puis écriture au
COMMAND_UPLOAD. Exfil stop/cancel ferme le handle et accuse ; resume
accusé sans effet (le beacon ne se met jamais en pause de lui-même).
Deux bugs attrapés par le test réel : `Task::path()` ne couvrait pas
Download/Upload (chemins vides — le test de couverture des accesseurs,
ajouté en itération 11, les a attrapés immédiatement) ; et surtout
`parse_save_memory` ne consommait pas le `u32 LE taskId` qui suit
chaque enregistrement de tâche — le parse lisait l'id comme la
commande suivante et abandonnait silencieusement le reste du pack
(découvert en hex-dumpant le pack réel depuis un rejeu Python).
Rejeu réel : download complet (fid 0aabbccd, état FINISHED, fichier
sauvé côté serveur), upload complet (chunk consommé + tâche accusée,
« File successfully uploaded »), exfil stop accusé. Budget relevé
20 480 → 24 576 en commit dédié (blob 22 052).

Itération 14 (2026-10-27) — le cœur du C2 : loader **BOF** + canal
**debug**. Côté beacon : `core::coff` (parse COFF x64 pur et borné —
l'original fait tout à la main dans un process où un segfault coûte le
beacon ; relocation COFF = **10 octets** (rva 4 + index 4 + type 2), pas
8 : attrapé en écrivant le parseur puis confirmé sur le runner.c natif,
qui a aussi révélé que les patchs sont **additifs** (`*P += S`, pas
`*P = S`) et que ADDR32 n'est jamais patché). Chargeur `beacon::coff` :
port fidèle de runner.c (layout data→mapFuncs→code, trampoline des
externals, `__imp_MODULE$Func` par hash, .pdata/RtlAddFunctionTable pour
les BOFs SEH). `BeaconPrintf` sans CRT : **C-variadic natif** (`extern "C"
fn(..., args: ...)`, stable sur la toolchain épinglée — `next_arg::<u64>`
lit le flux d'entiers win64) vers le formateur pur borné (pas de
`_vsnprintf` ntdll, pas de trampoline naked : plus simple et plus sûr).
Canal debug : case `debug` → `specter.log` (CreateFileA OPEN_ALWAYS +
SetFilePointer END), points de log repliés hors du blob par -Oz quand
désactivé. Plugin Go : CreateCommand `execute bof` + ProcessData
EXEC_BOF/EXEC_BOF_OUT (map bof_output) portés, dialogues ax natifs.
Règle pipeline nouvelle : **`==` sur des tranches d'octets dans le beacon
génère un `memcmp`** (reference compiler_builtins) — comparaisons
manuelles partout (déjà la règle pour starts_with, maintenant pour `==`).
Budget relevé 24 576 → 32 768 en commit dédié (blob 29 598 ; harnais Go :
29 673). Écarts documentés dans PARITE.md : async séquentiel, région RWX
unique, sous-ensemble API Beacon.

Itération 15 (2026-10-27) — **masque de sommeil chiffré validé sur implant
réel** + 2 bugs critiques attrapés par le VM. Le stub flippe
`NtProtectVirtualMemory` sur les images RX des packers (sonde RWX au
bootstrap, dégradation propre si un flip échoue) ; les plages chiffrées
sont **clampées aux frontières de pages excluant la page du stub**
(NtProtect agit par pages — le stub vit à l'offset 0x60, un flip naïf
rendait sa page non-exécutive en pleine exécution, constaté comme
violation d'exécution à RIP=stub+0x63). VEH diagnostique (builds DEBUG) :
capture code/RIP/addr de toute exception anormale avant de la laisser
suivre — il a localisé le bug du masque là où le WER n'arrivait jamais
dans le harnais. Correctif pipeline : file de résultats de cycle
512 → 16 KiB + records atomiques multi-entrées.

Itération 16 (2026-10-27) — **MVP : boucle réelle complète validée** sur
la VM Windows (serveur AdaptixC2 réel, RustPacker ntapc, harnais
`tools/harness`). Trois correctifs critiques découverts par la batterie :
exports **forwardés** du PEB (les chaînes de recherche des forwarded
exports ne sont pas celles des noms), check-in à **payload vide** (le
serveur n'écrit rien entre prepend/append quand aucune tâche n'est
hébergée), `___chkstk_ms` asymétrique (prologue push, épilogue double
pop — règle §8bis « propre ___chkstk_ms »). Toutes les commandes
fichiers/process/disks/download/exfil + `sleep`/`terminate` rendues en
live ; `ps run` + `jobs` validés (correctif SECURITY_ATTRIBUTES x64 :
`bInheritHandle` à +0x10, écrit à +4 il n'était jamais héritable —
l'enfant n'écrivait jamais dans le pipe). Budget 32 768 → 40 960 en
commit dédié.

Itération 17 (2026-10-28) — **screenshot** (capture GDI par hash, BMP
streameée comme un download, `TsScreenshotAdd` côté plugin) et **retspoof
complet** : fallback `ADD RSP, imm8; RET` (imm ≡ 8 mod 16, contrainte
d'alignement structurelle) quand aucun gadget `FF 23` n'est trouvé dans
les 6 modules signés de l'original ; knob de génération `force_addrsp`
pour la validation (87 check-ins propres en mode forcé sur l'implant).
Budget 40 960 → 49 152 (commit dédié).

Itération 18/18bis (2026-10-28) — **`tkn`** complet (port de token.c :
steal/make/impersonate/revert/list/remove/getuid/privs, wire 52-59, store
de tokens dans l'instance, impersonation au niveau thread) puis **shell
interactif** (Remote Shell : jobs type 4 + TerminalCallbacks v1.2 —
start/write/exit/kill validés en live, écho de la saisie car cmd.exe
n'écho pas l'entrée pipée, filtrage du line-echo, \n→\r\n en mode pipe).

Itération 19 (2026-10-28) — **tunnels socks/lportfwd/rportfwd validés
byte-exact** (20 Ko md5-identiques à travers le cycle check-in, sur
l'implant réel). Trois bugs racine corrigés : (1) les commandes tunnel
doivent être des tâches serveur `TASK_TYPE_TUNNEL` — une `TASK_TYPE_TASK`
vide empoisonne le parse du pack beacon (record inconnu → abandon du
reste du pack, les proxy tasks qui suivent sont perdues) ; (2)
`parse_tunnel_write` doit consommer le commandId ET le taskId final ;
(3) la file de résultats différés est consommée au POST réussi — sinon un
cycle à réponse vide renvoie les records (start record dupliqué →
double resume → réponse SOCKS5 en double au client). Enseignement : le
débit d'un tunnel beacon HTTP est borné par le sleep (~4 Ko/cycle/socket).

Itération 20 (2026-10-28) — **sommeil threadpool + TIB spoof** (port de
sleep.c 160-560 : worker TpAllocWork/TpPostWork, thread donneur, swap
TEB+Rsp par NtSuspend/NtGet/NtSet/NtResumeThread indirects pendant la
fenêtre chiffrée, restauration avant SetEvent) — validé sur l'implant
réel : 43 cycles pool, zéro exception. Deux leçons : le spoof passe par
une **COPIE du CONTEXT** (muter orig_ctx.rsp laissait le thread beacon
sur la pile du donneur après SetEvent — crash RIP=0), et le packer Rust
active CFG → whitelist obligatoire (port du SptCfgAddTarget natif :
`NtSetInformationVirtualMemory`/VmCfgCallTargetInformation par syscall
indirect 6 arguments, `spt_syscall6`). `async_active` (SptAsyncActive) :
jobs/tunnels actifs ⇒ pas de masque (corrige le crash latent d'un thread
job exécutant des pages chiffrées). Enseignement labo majeur : un serveur
AdaptixC2 restauré avec une DB chargée re-heberge des tâches aux nouveaux
beacons qui **crashent au sommeil suivant le dispatch** (RIP=0,
reproductible même avec le code d'avant l'itération) — le beacon doit
survivre un pack hostile (durcissement du parse : reste ouvert). Budget
49 152 → 53 248 (commit dédié).

**Phase 4 — Intégration & parité** : `agent_specter` invoque `cargo` au lieu de
`gcc` (même dialogue), `install.sh` étendu, parité commandes complète, A/B
détection en labo vs le beacon C, docs.

---

## 9. Points ouverts

1. ~~Nécessité réelle de `.pdata`/`.xdata`~~ → tranché en phase 0 : non émis
   sous `build-std` + `panic=abort` ; à revoir à l'arrivée du VEH/HWBP.
2. ~~Stack probes rustc~~ → absents du spike ; à re-surveiller avec du code réel.
3. ~~Nightly + `build-std` vs stable~~ → nightly, épinglé dans `rust-toolchain.toml`.
4. Budget de taille réel : à mesurer en phase 3 (23 octets pour le spike).
5. Format d'échange config plugin → `build.rs` (`Config.h` → JSON/env) : phase 1.

## 10. Décision

**GO conditionnel.** La réécriture est faisable, la philosophie est conservable
en totalité, et l'architecture hybride (beacon Rust, serveur Go) protège
l'intégration AdaptixC2. Engager la phase 0 ; les phases 1+ ne démarrent que
sur les résultats du spike.
