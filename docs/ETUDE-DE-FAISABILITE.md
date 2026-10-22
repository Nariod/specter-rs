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

**Phase 1 — Runtime** : `GlobalAlloc` sur le heap porté, hashing FNV par API,
instance TEB, `build.rs` consommant la config du plugin Go (contrat inchangé).

**Phase 2 — Evasion core** : port des stubs syscalls en `#[naked]` (Hell's
Gate / Tartarus / Hall), HWBP + VEH, retspoof (NASM conservé), Ekko/Astral
(sleepmask NASM conservé, embedding via `include_bytes!`).

**Phase 3 — Fonctionnel** : wire typé, HTTP (WinHTTP par hash), SMB pipe,
tasks (fs, ps, tokens, socks, portfwd), COFF loader — les tests unitaires
tournent sur la machine de dev.

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
