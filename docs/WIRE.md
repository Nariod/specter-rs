# Contrat wire specter-rs ↔ AdaptixC2 (agent natif "beacon", v1.2)

> Référence dérivée de l'implémentation installée :
> `AdaptixServer/extenders/beacon_listener_http/pl_transport.go` (cadre HTTP,
> chiffrement du beat, gabarit de réponse) et
> `AdaptixServer/extenders/beacon_agent/pl_main.go` / `pl_packer.go`
> (CreateAgent, Encrypt/Decrypt, PackTasks, ProcessData) — tag v1.2.
> specter-rs est conforme à ce contrat (c'est lui qui s'adapte à AdaptixC2,
> jamais l'inverse). Chaque format ci-dessous est épinglé par des tests
> host (`crates/core/src/transport.rs`) rejouant des vecteurs produits par
> la sémantique Go exacte (crypto/rc4, base64.StdEncoding, PackArray).

## Transaction HTTP (listener `BeaconHTTP`)

Une transaction par cycle de check-in — le listener valide, dans l'ordre :
l'URI (parmi `uri`), le `Host:` (si `host_header` est configuré), le
`User-Agent` (parmi `user_agent`), puis lit le beat dans le header
`hb_header` (`ParameterName` dans `TransportConfig`).

### Requête (beacon → serveur)

```
POST <uri> HTTP/1.1          # méthode du listener (http_method)
Host: <callback>             # hosts[0] du profil
User-Agent: <ua>             # user_agent[0] du listener
<request_headers du listener>
<hb_header>: <valeur du beat>   ← voir ci-dessous
[corps: résultats chiffrés]     ← vide au premier check-in
```

**Valeur du header beat** (chaque requête, check-in compris) :

```
base64_std( RC4( listener_key, u32 BE agentType || u32 BE agentId || beat ) )
```

- `listener_key` : 16 octets (`encrypt_key` du listener, 32 hex) — injecté
  au build via `SPT_CONFIG.listener_key` ; le plugin BuildPayload le lit
  du profil du listener (le listener est l'autorité : il override le
  profil malleable).
- `agentType` : watermark du plugin agent (`agent_watermark` de
  `config.yaml` = `0x5b3c7e21` → le serveur route vers le plugin).
- `agentId` : u32 généré par le beacon, stable pour toute la session.
- `beat` : les 19 champs ci-dessous.

Le serveur (`parseBeatAndData`) : base64-décode, RC4-déchiffre avec la clé
listener, lit `agentType` puis `agentId` (tous deux u32 BE), et passe le
reste à `CreateAgent` si l'agent est inconnu.

### Réponse (serveur → beacon)

Le listener substitue `<<<PAYLOAD_DATA>>>` dans son gabarit `page-payload` :

```
page = prepend || RC4( session_key, PackTasks() ) || append
```

`prepend`/`append` sont injectés au build (split du gabarit au marqueur —
`POST_SERVER_OUTPUT_PREPEND/APPEND` dans la config générée). Page sans
tâche = marqueur remplacé par la chaîne vide. Le beacon découpe le payload
par le gabarit, déchiffre en session, lit le pack des tâches.

**Corps de la requête (résultats, beacon → serveur)** : le serveur appelle
`Decrypt(corps, SessionKey)` puis `decompressZlibData` — un cadre de 5
octets précède les données :

```
u8  flags        (0 : pas de compression — pass-through natif)
u32 LE origLen   (taille des données qui suivent)
données = u32 BE size (== 4 + reste) || enregistrements de résultats
```

Chaque enregistrement de résultat :
`u32 BE taskId || u32 BE commandId || champs BE de la commande`.
Corps vide au premier check-in (le serveur ignore l'erreur).

## Packer (pl_packer.go)

- Lecture : tous les entiers **big-endian** ; `array` = `u32 BE (longueur)
  || octets` ; chaînes NUL-trimmées.
- `PackArray` (écriture côté serveur, pour les tâches) : `[]byte` brut,
  `int` en **u32 little-endian**, `bool` en 1 octet, `string` en
  `u32 LE (longueur incluant le NUL final) || octets || 00`.

## Premier check-in (beat) — `CreateAgent`

Séquence exacte (CheckPacker `int,int,int,int,word,word,byte,word,word,
int,byte,byte,int,byte,array,array,array,array,array`) :

```
u32 BE  sleep (secondes)
u32 BE  jitter (%)
u32 BE  killdate (epoch)
u32 BE  workingtime
u16 BE  ACP
u16 BE  OemCP
u8      GmtOffset (heures)
u16 BE  Pid
u16 BE  Tid
u32 BE  buildNumber
u8      majorVersion
u8      minorVersion
u32 BE  internalIp
u8      flags : bit0 = agent x64, bit1 = OS x64, bit2 = elevated, bit3 = server
array   SessionKey (aléatoire, générée par le beacon — 32 octets)
array   Domain
array   Computer
array   Username (code page OEM/ACP d'origine)
array   Process
```

MVP specter-rs (itération 9) : tout est collecté (`runtime::sysinfo`)
sauf `workingtime` (0) et le bit server (0) — l'élévation vient de
`TokenElevation`, l'IP interne de `GetIpAddrTable` (première IPv4 non
loopback, `dwAddr` brut : les octets en mémoire, que le serveur rend en
quadrique pointée), le domaine de `NetGetJoinInformation` (vide en
workgroup).

## Chiffrement de session — RC4

`Encrypt == Decrypt == RC4Crypt(data, SessionKey)` — RC4 standard
(`crypto/rc4` côté Go, `specter_core::rc4` côté Rust, vecteurs RFC 6429
épinglés). Un état neuf par requête des deux côtés.

## Tâches serveur → beacon — `PackTasks`

```
u32 LE (taille totale du pack) || concatène pour chaque tâche :
    [taskData.Data (octets bruts)] [u32 LE taskId]
```

`taskData.Data` = `PackArray([commandId, ...arguments])` →
`u32 LE commandId || arguments`. Le beacon lit la taille totale, puis
délimite chaque tâche par la structure de SA commande (le formatage de
chaque commande borne ses données) :

- `COMMAND_PROFILE` (21), subop 1 (sleep) : `u32 LE 21 || u32 LE 1 ||
  u32 LE sleepSec || u32 LE jitterPct || u32 LE taskId`.
- `COMMAND_TERMINATE` (10) : `u32 LE 10 || u32 LE taskId`.

Commande inconnue = désynchronisation : le beacon abandonne le reste du
pack (les tâches restent hébergées côté serveur et seront renvoyées).

## Réponses beacon → serveur — `ProcessData`

Le beacon accuse chaque tâche traitée au cycle suivant, dans le corps :

```
RC4(session, frame(flags=0, u32 LE origLen,
    u32 BE size (4+reste) || pour chaque résultat :
        u32 BE taskId || u32 BE commandId || champs BE))
```

- sleep (COMMAND_PROFILE) : `u32 BE taskId || u32 BE 21 || u32 BE 1 ||
  u32 BE sleepSec || u32 BE jitterPct` → « Sleep time has been changed ».
- terminate : le beacon sort silencieusement ; pas d'accusé.

## ps run + jobs — infrastructure jobs (itération 16, pinné sur beacon_agent CmdPsRun/JobsController)

Tâches (`PackArray` : bool = 1 octet, int = u32 LE, string = u32 LE len+NUL) :

```
ps run    u32 LE 43 || u8 progOutput || u8 useToken || u32 LE progState
          || pack_string progArgs || u32 LE taskId
jobs list u32 LE 46 || u32 LE taskId
jobs kill u32 LE 47 || u32 LE jobId || u32 LE taskId
```

`useToken` est parsé puis ignoré (pas d'infrastructure tokens — MVP).
`jobId` = le taskId de la tâche `ps run` d'origine (le plugin l'utilise
comme identifiant de job).

Résultats du beacon (BE, un ou plusieurs par cycle) :

- `COMMAND_PS_RUN` (43) : `u32 BE taskId || u32 BE 43 || u32 BE pid ||
  u8 isOutput || array prog` → « Program %v started with PID %d ».
- `COMMAND_JOB` (0x8437) : `u32 BE jobId || u32 BE 0x8437 || u8 jobType
  || u8 state [|| array data]`. `jobType` = 3 (process). États natifs :
  1 = RUNNING (porte la sortie drainée du pipe, `Completed=false`, la
  tâche reste ouverte), 2 = FINISHED, 3 = KILLED (fin de vie, tâche
  close). Le beacon garde au plus 8 jobs, draine le pipe à chaque cycle
  (cap 8 KiB par read) et récolte le job sur sortie détectée
  (`GetExitCodeProcess != STILL_ACTIVE`) ; le record JOB porte le taskId
  d'origine, pas un id de tâche jobs.
- `COMMAND_JOB_LIST` (46) : `u32 BE taskId || u32 BE 46 || u32 BE count`,
  puis par entrée `u32 BE jobId || u16 BE jobType || u16 BE pid`.
- `COMMAND_JOBS_KILL` (47) : `u32 BE taskId || u32 BE 47 || u8 found ||
  u32 BE jobId` → « Job %08x mark as Killed » / « Job %08x not found ».

## Screenshot — `screenshot` (itération 17, port du natif SptCmdScreenshot)

Tâche (`PackArray`) :

```
screenshot  u32 LE 44 || u32 LE taskId
```

44 est un id libre de la numérotation native beacon_agent (le voisinage
41-47 est ps/jobs, 44/45 inutilisés). Le natif specter utilise son propre
0x28 sur son propre wire ; côté AdaptixC2 c'est notre wire qui fait foi.

Le beacon capture l'écran à la réception de la tâche (GDI par hash :
user32/gdi32 résolus PEB puis `LoadLibraryA`, `GetSystemMetrics` →
`GetDC`/`CreateCompatibleDC`/`CreateCompatibleBitmap`/`BitBlt`/
`GetDIBits`) et écrit un BMP complet dans un buffer heap : 24bpp si les
pixels tiennent dans la borne heap (8 MiB), sinon 8bpp niveaux de gris
avec palette (tiering du natif ; un écran 2560x1440 ne tient pas en
24bpp sous la borne). Échec de capture = record COMMAND_ERROR.

Le BMP (typiquement ~6 Mo) ne tient pas dans le cadre body 0x12000 :
il est **streamé comme un download**, 48 KiB par cycle, records BE :

```
START    u32 BE taskId || u32 BE 44 || u8 1 || u64 BE totalSize
CONTINUE u32 BE taskId || u32 BE 44 || u8 2 || array chunk (48 KiB)
FINISH   u32 BE taskId || u32 BE 44 || u8 3
```

Une seule capture à la fois (une seconde tâche pendant un stream =
COMMAND_ERROR). Un push CONTINUE qui ne tient pas dans le body (download
concurrent) est retenté au cycle suivant. Côté plugin : le START affiche
« Screenshot capture started », les CONTINUE s'accumulent par task id
(map protégée mutex), le FINISH rend la main à `TsScreenshotAdd` avec le
BMP complet (« Screenshot captured »).

Validé sur l'implant réel (itération 17) : 1920x1122 24bpp, 6 462 774 o,
START→FINISH en 276 s à sleep 2s (~132 cycles), BMP valide côté serveur.

## BOF — `execute bof` (itération 14, pinné sur beacon_agent pl_main.go/pl_utils.go)

Tâche (`PackArray` : bool = 1 octet, bytes = brut, string = u32 LE len+NUL,
int = u32 LE) :

```
u32 LE 50 || u8 async || pack_string "go" || u32 LE bofLen || bof (COFF)
    || u32 LE paramsLen || params || u32 LE taskId
```

Résultats du beacon (ordre natif ; le lifecycle started va dans la file de
cycle, les outputs dans la file heap drainée par records entiers) :

- `COMMAND_EXEC_BOF` (50) : `u32 BE taskId || u32 BE 50 || u8 état`
  (1 = async started, Completed=false ; 2 = finished, Completed=true).
- `COMMAND_EXEC_BOF_OUT` (51) : `u32 BE taskId || u32 BE 51 || u32 BE
  outputType || array output`. Types : erreurs de chargement 0x101-0x105
  (PARSE/SYMBOL/MAX_FUNCS/ENTRY/ALLOC — SYMBOL porte le nom du symbole),
  callbacks BOF 0x0d (error), 0x1e (OEM), 0x20 (UTF8). Côté serveur, la
  map `bof_output` (par ProcessData) n'étiquette « BOF output » que le
  premier record de la tâche.

Semantics loader : relocations additives (`ADDR64 += S`, `ADDR32NB += S -
base`, `REL32_k += S - P - (4+k)`, ADDR32 jamais patché — runner.c),
externals résolus dans une page trampoline `mapFuncs` (les REL32 pointent
le slot), entry `go(args, argslen)`.

### Convention d'appel pour un BOF (validée en VM réelle, itération 16)

Un BOF n'appelle **jamais** une API Beacon directement : un `call/jmp
rel32` vers l'extern saute dans les 8 octets du slot `mapFuncs` (le
comportement est identique dans l'original — runner.c). La référence doit
être indirecte :

- en C (specter/beacon.h) : `DECLSPEC_IMPORT` (dllimport) — le compilateur
  émet `call qword ptr [rip+disp32]` vers le slot ;
- en Rust : un **extern static de type pointeur**, pas un extern `fn`.
  LLVM génère un `refptr` (section `.rdata$.refptr.SYM` avec relocation
  `ADDR64` vers l'extern) : le code charge l'adresse du slot depuis son
  propre `refptr`, puis déréférence le slot pour obtenir le pointeur de
  fonction (`mov reg, [refptr]; mov reg, [reg]; call reg`). Source de
  référence : `tools/bof/hello.rs` (build :
  `rustc --target x86_64-pc-windows-gnu --emit=obj -C opt-level=z`).

## Écart avec la version précédente de ce document

La relecture de la source serveur (2026-10-22, itération 6) a remplacé la
description « POST = RC4 du corps » par le cadre complet réel : header
beat RC4+base64 avec préfixe `agentType || agentId`, gabarit de page en
réponse, cadre 5 octets des résultats, préfixe `u32 LE` du pack de
tâches. Tout est épinglé par des vecteurs Go générés.
