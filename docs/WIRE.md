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

MVP specter-rs (documenté au PARITE) : `internalIp` = 0, `Domain` vide,
`workingtime` = 0, bits elevated/server à 0. Le reste est collecté
(`runtime::sysinfo`).

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

## Écart avec la version précédente de ce document

La relecture de la source serveur (2026-10-22, itération 6) a remplacé la
description « POST = RC4 du corps » par le cadre complet réel : header
beat RC4+base64 avec préfixe `agentType || agentId`, gabarit de page en
réponse, cadre 5 octets des résultats, préfixe `u32 LE` du pack de
tâches. Tout est épinglé par des vecteurs Go générés.
