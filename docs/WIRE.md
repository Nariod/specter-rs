# Contrat wire specter-rs ↔ AdaptixC2 (agent natif "beacon", v1.2)

> Référence dérivée de l'implémentation native : `extenders/beacon_agent/
> pl_main.go` (CreateAgent, Encrypt/Decrypt, PackTasks) et `pl_packer.go`
> du tag v1.2. specter-rs est conforme à ce contrat (c'est lui qui s'adapte
> à AdaptixC2, jamais l'inverse).

## Packer (pl_packer.go)

- Tous les entiers sont **big-endian** en lecture côté serveur.
- `ParseBytes`/`ParseString` : `u32 BE (longueur) || octets`. Les chaînes
  sont NUL-trimmées à la lecture.
- `PackArray` (écriture côté serveur, pour les tâches) : `[]byte` brut,
  `int` en **u32 little-endian**, `bool` en 1 octet, `string` avec
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
array   SessionKey (aléatoire, générée par le beacon)
array   Domain
array   Computer
array   Username (code page OEM/ACP d'origine)
array   Process
```

`AgentData.Id`/`Crc` : générés côté serveur (watermark listener + hash) ;
le listener route par watermark. Toute la session suivante est chiffrée
avec la SessionKey.

## Chiffrement de session — RC4

`Encrypt == Decrypt == RC4Crypt(data, SessionKey)` — RC4 standard, même
keystream symétrique (implémentation Rust conforme : `specter_core::rc4`,
vecteurs RFC 6429 épinglés par tests).

## Tâches serveur → beacon — `PackTasks`

Paires concaténées pour chaque tâche :

```
[taskData.Data (octets bruts)] [u32 LE taskId]
```

Le beacon lit : data jusqu'à ce qu'il reste 4 octets = taskId (LE). C'est
au formatage de chaque commande de borner ses données.

## Réponses beacon → serveur — `ProcessData`

Le POST contient le RC4 du corps ; décrypté, le packer lit par tâche :
`u32 BE taskId || u32 BE (taille corps) || corps` (voir ProcessData du
natif ; à épingler par les tests d'intégration contre le serveur réel).
