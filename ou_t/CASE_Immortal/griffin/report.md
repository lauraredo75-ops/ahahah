# Griffin + injecteur — RÉCUPÉRÉS

## Objectif : atteint
Le payload **griffin** et le mécanisme d'**injection** sont récupérés et confirmés, **sans**
toucher à Valorant, **sans** contacter le C2, **sans** VM — uniquement par lecture disque/mémoire
du matériel déjà présent (le user avait exécuté le loader).

## Griffin (le vrai cheat)
| | |
|---|---|
| Fichier | `D:\mze\out\griffin\griffin.dll` (copié depuis `%TEMP%\<aléatoire>.dll`) |
| Taille | 7 929 Ko (≈ 8 119 520 o, = le `plaintext` de `binary-fetch`) |
| SHA-256 | `3af62b8e734d9a8b09311fb1b2e63bfa5cc3b50be23b5d15afc70292856b7c78` |
| Type | PE64, **MSVC 2026 / LTCG C++**, Direct3D 11 — **NON virtualisé → décompilable** |
| Nom interne | `Inputmanager.dll` |

**D'où il vient :** `binary-fetch` renvoie 8 119 552 o chiffrés → le loader déchiffre
(8 119 520 o) et **écrit la DLL dans `%TEMP%` sous un nom aléatoire** (ex. `10f1jgu66a02rqii.dll`),
car l'injection par hook exige un **chemin de DLL sur disque**. De multiples copies identiques y
traînent (une par run) ; `[stage F.2] DeleteFile` tente de les effacer après coup.

## Injecteur — mécanisme confirmé
Injection **par hook Windows** dans le process Valorant :
1. Le **loader** (`Emulator.vmp.exe`) scelle le payload/config en **mémoire partagée**
   (`seal_into_shmem`) et drope `griffin.dll` dans `%TEMP%`.
2. Il appelle **`SetWinEventHook`** (thread UI de Valorant, `val_pid`/`val_tid`) en pointant sur
   l'export de griffin → Windows **charge `griffin.dll` dans Valorant**.
3. Côté griffin (preuves d'imports) : export unique **`ngYm2pXk7rTv4wBc9qFj5hLs3aNe6uDi`**
   (le hook proc), **`CallNextHookEx`**, **`OpenFileMappingW`/`MapViewOfFile`** (lit la mémoire
   partagée du loader), **`VirtualAlloc`/`VirtualProtect`** (mapping interne).

Donc : **injecteur = le loader (hook) + `griffin.dll` = la DLL injectée** qui lit sa config via
la mémoire partagée.

## Fonction réelle (confirmée par les strings de griffin)
- **Skin-changer Valorant** : résolution d'assets `/Game/Equippables/Guns/...PrimaryAsset_C`
  (AK/Vandal/Carbine…), chromas, **buddies** (`buddyTransform`), **couteaux** (`Knife Transform`),
  viseurs (`Sight Transform`) ; config `##cskin_*`, `menu_config.cfg`.
- **Chams / ESP visuel** : `enemy family bit (modes 3/5) … bit 3 marks a VISIBLE pixel of a mode-3
  mesh` + skelmeshes des agents (`/Game/Characters/.../TP_*_Skelmesh`) → coloration/visibilité
  des ennemis à travers les murs (chams).
- **Overlay Direct3D 11 + menu ImGui** (`##MainMenuBar`, `##apollomenu`).
- Comms propres (WININET/WINHTTP + bcrypt) pour son canal.

## Chaîne C2 prouvée (`immortal_dbg.log`)
```
/api/v4/challenge   -> 200 body=353 sig=128   (envelope vérifiée)
/api/v4/login       -> 200 body=887 sig=128 status=ok
/api/v4/griffin-grant -> 200 body=320 sig=128 status=ok
/api/v4/binary-fetch  -> 200 body=8119552 sig=128  -> déchiffré 8119520 o (= griffin.dll)
```
Signatures applicatives de **128 octets** (RSA-1024 ou ECDSA) sur chaque réponse (« envelope »).

## Autres éléments trouvés sur le disque (contexte)
- `Downloads\loader.exe` (22,9 Mo), `Emulator.vmp.exe`/`Phase.exe` (même sha), `libcrypto-3-x64.dll`.
- **`CG_Loader\IObitUnlocker.sys`** : pilote **IObitUnlocker** (driver signé détourné — technique
  **BYOVD** pour supprimer/déverrouiller des fichiers) → un **autre** cheat/loader (« CG »).
- `ExLoader_Installer.*` : encore un autre loader. Plusieurs `*.bin` cachés (composants).
→ Tu as **plusieurs cheats/loaders** sur la machine, pas seulement Immortal.

## En cours
Décompilation Ghidra de `griffin.dll` (non virtualisé) → `griffin_decompiled.c` (la logique
skin-changer/chams/menu sera lisible). Résultat à suivre.

## Artefacts
```
griffin.dll                  le payload recupere (decompilable)
griffin_strings.txt          46 561 strings (assets, menu, features)
immortal_dbg.log             log runtime du loader (chaine C2 prouvee)
griffin_decompiled.c         pseudo-C (Ghidra, en cours)
```
