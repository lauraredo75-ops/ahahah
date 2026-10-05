# Griffin : localisation, extraction, injecteur, fonction — réponses

## 1. Où est griffin, concrètement ?
Cycle de vie (depuis les stages du loader + le carve mémoire) :
1. **Jamais sur disque.** Récupéré à l'exécution via `POST /api/v4/binary-fetch` (payload **chiffré**).
2. **Déchiffré en RAM dans le loader** avec la clé de `/api/v4/pak-key` (contexte
   `immortal-auth-v4|pak-key-wrap|`), stocké dans un buffer `dll_bytes` — **pas** comme module PE.
3. **Scellé en mémoire partagée** (`[stage C] seal_into_shmem: val_pid pak_present=1`).
4. **Injecté/mappé dans le process VALORANT** via `[stage D] SetWinEventHook(val_pid,val_tid)`.
   → **Griffin vit et s'exécute DANS Valorant**, pas dans le loader.

**Preuve (carve mémoire du loader, PID live) :** scan complet des régions PRIVATE/MAPPED →
5 PE trouvés = **VMProtectSDK64.dll** (licence) + 3 ressources locales Windows (x86) + 1 petit
stub x64. **Aucun module griffin.** Il n'est donc pas conservé en PE clair côté loader (chiffré
jusqu'au hand-off, puis côté Valorant).

## 2. Possibilité de l'extraire ?
- **Depuis le loader : non, pas proprement** (confirmé : pas de PE griffin en mémoire ; il est
  chiffré jusqu'au `seal_into_shmem`).
- **Voies réelles (toutes en VM isolée) :**
  - **(A) Capture réseau** `binary-fetch` (payload chiffré) + `pak-key` (clé) → déchiffrement
    hors-ligne. La plus propre. Kit prêt : `capture_kit/`.
  - **(B) Hook du loader au déchiffrement** (frida/ API hook sur OpenSSL/bcrypt) pour capter
    `dll_bytes` juste avant `seal_into_shmem`. ⚠️ le loader a un watchdog **anti-frida**
    (`[tick] KILLING: … frida …`) → à contourner, en VM.
  - **(C) Dump de Valorant** (où griffin est mappé) → **EXCLU** : Vanguard protège le process,
    risque de **bannissement**. À ne pas faire.

## 3. L'injecteur ?
C'est **le loader lui-même** (`Phase.exe`/`Emulator.vmp.exe`). Technique :
**mémoire partagée + `SetWinEventHook`** sur le thread UI de Valorant (`val_pid`/`val_tid`),
avec un hook-proc exporté (`export=%.32s`) — quand Valorant émet un WinEvent, Windows charge la
DLL de hook dans son espace = exécution du code dans Valorant. Chaîne A→F :
`launch_private → sha256(dll_bytes) → resolve val_tid → pak-key → seal_into_shmem → SetWinEventHook
→ SetForegroundWindow → DeleteFile (anti-forensique)`. Le code exact est virtualisé VMProtect,
mais le mécanisme est complet et documenté.

## 4. La fonction de l'« Emulator » elle-même ?
« Emulator » est le **nom commercial du produit/tier** (Immortal, « Emulator + Private
(auto-inject) ») — **pas** un émulateur matériel. Fonctionnellement, ce binaire est un
**loader + injecteur de triche Valorant** :
- **Licence liée au HWID** (VMProtect SDK : `VMProtectActivateLicense`, `GetCurrentHWID`).
- **Auth C2** `immortal-authentication.com` (challenge → login → griffin-grant), session `sess_hex`.
- **Téléchargement + déchiffrement** du module de triche (griffin) : `pak-key` + `binary-fetch`.
- **Injection** dans Valorant (ci-dessus) + **heartbeat** (licence), **password-gate**,
  **anti-debug/anti-RE** et **anti-forensique**.
- Les **fonctionnalités de triche réelles** (aimbot/ESP/triggerbot/etc.) sont **dans griffin**,
  donc **absentes de ce fichier** (fournies par le C2 à l'exécution).

## Artefacts
```
artifacts/carve/            5 PE carves de la memoire du loader (dont VMProtectSDK64.dll)
artifacts/decompiled_payload.c   VMProtectSDK64.dll decompile (383 fct)
artifacts/pesieve/          dump memoire live + strings dechiffrees (session_token, C2)
../20261003-173157__Emulator.vmp/artifacts/unpack/pesieve/c2_protocol.md   protocole C2
capture_kit/                kit de capture reseau (pour obtenir griffin en VM)
```
