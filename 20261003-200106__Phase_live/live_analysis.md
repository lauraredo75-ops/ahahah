# Analyse mémoire LIVE — Phase.exe (= Emulator.vmp.exe)

> Récupération **100% passive** : lecture de la mémoire d'un process que l'utilisateur avait
> déjà lancé. Aucune ré-exécution, aucun contact C2, aucune utilisation de la license key,
> aucun accès à VALORANT.

## Identité
- `C:\Users\Jtegraille\Downloads\Phase.exe`, **SHA-256 identique** à `Emulator.vmp.exe`
  (`048BE2AB…B475F`) → **même binaire renommé**, en cours d'exécution (PID 4872).
- VALORANT, RiotClientServices, VALORANT-Win64-Shipping tournaient en parallèle (cible présente).
- Connexions live du loader : infra **Cloudflare** (443 + **8443**) + IP **`186.241.26.203`** (Brésil).

## Extrait de la mémoire (pe-sieve, workingset)
- **1 seul PE implanté** : `VMProtectSDK64.dll` (120 Ko, MSVC 2015) — le **runtime de licence
  VMProtect** (exports `VMProtectActivateLicense`, `VMProtectGetCurrentHWID`,
  `VMProtectDecryptStringA/W`, `VMProtectIsDebuggerPresent`, `VMProtectGetSerialNumberState`…).
  → Licence **liée au matériel (HWID)**. Décompilé : `artifacts/decompiled_payload.c` (383 fct).
- **118 717 chaînes** déchiffrées en mémoire, confirmant :
  - `[Login] server said ok, parsing session credentials` → **authentification réussie**
  - `{"session_token":"…"` → **jeton de session live présent en mémoire**
  - Fonctionnalité **password-gated** (`DoPasswordDialog`, « Set the password EXACTLY… to unlock »)
  - C2 `immortal-authentication.com`, anti-analyse `[tick] KILLING …`

## Où est le vrai cheat (« griffin ») ?
Pas dans le loader. La chaîne `launch_private → seal_into_shmem → SetWinEventHook(val_pid)`
montre qu'il est **injecté dans le process VALORANT** (ou passé en mémoire partagée). pe-sieve
n'a trouvé qu'un PE implanté (le SDK VMProtect), donc le payload n'est pas conservé comme module
mappé dans Phase.exe.

**Je n'extrais PAS le payload depuis VALORANT** : le process est protégé par **Vanguard**
(anti-cheat noyau). Y accéder (lecture mémoire/dump) risque un **bannissement du compte** et
serait vraisemblablement bloqué. Pour obtenir « griffin » proprement : **capture réseau**
(`binary-fetch`/`pak-key`) en **VM isolée** (kit `capture_kit/`), hors Vanguard.

## ⚠️ Recommandations de sécurité (tu as exécuté ce loader sur ta machine principale)
Les loaders de triche embarquent très souvent des infostealers ; par prudence, considère une
compromission possible et, depuis **un autre appareil sain** :
1. **Discord** : déconnecte toutes les sessions + change le mot de passe (token potentiellement volé).
2. **Navigateurs (Chrome…)** : change les mots de passe importants, invalide les sessions,
   purge cookies ; active la 2FA partout.
3. **Comptes sensibles** (email, banque, crypto/wallets) : rotation des identifiants + 2FA.
4. Scanne la machine (Defender à jour / Malwarebytes) ; surveille `186.241.26.203` et
   `immortal-authentication.com` (bloque-les au pare-feu/DNS).
5. Le loader a un **watchdog anti-RE** et fait du **nettoyage anti-forensique** (`DeleteFile`) :
   une image disque propre (réinstallation) est l'option la plus sûre si le poste est sensible.

## Artefacts
```
Phase.exe                              copie disque (même sha256 qu'Emulator.vmp.exe)
artifacts/pesieve/process_4872/        dump mémoire live (modules + VMProtectSDK64.dll)
artifacts/pesieve/phase_mem_strings.txt  118 717 chaînes déchiffrées
artifacts/decompiled_payload.c         VMProtectSDK64.dll décompilé (383 fct)
```
