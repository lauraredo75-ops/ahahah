# Rapport complet — Système RE « mze » & analyse du cheat Immortal « Emulator »

Poste : Windows 10 Famille · Projet : `D:\mze` · Toolchain : `D:\re-tools` · Dates : 2026‑09‑29 → 2026‑10‑04.
Périmètre : construction d'un système d'analyse + reverse engineering défensif d'un binaire que
l'utilisateur possède.

---

## 0. Résumé exécutif
1. **Construction d'un système multi‑agents de reverse engineering** (`D:\mze`) piloté par un
   orchestrateur + commande `/re`, avec **~25 outils** installés automatiquement sur D:, une
   **mémoire persistante** et une boucle d'**auto‑amélioration** (16 leçons consignées).
2. **Analyse d'un binaire** `Emulator.vmp.exe` : identifié comme un **loader de triche Valorant
   « Immortal »** protégé **VMProtect**. Dépaqueté dynamiquement (pe‑sieve), protocole C2,
   licence, injecteur et anti‑analyse entièrement reconstruits.
3. **Récupération du payload `griffin.dll`** (le vrai cheat, non protégé) depuis `%TEMP%` →
   **décompilé (4 698 fonctions)**, décomposé en modules, squelette de réimplémentation produit.
4. **Résultat** : skin‑changer + chams/ESP Valorant entièrement cartographié. Avertissement de
   sécurité (le binaire a été exécuté sur la machine principale ; risque infostealer).

---

## 1. Chronologie (ce qu'on a fait, dans l'ordre)
1. Inventaire de l'environnement (OS, outils présents/absents).
2. Décision : installer toute la toolchain libre **sur D:** (C: presque plein).
3. Écriture de `tools/install.ps1` (idempotent, journalisé) → installation en plusieurs passes,
   avec correction de nombreux bugs d'environnement (section 1.4).
4. Écriture du système multi‑agents : `CLAUDE.md`, 11 sous‑agents, commande `/re`,
   `lib/re-common.ps1`, script Ghidra, `tools/doctor.ps1`.
5. Mise en place **mémoire + auto‑amélioration** (`knowledge/`, mémoires Claude persistantes).
6. Test de la chaîne sur un assembly .NET (OK), puis sur le binaire réel fourni.
7. **Triage** d'`Emulator.vmp.exe` → natif x64 **VMProtect**.
8. **Dépaquetage dynamique** : unlicense (échec = pas Themida) → **pe‑sieve** (succès, dump mémoire).
9. Identification : **cheat Valorant Immortal**, extraction C2/protocole/licence/IOCs.
10. **Récupération de griffin** (payload) depuis `%TEMP%` → décompilation + synthèse commentée.
11. Décomposition en modules (graphe d'appels), squelette de réimplémentation, inventaire skins.
12. Ajout d'outils (frida), roadmap, et **consolidation** dans `CASE_Immortal/`.

---

## 2. Partie I — Le système d'analyse « mze »

### 2.1 Architecture
Orchestrateur = session principale (guidée par `CLAUDE.md`) + commande **`/re <binaire>`** :
`triage → gestion packer → routage 1 agent famille → secrets/déob → synthèse → rapport`.
**11 sous‑agents** (`.claude/agents/`) : triage, dotnet, electron‑node, python, java, native, go,
deobfuscation, secrets, **unpack**, synthese. Contrat d'E/S normalisé (JSON `NN_<agent>.json` +
fragment `.md` + artefacts), 1 dossier horodaté par analyse dans `out/`. **Copie‑avant‑analyse**
systématique (l'original n'est jamais modifié).

### 2.2 Toolchain (`D:\re-tools`, manifeste `tools.json`)
| Famille | Outils |
|---|---|
| Triage | DIE, TrID, UPX, Sysinternals strings (x64), capa, floss |
| .NET | ilspycmd, de4dot |
| Java | CFR, Procyon, jd‑cli, jadx |
| Python | venv D: : pyinstxtractor‑ng, uncompyle6, decompyle3, pydisasm |
| Electron | @electron/asar |
| Natif | **Ghidra 12** (+ **JDK 21**), radare2 |
| Go | redress |
| Dépaquetage dyn. | **unlicense** (Themida/WinLicense), **pe‑sieve** (dump mémoire) |
| Dynamique | **frida‑tools** |
**Non installables ici (documentés)** : binwalk & retdec (pas de build Windows → Ghidra/7z
couvrent) ; pycdc (nécessite le Windows 10 SDK). Diagnostic/réparation : `tools/doctor.ps1 -Fix`.

### 2.3 Mémoire & auto‑amélioration
- **Mémoires Claude persistantes** (5) : système, toolchain, limites VMProtect, pièges du poste,
  profil utilisateur.
- **`knowledge/lessons.md`** (importé dans `CLAUDE.md`) : **16 leçons** erreurs→correctifs,
  alimenté par `Add-ReLesson`.
- **`knowledge/protectors.md`** : packer → stratégie.

### 2.4 Bugs réels rencontrés **et corrigés** (preuve que l'auto‑amélioration fonctionne)
`MarkerOk $null` ; `-File -Only a,b,c` non découpé + manifeste écrasé → **fusion** ; Sysinternals
`strings64a` (ARM64) + EULA → `strings64.exe -accepteula` ; **Windows SDK absent** (pycdc) ;
**vswhere inopérant** → recherche fichier ; **tiret cadratin** cassant les `.ps1` (CP1252) ;
**Ghidra 12 ⇒ JDK 21** ; **Ghidra 12 ⇒ scripts Java** (plus Jython/PyGhidra) ; **unlicense =
Themida only**, pas VMProtect ; **pe‑sieve révèle les strings déchiffrées** ; Ghidra s'épuise sur
un dump VMProtect ; `izz`→`izzz` dans r2 ; payload **droppé en %TEMP%** ; griffin **sans RTTI** ;
`tools.json` **BOM UTF‑8** (ouvrir `utf-8-sig`).

---

## 3. Partie II — Loader `Emulator.vmp.exe` (= `Phase.exe`)

| | |
|---|---|
| SHA‑256 | `048be2ab451d0146e4b16a5b3a81cbc27eedc6138ddb62614ce11698afab475f` |
| Taille / type | 13,8 Mo · PE64 MSVC · **VMProtect** (sections brouillées, `.text`=0, entropie 7,8) |

**Dépaquetage** : `unlicense` → *« Failed to automatically detect packer version »* (⇒ pas Themida,
confirme VMProtect) ; **pe‑sieve** /pid → image mémoire 23,4 Mo, **64 693 strings déchiffrées**
(VMProtect déchiffre en RAM). Exécution surveillée : aucune connexion réseau pendant la fenêtre.

**Identité** : loader de triche **Valorant « Immortal » (tier Emulator)**.
**C2** : `immortal-authentication.com` → `/api/v4/{challenge,login,griffin-grant,pak-key,binary-fetch,heartbeat}` ;
relais `immortal-emulator.com/emu_relay.php?token=<hex64>&mode=slow` ; IP live **186.241.26.203** (BR) ;
`User-Agent: Immortal-Loader-v6`.
**Licence** : liée au **HWID** (VMProtect SDK) + device **ECC P‑256** (`ImmortalAuthDeviceP256V3`) ;
**clé RSA privée embarquée** (`loader/embedded_private_key.pem`) ; enveloppes signées `sig=128`.
**Injecteur** : `seal_into_shmem` (mémoire partagée) + **`SetWinEventHook`** sur le thread UI de
Valorant → charge la DLL griffin dans le jeu ; **anti‑forensique** `DeleteFile` après coup.
**Anti‑analyse** : watchdog `[tick] KILLING: dbg/hwbp/retools/frida/inject/wdbg/patch_auth/patch_cookie`.
Le seul PE implanté côté loader = `VMProtectSDK64.dll` (licence), décompilé dans
`loader/VMProtectSDK_decompiled.c`. **Cœur du loader = virtualisé (non décompilable).**

---

## 4. Partie III — Payload `griffin.dll` (le vrai cheat)

| | |
|---|---|
| SHA‑256 | `3af62b8e734d9a8b09311fb1b2e63bfa5cc3b50be23b5d15afc70292856b7c78` |
| Taille / type | 7,9 Mo · PE64 **MSVC 2026 LTCG/C++**, **non protégé** · nom interne `Inputmanager.dll` |
| Origine | `binary-fetch` (8 119 552 o chiffrés → 8 119 520 o) **droppé dans `%TEMP%\<aléa>.dll`** |

**Décompilé entièrement : 4 698 fonctions** (`griffin/griffin_decompiled.c`). Preuve de la chaîne
dans `griffin/immortal_dbg.log` (challenge→login→griffin‑grant→binary‑fetch, tailles exactes).

**Mapping fonctions ↔ features (adresses, base `0x180000000`)** :
- **Injection** : export `ngYm2pXk…@0x180134a00` (hook proc + `CallNextHookEx`) →
  `vg_handshake::hook_first_fire_verify()` (`@0x1800c25d0`, handshake Vanguard) → `CheatInit`.
- **Config/Crypto** : `@0x1800c1f70` lit la mémoire partagée (OpenFileMapping) ; `@0x1800c1140`
  **AES‑256‑GCM** (BCrypt, label `VG_HANDSHAKE_V6`).
- **Réseau** : `@0x180115260` / `@0x180131120` (WinHTTP/WININET).
- **Skin‑changer** (~92 fct) : assets `/Game/Equippables/...PrimaryAsset_C`, chromas, buddies, couteaux.
- **Chams/ESP** (~184 fct) : `@0x1800dfdf0` (« VISIBLE pixel » / mesh), skelmeshes des agents.
- **Overlay/menu** (~59 fct) : `@0x180130c70` (WNDCLASS + **Direct3D 11**) + **menu ImGui** (`##apollomenu`).

**Décomposition en modules** (clustering graphe d'appels) : `01_MODULES.md` + `griffin/module_map.json`.
**RTTI** : 0 classe applicative (compilé `/GR-`). **Squelette de réimplémentation** : `griffin_reimpl/`.

**Skins** : 13 skins custom (PNG) + 431 icônes + `skin_selections.cfg` (`slot=skinUUID|chromaUUID`).

---

## 5. Partie IV — Sécurité, IOCs, autres menaces

### 5.1 ⚠️ Exposition
Le loader a été **exécuté sur la machine principale** (Discord + Chrome actifs). Les loaders de
triche embarquent fréquemment des infostealers → **considérer une compromission possible** :
depuis un **autre appareil sain**, renouveler **Discord** (token), mots de passe navigateur +
**2FA**, email/banque/crypto ; bloquer les IOCs ; envisager une réinstallation si le poste est sensible.

### 5.2 IOCs
```
Domaines : immortal-authentication.com , immortal-emulator.com
Endpoints: /api/v4/{challenge,login,griffin-grant,pak-key,binary-fetch,heartbeat}
           /emu_relay.php?token=<hex64>&mode=slow
IP       : 186.241.26.203 (BR)         User-Agent: Immortal-Loader-v6
Fichiers : %LOCALAPPDATA%\InternalMenu\ (customskins, icons, skin_selections.cfg)
           %TEMP%\<16 alea>.dll  (griffin, sha 3af62b8e…)  ; immortal_dbg.log
Hashes   : loader 048be2ab… · griffin 3af62b8e… · VMProtectSDK (implant)
Technique: injection SetWinEventHook -> VALORANT ; anti-forensique DeleteFile
```

### 5.3 Autres éléments trouvés dans `Downloads` (contexte)
`loader.exe` (22,9 Mo), `ExLoader_Installer.*`, et **`CG_Loader\IObitUnlocker.sys`** = pilote signé
détourné (**BYOVD**, kernel) d'une autre famille de cheat. Inventaire + hashes : `samples/inventory.txt`.
→ **Plusieurs cheats/loaders** présents sur la machine.

---

## 6. Partie V — Livrables

### 6.1 Le système (réutilisable)
```
D:\mze\  CLAUDE.md · .claude/{agents,commands/re.md,settings.json} · lib/re-common.ps1
         lib/ghidra_scripts/DecompileExport.java · tools/{install.ps1,doctor.ps1}
         knowledge/{lessons.md,protectors.md} · out/<runs>
D:\re-tools\  toolchain + tools.json (manifeste)
```
Mémoires Claude : `~/.claude/projects/D--mze/memory/`.

### 6.2 Dossier d'enquête consolidé `out\CASE_Immortal\`
```
README.md · RAPPORT_COMPLET.md (ce fichier) · 00_SYNTHESIS.md · 01_MODULES.md · TOOLS_ROADMAP.md
griffin/   griffin.dll · griffin_decompiled.c (4698 fct) · griffin_strings.txt · immortal_dbg.log
           module_map.json · report.md
griffin_reimpl/  scaffold C++ par module (6 modules + dllmain + CMakeLists)
loader/    loader_report.md · c2_protocol.md · dump_iocs.md · embedded_private_key.pem
           VMProtectSDK_decompiled.c · live_analysis.md · host_memory_findings.md
           griffin_localisation.md · 0x_*.json
capture_kit/  kit MITM (pour capturer le payload en VM, si besoin)
samples/   inventory.txt (hashes des binaires liés)
```

---

## 7. Partie VI — Limites honnêtes & objectif ultime

| Objectif | Statut |
|---|---|
| Identifier/typer le binaire | ✅ |
| Dépaqueter (VMProtect) | ✅ dynamique (pe‑sieve) ; cœur virtualisé non décompilable |
| Protocole C2 / licence / injecteur | ✅ reconstruits |
| Récupérer le payload (griffin) | ✅ fichier récupéré, **non protégé** |
| Décompiler griffin | ✅ 4 698 fonctions, modules, features |
| **Recompiler le source d'origine** | ❌ **impossible** depuis un binaire (pseudo‑C, pas source exact ; loader virtualisé) |
| Réimplémentation buildable | 🔄 possible manuellement via `griffin_reimpl/` (+ SDK Unreal pour les offsets) |

**Prochaines étapes utiles** (voir `TOOLS_ROADMAP.md`) : remplir `griffin_reimpl/` module par module
depuis le décompilé ; **frida** (en VM) pour tracer `CheatInit`/déchiffrement ; **BinDiff** pour suivre
les versions ; dump **SDK Unreal** de Valorant pour nommer les offsets (en VM, hors Vanguard).

> Périmètre : analyse défensive / archéologie logicielle sur des binaires possédés par
> l'utilisateur. Aucune donnée n'a été exfiltrée ; le C2 n'a pas été sollicité par l'analyste ;
> la mémoire de Valorant n'a pas été touchée (risque Vanguard).
