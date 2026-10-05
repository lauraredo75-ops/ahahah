# Synthèse commentée — Immortal « Emulator » (loader + griffin)

Analyse RE complète d'un **cheat Valorant** (loader VMProtect + payload griffin), menée sur
le poste de l'utilisateur à partir de binaires qu'il possède. Deux composants :

| Composant | Fichier | État | Décompilable |
|---|---|---|---|
| **Loader / injecteur** | `Emulator.vmp.exe` = `Phase.exe` (sha `048be2ab…`) | **VMProtect** (virtualisé) | ❌ logique virtualisée ; comportement reconstruit via strings/dump |
| **Payload (le cheat)** | `griffin.dll` (sha `3af62b8e…`, 7,9 Mo) | MSVC 2026, **non protégé** | ✅ **4 698 fonctions décompilées** (`griffin/griffin_decompiled.c`) |

---

## 1. Chaîne d'exécution de bout en bout

```
Emulator.vmp.exe (loader, VMProtect)
 ├─ licence HWID (VMProtectActivateLicense / GetCurrentHWID) + device ECC P-256 (ImmortalAuthDeviceP256V3)
 ├─ C2 immortal-authentication.com : challenge → login → griffin-grant → pak-key → binary-fetch
 │     (réponses signées, enveloppe sig=128 o ; cf. loader/immortal_dbg.log)
 ├─ binary-fetch (8 119 552 o) → déchiffré (8 119 520 o) = griffin.dll, écrit dans %TEMP%\<aléa>.dll
 ├─ config/handshake scellé en MÉMOIRE PARTAGÉE (seal_into_shmem)
 └─ INJECTION : SetWinEventHook/SetWindowsHookEx sur le thread UI de VALORANT, pointant sur
      l'export de griffin  →  Windows charge griffin.dll DANS Valorant
         └─ griffin: hook proc → vg_handshake → CheatInit → menu/skins/chams
```

---

## 2. griffin.dll — carte fonctions ↔ features (adresses réelles)

> Noms `FUN_xxxx` = auto-nommés par Ghidra (le binaire n'a pas de symboles). Adresses = RVA base `0x180000000`.

### 2.1 Injection / point d'entrée injecté
- **`ngYm2pXk7rTv4wBc9qFj5hLs3aNe6uDi` @ `0x180134a00`** — **le hook proc exporté** (signature
  `(int, WPARAM, LPARAM)` + `CallNextHookEx`). C'est le code que Windows exécute **dans Valorant**.
  Au premier déclenchement :
  ```c
  FUN_180131a80("[STAGE 05] hook_proc: first fire, running vg_handshake::hook_first_fire_verify()");
  cVar2 = FUN_1800c25d0();                       // vg_handshake::hook_first_fire_verify()
  wsprintfA(..,"[STAGE 05.1] hook_first_fire_verify=%d");
  if (cVar2 == 0)  // "gate NEVER signaled; CheatInit will NEVER run"
  ```
  → **handshake anti-Vanguard** (`vg_handshake`) qui conditionne le lancement du cheat (`CheatInit`).
- `FUN_1800c25d0` = `vg_handshake::hook_first_fire_verify()` (vérif d'intégrité/contexte avant init).

### 2.2 Lecture de la config via mémoire partagée (lien loader→griffin)
- **`FUN_1800c1f70` @ `0x1800c1f70`** — `OpenFileMappingW` + `MapViewOfFile` : lit la section
  partagée créée par le loader (`seal_into_shmem`) = licence/session/config.
- **`FUN_1800c1140` @ `0x1800c1140`** — **déchiffrement AES-256-GCM** de cette config :
  ```c
  BCryptOpenAlgorithmProvider(&h,L"AES",..);
  BCryptSetProperty(h,L"ChainingMode",L"ChainingModeGCM",..);
  BCryptGenerateSymmetricKey(h,&key,..,param_1,0x20,..);   // clé 32 o
  // label/AAD : "VG_HANDSHAKE_V6"
  ```
  → la liaison loader↔griffin est protégée par **AES-GCM, contexte `VG_HANDSHAKE_V6`**.

### 2.3 C2 / réseau propre à griffin
- **`FUN_180115260`** (`InternetOpenUrlA`…) et **`FUN_180131120`** (`WinHttpSendRequest`) —
  griffin a son **propre canal HTTP(S)** (en plus du loader) : télémétrie / relais
  `immortal-emulator.com/emu_relay.php`.

### 2.4 Moteur SKIN-CHANGER (~92 fonctions)
- Bloc `FUN_1800035d0, 180003e30, 1800169e0, 18006d130…` — résolution/échange d'assets Unreal :
  `/Game/Equippables/Guns/Rifles/AK/Afterglow/...PrimaryAsset_C`, chromas, **buddies**
  (`buddyTransform`), **couteaux** (`Knife Transform`), viseurs (`Sight Transform`).
  Applique les skins sélectionnés (`##cskin_*`, `menu_config.cfg`, `loader\…\customskins\*.png`).

### 2.5 CHAMS / ESP visuel (~61 fonctions)
- **`FUN_1800dfdf0` / `FUN_1800dfea0` / `FUN_18012e3f0`** — logique « chams » :
  commentaire décompilé *« enemy family bit (modes 3/5) … bit 3 marks a VISIBLE pixel of a mode-3
  mesh »* → coloration/visibilité des ennemis (mesh des agents `/Game/Characters/.../TP_*_Skelmesh`),
  y compris à travers les murs.

### 2.6 Overlay Direct3D 11 + menu ImGui (~22 fonctions)
- **`FUN_180130c70` @ `0x180130c70`** — crée la fenêtre (`WNDCLASSEXW`) + `D3D11CreateDeviceAndSwapChain`
  = **overlay** de rendu.
- `FUN_1801c9920, 1801ce530, 1801d3480…` — **menu ImGui** (`##apollomenu`, `##MainMenuBar`,
  toggles `##skin_toggle`, `##cskin_*`). C'est l'UI du cheat.

### 2.7 Accès monde / entités (offsets Unreal)
- **`FUN_180027820, 180131d70, 180132a70`** (`LocalPlayer`), `GetActor`, `UWorld` — accès aux
  objets du jeu (GObjects/acteurs) via offsets UE pour piloter skins/chams.

---

## 3. Côté loader (rappel, car virtualisé)
Logique virtualisée VMProtect → non décompilable, mais comportement établi via dump mémoire :
licence HWID + P-256, protocole C2 `immortal-auth-v4` (`loader/c2_protocol.md`), clé RSA
embarquée (`loader/embedded_private_key.pem`), watchdog anti-RE `[tick] KILLING dbg/frida/…`,
anti-forensique `DeleteFile`. Le seul PE implanté côté loader = `VMProtectSDK64.dll`
(`loader/VMProtectSDK_decompiled.c`) — runtime de licence, pas le cheat.

## 4. Chiffres
griffin : **4 698 fonctions** ; ~92 skin-changer, ~61 chams/ESP, ~22 overlay/ImGui, +
réseau/crypto/hook. Non obfusqué, non virtualisé → entièrement analysable.

## 5. Honnêteté / limites
- ✅ griffin : logique **lisible** (pseudo-C), features identifiées et localisées.
- ⚠️ Noms d'origine (variables/fonctions) **perdus** : Ghidra nomme `FUN_xxx` ; la structure de
  classes C++ se récupère via RTTI/offsets UE (voir `TOOLS_ROADMAP.md`).
- ❌ loader : cœur **virtualisé** VMProtect — non récupérable en code.
- ❌ « Source d'origine recompilable » : **impossible** depuis un binaire (voir roadmap) — on
  obtient du pseudo-C et une *réimplémentation* possible, pas le source exact.
```
```
