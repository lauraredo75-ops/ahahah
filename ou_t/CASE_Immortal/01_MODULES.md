# Décomposition en modules de griffin (A — clustering graphe d'appels)

Obtenu en construisant le **graphe d'appels** depuis `griffin_decompiled.c` (6 630 fonctions au
total) et en expandant depuis les fonctions-pivots de chaque feature, en ignorant les **hubs**
très partagés (runtime/ImGui/CRT). Détail machine : `griffin/module_map.json`.

| Module | Fonctions (cluster) | Pivots |
|---|---|---|
| **Injection** | 9 | `180134a00` (hook proc exporté), `1800c25d0` (vg_handshake) |
| **Config/Crypto** | 12 | `1800c1f70` (shmem), `1800c1140` (AES-256-GCM `VG_HANDSHAKE_V6`) |
| **Net/C2** | 10 | `180115260` (InternetOpenUrl), `180131120` (WinHttpSendRequest) |
| **Overlay/Menu** | 59 | `180130c70` (D3D11 + WNDCLASS) |
| **Chams/ESP** | 184 | `1800dfdf0/1800dfea0/18012e3f0` (VISIBLE pixel / mesh) |
| **World/Entities** | 67 | `180027820/180131d70/180132a70` (LocalPlayer/UWorld) |

**Hubs (à ignorer = bibliothèque/runtime)** : `FUN_1802862f0` (appelé 798×), `FUN_1800125b0`
(416×), `FUN_1801d5860` (375×)… = allocateur/ImGui/CRT, non spécifiques au cheat.

## Classes C++ (RTTI) — résultat honnête
Scan RTTI du binaire : **36 type-descriptors, 0 classe applicative** (tous std/lib). → griffin est
compilé **sans RTTI pour son propre code** (`/GR-`, fréquent sur les cheats). La reconstruction de
classes nommées via RTTI est donc **impossible** ici ; la structure vient du **clustering** ci-dessus
et des **offsets Unreal** (voir roadmap : un dump SDK de Valorant nommerait les accès `UWorld`/`APawn`).

## Squelette de réimplémentation (B)
`griffin_reimpl/` : scaffold C++ par module, chaque stub pointant vers son adresse Ghidra
(`// TODO @ <addr>`), pivots annotés. Base **navigable** pour remplir la logique depuis le
décompilé, module par module (commencer par Config/Crypto, le plus compact).

## Skins (C) — récupérés
`loader\…\InternalMenu\` : **13 skins custom** (vandal_1..5, phantom_3/4, operator_1/2, guardian_1,
bandit_1, melee_1/2 en PNG), **431 icônes** (UUID Valorant), et **`skin_selections.cfg`** =
mapping `slot = skinUUID|chromaUUID|-1`. Les skins sont déjà en PNG (pas besoin d'extraire des
`.pak`). FModel ne servirait qu'à explorer les paks *de Valorant* (clé AES du jeu requise).

## Outils ajoutés (D)
- **frida-tools** installé (venv D:, v14.11) → instrumentation dynamique **en VM**.
- **Cutter** : non trouvé dans scoop par défaut → `scoop bucket add extras; scoop install cutter`
  (ou release portable GitHub). **BinDiff + Ghidra BinExport** : à ajouter pour le diff de versions.
