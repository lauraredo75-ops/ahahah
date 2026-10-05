# griffin_reimpl — squelette de réimplémentation (scaffold d'analyse)

⚠️ **Ce n'est PAS le code source d'origine** (irrécupérable depuis un binaire) ni du code
fonctionnel. C'est un **squelette d'analyse** : la structure de `griffin.dll` reconstruite par
RE, en modules, où **chaque stub pointe vers l'adresse Ghidra** à compléter depuis
`../griffin/griffin_decompiled.c`.

But : offrir une base **compilable** et **navigable** pour, module par module, remplir les
fonctions à partir du pseudo-C, jusqu'à une réimplémentation (travail manuel).

## Modules (clustering par graphe d'appels — voir `../griffin/module_map.json`)
| Module | Fichier | Fonctions (cluster) | Rôle |
|---|---|---|---|
| Injection | `modules/injection.hpp` | ~9 | hook proc exporté, handshake Vanguard, CheatInit |
| Config/Crypto | `modules/config_crypto.hpp` | ~12 | lecture mémoire partagée + AES-256-GCM (`VG_HANDSHAKE_V6`) |
| Net/C2 | `modules/net_c2.hpp` | ~10 | HTTP(S) WinHTTP/WININET vers le C2/relais |
| Overlay/Menu | `modules/overlay_menu.hpp` | ~59 | fenêtre + D3D11 + menu ImGui |
| Chams/ESP | `modules/chams_esp.hpp` | ~184 | visibilité/chams des ennemis (mesh) |
| World/Entities | `modules/world.hpp` | ~67 | accès objets Unreal (UWorld, LocalPlayer, offsets) |

Les **hubs** très appelés (`FUN_1802862f0` in-deg 798, etc.) = runtime/ImGui/CRT → **non
réimplémentés** (bibliothèques).

## Build
`cmake -B build && cmake --build build` compile les stubs. ⚠️ Sur ce poste le **link DLL échoue**
sans le **Windows 10 SDK** (rc.exe/mt.exe absents — cf. `../../../knowledge/lessons.md`) ; installer
le SDK via le VS Installer pour linker. La compilation en objets valide déjà la structure. Remplir
ensuite chaque `// TODO @ <addr>` depuis le décompilé.

## Workflow conseillé
1. Ouvrir `griffin_decompiled.c` à l'adresse indiquée dans le stub.
2. Traduire le pseudo-C en C++ lisible dans le stub (renommer variables, types).
3. Itérer module par module (commencer par Config/Crypto — le plus petit/clair).
