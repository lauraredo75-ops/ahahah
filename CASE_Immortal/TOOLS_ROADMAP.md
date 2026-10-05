# Roadmap — pousser plus loin (recompiler / source / exécuter séparément)

## La vérité sur l'objectif ultime
**On ne récupère PAS le code source d'origine recompilable depuis un binaire.** Un compilateur
détruit l'information (noms, types, templates, macros, commentaires). Un décompilateur reconstruit
du **pseudo-C/C++ lisible**, pas un projet buildable à l'identique. Objectif réaliste par composant :

| Composant | Atteignable | Pas atteignable |
|---|---|---|
| **griffin.dll** (non protégé) | pseudo-C lisible (fait) → **labellisé** (RTTI/SDK) → **réimplémentation** compilable à la main | source exact d'origine |
| **loader** (VMProtect) | comportement + protocole + strings (fait) | code des fonctions **virtualisées** |
| **skins** (`.pak/.utoc`) | **extraction des assets** (textures/modèles) via outils UE | — |

Donc « tout recompiler » = (1) pour griffin : produire une **réimplémentation** à partir du
pseudo-C labellisé (faisable, du travail manuel) ; (2) pour le loader : hors de portée (virtualisé).

## Ce qui manque et qu'il faut AJOUTER à la toolchain

### Priorité 1 — gratuit, gros gain, sans rien installer (déjà dans Ghidra)
- **Ghidra FunctionID / FidDb** : identifie les fonctions de bibliothèque (ImGui, nlohmann::json,
  CRT MSVC) → sur 4 698 fonctions, isole les **~200 propres au cheat**. Analyzer intégré.
- **RecoverClassesFromRTTIScript** (script Ghidra intégré) : MSVC conserve le **RTTI** →
  reconstruit les **classes C++** et leurs vtables (noms de classes, hiérarchie). Énorme pour
  la structure « source ».
➡️ Action concrète : relancer griffin dans Ghidra avec FunctionID activé + ce script → un
   décompilé **labellisé** (classes nommées, libs écartées).

### Priorité 2 — outils à installer
| Outil | Rôle | Install |
|---|---|---|
| **Cutter** (réverse Ghidra, GUI libre) | navigation/renommage interactif du décompilé | zip portable / `scoop install cutter` |
| **IDA Free 9** | navigation de référence (pas de décompileur en Free, mais graphe/xrefs top) | téléchargement Hex-Rays |
| **BinDiff** (libre) + **Ghidra BinExport** | **diff** entre versions du cheat (suivi des mises à jour) | releases Google/zynamics |
| **FModel / CUE4Parse** (.NET) | ouvrir les **`.pak`/`.utoc`** → extraire les **skins** (textures, modèles) | release FModel (dotnet présent) |
| **frida** (+ frida-tools) | instrumentation **dynamique** de griffin (en VM) : tracer les appels, dumper la config déchiffrée | `pip install frida-tools` dans le venv |
| **Dumper-7 / UE SDK dumper** | générer le **SDK Unreal de Valorant** → nommer les **offsets** (UWorld, APawn…) que griffin utilise | source à compiler ; **en VM/recherche** (Vanguard) |

### Rappels des manques déjà connus
- **pycdc** (Python 3.10+ décompilation) : nécessite le **Windows 10 SDK** (cf. `knowledge/lessons.md`).
- **retdec** : pas de build Windows ; Ghidra couvre.

## « Exécuter / analyser séparément » griffin
griffin **ne tournera pas seul** de façon utile : il attend les internes de Valorant (offsets UE
lus via la mémoire partagée du loader) et le handshake `vg_handshake`. Options réalistes **en VM** :
1. **Harnais** : un petit loader qui `LoadLibrary(griffin.dll)` + fournit une fausse section
   partagée, pour atteindre et tracer `CheatInit`/le menu sans Valorant.
2. **frida** : hook des fonctions clés (`FUN_1800c1140` déchiffrement, `FUN_1800c1f70` config,
   le hook proc) pour capturer entrées/sorties réelles.
3. Analyse **statique par fonction** (déjà possible) : c'est le plus sûr et suffisant pour la logique.

## Prochaines actions que je peux faire tout de suite
- [A] **Relancer Ghidra sur griffin avec FunctionID + RecoverClassesFromRTTI** → décompilé
  **labellisé** (classes C++ nommées, libs écartées). *Recommandé — plus gros gain immédiat.*
- [B] **Squelette de réimplémentation** de griffin : headers + stubs des ~200 fonctions cheat,
  regroupés par module (skins / chams / overlay / net / crypto), prêt à compléter → compilable.
- [C] **Installer FModel** et extraire les **skins** des `.pak/.utoc`.
- [D] Ajouter **Cutter + BinDiff + frida** au `install.ps1` (nouveaux outils de la toolchain).
```
