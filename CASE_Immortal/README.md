# CASE_Immortal — dossier consolidé

Analyse complète du cheat Valorant **Immortal « Emulator »** (loader VMProtect + payload griffin).

## À lire en premier
- **`00_SYNTHESIS.md`** — synthèse commentée : fonctions ↔ features (adresses réelles), flux complet.
- **`TOOLS_ROADMAP.md`** — pousser plus loin (recompile/source/exécution), outils à ajouter.

## Arborescence
```
00_SYNTHESIS.md           synthèse commentée (griffin décompilé + flux)
TOOLS_ROADMAP.md          étapes & outils pour aller plus loin
griffin/                  LE PAYLOAD (le vrai cheat)
  griffin.dll             binaire récupéré (7,9 Mo, sha 3af62b8e…) — non virtualisé
  griffin_decompiled.c    décompilation Ghidra — 4 698 fonctions
  griffin_strings.txt     strings (assets, menu, features)
  immortal_dbg.log        log runtime du loader (preuve de la chaîne C2)
  report.md               rapport griffin + injecteur
  capa.json / floss.json  (capacités — à regénérer si vide)
loader/                   LE LOADER / INJECTEUR (Emulator.vmp.exe, VMProtect)
  loader_report.md        rapport principal du loader
  c2_protocol.md          protocole C2 immortal-auth-v4 reconstruit
  dump_iocs.md            IOCs (C2, endpoints, relais)
  embedded_private_key.pem clé RSA embarquée extraite
  VMProtectSDK_decompiled.c  SDK licence VMProtect décompilé
  live_analysis.md / host_memory_findings.md / griffin_localisation.md
  00_triage.json … synthesis.json  findings normalisés
samples/
  inventory.txt           SHA-256 des binaires liés (loader, CG_Loader, IObitUnlocker.sys…)
capture_kit/              kit de capture C2 en VM (si besoin du binaire via réseau)
```

## Résumé en 3 lignes
Skin-changer + chams/ESP Valorant, chargé par un loader **VMProtect** (licence HWID, C2
`immortal-authentication.com`, injection par hook dans Valorant). Le cheat lui-même
(`griffin.dll`) est **non protégé et entièrement décompilé**. Le loader reste virtualisé.
IOCs & recommandations défensives dans `loader/`.
