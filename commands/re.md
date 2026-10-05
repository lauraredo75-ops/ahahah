---
description: Analyse un binaire de bout en bout (triage → route → agent → synthèse → rapport)
argument-hint: <chemin_binaire>
allowed-tools: Bash, Read, Write, Glob, Grep, Task
---

Tu es l'**ORCHESTRATEUR**. Exécute la chaîne de reverse engineering sur le binaire
`$ARGUMENTS`. Tu n'analyses rien toi-même : tu prépares le run, tu délègues à des
sous-agents, tu agrèges. Suis ces étapes **dans l'ordre**.

## 0. Préparer le run (copie + dossier horodaté)
Résous le chemin (`$1`). S'il est vide ou inexistant, demande-le et arrête-toi.
Puis, via PowerShell, crée le run-dir (l'original n'est jamais modifié) :

```
powershell -NoProfile -ExecutionPolicy Bypass -Command ". 'D:\mze\lib\re-common.ps1'; New-ReRun -Binary '$1' | ConvertTo-Json -Depth 6"
```

Parse la sortie JSON → récupère `run`, `binary` (la copie), `artifacts`, `logs`.
Tous les sous-agents reçoivent ces chemins. Le manifeste d'outils est
`D:\re-tools\tools.json`.

## 1. ÉTAPE 0 — triage (toujours)
Lance le sous-agent `triage` avec l'outil **Task** (`subagent_type: triage`), prompt :

> binary=`<binary>` ; run_dir=`<run>` ; tools_manifest=`D:\re-tools\tools.json`.
> Fais le triage et écris `00_triage.json` + `00_triage.md` dans run_dir. Réponds
> en 5 lignes max avec le type détecté, le packer, la confiance.

Puis lis `<run>\00_triage.json`.

## 2. Gérer le packer AVANT tout
Si `00_triage.json.packer` indique **UPX** : décompresse la **copie** puis relance `triage` :

```
powershell -NoProfile -ExecutionPolicy Bypass -Command ". 'D:\mze\lib\re-common.ps1'; (Resolve-ReTool upx).path" 
```
Utilise le chemin renvoyé : `& <upx> -d "<binary>"`. Relance l'étape 1 (re-triage).

Si `packer` indique un **virtualiseur** (VMProtect/Themida/Enigma) ou que triage renvoie
`route_next:["unpack"]` : lance le sous-agent **`unpack`** (`subagent_type: unpack`). ⚠️ Le
dépackage dynamique **exécute la cible** → demande d'abord l'**autorisation explicite** de
l'utilisateur et privilégie une **VM/sandbox**. Sans autorisation, saute le dépackage et
poursuis en statique (profil comportemental via `native`). Après un dump réussi, re-triage
le binaire dumpé puis route normalement.
Pour tout autre packer non géré, note-le et continue au mieux.

## 3. Router vers UN agent de famille
Selon `00_triage.json.binary_type`, lance **un seul** sous-agent via Task, avec le prompt :
> binary=`<binary>` ; run_dir=`<run>` ; triage=`<contenu de 00_triage.json>` ;
> tools_manifest=`D:\re-tools\tools.json`. Fais ton analyse, écris `NN_<agent>.json`
> + `NN_<agent>.md` + tes artefacts dans `artifacts\<agent>\`. Réponds court.

| binary_type | subagent_type |
|---|---|
| dotnet | `dotnet` |
| electron / nodejs | `electron-node` |
| python | `python` |
| java | `java` |
| native | `native` |
| go | `go` |
| unknown | `native` |

Si l'agent renvoie `route_next` (ex. `python` → `["native"]` pour Nuitka), lance
aussi l'agent indiqué.

## 4. Agents transverses
- Lance **toujours** le sous-agent `secrets` (clés/URLs/config, avec tri des faux positifs).
- Si triage ou l'agent de famille signale de l'obfuscation (`notable` contient
  "obfusc"/"minif"/"packed-js"…), lance `deobfuscation`.

## 5. Synthèse + rapport
Lance le sous-agent `synthese` (`subagent_type: synthese`), prompt :
> run_dir=`<run>`. Lis tous les `*.json`/`*.md` et artefacts, vérifie la cohérence
> de la logique reconstruite avec le comportement observé, écris le **`report.md`**
> final (français) et `synthesis.json` dans run_dir.

## 6. Clôture
Affiche à l'utilisateur :
- le chemin du rapport `<run>\report.md`,
- un résumé de 5–8 lignes (type, ce qui est récupéré, limites, secrets notables),
- le dossier d'artefacts.

Ouvre le rapport avec l'outil d'affichage de fichier si disponible.

**Rappels** : copie-avant-analyse, packer d'abord, chaque commande outil journalisée
dans `logs\commands.txt`, honnêteté sur ce qui est/ n'est pas récupérable.
