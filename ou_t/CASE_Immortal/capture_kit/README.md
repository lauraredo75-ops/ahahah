# Kit de capture C2 — Emulator.vmp.exe (Immortal loader)

> ⚠️ **À exécuter UNIQUEMENT dans un environnement isolé jetable** (VM sans données perso,
> réseau host-only/NAT dédié). Le loader télécharge et injecte un payload de triche depuis
> `immortal-authentication.com` — **malware potentiel**. Ne jamais lancer sur une machine
> contenant tes données.

But : capturer en clair le trafic TLS vers le C2, notamment **`/api/v4/pak-key`** (la clé de
déchiffrement) et **`/api/v4/binary-fetch`** (le payload « griffin » chiffré), pour ensuite
déchiffrer et analyser la DLL hors-ligne.

## Prérequis dans la VM
- Windows 10/11 x64, Python 3.x, le loader `Emulator.vmp.exe` **et** `libcrypto-3-x64.dll`
  dans le même dossier, ta license key.
- `pip install mitmproxy` (fournit `mitmdump`).

## Étapes
1. Copier ce dossier `capture_kit\` + le binaire + la DLL dans la VM.
2. Lancer (PowerShell **admin** dans la VM — l'import du CA et le proxy le nécessitent) :
   ```
   powershell -ExecutionPolicy Bypass -File run_capture.ps1 -LoaderPath .\Emulator.vmp.exe -LicenseKey EMU-XXXX-XXXX-XXXX-XXXX
   ```
   Le script : génère et importe le CA mitmproxy, active le proxy système, démarre `mitmdump`
   avec l'addon, lance le loader, puis **restaure le proxy et retire le CA** à l'arrêt.
3. Résultats dans `.\capture\` :
   - `flows.mitm` (toutes les transactions, rejouables avec `mitmweb -r flows.mitm`)
   - `login.json`, `challenge.json`, `pak-key.json`, `binary-fetch.*` (requête+réponse)
   - `payload_griffin.bin` (corps brut de binary-fetch = payload chiffré)
   - `pak_key.txt` (clé extraite de la réponse pak-key)

## Si l'auth échoue sous MITM
Le client signe ses requêtes (`sig`, préfixe `immortal-auth-v4|…`) et épingle peut-être le
certificat. Deux cas :
- **Cert-pinning** → le login échoue sous MITM. Option : hooker la fonction OpenSSL/WinHTTP
  côté client (frida) pour logguer avant chiffrement, OU accepter de ne récupérer que les
  métadonnées réseau (IP/SNI/volumes).
- **Signature applicative** (pas de pinning TLS) → MITM passe ; tu obtiens tout en clair.

## Déchiffrement du payload (après capture)
`pak-key` fournit la clé (dérivée via contexte `immortal-auth-v4|pak-key-wrap|`). Une fois
`pak_key.txt` + `payload_griffin.bin` en main, adapter `decrypt_pak.py` (squelette fourni) au
schéma exact observé dans les réponses (AES-GCM/CTR probable, cf. imports bcrypt/OpenSSL),
puis analyser la DLL obtenue avec l'agent `native` (Ghidra).

## Puis : analyse de la DLL griffin
C'est la vraie charge de triche. Une fois déchiffrée → `native` (Ghidra headless, JDK 21) +
`secrets` + `capa` sur la DLL, comme pour tout binaire natif.
