# Découvertes — scan mémoire PASSIF complet du loader (hôte, sans VM)

Scan read-only de toute la mémoire PRIVATE/MAPPED de `Phase.exe` (= Emulator.vmp.exe) en cours.
Aucun contact C2, aucune exécution, aucun accès à Valorant. 20 913 strings uniques →
`artifacts/loader_full_mem_strings.txt`.

## Nature / fonction : SKIN-CHANGER Valorant
- Dossier de la triche : `C:\Users\Jtegraille\AppData\Local\InternalMenu\customskins\`
- Skins d'armes (noms d'armes Valorant) : `vandal_*`, `phantom_*`, `operator_*`, `guardian_*`,
  `bandit_*`, `melee_*` (.png) + fichiers **`.pak` / `.utoc`** (assets Unreal Engine).
  → Le payload **remplace/applique des skins** dans Valorant (cosmétique) — pas (visible ici)
  un aimbot/ESP. « Emulator » = tier qui *émule* la possession de skins via un relais serveur.
- Lit la présence/état de match Valorant : `"queueId":"competitive","sessionLoopState":"MENUS"`.

## Infrastructure C2 (deux domaines)
- **Auth** : `immortal-authentication.com` → `/api/v4/{challenge,login,griffin-grant,pak-key,binary-fetch,heartbeat}`
- **Relais « Emulator »** : `immortal-emulator.com` →
  `GET /emu_relay.php?token=<hex 64>&mode=slow` (relais applicatif, mode `slow`).
- `Host:` et `User-Agent: Immortal-Loader-v6` observés dans les requêtes en mémoire.

## Licence / identité
- **HWID-locked** : `VMProtectGetCurrentHWID`, `KeyHWID`/`MyHWID`,
  `VMProtectLicense.ini … AcceptedSerialNumber/serialnumber/BlackListedSerialNumber`.
- **Clé device ECC P-256** : `ImmortalAuthDeviceP256V3` (signature P-256 en plus de la RSA embarquée).
- Loader : `Immortal-Loader-v6` (`-R1`).

## Divers
- Énumération des cartes réseau (Npcap/WiFi/Ethernet) — vraisemblablement fingerprint HWID.
- Chaînes d'overlay (`DiscordDesktopOverlayInputTrap`, `TaskListOverlayWnd`, `GDI+ Window
  (DeviceDriver.exe)`) — overlay / énumération de fenêtres (cible de hook).
- Un **token de relais** en clair est présent dans la mémoire du process (ton jeton de session) —
  conservé seulement en local dans `loader_full_mem_strings.txt`, non reproduit ici.

## Conséquence pour « griffin »
Le payload (skin-changer) est fourni par le C2 et appliqué dans Valorant. On a maintenant sa
**fonction, son infra, son protocole, son injecteur, sa licence** — sans l'extraire. Le binaire
griffin lui-même reste récupérable uniquement via capture réseau (VM) ou dump Valorant (exclu).

## IOCs (défensif)
```
immortal-authentication.com        (C2 auth, /api/v4/*)
immortal-emulator.com              (relais, /emu_relay.php?token=..&mode=slow)
186.241.26.203                     (IP vue en connexion live, Bresil)
User-Agent: Immortal-Loader-v6
Dossier: %LOCALAPPDATA%\InternalMenu\customskins\   + .pak/.utoc injectes
Injection: SetWinEventHook sur le thread UI de VALORANT + memoire partagee
```
