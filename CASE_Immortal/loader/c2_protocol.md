# Protocole C2 « immortal-auth-v4 » — reconstruit (statique, depuis le dump)

Source : chaînes déchiffrées du dump mémoire (`izzz`) + format-strings de log internes.
Aucune requête n'a été émise vers le C2 pour établir ceci (reconstruction **statique**).

## Transport
- Hôte C2 : `immortal-authentication.com` (HTTPS, WinHTTP/WININET + OpenSSL).
- Corps : JSON (nlohmann::json). En-tête `Authorization: Basic`.
- Intégrité/anti-tamper applicatif : préfixe de signature **`immortal-auth-v4|...`** ;
  clé **RSA privée embarquée** (→ `embedded_private_key.pem`) utilisée pour signer/vérifier.
- Session : jeton **`sess_hex`** (hex) obtenu au login, rejoué ensuite.

## Séquence (API v4)
1. **`POST /api/v4/challenge`** — « [Login] posting /api/v4/challenge ». Obtient un
   challenge/nonce serveur (anti-rejeu).
2. **`POST /api/v4/login`** — « [Login] posting /api/v4/login ». Envoie la **license key**
   + réponse au challenge. Réponse journalisée : `http`, `body`, **`sig`** (signature),
   `status`, `ec` (error code). Établit `sess_hex`.
3. **`POST /api/v4/griffin-grant`** — octroi d'entitlement pour le module « griffin ».
4. **`POST /api/v4/pak-key`** — récupère la clé de déchiffrement du payload (« pak »).
   Champs vus : `pak-key sign`, `pak-key sig`, `pak-key transport`, `pak-key response`,
   `pak-key hex`, `pak-key mask`. Dérivation enveloppée avec le contexte
   **`immortal-auth-v4|pak-key-wrap|`** (key-wrap, type HKDF/HMAC).
5. **`POST /api/v4/binary-fetch`** — télécharge **`dll_bytes`** (le payload chiffré = la DLL
   de triche). Intégrité : **SHA-256** (`[loader stage A.1] dll_bytes sha256=%.64s`).
6. **`POST /api/v4/heartbeat`** — keep-alive/licence récurrent (`next_heartbeat_after_ms`,
   état `HeartbeatDegraded`).

## Chaîne du loader (après fetch) — `launch_private`
`dll_bytes` (déchiffré via pak-key) → `[stage C] seal_into_shmem` (mémoire partagée vers le
process Valorant, `val_pid`) → `[stage D] SetWinEventHook val_pid/val_tid` (déclencheur
d'injection dans le thread UI de Valorant) → `[stage E]` focus HWND Valorant →
`[stage F.2] DeleteFile après FreeLibrary` (nettoyage anti-forensique).

## Anti-analyse
Watchdog périodique : `[tick] KILLING: dbg hwbp retools frida inject wdbg patch_auth
patch_cookie cookie_miss` — tue/détecte debuggers, breakpoints matériels, outils de RE,
frida, injecteurs, et repère le patch de l'auth/cookie. + virtualisation VMProtect.

## Pour capturer réellement /api/v4/binary-fetch + pak-key (à faire EN VM isolée)
1. VM Windows jetable, **sans** données personnelles, réseau isolé/host-only.
2. MITM TLS : `mitmproxy`/`mitmdump` ; installer son CA dans la VM ; proxy système → mitm.
   (Le client épingle peut-être la signature applicative `sig` : si l'auth échoue sous MITM,
   c'est du cert/much-pinning → capturer au niveau API via hook, ou accepter les métadonnées.)
3. Lancer le loader avec la license key ; `binary-fetch` renverra le payload chiffré,
   `pak-key` la clé → déchiffrer hors-ligne, puis analyser la DLL « griffin » comme un
   binaire natif (agent `native`).
> ⚠️ `binary-fetch` télécharge un exécutable de triche depuis un C2 : **malware potentiel**
> (les loaders de triche embarquent fréquemment des infostealers). À ne détoner qu'en VM
> isolée, jamais sur une machine contenant tes données.
