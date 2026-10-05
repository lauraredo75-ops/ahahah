#!/usr/bin/env python3
"""
decrypt_pak.py — SQUELETTE de dechiffrement du payload 'griffin' (a adapter).

Entrees (depuis capture\ apres run_capture.ps1) :
  - payload_griffin.bin  : corps brut de /api/v4/binary-fetch (payload chiffre)
  - pak-key_response.txt : reponse /api/v4/pak-key (contient la cle, possiblement
                           signee/masquee/wrappee : contexte 'immortal-auth-v4|pak-key-wrap|')

Le schema exact (cipher, IV, tag, derivation) doit etre confirme en lisant la reponse
pak-key et/ou la fonction cliente. Imports observes cote client : OpenSSL + bcrypt
=> AES-GCM ou AES-CTR tres probable. Ci-dessous : tentatives AES-256-GCM / AES-256-CBC.

  pip install cryptography
  python decrypt_pak.py
"""
import json, os, sys, binascii

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("pip install cryptography")

CAP = os.path.join(os.path.dirname(__file__), "capture")

def load_key():
    # Adapter : extraire la cle (hex/base64) depuis la reponse pak-key.
    p = os.path.join(CAP, "pak-key_response.txt")
    raw = open(p, "r", encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""
    # Heuristique : cherche un champ hex de 32/64 octets dans le JSON.
    try:
        j = json.loads(raw)
        for k, v in j.items():
            if isinstance(v, str) and all(c in "0123456789abcdefABCDEF" for c in v) and len(v) in (64, 128):
                print("[i] cle candidate: champ '%s' (%d hex)" % (k, len(v)))
                return binascii.unhexlify(v)
    except Exception:
        pass
    print("[!] cle non auto-detectee — editer load_key() avec le bon champ")
    return None

def try_decrypt(key, blob):
    # AES-GCM : [12o nonce][ciphertext][16o tag]  (schema courant)
    try:
        nonce, ct = blob[:12], blob[12:]
        pt = AESGCM(key).decrypt(nonce, ct, None)
        return ("AES-GCM(nonce=12)", pt)
    except Exception:
        pass
    # AES-CBC : [16o IV][ciphertext]
    try:
        iv, ct = blob[:16], blob[16:]
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = d.update(ct) + d.finalize()
        return ("AES-CBC(iv=16)", pt)
    except Exception:
        pass
    return (None, None)

def main():
    blob = open(os.path.join(CAP, "payload_griffin.bin"), "rb").read()
    key = load_key()
    if not key:
        sys.exit(1)
    mode, pt = try_decrypt(key, blob)
    if pt and pt[:2] == b"MZ":
        open(os.path.join(CAP, "griffin_decrypted.dll"), "wb").write(pt)
        print("[+] %s OK -> griffin_decrypted.dll (PE valide)" % mode)
    elif pt:
        open(os.path.join(CAP, "griffin_decrypted.bin"), "wb").write(pt)
        print("[~] %s : dechiffre mais pas un MZ — verifier le schema" % mode)
    else:
        print("[!] echec : adapter le cipher/derivation (lire la reponse pak-key)")

if __name__ == "__main__":
    main()
