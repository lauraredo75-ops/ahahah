# Addon mitmproxy : capture ciblee du C2 Immortal.
# Usage : mitmdump -s mitm_addon.py -w capture\flows.mitm
# A executer UNIQUEMENT en VM isolee.

import os
import json

OUT = os.path.join(os.getcwd(), "capture")
C2 = "immortal-authentication.com"
os.makedirs(OUT, exist_ok=True)


def _save_text(name, data):
    with open(os.path.join(OUT, name), "w", encoding="utf-8", errors="replace") as f:
        f.write(data)


def _save_bin(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data or b"")


def response(flow):
    host = flow.request.pretty_host
    if C2 not in host:
        return
    path = flow.request.path
    tag = path.strip("/").split("?")[0].replace("/", "_") or "root"

    meta = {
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "req_headers": dict(flow.request.headers),
        "req_body": flow.request.get_text(strict=False),
        "status": flow.response.status_code,
        "resp_headers": dict(flow.response.headers),
    }
    # Corps de reponse : texte si JSON, sinon brut
    ctype = flow.response.headers.get("content-type", "")
    if "json" in ctype or "text" in ctype:
        meta["resp_body"] = flow.response.get_text(strict=False)
    _save_text("%s.json" % tag, json.dumps(meta, indent=2, ensure_ascii=False))

    # Extractions specifiques
    if "binary-fetch" in path:
        _save_bin("payload_griffin.bin", flow.response.content)
        print("[capture] payload binary-fetch -> payload_griffin.bin (%d octets)" % len(flow.response.content or b""))
    if "pak-key" in path:
        _save_text("pak-key_response.txt", flow.response.get_text(strict=False) or "")
        print("[capture] pak-key reponse sauvegardee")
    print("[capture] %s %s -> %d" % (flow.request.method, path, flow.response.status_code))
