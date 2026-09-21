"""Run Time Spy officiel complet via l'API interne de 3DMark.

Le bench est lancé par l'app elle-même (pipeline officiel : SI + monitoring +
contenu chops). À la fin, le résultat est diffusé à TOUTE l'UI via la route
HTTP /v1/result/loadBroadcastPath → la GUI affiche la page de résultats
comme si le run avait été cliqué dedans.
"""
import asyncio, json, ssl, time, urllib.request

PORT = open("/home/cheurteen/proton-3dmark/pfx/drive_c/users/steamuser/AppData/Local/UL/3DMark/port.state").read().strip()
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
SETTINGS = json.load(open("/home/cheurteen/.local/share/3dmark/timespy_settings.json"))
DOCS = "C:\\users\\steamuser\\Documents\\3DMark"
WORKLOADS = ["TIME_SPY_GT1_PERFORMANCE", "TIME_SPY_GT2_PERFORMANCE", "TIME_SPY_CPU_TEST_PERFORMANCE"]


def broadcast_result_to_ui(result_filename: str):
    """Diffuse OPEN_RESULT à tous les clients (UI comprise) — HTTP POST."""
    url = (f"https://127.0.0.1:{PORT}/v1/result/loadBroadcastPath"
           f"?path={urllib.parse.quote(DOCS + chr(92) + result_filename)}")
    req = urllib.request.Request(url, data=b"", method="POST")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            print("→ résultat diffusé à l'UI:", r.status, flush=True)
    except Exception as e:
        print("→ diffusion résultat échouée:", e, flush=True)


async def main():
    import websockets
    before = set()
    import os
    docs_dir = "/home/cheurteen/proton-3dmark/pfx/drive_c/users/steamuser/Documents/3DMark"
    if os.path.isdir(docs_dir):
        before = set(os.listdir(docs_dir))
    async with websockets.connect(f"wss://127.0.0.1:{PORT}/elevation", ssl=CTX,
                                  open_timeout=8, max_size=None) as ws:
        req = {"service": "/v1/run", "request": "/TIME_SPY_PERFORMANCE",
               "parameters": {"workloads": WORKLOADS, "settings": SETTINGS}, "messageId": 1}
        await ws.send(json.dumps(req))
        print("→ run envoyé: /TIME_SPY_PERFORMANCE", flush=True)
        t0 = time.time(); new_result = None
        while time.time() - t0 < 2400:
            try:
                raw = await asyncio.wait_for(ws.recv(), 300)
            except asyncio.TimeoutError:
                print(f"[{time.time()-t0:.0f}s] (silence)", flush=True)
                continue
            try:
                m = json.loads(raw)
            except Exception:
                continue
            mt = m.get("messageType", ""); msg = m.get("message") or {}
            if mt == "CHOPS_STATE":
                continue
            if mt in ("PROGRESS", "PROGRESS_END"):
                p = msg.get("progressType", mt)
                print(f"[{time.time()-t0:6.0f}s] {p}", flush=True)
            elif "ERROR" in mt or "FAILED" in mt:
                print(f"[{time.time()-t0:6.0f}s] !! {mt}: {json.dumps(msg, ensure_ascii=False)[:300]}", flush=True)
                break
            elif mt == "OPEN_RESULT":
                print(f"[{time.time()-t0:6.0f}s] OPEN_RESULT reçu", flush=True)
            # détection du nouveau fichier résultat
            now = set(os.listdir(docs_dir)) if os.path.isdir(docs_dir) else before
            diff = now - before
            if diff:
                new_result = sorted(diff)[-1]
            if new_result and time.time() - t0 > 60 and mt == "PROGRESS_END":
                break
        if new_result:
            print("résultat:", new_result, flush=True)
            time.sleep(2)
            broadcast_result_to_ui(new_result)
        else:
            print("aucun nouveau résultat détecté", flush=True)


asyncio.run(main())
