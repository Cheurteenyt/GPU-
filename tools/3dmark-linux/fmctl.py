#!/usr/bin/env python3
"""fmctl — pilotage programmatique de 3DMark via son API interne (wss://127.0.0.1:<port>/elevation).

Usage:
  fmctl.py state                       # dumps product-state/client-state/chops dans /tmp/fmctl_*.json
  fmctl.py send <service> <request> [json_params]
  fmctl.py update <dlcName>            # lance la maj du pack + suit la progression
  fmctl.py watch [secondes]            # écoute les broadcasts (progression bench, chops, erreurs)
"""
import asyncio, json, ssl, sys, time, os

PORT_FILE = "/home/cheurteen/proton-3dmark/pfx/drive_c/users/steamuser/AppData/Local/UL/3DMark/port.state"

def port():
    return open(PORT_FILE).read().strip()

def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

async def session(handler):
    import websockets
    uri = f"wss://127.0.0.1:{port()}/elevation"
    async with websockets.connect(uri, ssl=ctx(), open_timeout=8, max_size=None) as ws:
        await handler(ws)

async def cmd_send(ws, svc, req, params):
    msg_id = int(time.time() * 1000) % 100000
    await ws.send(json.dumps({"service": svc if svc.startswith("/") else "/v1/" + svc,
                              "request": req, "parameters": params, "messageId": msg_id}))
    while True:
        raw = await asyncio.wait_for(ws.recv(), 15)
        m = json.loads(raw)
        if m.get("messageId") == msg_id and m.get("messageType") not in (None,):
            if "CHOPS_STATE" in str(m.get("messageType")) or "BROADCAST" in str(m.get("messageType")):
                continue
            return m

async def do_state(ws):
    for svc in ("product-state", "client-state", "chops", "settings"):
        try:
            r = await cmd_send(ws, svc, "/", {})
            open(f"/tmp/fmctl_{svc}.json", "w").write(json.dumps(r, indent=1))
            print(f"{svc}: {len(json.dumps(r))} octets → /tmp/fmctl_{svc}.json")
        except Exception as e:
            print(f"{svc}: ERREUR {e}")

async def do_update(ws, dlc):
    print(f"→ /v1/chops /update/{dlc}")
    try:
        await ws.send(json.dumps({"service": "/v1/chops", "request": f"/update/{dlc}",
                                  "parameters": {}, "messageId": 1}))
    except Exception as e:
        print("envoi impossible:", e); return
    t0 = time.time(); last_pct = -1; done = False
    while time.time() - t0 < 1800:
        try:
            raw = await asyncio.wait_for(ws.recv(), 60)
        except asyncio.TimeoutError:
            print("(silence 60s — fin d'écoute)"); break
        try: m = json.loads(raw)
        except Exception: continue
        mt = m.get("messageType", ""); msg = m.get("message") or {}
        if mt == "CHOPS_STATE":
            for b in msg.get("benchmarks", []):
                if b.get("dlcName") == dlc:
                    st, pr = b.get("installState"), b.get("progress")
                    if pr != last_pct or st != "UPDATE_REQUIRED":
                        print(f"  [{time.time()-t0:6.0f}s] {dlc}: {st} {pr}%")
                        last_pct = pr
                    if st == "CURRENT" or (st not in ("UPDATING", "DOWNLOADING", "INSTALLING", "VERIFYING", "PENDING", "UPDATE_REQUIRED", "QUEUED") and pr in (0, 100)):
                        done = True
        elif "ERROR" in mt or "FAILED" in mt:
            print(f"  !! {mt}: {json.dumps(msg)[:300]}")
        elif mt not in ("CHOPS_STATE",):
            s = json.dumps(m)
            if any(k in s for k in (dlc, "error", "Error")) and len(s) < 600:
                print(f"  · {mt}: {s[:300]}")
    # état final
    r = await cmd_send(ws, "chops", "/", {})
    for b in r.get("message", {}).get("benchmarks", []):
        if b.get("dlcName") == dlc:
            print(f"FINAL {dlc}: {b.get('installState')} v{b.get('version')}")

async def do_watch(ws, secs):
    t0 = time.time()
    while time.time() - t0 < secs:
        try:
            raw = await asyncio.wait_for(ws.recv(), max(1, secs - (time.time() - t0)))
        except asyncio.TimeoutError:
            break
        m = json.loads(raw)
        s = json.dumps(m, ensure_ascii=False)
        print(f"{m.get('messageType','?')}: {s[:260]}")

async def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "state"
    async def handler(ws):
        if cmd == "state":
            await do_state(ws)
        elif cmd == "send":
            params = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
            r = await cmd_send(ws, sys.argv[2], sys.argv[3], params)
            open("/tmp/fmctl_send.json", "w").write(json.dumps(r, indent=1, ensure_ascii=False))
            print(json.dumps(r, indent=1, ensure_ascii=False)[:4000])
        elif cmd == "update":
            await do_update(ws, sys.argv[2])
        elif cmd == "watch":
            await do_watch(ws, int(sys.argv[2]) if len(sys.argv) > 2 else 120)
        else:
            print(__doc__)
    try:
        await session(handler)
    except Exception as e:
        print(f"connexion impossible ({e}) — l'app 3DMark est-elle lancée ?", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    asyncio.run(main())
