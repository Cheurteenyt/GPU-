#!/usr/bin/env python3
"""fan-boost-experiment — does a more aggressive mid-range fan curve raise
sustained boost clocks? Three-phase: baseline load, curve swap, repeat load.
Decision rule: keep the new curve only if steady-state median core clock
improves. Full telemetry saved; the old curve is restored otherwise.
Usage: python3 fan-boost-experiment.py   (desktop must stay usable; ~11 min)
"""
import json
from pathlib import Path
import socket
import statistics
import sys
import subprocess
import time

GPU = '10DE:2488-1462:3904-0000:07:00.0'
OUT = Path(__file__).resolve().parent / 'fan-boost-experiment'
OUT.mkdir(exist_ok=True)
QUERY = 'timestamp,pstate,clocks.current.graphics,clocks.current.memory,temperature.gpu,power.draw,fan.speed,utilization.gpu'
LOAD_SECONDS = int(sys.argv[3]) if len(sys.argv) > 3 else 300
RES = sys.argv[2] if len(sys.argv) > 2 else '2560x1440'
INSTANCES = int(sys.argv[1]) if len(sys.argv) > 1 else 3
NEW_CURVE = {'40': 0.4, '45': 0.45, '50': 0.55, '55': 0.65, '60': 0.8, '65': 0.95, '70': 1.0}


def api(command, args=None):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect('/run/lactd.sock')
        with sock.makefile('rwb') as stream:
            stream.write((json.dumps({'command': command, 'args': args if args is not None else {'id': GPU}}) + '\n').encode())
            stream.flush()
            resp = json.loads(stream.readline())
    if resp.get('status') != 'ok':
        raise RuntimeError(resp)
    return resp.get('data')


def set_curve(curve):
    cfg = api('get_gpu_config')
    old = json.loads(json.dumps(cfg['fan_control_settings']))
    cfg['fan_control_settings']['curve'] = {int(k): v for k, v in curve.items()}
    api('set_gpu_config', {'id': GPU, 'config': cfg})
    return old


def sustained_load(tag):
    csv = OUT / f'{tag}-telemetry.csv'
    procs = [subprocess.Popen(['glmark2-wayland', '--off-screen', '-s', RES, '--run-forever'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(INSTANCES)]
    rows = []
    t0 = time.monotonic()
    try:
        with csv.open('w') as fh:
            fh.write(QUERY + '\n')
            while time.monotonic() - t0 < LOAD_SECONDS:
                row = subprocess.check_output(['nvidia-smi', '--query-gpu=' + QUERY,
                                               '--format=csv,noheader,nounits'], text=True, timeout=10).strip()
                fh.write(row + '\n')
                fh.flush()
                rows.append([v.strip() for v in row.split(',')])
                time.sleep(2)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=10)
    # steady state = after 120 s
    steady = [r for r, ts in zip(rows, [2 * i for i in range(len(rows))]) if ts >= 120]
    core = statistics.median(float(r[2]) for r in steady)
    temp = statistics.median(float(r[4]) for r in steady)
    temp_max = max(float(r[4]) for r in steady)
    watts = statistics.median(float(r[5]) for r in steady)
    fan = statistics.median(float(r[6]) for r in steady)
    result = {'tag': tag, 'steady_median_core_mhz': core, 'steady_median_temp_c': temp,
              'temp_max_c': temp_max, 'steady_median_watts': watts, 'steady_median_fan_pct': fan, 'rows': len(rows)}
    (OUT / f'{tag}-result.json').write_text(json.dumps(result, indent=1))
    print(json.dumps(result), flush=True)
    return result


old_curve = None
try:
    print('phase 1/3: baseline with the current curve', flush=True)
    a = sustained_load('baseline')
    print('phase 2/3: swapping to the boost-preservation curve', flush=True)
    old_cfg = api('get_gpu_config')
    old_curve = json.loads(json.dumps(old_cfg['fan_control_settings']['curve']))
    set_curve(NEW_CURVE)
    applied = api('get_gpu_config')['fan_control_settings']['curve']
    print('  applied curve:', applied, flush=True)
    time.sleep(20)
    print('phase 3/3: repeat load with the new curve', flush=True)
    b = sustained_load('newcurve')
    gain = b['steady_median_core_mhz'] - a['steady_median_core_mhz']
    verdict = {'gain_mhz': gain,
               'keep_new_curve': gain > 0 and b['steady_median_temp_c'] <= a['steady_median_temp_c'] + 2}
    print(json.dumps(verdict), flush=True)
    if not verdict['keep_new_curve'] and old_curve is not None:
        set_curve(old_curve)
        print('restored the original curve', flush=True)
    else:
        print('kept the new curve', flush=True)
    (OUT / 'verdict.json').write_text(json.dumps({**verdict, 'old_curve': old_curve, 'new_curve': NEW_CURVE}, indent=1))
except Exception as e:
    print('ERROR:', e, flush=True)
    if old_curve is not None:
        set_curve(old_curve)
        print('original curve restored after error', flush=True)
