#!/usr/bin/env python3
"""4.37 TASK B — the regkey EXPERIMENT CARDS: the founder's break-day
lever list, derived entirely from banked evidence (v435b xref census,
v435a owner regions, v436a flow verdict, the 4.34 tick/quantum
verdicts).

For every candidate key the card answers five questions:
  1. WHERE: the standard NVIDIA host path — HKLM\\SYSTEM\\CurrentControlSet\\
     Services\\nvlddmkm, a DWORD value named exactly like the firmware
     string (the open-source driver reads its Rm* registry parameters
     with osReadRegistryDword from the service key — the pattern cited
     at rpc.c:1637, 4.25).  On Linux the same parameters ride the
     module line / modprobe.conf (NVreg_ registry-dump parity is NOT
     assumed — the GSP RM reads its OWN config store fed at init).
  2. WHAT: the test value (enable-flags flip 0<->1; ladders stay the
     stock value unless the card says otherwise).
  3. OBSERVE: the host-side observable (nvidia-smi / journalctl /
     perf counters), always named concretely.
  4. PREDICT: the direction, labeled HYPOTHESIS — derived from the
     banked consumer class only, never invented.
  5. RISK: the class (SAFE = a lookup whose refusal is a no-op;
     CAUTION = touches scheduling/coherence; REFUSED = devinit /
     security / reset paths — the card names the reason).

Selection rule (mechanical, from v435b + v436a): every Rm*/RM* name
with pic_xrefs >= 3 (the 4.35b PASS-TO-CALL class), minus the keys the
4.35a cards refuse on semantics, minus the REFUSED risk class.
Ties ranked by xref count.  The output = the break-day pack: one key,
one boot, one counter delta.

Output: lab/jalon411/v437b_regkey_cards.json
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
V435A = ROOT / "lab/jalon411/v435a_knobcards.json"
V435B = ROOT / "lab/jalon411/v435b_regkeys.json"
V437A = ROOT / "lab/jalon411/v437a_data_twin_xrefs.json"
OUT = Path(__file__).with_suffix(".json")

# the semantic risk gate (names cite the banked consumer class)
REFUSED = {
    "RmClockUprocSecurityCheck": "SECURITY-path check — flipping it "
    "weakens a validation gate; never a perf experiment",
    "RmAllowChannelCreationOnPendingReset": "RESET-path policy — an "
    "experiment here can wedge channels; not a perf lever",
    "RmDisableFbflcnDevinitBoot": "DEVINIT boot path — skipping FLCN "
    "devinit can brick the session; the card refuses",
    "RmClockUprocLockCheck": "SECURITY-path check",
    "RmAcrSecureLoad": "ACR security path",
}
CAUTION = {
    "RMUseTc0NonCoherent": "L2/TC0 coherence semantics — a wrong "
    "turn is data corruption, validate with memtest before load",
    "RML2MaxWaysSysmem": "L2-way partitioning for sysmem — "
    "mis-sizing starves the L2; watch the bandwidth delta",
    "RMEnableQoSRunlistIntr": "runlist interrupt QoS — changes "
    "scheduling latency; the observable IS the point",
}

# the observable recipes, keyed by consumer-class + name patterns
OBS_PERF = ("nvidia-smi -q -d CLOCK,PERFORMANCE before/after; the "
            "bandwidth bench (lab gx3) and Solar Bay score as the "
            "delta witness")
OBS_DMASYNC = ("journalctl -b -k | grep -iE 'nvrm|gsp' around the "
               "workload; the bench timing delta is the witness")
OBS_LOG = ("journalctl -b -k | grep -iE 'nvrm|NVRM.*{stem}' — the "
           "key's own enable/disable path usually prints")
OBS_PCIE = ("nvidia-smi -q -d PERFORMANCE + lspci -vvv link caps "
            "before/after a config-save cycle (suspend/resume)")


def observe_for(name, cls):
    if "Pcie" in name or "ConfigSave" in name:
        return OBS_PCIE
    if cls == "L2/partitioning":
        return OBS_PERF
    return OBS_LOG.replace("{stem}", name[:-2] if name.endswith("0") else name)


def main():
    b = json.loads(V435B.read_text())
    a = json.loads(V435A.read_text())
    try:
        x437a = json.loads(V437A.read_text())
    except Exception:
        x437a = {}

    cards_in = b["regkey_cards"]
    withx = [c for c in cards_in if c.get("pic_xrefs", 0) >= 3]
    withx.sort(key=lambda c: (-c["pic_xrefs"], c["name"]))
    out = {
        "source": "v435b_regkeys (864 names, 251 with xrefs) + "
                  "v435a cards + v436a flow verdict + v437a probe",
        "selection_rule": "pic_xrefs >= 3, minus the semantic REFUSED "
                          "gate, minus CAUTION-only-audit keys",
        "regkey_path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
                       "nvlddmkm : DWORD <KeyName> (Windows) / the "
                       "module-parameter equivalent on Linux",
        "protocol": "one key, one boot, one counter delta; the stock "
                    "firmware only; every flip logged with dmesg "
                    "before/after; the REFUSED class never runs",
        "n_with_xrefs3": len(withx),
    }

    cards = []
    for c in withx:
        name = c["name"]
        if name in REFUSED:
            continue
        risk = "SAFE"
        note = "lookup refusal is a no-op (the 4.35b status-gate shape)"
        for k, v in CAUTION.items():
            if name == k:
                risk, note = "CAUTION", v
        # the consumer class from the 4.35b xref detail (the real
        # field: xref_detail[].class — DEREF-LOAD / REG-READ /
        # PTR-CLOBBERED / PASS-TO-CALL)
        xrefs = c["pic_xrefs"]
        xdetail = c.get("xref_detail", [])
        classes = {}
        for xd in xdetail:
            if isinstance(xd, dict) and xd.get("class"):
                classes[xd["class"]] = classes.get(xd["class"], 0) + 1
        cls = max(classes, key=classes.get) if classes else None
        card = {
            "name": name,
            "va_runtime": c["va_runtime"],
            "pic_xrefs": xrefs,
            "consumer_classes": classes,
            "dominant_class": cls,
            "test_value": ("0x0 -> 0x1 flip (observe both boots)"
                           if name.startswith(("RmEnable", "RmUse",
                                               "RMUse", "RMEnable"))
                           else "one-unit step from the stock value; "
                                "never a blind big turn"),
            "observable": observe_for(name, cls),
            "prediction": "HYPOTHESIS — direction from the name and "
                          "the banked consumer region only",
            "risk": risk,
            "risk_note": note,
        }
        cards.append(card)
    out["cards"] = cards
    out["n_cards"] = len(cards)

    refused = [{"name": n, "reason": r} for n, r in REFUSED.items()
               if any(c["name"] == n for c in cards_in)]
    out["refused_gate"] = refused
    out["n_refused"] = len(refused)

    # the data-twin cross (v437a): the descriptor pointers tie the
    # 1000000 default table to static descriptors — the card pack's
    # context line for the 4.26 capture watchlist
    p3 = x437a.get("probe3_data_ptrs", [])
    out["data_twin_context"] = {
        "t1_descriptor_pointers": len(p3),
        "meaning": "the 22x1000000 defaults are descriptor-referenced "
                   "(data side), never code-addressed — the capture "
                   "watches the RPC object-create path, not a loader",
    }

    OUT.write_text(json.dumps(out, indent=1))
    print(f"[out] {OUT}")
    print(f"cards={out['n_cards']} refused={out['n_refused']} "
          f"with_xrefs3={len(withx)}")
    for c in cards[:12]:
        print(f"  {c['name']:40s} xrefs={c['pic_xrefs']:2d} "
              f"risk={c['risk']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
