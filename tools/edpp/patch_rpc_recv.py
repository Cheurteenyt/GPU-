#!/usr/bin/env python3
"""Le patch RECEVEUR 4.25 (le chemin GSP→CPU de fn=76) — depuis l'arbre stock
610.57.04. Le point de complétion PROUVÉ (findings-4.25-recv-edpp.md §1) :

  rpcRmApiControl_GSP (rpc.c:10659, l'entonnoir UNIQUE fn=76)
    -> _issueRpcAndWait (:10860) -> rpcRecvPoll (:1990)
    -> _kgspRpcRecvPoll (kernel_gsp.c:2848) -> _kgspRpcDrainOneEvent (:1802)
       :1819 GspMsgQueueReceiveStatus (la réponse copiée DANS le buffer staging)
       :1825-1828 function==expectedFunc && sequence==expectedSequence = LA complétion
    <- rpc.c:2012 lecture de rpc_result (quitté NV_VGPU_MSG_RESULT_RPC_PENDING)
    <- rpc.c:10893 le COPYOUT portMemCopy(params OUT -> l'appelant)

Le buffer message est RÉUTILISÉ pour la réponse (message_queue_cpu.c:188 :
pRpcMsgBuf = le header RPC DANS pCmdQueueElement — le MÊME buffer que le dump
send 4.23). Le dump receveur imprime donc la même vue (rpc_len octets depuis
rpc_message_data) et la LOI DE LONGUEUR 4.24 s'applique à l'identique (résidu
32 octets en fin, à tronquer).

1. LE DUMP (lecture seule ABSOLUE — AUCUNE écriture sur le chemin réponse) :
   au retour GSP (status == NV_OK, chemin petit uniquement — les contrôles à
   gros params réassemblent leur réponse dans une copie locale, hors périmètre),
   imprime :
     RPCRECVINFO seq=.. fn=.. cmd=0x.. status=0x.. psz=.. rres=0x.. rpriv=0x.. len=.. dump=..
     RPCRECV76 seq=.. off=.. len=..: octets...   (blocs de 512, send-compatible)
   Registres : RpcDump (la clé send 4.23 — 1 boot capture les DEUX sens) ;
   RpcRecvMode (1 = toutes les petites réponses fn=76, 2 = EDPp seul
   [0x20800ad0 / 0x20800afd]). La séquence imprimée = le header RPC (la
   corrélation send/receveur autoritaire).
2. --force-get (opt-in, défaut OFF) : si le SBIOS ne lève pas
   _PLATFORM_SETEDPPEAKLIMITINFO_SET au boot, l'émission UNIQUE du GET par le
   chemin PRH (findings-4.24-edpp-flow.md §2.2 « 2 ») : un appel à
   pfmreqhndlrHandlePlatformSetEdppLimitInfo en tête du work item post-load
   (_pfmreqhndlrPmgrPmuPostLoadWorkItem, platform_request_handler.c:925),
   gated par la clé EdppForceGet. C'est l'ÉMISSION d'une requête OUT-only —
   le chemin réponse reste intact.
   (Toute écriture future dans un payload DOIT filtrer par cmd ET offset —
   la leçon du rewriter 4.23. Ce patch n'écrit RIEN.)

Convention d'insertion (le --revert est BYTE-EXACT) : chaque région posée =
une ligne vide + les lignes BEGIN..END complètes, immédiatement après la
fin de ligne d'ancrage ; le retrait avale cette ligne vide + les lignes du
marqueur. Les marqueurs sont disjoints deux à deux.

Usage :
  sudo python3 patch_rpc_recv.py [--src /usr/src/nvidia-610.57.04] [--force-get]
  sudo python3 patch_rpc_recv.py --src ... --revert     (retire TOUT, propre)
"""
import argparse
import sys

MARK_STAT = "EDPP-RECV-STATICS (4.25)"
MARK_RECV = "EDPP-RECV-DUMP (4.25)"
MARK_FORCE = "EDPP-FORCE-GET (4.25)"

# --- le hook receveur (rpc.c) -------------------------------------------------
# anchors vérifiés UNIQUES dans rpc.c 610.57.04 (grep -c == 1)
A_STATIC = "NV_STATUS rpcRmApiControl_GSP\n("                      # :10659
A_DUMP = """    // Issue RPC
    if (large_message_copy)
    {
        status = _issueRpcAndWaitLarge(pGpu, pRpc, total_size, large_message_copy, NV_TRUE);
    }
    else
    {
        status = _issueRpcAndWait(pGpu, pRpc);
    }
"""                                                                # :10853-10861

STATIC_LINES = """/* BEGIN %(M)s */
static NvBool nvRpcRecvInited = NV_FALSE;
static NvU32  nvRpcRecvMode   = 0;
/* END %(M)s */
""" % {"M": MARK_STAT}

DUMP_LINES = """/* BEGIN %(M)s - le hook receveur : LECTURE SEULE ABSOLUE (aucune
   ecriture sur le chemin reponse - la lecon du rewriter 4.23). */
    if (status == NV_OK && large_message_copy == NULL)
    {
        rpc_message_header_v *rr_hdr = rpcGetVgpuMessageHeader(pRpc);
        rpc_gsp_rm_control_v03_00 *rr_ctl = &rpcGetVgpuMessageData(pRpc)->gsp_rm_control_v03_00;
        if (!nvRpcRecvInited)
        {
            NvU32 rr_v = 0;
            if (osReadRegistryDword(pGpu, "RpcDump", &rr_v) != NV_OK)
                rr_v = 0;
            if (rr_v != 0)
                nvRpcRecvMode = 1;
            if (osReadRegistryDword(pGpu, "RpcRecvMode", &rr_v) == NV_OK && rr_v != 0)
                nvRpcRecvMode = rr_v;
            nvRpcRecvInited = NV_TRUE;
        }
        if (nvRpcRecvMode != 0 &&
            rr_hdr->function == NV_VGPU_MSG_FUNCTION_GSP_RM_CONTROL &&
            (nvRpcRecvMode == 1 ||
             rr_ctl->cmd == 0x20800ad0 ||
             rr_ctl->cmd == 0x20800afd))
        {
            NvU32 rr_len  = rr_hdr->length;
            NvU32 rr_dump = (rr_len > 16384) ? 16384 : rr_len;
            NvU32 rr_off;
            NvU8 *rr_d = (NvU8 *)rr_hdr->rpc_message_data;
            NV_PRINTF(LEVEL_ERROR,
                      "RPCRECVINFO seq=%%u fn=%%u cmd=0x%%08x status=0x%%08x psz=%%u "
                      "rres=0x%%08x rpriv=0x%%08x len=%%u dump=%%u\\n",
                      rr_hdr->sequence, rr_hdr->function, rr_ctl->cmd, rr_ctl->status,
                      rr_ctl->paramsSize, rr_hdr->rpc_result, rr_hdr->rpc_result_private,
                      rr_len, rr_dump);
            for (rr_off = 0; rr_off < rr_dump; rr_off += 512)
            {
                NvU32 rr_i;
                NvU32 rr_end = (rr_off + 512 > rr_dump) ? rr_dump : rr_off + 512;
                NV_PRINTF(LEVEL_ERROR, "RPCRECV76 seq=%%u off=%%u len=%%u:",
                          rr_hdr->sequence, rr_off, rr_dump);
                for (rr_i = rr_off; rr_i < rr_end; rr_i++)
                    NV_PRINTF(LEVEL_ERROR, " %%02x", rr_d[rr_i]);
                NV_PRINTF(LEVEL_ERROR, "\\n");
            }
        }
    }
/* END %(M)s */
""" % {"M": MARK_RECV}

# --- le force-get (platform_request_handler.c) --------------------------------
# anchor = la tête du work item post-load (:941-946). Le commentaire amont
# "pGpu acquiring..." existe ×2 dans le fichier ; la suite "EDPpeak event
# update" n'existe qu'après le work item (l'autre site enchaîne sur pRmApi).
FORCE_HEAD = "    // Keep going so that we find bugs where this doesn't succeed..\n"
FORCE_TAIL = """
    //
    // EDPpeak event update, at this point SBIOS requested state should match
    // with current control state if not trigger an update.
    //
"""
A_FORCE = FORCE_HEAD + FORCE_TAIL                                   # :941-946, unique

FORCE_LINES = """/* BEGIN %(M)s - opt-in (cle EdppForceGet) : si le SBIOS ne leve pas
   _PLATFORM_SETEDPPEAKLIMITINFO_SET au boot, forcer l'emission UNIQUE du
   GET_EDPP_LIMIT_INFO par le chemin PRH (findings-4.24-edpp-flow.md S2.2 "2").
   Requete OUT-only - le chemin reponse n'est PAS touche. */
    {
        NvU32 fg_v = 0;
        if (osReadRegistryDword(pGpu, "EdppForceGet", &fg_v) == NV_OK && fg_v != 0)
        {
            lcstatus = pfmreqhndlrHandlePlatformSetEdppLimitInfo(pPlatformRequestHandler, pGpu);
            NV_PRINTF(LEVEL_ERROR,
                      "EDPP-FORCE-GET: pfmreqhndlrHandlePlatformSetEdppLimitInfo status=0x%%08x\\n",
                      lcstatus);
        }
    }
/* END %(M)s */
""" % {"M": MARK_FORCE}


def _read(path):
    with open(path, "r") as f:
        return f.read()


def _write(path, s):
    with open(path, "w") as f:
        f.write(s)


def _cut_markers(s, marker):
    """Retrait BYTE-EXACT : la ligne vide insérée + les lignes BEGIN..END."""
    n = 0
    while True:
        i = s.find("/* BEGIN " + marker)
        if i < 0:
            return s, n
        j = s.find("/* END " + marker, i)
        assert j > i, marker + " : BEGIN sans END"
        k = s.find("*/", j) + 2
        nl = s.find("\n", k)
        assert nl > 0, marker + " : END non terminé par un saut de ligne"
        ls = s.rfind("\n", 0, i) + 1
        assert s[ls:i].strip() == "", marker + " : indentation inattendue avant BEGIN"
        pre = s[:ls]
        assert pre.endswith("\n\n"), marker + " : la ligne vide insérée est absente"
        s = pre[:-1] + s[nl + 1:]
        n += 1


def patch_recv(src, revert=False):
    p = src + "/src/nvidia/src/kernel/vgpu/rpc.c"
    s = _read(p)
    if revert:
        s, n1 = _cut_markers(s, MARK_STAT)
        s, n2 = _cut_markers(s, MARK_RECV)
        _write(p, s)
        print("rpc.c : %d statics + %d bloc(s) receveur retirés" % (n1, n2))
        return
    if MARK_RECV in s or MARK_STAT in s:
        print("rpc.c : déjà patché receveur (aucune action)")
        return
    assert s.count(A_STATIC) == 1, "anchor statics absent/non unique (rpc.c)"
    assert s.count(A_DUMP) == 1, "anchor dump absent/non unique (rpc.c)"
    s = s.replace(A_STATIC, "\n" + STATIC_LINES + A_STATIC, 1)
    s = s.replace(A_DUMP, A_DUMP + "\n" + DUMP_LINES, 1)
    _write(p, s)
    print("rpc.c : hook receveur écrit (dump lecture seule, RpcDump/RpcRecvMode)")


def patch_force(src, revert=False):
    p = src + "/src/nvidia/src/kernel/platform/platform_request_handler.c"
    s = _read(p)
    if revert:
        s, n = _cut_markers(s, MARK_FORCE)
        _write(p, s)
        print("platform_request_handler.c : %d bloc(s) force-get retirés" % n)
        return
    if MARK_FORCE in s:
        print("platform_request_handler.c : déjà patché force-get (aucune action)")
        return
    assert s.count(A_FORCE) == 1, "anchor force-get absent/non unique (platform_request_handler.c)"
    s = s.replace(A_FORCE, FORCE_HEAD + "\n" + FORCE_LINES + FORCE_TAIL, 1)
    _write(p, s)
    print("platform_request_handler.c : force-get écrit (clé EdppForceGet, opt-in)")


def main():
    ap = argparse.ArgumentParser(description="le hook receveur 4.25 (GSP→CPU, fn=76)")
    ap.add_argument("--src", default="/usr/src/nvidia-610.57.04",
                    help="la racine open-gpu-kernel-modules (défaut : l'arbre DKMS 610.57.04)")
    ap.add_argument("--revert", action="store_true",
                    help="retire proprement TOUT ce que ce script pose (byte-exact)")
    ap.add_argument("--force-get", action="store_true",
                    help="pose AUSSI l'émission opt-in du GET (clé EdppForceGet) — le fallback §2.2 « 2 »")
    a = ap.parse_args()
    try:
        patch_recv(a.src, a.revert)
        if a.force_get or a.revert:
            patch_force(a.src, a.revert)
    except AssertionError as e:
        print("ÉCHEC : %s" % e, file=sys.stderr)
        sys.exit(1)
    if not a.revert:
        print("\nVérif : grep -n 'EDPP-RECV\\|EDPP-FORCE-GET' sur les fichiers patchés")
        print("Registres : RpcDump=1 (+RpcRecvMode=2 pour EDPp seul ; EdppForceGet=1 si le SBIOS ne demande pas)")


if __name__ == "__main__":
    main()
