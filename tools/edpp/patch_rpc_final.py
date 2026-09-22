#!/usr/bin/env python3
"""Le patch FINAL 4.23 (depuis kernel_gsp.c.stock-4.23) :
1. les clés registre RpcDump (le dump) et EdppOverride (la cible mW)
2. le rewrite en vol : dans les payloads fn=76, chaque u32 == 250000
   devient EdppOverride (ex. 280000) — la table EDPp avant l'envoi.
Le default : EdppOverride absent = AUCUN rewrite (le driver = stock).
"""
import sys

P = '/usr/src/nvidia-610.57.04/src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c'
s = open(P).read()

if 'EdppOverride' in s:
    print('déjà patché v4'); sys.exit(0)

anchor = "static NV_STATUS _kgspRpcSendMessage(OBJGPU *, OBJRPC *, NvU32 *);"
assert anchor in s, 'anchor1 absent'
s = s.replace(anchor, """static NvBool nvRpcDumpInited = NV_FALSE;
static NvU32 nvRpcDumpEnable = 0;
static NvBool nvEdppInited = NV_FALSE;
static NvU32 nvEdppOverride = 0;

static NV_STATUS _kgspRpcSendMessage(OBJGPU *, OBJRPC *, NvU32 *);""", 1)

anchor2 = "    nvStatus = GspMsgQueueSendCommand(pRpc->pMessageQueueInfo, pGpu);"
assert anchor2 in s, 'anchor2 absent'
s = s.replace(anchor2, """    {
        NvU32 rpc_fn = vgpuHeader->function;
        NvU32 rpc_len = vgpuHeader->length;
        NvU8 *rpc_d = (NvU8 *)vgpuHeader->rpc_message_data;
        if (!nvRpcDumpInited)
        {
            NvU32 rpc_v = 0;
            osReadRegistryDword(pGpu, "RpcDump", &rpc_v);
            nvRpcDumpEnable = rpc_v;
            osReadRegistryDword(pGpu, "EdppOverride", &nvEdppOverride);
            nvRpcDumpInited = NV_TRUE;
        }
        // le rewrite EDPp en vol : EdppOverride = la cible en mW (0 = off)
        if (nvEdppOverride >= 100000 && nvEdppOverride <= 350000 && rpc_fn == 76)
        {
            NvU32 rw_i;
            NvU32 rw_lim = rpc_len > 1616 ? 1616 : rpc_len;
            for (rw_i = 0; rw_i + 4 <= rw_lim; rw_i += 4)
            {
                NvU32 rw_v;
                memcpy(&rw_v, rpc_d + rw_i, 4);
                if (rw_v == 250000)
                {
                    NvU32 rw_t = nvEdppOverride;
                    memcpy((void *)(rpc_d + rw_i), &rw_t, 4);
                    nv_printf(LEVEL_ERROR, "EDPPREWRITE offset=%u : 250000 -> %u\\n", rw_i, rw_t);
                }
            }
        }
        if (nvRpcDumpEnable)
        {
            if (rpc_fn == 76)
            {
                NvU32 rpc_off;
                static NvU32 rpcSeq = 0;
                NvU32 rpc_seq = rpcSeq++;
                for (rpc_off = 0; rpc_off < rpc_len; rpc_off += 512)
                {
                    NvU32 rpc_i, rpc_end = (rpc_off + 512 > rpc_len) ? rpc_len : rpc_off + 512;
                    nv_printf(LEVEL_ERROR, "RPCDUMP76 seq=%u off=%u len=%u:", rpc_seq, rpc_off, rpc_len);
                    for (rpc_i = rpc_off; rpc_i < rpc_end; rpc_i++)
                        nv_printf(LEVEL_ERROR, " %02x", rpc_d[rpc_i]);
                    nv_printf(LEVEL_ERROR, "\\n");
                }
            }
            else
            {
                nv_printf(LEVEL_ERROR, "RPCDUMP fn=%u len=%u\\n", rpc_fn, rpc_len);
            }
        }
    }

    nvStatus = GspMsgQueueSendCommand(pRpc->pMessageQueueInfo, pGpu);""", 1)

open(P, 'w').write(s)
print('patch v4 final écrit (dump + rewrite EDPp)')
