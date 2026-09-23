# 4.41 — la boucle de transfert décodée : la pile memdesc = la SOURCE, la destination RM = le registre

Substrate: tools/analysis/gsp-extract/bootloader.asm (le booter
plaintext, OUR build). La boucle 0x100b00-0x100b60 = décodée
instruction par instruction.

## La mécanique complète

| adresse | instruction | le rôle |
|---|---|---|
| 0x100b04 | ld a5, 0x490(a4) | la TAILLE de la transfer-list |
| 0x100b0a | ld a5, 0x498(a4) | la DESTINATION de base |
| 0x100b14 | addi a5, sp, 0x18 | **NOTRE pile memdesc = la source** |
| 0x100b18 | sd a5, 0x8(sp) | le pointeur sauvegardé |
| 0x100b3e | ld a5, 0x8(sp) | NOTRE valeur |
| 0x100b40 | addi a6, a5, 0x8 | le pointeur avance |
| 0x100b44 | ld a5, 0x0(a5) | la charge |
| 0x100b46 | sd a6, 0x8(sp) | le pointeur sauvegardé |
| 0x100b48 | sd a5, 0x0(a1) | **L'ÉCRITURE** |
| 0x100b5a | sd a5, 0x488(a4) | le flag = succès |

## La conclusion

La pile memdesc 0xF800 (notre injection driver) = LA SOURCE de la
transfer-list. Le booter transfère les données de notre pile vers le
registre de l'état RM par le booter LUI-MÊME. Nous contrôlons la
SOURCE (la pile 0xF800). Le contenu = écrit dans l'état RM = la
politique.
