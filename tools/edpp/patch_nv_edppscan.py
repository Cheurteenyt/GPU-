#!/usr/bin/env python3
"""Le patch v9 UNIX : le scanner EDPp dans nv.c (le contexte kernel complet).
- le param module : edpp_fix (la cible mW, 0 = off)
- le workqueue différée 30 s après l'init du module
- le scan du physmap pour l'empreinte {100000, 240000, 250000} ±32 octets
- le patch : 250000 → edpp_fix dans chaque empreinte
Run as root. Idempotent (EdppScanMarker)."""
import sys

P = '/usr/src/nvidia-610.57.04/kernel-open/nvidia/nv.c'
s = open(P).read()

if 'EdppScanMarker' in s:
    print('déjà patché'); sys.exit(0)

# 1. les declarations globales avant nvidia_init_module
anchor = 'static int __init nvidia_init_module(void)'
assert anchor in s, 'l"ancre init absente'
s = s.replace(anchor, '''/* EdppScanMarker — la chasse à la politique EDPp dans la RAM kernel */
static int edpp_fix = 0;
module_param(edpp_fix, int, 0444);
MODULE_PARM_DESC(edpp_fix, "EDPp limit override target in mW (0 = disabled)");
static struct delayed_work edpp_work;
static void edpp_scan_worker(struct work_struct *w);

static int __init nvidia_init_module(void)''', 1)

# 2. le worker + l'ordonnancement au début de nvidia_init_module
anchor2 = '''    nv_memdbg_init();

    rc = nv_procfs_init();'''
assert anchor2 in s, 'l"ancre nv_memdbg absente'
s = s.replace(anchor2, '''    nv_memdbg_init();

    {
        static NvBool edpp_scheduled = NV_FALSE;
        if (!edpp_scheduled && edpp_fix >= 100000 && edpp_fix <= 350000)
        {
            edpp_scheduled = NV_TRUE;
            INIT_DELAYED_WORK(&edpp_work, edpp_scan_worker);
            schedule_delayed_work(&edpp_work, msecs_to_jiffies(30000));
            printk(KERN_ERR "EDPPSCAN armé : cible %d mW, scan dans 30 s\\n", edpp_fix);
        }
    }

    rc = nv_procfs_init();''', 1)

# 3. le worker (avant nvidia_init_module, après les declarations)
worker = '''
static void edpp_scan_worker(struct work_struct *w)
{
    const unsigned int V_MIN = 100000, V_DEF = 240000, V_MAX = 250000;
    unsigned int n_match = 0, n_patch = 0;
    unsigned long pfn;
    printk(KERN_ERR "EDPPSCAN : le scan de la RAM kernel démarre (cible %d)\\n", edpp_fix);
    for (pfn = 0; pfn < max_pfn; pfn++)
    {
        unsigned char *page;
        unsigned int off;
        if (!pfn_valid(pfn))
            continue;
        page = phys_to_virt((phys_addr_t)pfn << PAGE_SHIFT);
        for (off = 0; off + 4 <= PAGE_SIZE; off += 4)
        {
            unsigned int v;
            memcpy(&v, page + off, 4);
            if (v != V_MAX)
                continue;
            {
                unsigned int lo = off > 32 ? off - 32 : 0;
                unsigned int hi = off + 36 > PAGE_SIZE ? PAGE_SIZE : off + 36;
                unsigned int i, saw_min = 0, saw_def = 0;
                for (i = lo; i + 4 <= hi; i += 4)
                {
                    unsigned int u;
                    memcpy(&u, page + i, 4);
                    if (u == V_MIN) saw_min = 1;
                    if (u == V_DEF) saw_def = 1;
                }
                if (saw_min && saw_def)
                {
                    n_match++;
                    memcpy(page + off, &edpp_fix, 4);
                    n_patch++;
                    printk(KERN_ERR "EDPPSCAN pfn=%lx off=%u : 250000 -> %d\\n",
                           pfn, off, edpp_fix);
                }
            }
        }
    }
    printk(KERN_ERR "EDPPSCAN FINI : %u empreinte(s), %u patch(s) vers %d\\n",
           n_match, n_patch, edpp_fix);
}
'''
anchor3 = '''/* EdppScanMarker — la chasse à la politique EDPp dans la RAM kernel */'''
assert anchor3 in s
s = s.replace(anchor3, anchor3 + worker, 1)

open(P, 'w').write(s)
print('v9-UNIX appliqué : le scanner dans nv.c ✓')
