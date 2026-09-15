# findings-gx13 — the thirteenth ring: the wall, measured

Scope: five scripted in-session attempts (v2 → v2.6, each hardening the
previous run's failure: logging that survives crashes, the mount check,
the unload retry loop, both GPU-control daemons, a detached 240 s
watchdog that forces the restore). Every attempt admitted only its log;
the final one is measured to the reference count. Zero writes to the
card at any point.

## The peeling, layer by layer

1. `coolercontrold` (root) holds `/dev/nvidia0` open — stopped, restored.
2. `lactd` (root) holds it too — stopped, restored. Two GPU-control
   daemons on one machine, each a holder.
3. Remaining holders terminated by signal; the module still busy.
4. **The final wall: `lsof` on `/dev/nvidia*` returns NOTHING, yet
   `nvidia` carries 371 kernel references, `nvidia_drm` 54,
   `nvidia_modeset` 13, `nvidia_uvm` 8.** No file descriptor holds the
   device: the reference is kernel-internal — the active VT console
   itself is bound to the `nvidia_drm` framebuffer. A display driver
   cannot be unloaded while the console it displays is in use, and the
   console is always in use on the machine you are typing on.

## The verdict

The in-session route to the full-SPI read is **exhausted, with the wall
named**: the last blocker is not a process (those were all peeled), it
is the console pinning the display driver. The remaining paths:

1. **the live USB** — a boot where no display driver exists and the
   console belongs to the firmware framebuffer: `iomem=relaxed` at the
   boot prompt, `nvflash --save` from there. Zero interaction with the
   installed system.
2. a hardware SPI clip (CH341A-class) — the offline path, out of scope
   for now.

The five attempts are not a failure: they produced the hardened script
suite (committed, v2.6 with the watchdog), the holder inventory, and
the refcount proof. The gsp.bin unpacking (ring 9) and the full-SPI read
now both stand behind the same gate: a boot outside the running system.

## The incidental lessons (banked in the script history)

- `set -u` kills scripts on uninitialized variables — the v2.4 bug that
  left a black screen until reboot (caught by the drive-side log in
  seconds, fixed in v2.6),
- tmpfs logs die with reboots — the lab log lives on the data drive,
- any script that can black the screen must run under a detached
  watchdog (v2.6's 240 s restore) — the screen can no longer stay dark.

## Honesty ledger

- Proven: the holder inventory (two daemons), the signal pass, the empty
  `lsof` against 371/54/13/8 refcounts, the full restore after every
  attempt (sddm, coolercontrold, lactd, the GPU all verified back).
- Inferred: the console-fbcon attribution of the 54 `nvidia_drm`
  references (the only kernel-side candidate once userspace is empty).
- Unknown: whether a VT-less boot (systemd without a getty on the
  nvidia fbcon, SSH-in) could release the console — untested; the live
  USB remains the documented path.
