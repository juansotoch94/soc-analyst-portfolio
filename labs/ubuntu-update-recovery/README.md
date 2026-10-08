# Ubuntu Server: interrupted update recovery

October 8, 2026 | Guided personal lab | Juan Soto

## Scope

I installed Ubuntu Server in VirtualBox on a Windows laptop, using 4 GB RAM, 2 vCPUs and a dynamically allocated 40 GB virtual disk. SSH access used a NAT forwarding rule bound to host loopback. This was personal training, not production support.

## Problem

During an update, progress remained at initramfs generation. The SSH session closed and the VM console stopped responding. An orderly shutdown attempt did not succeed; I powered off the VM with guidance. A copy of the virtual disk and configuration was preserved before recovery, with matching SHA-256 hashes for the disk copy. The freeze cause remains unknown.

## Recovery record

The following is a reconstruction from session screenshots and my reported results, not a raw terminal transcript or a script to run blindly.

| Step | Observed result |
| --- | --- |
| Check processes with `ps -eo pid,comm` and filter for apt, dpkg, dracut and initramfs | No matching processes reported before repair |
| `sudo dpkg --audit` | dracut partially configured; libc-bin trigger processing pending |
| `sudo dpkg --configure -a` | Configuration and initramfs generation completed; prompt returned |
| Repeat `sudo dpkg --audit` | No output reported |
| `sudo apt-get check` | Dependency check completed without errors in the screenshot |
| `sudo reboot` | Login succeeded after reboot |
| `systemctl --failed --no-pager` | 0 loaded units listed, reported from the console |

One guided command, `sudo apt check`, was rejected as an invalid operation. I then used `sudo apt-get check` successfully.

## Interpretation and limits

The checks support basic recovery of package configuration, dependency consistency, boot and failed-unit status at that time. They do not prove the original freeze cause was fixed, that every available update was installed, or that the system is stable under prolonged load. The backup preserves the interrupted state, not a verified clean baseline.

## My work and assistance

I performed the installation, console commands and recovery checks with step-by-step AI mentor guidance. The mentor helped interpret results, preserve the disk backup and draft this record. This is guided practice, not an independent troubleshooting claim. Original screenshots and backup verification records remain private; no raw logs or screenshots are bundled with this public note.

## What I learned

Reaching the login prompt is only one check. I also need to inspect package state and services, then state what those results establish and what remains unknown. My next exercise is to explain these checks and repeat a non-destructive health assessment with fewer hints.
