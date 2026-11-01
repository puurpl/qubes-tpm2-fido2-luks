# TPM-Sealed FIDO2 Salt for LUKS Unlock on Qubes OS

## Community Writeup Notes

### What This Is

A method to unlock your Qubes OS LUKS2-encrypted root drive using a hardware
FIDO2 token (e.g. Trezor Safe 5, YubiKey, SoloKeys) with boot integrity verification via TPM2. Both
factors are required simultaneously. The TPM ensures the boot chain hasn't been
tampered with, and the FIDO2 token ensures physical presence.

### Why This Is Hard on Qubes

Qubes OS isolates USB controllers in a dedicated `sys-usb` qube. LUKS decryption
happens in dom0's initramfs *before* sys-usb starts. This creates a timing
challenge, but also an opportunity: USB controllers are naturally available in
dom0 during early boot, and we can release them to sys-usb after decryption.

### Threat Model

| Threat | Protected? | How |
|--------|-----------|-----|
| Stolen laptop (off) | Yes | LUKS encryption + key requires both TPM state and physical token |
| Evil maid (tampered initramfs) | Yes, if PCR 9 is bound | PCR 9 changes → TPM refuses to unseal salt; shipped default omits PCR 9 (see PCR Selection) |
| Stolen FIDO2 token alone | Yes | Token produces HMAC, but without correct salt (sealed in TPM) the output is useless |
| Compromised initramfs + stolen token | Yes | Tampered initramfs = wrong PCRs = no salt = wrong HMAC even with real token |
| Cold boot / DMA while running | Partial | Out of scope: key is in RAM while system is running |
| Physical TPM attack (decapping) | No | Nation-state level; out of scope |

### Architecture

```
                    ┌──────────────┐
                    │   TPM2 Chip  │
                    │              │
                    │  Sealed Salt ├──── bound to PCR 0,4,7
                    │  (32 bytes)  │    (firmware, bootloader,
                    └──────┬───────┘     secure boot; +9 if enabled)
                           │
                    PCRs match?
                    ├── No → refuse (fall back to passphrase)
                    ├── Yes → unseal salt
                    │
                    ▼
    ┌──────────────────────────────┐
    │      FIDO2 Token             │
    │                              │
    │  HMAC(device_secret, salt)   │◄── user enters PIN on touchscreen
    │  = 32-byte result            │◄── user confirms relying party
    └──────────────┬───────────────┘
                   │
                   ▼
    ┌──────────────────────────────┐
    │  Key Derivation              │
    │                              │
    │  SHA-256(salt ‖ hmac_result) │
    │  = LUKS keyslot passphrase   │
    └──────────────┬───────────────┘
                   │
                   ▼
    ┌──────────────────────────────┐
    │  cryptsetup open             │
    │  LUKS2 volume unlocked       │
    └──────────────────────────────┘
```

### Boot Sequence

```
1. BIOS/UEFI powers on, measures firmware into PCRs 0-1
2. GRUB loads, measured into PCRs 4-5
3. GRUB loads Xen hypervisor + dom0 kernel + initramfs
4. Xen starts dom0
5. dom0 initramfs begins
6. ── Our dracut module runs ──────────────────────────
   a. USB HID drivers loaded (controllers still in dom0)
   b. Wait for FIDO2 token to appear on /dev/hidraw*
   c. Read sealed objects from LUKS2 header token
   d. TPM unseal: tpm2_unseal with PCR policy → salt
      (fails if initramfs/kernel/firmware tampered)
   e. FIDO2 assertion: fido2-assert with hmac-secret
      (user enters PIN + confirms on token)
   f. Derive LUKS key: SHA-256(salt ‖ hmac)
   g. cryptsetup open
   h. Shred all secrets from memory
   i. Unbind USB controllers → bind to xen-pciback
7. ── Normal boot continues ───────────────────────────
8. switch_root to real filesystem
9. systemd starts
10. sys-usb qube starts, claims USB controllers (already on xen-pciback)
11. Other qubes start normally
```

### Key Insight: USB Controller Timing

The standard Qubes `rd.qubes.hide_all_usb` hides USB controllers early in
initramfs by binding them to xen-pciback. We replace this with our own hook that
does the same thing *after* LUKS decryption. The security posture is identical
once the system is running. During the brief initramfs window, the disk is still
encrypted and we're physically present.

---

## Implementation Log

### Prerequisites Verified

- Qubes OS with LUKS2 root encryption
- TPM2 chip present
- FIDO2 token with hmac-secret extension (e.g. Trezor Safe 5, YubiKey 5, SoloKeys Solo 2)
- dom0 based on Fedora, uses dracut for initramfs generation
- cryptsetup 2.8.4

### Key Technical Decisions

**Decision: Fully custom dracut module (not systemd-cryptenroll)**
- Reason: systemd-cryptenroll stores the FIDO2 salt in the LUKS2 header in
  cleartext. At unlock time, systemd-cryptsetup always reads it from there. You
  can't override it dynamically. We need the salt to come from the TPM, so we
  bypass systemd-cryptsetup entirely and do our own unlock.

**Decision: SHA-256(salt ‖ hmac) as key derivation, raw binary output**
- Reason: The salt from TPM (32 bytes) and the HMAC from FIDO2 (32 bytes) are
  independent secrets. Concatenating and hashing ensures both must be correct.
  Neither alone is sufficient.
- The derived key is passed to cryptsetup as raw 32 bytes (via xxd -r -p), not
  as a hex string. This avoids fragile encoding mismatches between enrollment
  and boot-time unlock.

**Decision: Release USB controllers post-decrypt instead of hiding pre-decrypt**
- Reason: We need USB access for the FIDO2 token during initramfs. Rather than
  carving out one controller, we keep all controllers available during the brief
  decrypt phase, then hand them all to xen-pciback. Net security is identical.

**Decision: Encrypted salt backup for kernel update workflow**
- Reason: Kernel/initramfs updates change PCR 9, breaking the TPM seal. We can't
  unseal the old salt with new PCRs. An encrypted backup (AES-256-CBC with
  HMAC-SHA256 integrity, key derived from LUKS passphrase via PBKDF2) lets us
  re-seal after updates without regenerating everything.

**Decision: Sealed objects stored in LUKS2 header token (not initramfs)**
- Reason: If seal.pub/seal.priv are baked into the initramfs, every reseal changes
  the initramfs, which changes PCR 9, which invalidates the seal, requiring a
  second reseal. By storing the sealed objects as a LUKS2 custom JSON token
  (type "tpm-fido2-luks"), resealing only updates the LUKS header, leaving the
  initramfs unchanged and PCR 9 stable. This reduces the kernel update workflow
  from 2 reboots + 2 reseals to 1 reboot + 1 reseal.
- Security: seal.pub/seal.priv are TPM-wrapped and useless without the TPM and
  correct PCR values. They were already on unencrypted storage (in the initramfs
  on /boot). The LUKS header is equally unencrypted, so exposure is identical.
- The unlock script has a backward-compat fallback: if no LUKS2 token is found,
  it reads from /etc/tpm-fido2-luks/ in the initramfs (pre-migration installs).

### fido2-assert CLI Interface (libfido2)

The `fido2-assert -G -h` command (get assertion with hmac-secret).
Use stdin/stdout redirection (not `-i`/`-o` flags) for portability across
libfido2 versions:

```bash
fido2-assert -G -h /dev/hidrawX < input.txt > output.txt
```

**Input (stdin, newline-separated):**
1. Client data hash (base64, 32 bytes random)
2. Relying party ID (UTF-8 string, e.g., "qubes-luks-unlock")
3. Credential ID (base64, from enrollment)
4. HMAC salt (base64, 32 bytes, unsealed from TPM)

**Output (stdout, newline-separated):**
1. Client data hash (base64)
2. Relying party ID (string)
3. Authenticator data (base64, CBOR)
4. Assertion signature (base64)
5. User ID (base64, if resident credential)
6. **HMAC secret (base64, 32 bytes)** ← this is what we need

Note: For non-resident credentials (our case), user ID is omitted and the
HMAC secret is on line 5. The scripts extract it as `tail -1` with a fallback
that scans all lines for a 32-byte base64 value.

### Code Review Fixes Applied

After automated code review, the following issues were identified and fixed:

1. **LUKS key now raw binary**: sha256sum hex output piped through `xxd -r -p`
   to produce 32 raw bytes. Consistent across enroll, unlock, and reseal scripts.
2. **TPM primary key uses owner hierarchy**: changed from `-C e` (endorsement)
   to `-C o` (owner). Endorsement hierarchy has access restrictions on some TPMs.
3. **fido2 CLI uses stdin/stdout**: replaced `-i`/`-o` flags with shell
   redirection for portability across libfido2 versions.
4. **Credential ID extraction is resilient**: tries multiple output lines (3, 4)
   and validates authdata flags before parsing byte offsets.
5. **initramfs working dir uses /run**: guaranteed tmpfs in dracut, not /tmp.
6. **set -u added to initramfs scripts**: catches undefined variable bugs.
7. **TPM device wait added**: waits up to 10s for /dev/tpmrm0 before trying unseal.
8. **xen-pciback check added**: usb-handoff.sh verifies driver exists first.
9. **dracut module depends on `crypt`**: ensures systemd-cryptsetup (passphrase
   fallback) is present in the initramfs.
10. **Removed mssim TCTI**: TPM2 simulator library not needed in production.
11. **hidraw glob guard**: `[[ -e "$dev" ]] || continue` added to all scripts.

### Security Audit Fixes Applied

12. **Authenticated salt backup**: salt.enc now has HMAC-SHA256 integrity
    verification (salt.enc.mac). Verified before decrypt, recomputed after encrypt.
13. **Config file safe parsing**: enroll.sh no longer `source`s the config file.
    Uses explicit key=value parsing with an allowlist of accepted variable names.
14. **Passphrase lifetime minimized**: reseal.sh unsets $PASSPHRASE immediately
    after each use (decrypt/encrypt) instead of holding it for the entire script.
15. **HMAC extraction last-match-wins**: fallback loop in enroll.sh and unlock
    script keeps the last 32-byte match (HMAC is always the final field).
16. **TPM handle collision warning**: enroll.sh checks if the persistent handle is
    occupied and warns before evicting.
17. **LUKS_NAME crypttab validation**: install.sh warns if the configured name
    doesn't match /etc/crypttab.
18. **xxd in require_binaries**: module-setup.sh now checks for xxd at dracut time.
19. **Sealed objects in LUKS2 header token**: seal.pub/seal.priv stored as a custom
    LUKS2 JSON token instead of baked into initramfs. Eliminates the double-reseal
    chicken-and-egg problem after kernel updates.

### Token-Specific Notes

**Trezor Safe 5 / Model T** (1209:53c1): Requires PIN on touchscreen + relying party
confirmation. Excellent security: an attacker can't just tap a button.

**YubiKey 5** (1050:0407): Supports hmac-secret. PIN entry via host (enroll.sh
prompts on terminal). Touch required for assertion.

**SoloKeys Solo 2** (1209:beee): Supports hmac-secret. Touch to confirm.

**Nitrokey FIDO2** (20a0:42b1): Supports hmac-secret. Touch to confirm.

Any FIDO2 token that supports the `hmac-secret` extension should work. The
token must hold a device-bound secret that produces a deterministic HMAC for
the same salt input. Update `FIDO2_USB_VID`/`FIDO2_USB_PID` in the config
for your specific device.

### PCR Selection Rationale

| PCR | What It Measures | Why We Bind To It |
|-----|-----------------|-------------------|
| 0 | Core firmware (BIOS/UEFI) | Detect firmware tampering |
| 4 | Bootloader (GRUB) + boot config | Detect bootloader replacement |
| 7 | Secure Boot state | Detect secure boot policy changes |
| 9 | Kernel + initramfs | Detect kernel/initramfs tampering (the big one) |

We intentionally skip:
- PCR 1 (firmware config): changes with BIOS settings, too fragile
- PCR 8 (GRUB commands): changes with grub.cfg edits, too fragile

### Files Delivered

```
tpm-fido2-luks/
├── LICENSE                         # MIT
├── README.md                       # Install guide, threat model, PCR table
├── notes.md                        # This file (writeup + implementation log)
├── config/
│   └── tpm-fido2-luks.conf        # Configuration (LUKS device, PCR banks, etc.)
├── scripts/
│   ├── enroll.sh                   # One-time direct enrollment (needs USB in dom0)
│   ├── enroll-fido2.sh             # Split enrollment part 1 (USB-capable qube)
│   ├── enroll-dom0.sh              # Split enrollment part 2 (dom0)
│   ├── reseal.sh                   # Re-seal after kernel updates (run in dom0)
│   └── install.sh                  # Install dracut module + rebuild initramfs
└── dracut/
    └── 50tpm-fido2-luks/
        ├── module-setup.sh         # Dracut module definition
        ├── tpm-fido2-unlock.sh     # Initramfs: TPM unseal → FIDO2 → LUKS open
        └── usb-handoff.sh          # Initramfs: release USB to xen-pciback
```

---

## Gotchas & Warnings

1. **NEVER remove the passphrase keyslot.** It's your only recovery path if the
   token breaks, TPM is cleared, or a kernel update changes PCRs before you re-seal.

2. **Kernel updates break the seal.** PCR 9 changes every time the kernel or
   initramfs is rebuilt. You must re-seal after every update. The reseal script
   handles this, but you need your LUKS passphrase.

3. **TPM clear = game over for token unlock.** If the TPM is cleared (BIOS reset,
   firmware update), the sealed salt is gone. You'll need your passphrase to boot,
   then re-enroll from scratch.

4. **Test with a rescue kernel first.** Always keep a known-good rescue kernel
   entry in GRUB that doesn't use the custom initramfs. If the dracut module
   breaks boot, you can recover.

5. **The FIDO2 token must be plugged in BEFORE the unlock prompt.** The script
   waits for the token to appear (timeout configurable via `FIDO2_TIMEOUT`,
   default 30s). If you miss the window, it falls back to the passphrase prompt.

6. **USB port matters during initial enrollment but not after.** The credential
   is tied to the FIDO2 device, not the USB port. Any port works at boot.

7. **initramfs size will increase.** The FIDO2 and TPM2 libraries add ~2-5MB to
   the initramfs. This is fine but worth verifying.

8. **Kernel updates require a single reseal.** PCR 9 changes when the kernel or
   initramfs is updated. Because sealed objects are stored in the LUKS2 header
   (not baked into the initramfs), resealing doesn't change PCR 9.

   Workflow after kernel update:
   ```
   1. Boot with passphrase (TPM unseal fails, expected)
   2. Run reseal.sh (re-seals with current PCR values, updates LUKS2 token)
   3. Reboot. Token unlock works
   ```

9. **rd.qubes.hide_all_usb must be removed.** Our usb-handoff.sh replaces it by
   doing the same thing (binding controllers to xen-pciback) AFTER LUKS decrypt.
   The install.sh script handles this interactively.
