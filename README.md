# TPM + FIDO2 Two-Factor LUKS Unlock for Qubes OS

Unlock your Qubes OS LUKS2-encrypted root drive using a hardware FIDO2 token
with boot integrity verification via TPM2. Both factors are required. The TPM
ensures the boot chain hasn't been tampered with, and the FIDO2 token ensures
physical presence.

**Tested with:** Trezor Safe 5. Should work with any FIDO2 token that supports
the `hmac-secret` extension (YubiKey 5, SoloKeys Solo 2, Nitrokey FIDO2, etc.)

## How It Works

```
 TPM2 Chip                         FIDO2 Token
 ──────────                        ───────────
 Sealed salt (32 bytes)            HMAC(device_secret, salt)
 bound to PCR 0,4,7,9             user enters PIN + confirms
        │                                  │
        └──── PCRs match? ───Yes───┐       │
              No → passphrase      │       │
                                   ▼       ▼
                              SHA-256(salt ‖ hmac)
                                   │
                                   ▼
                            cryptsetup open
```

The TPM seals a random salt to specific PCR values (firmware, bootloader, secure
boot, kernel+initramfs). At boot, if the PCRs match (boot chain untampered), the
TPM releases the salt. The FIDO2 token computes an HMAC over the salt using its
internal device secret. The two outputs are combined via SHA-256 to derive the
LUKS key.

## Threat Model

| Threat | Protected? | How |
|--------|-----------|-----|
| Stolen laptop (powered off) | Yes | Requires both TPM state and physical token |
| Evil maid (tampered initramfs) | Yes | PCR 9 changes → TPM refuses to unseal |
| Stolen FIDO2 token alone | Yes | Without correct salt, HMAC output is useless |
| Tampered boot + stolen token | Yes | Wrong PCRs = no salt = wrong key |
| Cold boot / DMA while running | Partial | Key is in RAM while system runs (out of scope) |

## Prerequisites

- Qubes OS with **LUKS2** root encryption (check: `cryptsetup luksDump /dev/<device> | grep Version`)
- **TPM2** chip present and accessible (`tpm2_pcrread sha256:0` should work in dom0)
- **FIDO2 token** with `hmac-secret` support (most modern keys)
- dom0 packages: `tpm2-tools`, `libfido2`, `fido2-tools`, `cryptsetup`, `openssl`

### Installing Dependencies in dom0

Qubes dom0 doesn't have direct network access. You'll need to download RPMs in
a networked VM and copy them to dom0.

`tpm2-tools` is typically already installed in dom0. Verify with `which tpm2_pcrread`.

For FIDO2 tools:

```bash
# In a Fedora-based AppVM or template (one with dnf + network):
mkdir -p /tmp/fido2-rpms
sudo dnf download --resolve --destdir=/tmp/fido2-rpms \
    libfido2 fido2-tools libcbor libhidapi

# In dom0, pull RPMs from that VM and install:
qvm-run --pass-io <vm-name> 'tar -czf - -C /tmp fido2-rpms' \
    > /tmp/fido2-rpms.tar.gz
cd /tmp && tar xzf fido2-rpms.tar.gz
sudo rpm -ivh /tmp/fido2-rpms/*.rpm

# Verify:
fido2-token -L
```

Note: the exact package names may vary by Fedora version. If `libhidapi` isn't
found, try `hidapi`. The key packages are `libfido2` (library) and `fido2-tools`
(CLI utilities including `fido2-token`, `fido2-cred`, `fido2-assert`).

**Troubleshooting libcbor version mismatch:** If `fido2-token` fails with
`libcbor.so.0.XX: cannot open shared object file`, check what you have vs.
what it wants:

```bash
ldd $(which fido2-token) | grep cbor    # shows what version it wants
ls /usr/lib64/libcbor*                  # shows what you have
```

If it's a minor version difference (e.g. wants 0.12, you have 0.11), symlink:

```bash
sudo ln -s /usr/lib64/libcbor.so.0.11 /usr/lib64/libcbor.so.0.12
sudo ldconfig
```

**rpm dependency errors for system libs:** dom0 may report missing deps for
`libc.so.6`, `libcrypto.so.3`, `libz.so.1`, etc. These are core system
libraries already present. Use `rpm -ivh --nodeps` for the three FIDO2
packages only. Do NOT reinstall glibc/openssl/zlib in dom0.

## Getting the Files to dom0

If you're developing in a qube (e.g. an AppVM), you can't just `scp` to dom0.
Use `qvm-run --pass-io` from a **dom0 terminal**:

```bash
# In dom0:
qvm-run --pass-io <your-qube> 'tar -czf - -C /home/user tpm-fido2-luks' \
    > /tmp/tpm-fido2-luks.tar.gz
cd /tmp && tar xzf tpm-fido2-luks.tar.gz
cd /tmp/tpm-fido2-luks
```

## Step 0: Identify Your System

Before editing the config, gather your system info in dom0:

```bash
# Find your LUKS device
lsblk -f | grep -i luks
# or
sudo blkid | grep LUKS

# Find your LUKS mapped name (first column of crypttab)
cat /etc/crypttab

# Verify TPM2 is accessible
tpm2_pcrread sha256:0

# Check for FIDO2 tools
fido2-token -L
```

## Quick Start (Split Enrollment, Recommended for Qubes)

Qubes dom0 typically cannot access USB devices directly (`sys-usb` owns the
controllers). Split enrollment solves this: FIDO2 operations run in a qube
with USB access, TPM/LUKS operations run in dom0.

```bash
# 1. Edit configuration with the values from Step 0
cp config/tpm-fido2-luks.conf config/tpm-fido2-luks.conf.bak
vi config/tpm-fido2-luks.conf    # Set LUKS_DEVICE, LUKS_NAME, USB VID/PID
```

**In a USB-capable qube** (attach token via `qvm-usb`, or use a DispVM):

```bash
# 2. Run FIDO2 enrollment (creates credential, computes HMAC)
#    Requires: fido2-tools, libfido2, libcbor
cd /path/to/tpm-fido2-luks
sudo bash scripts/enroll-fido2.sh
# Token will prompt for PIN + confirmation (twice)
# Artifacts saved to /tmp/tpm-fido2-artifacts/
```

**In dom0:**

```bash
# 3. Pull artifacts from the enrollment qube
qvm-run --pass-io <qube-name> 'sudo tar -czf - -C /tmp tpm-fido2-artifacts' \
    > /tmp/tpm-fido2-artifacts.tar.gz
cd /tmp && tar xzf tpm-fido2-artifacts.tar.gz

# 4. Run dom0 enrollment (seals salt in TPM, adds LUKS keyslot)
cd /tmp/tpm-fido2-luks
sudo bash scripts/enroll-dom0.sh /tmp/tpm-fido2-artifacts
# Will prompt for your existing LUKS passphrase (twice)

# 5. Install dracut module + rebuild initramfs
sudo bash scripts/install.sh

# 6. Reboot and test
#    - Plug in token before powering on (or within 30s)
#    - Enter PIN on token when prompted
#    - Confirm relying party
#    - Keep passphrase ready as fallback
```

**Security note:** The enrollment qube briefly sees the HMAC secret. Use a
DispVM if possible and destroy it after transferring artifacts. The dom0
script automatically shreds the artifact bundle after enrollment.

### Alternative: Direct Enrollment

If you can attach the token to dom0 (e.g. by stopping sys-usb and unbinding
controllers from xen-pciback), you can use the single-step `enroll.sh`:

```bash
# Stop sys-usb so dom0 gets USB controllers
qvm-shutdown sys-usb
# Plug in token, then:
sudo bash scripts/enroll.sh
# Restart sys-usb after
qvm-start sys-usb
```

## Configuration

Edit `config/tpm-fido2-luks.conf`:

```bash
# Your LUKS device (find with: lsblk -f, blkid, or pvs)
LUKS_DEVICE="/dev/nvme0n1p3"

# LUKS mapped name (check /etc/crypttab)
LUKS_NAME="luks-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# PCR banks to bind (don't change unless you know why)
PCR_BANKS="sha256:0,4,7,9"

# TPM persistent handle
TPM_HANDLE="0x81000001"

# FIDO2 relying party (arbitrary, identifies this use on the token)
RELYING_PARTY="qubes-luks-unlock"

# Your token's USB VID:PID (for detection)
# Trezor: 1209:53c1 | YubiKey 5: 1050:0407 | SoloKeys: 1209:beee
FIDO2_USB_VID="1209"
FIDO2_USB_PID="53c1"

# Seconds to wait for token at boot
FIDO2_TIMEOUT=30
```

## After Kernel Updates

Kernel or initramfs updates change PCR 9, breaking the TPM seal. This is
expected and by design. It proves the boot chain changed.

```bash
# 1. Boot normally. TPM unseal will fail, passphrase prompt appears
#    Enter your LUKS passphrase

# 2. After booting, re-seal with new PCR values
sudo bash scripts/reseal.sh

# 3. Reboot. Token unlock works again
```

This is a single reseal + single reboot. The sealed objects are stored in the
LUKS2 header (not the initramfs), so resealing doesn't change PCR 9.

## PCR Selection

| PCR | Measures | Why | Default |
|-----|----------|-----|---------|
| 0 | Core firmware (BIOS/UEFI) | Detect firmware tampering | Yes |
| 4 | Bootloader (GRUB) + config | Detect bootloader replacement | Yes |
| 7 | Secure Boot state | Detect policy changes | Yes |
| 9 | Kernel + initramfs | Detect kernel/initramfs tampering | No* |

Intentionally skipped: PCR 1 (firmware config, too fragile), PCR 8 (GRUB
commands, changes with grub.cfg edits).

**\*PCR 9 requires GRUB TPM measurements.** Check if it's active:

```bash
tpm2_pcrread sha256:9
```

If the value is all zeros, GRUB isn't measuring the kernel/initramfs into the
TPM. Without PCR 9, the sealed salt won't detect initramfs tampering (evil
maid). PCRs 0, 4, and 7 still protect against firmware and bootloader attacks.

### Enabling PCR 9 (GRUB TPM Measurements)

GRUB must load its `tpm` module to measure files into the TPM. On Fedora-based
systems (including Qubes dom0):

```bash
# Check if GRUB has TPM support
grub2-install --version
ls /usr/lib/grub/x86_64-efi/tpm.mod 2>/dev/null   # EFI systems
ls /usr/lib/grub/i386-pc/tpm.mod 2>/dev/null       # BIOS systems

# If the module exists, add it to GRUB's preload list
echo 'GRUB_PRELOAD_MODULES="tpm"' | sudo tee -a /etc/default/grub

# Regenerate GRUB config
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# Reboot required, then check:
tpm2_pcrread sha256:9
```

If PCR 9 shows non-zero values after reboot, add it to your config:

```
PCR_BANKS="sha256:0,4,7,9"
```

Then re-run `reseal.sh` to bind to the new PCR set. Note: kernel updates will
change PCR 9 and require resealing. This is the intended behavior.

## How Qubes USB Isolation Is Preserved

Qubes normally hides USB controllers early in initramfs (`rd.qubes.hide_all_usb`)
by binding them to `xen-pciback`. We need USB during initramfs for the FIDO2
token, so:

1. `install.sh` removes `rd.qubes.hide_all_usb` from GRUB config
2. Our `usb-handoff.sh` hook runs **after** LUKS decrypt
3. It binds all USB controllers to `xen-pciback` (same as the original)
4. When `sys-usb` starts, it claims the controllers normally

Security is identical once the system is running. During the brief initramfs
window, the disk is still encrypted and you're physically present.

## Files

```
tpm-fido2-luks/
├── README.md                              # This file
├── notes.md                               # Design notes + implementation log
├── config/
│   └── tpm-fido2-luks.conf               # Configuration (edit before enrollment)
├── scripts/
│   ├── enroll.sh                          # One-time enrollment (direct, needs USB in dom0)
│   ├── enroll-fido2.sh                    # Split enrollment part 1 (runs in USB-capable qube)
│   ├── enroll-dom0.sh                     # Split enrollment part 2 (runs in dom0)
│   ├── reseal.sh                          # Re-seal after kernel updates
│   └── install.sh                         # Install dracut module
└── dracut/
    └── 50tpm-fido2-luks/
        ├── module-setup.sh                # Dracut module definition
        ├── tpm-fido2-unlock.sh            # Initramfs: TPM → FIDO2 → LUKS open
        └── usb-handoff.sh                 # Initramfs: USB → xen-pciback
```

## Supported FIDO2 Tokens

Any token with `hmac-secret` extension support. Known working / expected to work:

| Token | USB VID:PID | Notes |
|-------|------------|-------|
| Trezor Safe 5 | 1209:53c1 | PIN on touchscreen, relying party confirmation |
| Trezor Model T | 1209:53c1 | Same as Safe 5 |
| YubiKey 5 series | 1050:0407 | PIN via host terminal, touch to confirm |
| SoloKeys Solo 2 | 1209:beee | Touch to confirm |
| Nitrokey FIDO2 | 20a0:42b1 | Touch to confirm |
| Google Titan | 18d1:5026 | Touch to confirm |

## Important Warnings

1. **NEVER remove your passphrase keyslot.** It's your only recovery path.

2. **Keep a rescue kernel.** Always have a GRUB entry with a stock initramfs
   that doesn't include the custom module. If something breaks, boot that.

3. **TPM clear = re-enroll from scratch.** BIOS reset or firmware update may
   clear the TPM. You'll need your passphrase, then run `enroll.sh` again.

4. **Test before relying on it.** Boot with the token a few times. Verify the
   passphrase fallback works. Then trust it.

## Troubleshooting

**"TPM UNSEAL FAILED" at boot:**
PCR mismatch: kernel, initramfs, firmware, or bootloader changed. Boot with
passphrase, then run `reseal.sh`.

**"No FIDO2 token found":**
Token not plugged in, or USB drivers didn't load. Check that your VID:PID is
correct in the config. Try plugging into a different USB port.

**"FIDO2 assertion failed":**
PIN timeout or user declined. Wait for passphrase fallback, boot normally,
and try again next reboot.

**Double passphrase prompt:**
`LUKS_NAME` in config doesn't match `/etc/crypttab`. Run `install.sh`. It
warns about this.

## License

MIT. See [LICENSE](LICENSE).

No warranty. Test with a rescue kernel before relying on this, and never
remove your passphrase keyslot.
