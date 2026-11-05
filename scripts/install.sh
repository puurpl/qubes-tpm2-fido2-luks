#!/bin/bash
# =============================================================================
# install.sh: Install the dracut module and rebuild initramfs
#
# Run this in dom0 after enrollment has completed (enroll.sh or enroll-dom0.sh).
# Copies the dracut module to the system location and rebuilds initramfs.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DRACUT_MODULE_SRC="$PROJECT_DIR/dracut/50tpm-fido2-luks"
DRACUT_MODULE_DST="/usr/lib/dracut/modules.d/50tpm-fido2-luks"

# --- Sanity checks ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root in dom0."
    exit 1
fi

if [[ ! -d "$DRACUT_MODULE_SRC" ]]; then
    echo "ERROR: Dracut module source not found at $DRACUT_MODULE_SRC"
    exit 1
fi

if [[ ! -f /etc/tpm-fido2-luks/seal.pub ]]; then
    echo "ERROR: Enrollment not completed. Run enroll.sh first."
    exit 1
fi

# --- Verify LUKS_NAME matches crypttab ---
if [[ -f /etc/crypttab && -f /etc/tpm-fido2-luks/luks_name ]]; then
    CONFIGURED_NAME=$(cat /etc/tpm-fido2-luks/luks_name)
    CRYPTTAB_NAME=$(awk '!/^#/ && NF {print $1; exit}' /etc/crypttab)
    if [[ -n "$CRYPTTAB_NAME" && "$CONFIGURED_NAME" != "$CRYPTTAB_NAME" ]]; then
        echo ""
        echo "WARNING: LUKS_NAME mismatch!"
        echo "  Configured:  $CONFIGURED_NAME"
        echo "  /etc/crypttab: $CRYPTTAB_NAME"
        echo ""
        echo "If these differ, systemd-cryptsetup may try to open the volume a second"
        echo "time with a different name, causing a confusing double-prompt."
        echo "Consider updating LUKS_NAME in the config and re-enrolling."
        echo ""
    fi
fi

echo "=== TPM-FIDO2-LUKS Installation ==="
echo ""

# --- Check for existing rd.qubes.hide_all_usb ---
echo "=== Checking GRUB configuration ==="
GRUB_FILE="/etc/default/grub"
if grep -q "rd.qubes.hide_all_usb" "$GRUB_FILE" 2>/dev/null; then
    echo ""
    echo "WARNING: rd.qubes.hide_all_usb is set in $GRUB_FILE"
    echo ""
    echo "This hides USB controllers BEFORE our unlock script runs, which means"
    echo "the FIDO2 token won't be accessible during LUKS decryption."
    echo ""
    echo "Our usb-handoff.sh script replaces this: it hides controllers AFTER"
    echo "decryption, achieving identical security once the system is running."
    echo ""
    echo "Remove rd.qubes.hide_all_usb from $GRUB_FILE? (y/N)"
    read -r ANSWER
    if [[ "$ANSWER" =~ ^[Yy] ]]; then
        # Remove rd.qubes.hide_all_usb from GRUB config
        sed -i '/rd\.qubes\.hide_all_usb/s/rd\.qubes\.hide_all_usb//;s/  */ /g' "$GRUB_FILE"
        echo "[OK] Removed rd.qubes.hide_all_usb from $GRUB_FILE"
        echo ""
        echo "Regenerating GRUB configuration..."
        grub2-mkconfig -o /boot/grub2/grub.cfg
        echo "[OK] GRUB config regenerated"
    else
        echo ""
        echo "WARNING: Keeping rd.qubes.hide_all_usb. The FIDO2 unlock will NOT"
        echo "work unless you remove it manually."
        echo "Edit $GRUB_FILE and run: grub2-mkconfig -o /boot/grub2/grub.cfg"
    fi
else
    echo "[OK] rd.qubes.hide_all_usb is not set (good)"
fi

# Also check for rd.qubes.hide_pci targeting USB controllers
if grep -q "rd.qubes.hide_pci" "$GRUB_FILE" 2>/dev/null; then
    echo ""
    echo "NOTE: rd.qubes.hide_pci is set in $GRUB_FILE:"
    grep "rd.qubes.hide_pci" "$GRUB_FILE"
    echo ""
    echo "If any of these PCI addresses are USB controllers, they will be hidden"
    echo "before the FIDO2 unlock runs. You may need to adjust this."
fi

echo ""
echo "=== Installing dracut module ==="

# Copy module to system dracut directory
if [[ -d "$DRACUT_MODULE_DST" ]]; then
    echo "Existing module found at $DRACUT_MODULE_DST, backing up..."
    cp -a "$DRACUT_MODULE_DST" "${DRACUT_MODULE_DST}.bak.$(date +%s)"
fi

cp -a "$DRACUT_MODULE_SRC" "$DRACUT_MODULE_DST"
chmod 755 "$DRACUT_MODULE_DST"
chmod 755 "$DRACUT_MODULE_DST"/*.sh

echo "[OK] Dracut module installed to $DRACUT_MODULE_DST"
echo ""
echo "Module contents:"
ls -la "$DRACUT_MODULE_DST/"

# --- Verify dracut can find the module ---
echo ""
echo "=== Verifying module detection ==="
if dracut --list-modules 2>/dev/null | grep -q "tpm-fido2-luks"; then
    echo "[OK] Module 'tpm-fido2-luks' detected by dracut"
else
    echo "WARNING: Module not detected by dracut --list-modules"
    echo "This may be normal if dependencies are loaded differently."
fi

# --- Verify rescue kernel exists ---
echo ""
echo "=== Checking for rescue kernel ==="
if ls /boot/vmlinuz-*rescue* 2>/dev/null | head -1 >/dev/null; then
    echo "[OK] Rescue kernel found:"
    ls /boot/vmlinuz-*rescue* 2>/dev/null
    echo "You can boot this if the custom initramfs causes issues."
else
    echo "WARNING: No rescue kernel found in /boot/"
    echo "Consider creating one before proceeding."
fi

# --- Build initramfs ---
echo ""
echo "=== Building initramfs ==="
echo ""
echo "This will rebuild the initramfs for the current kernel."
echo "dracut -f OVERWRITES the existing initramfs; it is not backed up."
echo "Copy /boot/initramfs-$(uname -r).img somewhere first if you want a fallback."
echo ""
echo "Proceed? (y/N)"
read -r ANSWER
if [[ "$ANSWER" =~ ^[Yy] ]]; then
    KERNEL_VER=$(uname -r)
    echo "Building initramfs for kernel $KERNEL_VER..."
    dracut -f --add tpm-fido2-luks -v 2>&1 | tail -20
    echo ""
    echo "[OK] Initramfs rebuilt"
    echo ""

    # Show size comparison
    echo "Initramfs size:"
    ls -lh "/boot/initramfs-${KERNEL_VER}.img" 2>/dev/null
else
    echo "Skipped. Build manually with:"
    echo "  dracut -f --add tpm-fido2-luks"
fi

echo ""
echo "=========================================="
echo "  INSTALLATION COMPLETE"
echo "=========================================="
echo ""
echo "Before rebooting, verify:"
echo "  1. You know your LUKS passphrase (fallback if token fails)"
echo "  2. A rescue kernel is available in GRUB"
echo "  3. Your FIDO2 token is charged and functional"
echo ""
echo "First boot:"
echo "  1. Plug in FIDO2 token BEFORE powering on (or within 30s of initramfs start)"
echo "  2. Watch for 'tpm-fido2:' messages on the console"
echo "  3. Enter PIN on token when prompted (touchscreen or host)"
echo "  4. Confirm the relying party on the token"
echo "  5. System should unlock and boot normally"
echo ""
echo "If anything goes wrong:"
echo "  - Wait for passphrase prompt (automatic fallback)"
echo "  - Or boot the rescue kernel from GRUB menu"
echo ""
echo "IMPORTANT: After kernel updates, boot with passphrase then run reseal.sh"
