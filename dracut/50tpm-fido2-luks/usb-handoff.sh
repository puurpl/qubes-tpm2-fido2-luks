#!/bin/bash
# =============================================================================
# usb-handoff.sh: Release USB controllers to xen-pciback after LUKS unlock
#
# Runs at pre-mount (after LUKS is open, before switch_root).
# This replaces rd.qubes.hide_all_usb: it does the same thing but AFTER
# we've used the USB-connected FIDO2 token.
#
# After this script runs, USB controllers are bound to xen-pciback and will
# be claimed by sys-usb when it starts, restoring normal Qubes USB isolation.
# =============================================================================

set -u

echo "tpm-fido2: Releasing USB controllers to xen-pciback..."

# Verify xen-pciback is available
if [[ ! -d /sys/bus/pci/drivers/xen-pciback ]]; then
    echo "tpm-fido2: xen-pciback driver not available, skipping USB handoff"
    echo "tpm-fido2: (this is normal if not running on Xen)"
    exit 0
fi

USB_DRIVERS="xhci_hcd ehci-pci ohci-pci"
RELEASED=0
FAILED=0

# Find all USB controllers by class (0c03 = USB controller)
for dev_path in /sys/bus/pci/devices/*; do
    [[ -e "$dev_path/class" ]] || continue
    class=$(cat "$dev_path/class" 2>/dev/null)
    # PCI class 0x0c03xx = USB controller
    if [[ "$class" == 0x0c03* ]]; then
        bdf=$(basename "$dev_path")
        current_driver=$(basename "$(readlink "$dev_path/driver" 2>/dev/null)" 2>/dev/null)

        if [[ -z "$current_driver" ]]; then
            echo "tpm-fido2:   $bdf: no driver bound, binding to xen-pciback"
        elif [[ "$current_driver" == "xen-pciback" ]]; then
            echo "tpm-fido2:   $bdf: already on xen-pciback, skipping"
            RELEASED=$((RELEASED + 1))
            continue
        else
            echo "tpm-fido2:   $bdf: unbinding from $current_driver"
            # Unbind from current driver
            if ! echo "$bdf" > "$dev_path/driver/unbind" 2>/dev/null; then
                echo "tpm-fido2:   WARNING: Failed to unbind $bdf from $current_driver"
                FAILED=$((FAILED + 1))
                continue
            fi
        fi

        # Bind to xen-pciback
        if ! echo "$bdf" > /sys/bus/pci/drivers/xen-pciback/new_slot 2>/dev/null; then
            echo "tpm-fido2:   WARNING: Failed to add $bdf to xen-pciback new_slot"
            FAILED=$((FAILED + 1))
            continue
        fi
        if ! echo "$bdf" > /sys/bus/pci/drivers/xen-pciback/bind 2>/dev/null; then
            echo "tpm-fido2:   WARNING: Failed to bind $bdf to xen-pciback"
            FAILED=$((FAILED + 1))
            continue
        fi

        echo "tpm-fido2:   $bdf: bound to xen-pciback"
        RELEASED=$((RELEASED + 1))
    fi
done

if [[ $RELEASED -gt 0 ]]; then
    echo "tpm-fido2: Released $RELEASED USB controller(s) to xen-pciback"
fi
if [[ $FAILED -gt 0 ]]; then
    echo "tpm-fido2: WARNING: Failed to release $FAILED controller(s)"
    echo "tpm-fido2: sys-usb may not have full USB access"
fi
if [[ $RELEASED -eq 0 && $FAILED -eq 0 ]]; then
    echo "tpm-fido2: No USB controllers found to release"
fi
