#!/bin/bash
# =============================================================================
# module-setup.sh: Dracut module definition for TPM-sealed FIDO2 LUKS unlock
#
# Installs into initramfs:
#   - TPM2 tools and libraries (tpm2_load, tpm2_unseal, etc.)
#   - FIDO2 tools and libraries (fido2-assert)
#   - USB HID kernel modules
#   - Credential metadata from /etc/tpm-fido2-luks/ (sealed objects in LUKS2 header)
#   - Unlock hook (runs before cryptsetup)
#   - USB handoff hook (runs after LUKS is opened)
# =============================================================================

check() {
    # Only include this module if enrollment has been completed
    [[ -f /etc/tpm-fido2-luks/seal.pub ]] || return 1
    [[ -f /etc/tpm-fido2-luks/credential_id ]] || return 1

    require_binaries tpm2_load tpm2_unseal tpm2_startauthsession \
                     tpm2_policypcr tpm2_flushcontext \
                     fido2-assert fido2-token \
                     sha256sum base64 xxd || return 1
    return 0
}

depends() {
    echo "systemd crypt"
    return 0
}

install() {
    # --- TPM2 tools ---
    inst_multiple tpm2_load tpm2_unseal tpm2_startauthsession \
                  tpm2_policypcr tpm2_flushcontext tpm2_pcrread

    # --- TPM2 libraries (find and install all libtss2 shared objects) ---
    for lib in \
        libtss2-esys.so* \
        libtss2-sys.so* \
        libtss2-mu.so* \
        libtss2-tcti-device.so* \
        libtss2-tcti-cmd.so* \
        libtss2-rc.so* \
        libtss2-tctildr.so*; do
        for path in /usr/lib64/$lib /usr/lib/$lib; do
            [[ -e "$path" ]] && inst_library "$path"
        done
    done

    # --- FIDO2 tools ---
    inst_multiple fido2-assert fido2-token

    # --- FIDO2 libraries ---
    for lib in \
        libfido2.so* \
        libcbor.so* \
        libhidapi-hidraw.so* \
        libudev.so*; do
        for path in /usr/lib64/$lib /usr/lib/$lib; do
            [[ -e "$path" ]] && inst_library "$path"
        done
    done

    # --- General utilities ---
    inst_multiple sha256sum base64 xxd cat head tail sed awk od dd shred \
                  cryptsetup lsmod modprobe sleep

    # --- Kernel modules for USB HID (to talk to the FIDO2 token) ---
    instmods usbhid hid_generic hid xhci_hcd xhci_pci ehci_hcd ehci_pci \
             ohci_hcd ohci_pci usbcore usb_common

    # --- Configuration (sealed objects are in the LUKS2 header, not here) ---
    inst_dir /etc/tpm-fido2-luks
    inst /etc/tpm-fido2-luks/credential_id
    inst /etc/tpm-fido2-luks/relying_party
    inst /etc/tpm-fido2-luks/pcr_banks
    inst /etc/tpm-fido2-luks/tpm_handle
    inst /etc/tpm-fido2-luks/luks_device
    inst /etc/tpm-fido2-luks/luks_name
    [[ -f /etc/tpm-fido2-luks/fido2_timeout ]] && inst /etc/tpm-fido2-luks/fido2_timeout
    [[ -f /etc/tpm-fido2-luks/fido2_usb_id ]] && inst /etc/tpm-fido2-luks/fido2_usb_id

    # --- Install the unlock script (runs early, before systemd-cryptsetup) ---
    inst_hook initqueue/settled 10 "$moddir/tpm-fido2-unlock.sh"

    # --- Install USB handoff script (runs after LUKS is opened) ---
    inst_hook pre-mount 99 "$moddir/usb-handoff.sh"
}
