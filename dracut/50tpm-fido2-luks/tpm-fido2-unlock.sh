#!/bin/bash
# =============================================================================
# tpm-fido2-unlock.sh: Initramfs hook: TPM unseal → FIDO2 HMAC → LUKS open
#
# Runs at initqueue/settled (after udev has settled, before cryptsetup.target).
# If this script successfully opens the LUKS volume, systemd-cryptsetup will
# see it's already open and skip its own prompt.
#
# On any failure, this script exits cleanly and the system falls back to the
# normal passphrase prompt.
# =============================================================================

# Catch undefined variables but do NOT use set -e (we handle all errors manually)
set -u

CONF_DIR="/etc/tpm-fido2-luks"

# --- Load configuration from installed files ---
LUKS_DEVICE=$(cat "$CONF_DIR/luks_device" 2>/dev/null)
LUKS_NAME=$(cat "$CONF_DIR/luks_name" 2>/dev/null)
CRED_ID_B64=$(cat "$CONF_DIR/credential_id" 2>/dev/null)
RELYING_PARTY=$(cat "$CONF_DIR/relying_party" 2>/dev/null)
PCR_BANKS=$(cat "$CONF_DIR/pcr_banks" 2>/dev/null)
TPM_HANDLE=$(cat "$CONF_DIR/tpm_handle" 2>/dev/null)

# --- Validate configuration ---
if [[ -z "$LUKS_DEVICE" || -z "$LUKS_NAME" || -z "$CRED_ID_B64" || \
      -z "$RELYING_PARTY" || -z "$PCR_BANKS" || -z "$TPM_HANDLE" ]]; then
    echo "tpm-fido2: Missing configuration, skipping (passphrase fallback)"
    exit 0
fi

# --- Check if already unlocked ---
if [[ -b "/dev/mapper/$LUKS_NAME" ]]; then
    exit 0
fi

# --- Wait for LUKS device to appear ---
if [[ ! -b "$LUKS_DEVICE" ]]; then
    echo "tpm-fido2: Waiting for $LUKS_DEVICE..."
    for i in $(seq 1 10); do
        sleep 1
        [[ -b "$LUKS_DEVICE" ]] && break
    done
    if [[ ! -b "$LUKS_DEVICE" ]]; then
        echo "tpm-fido2: $LUKS_DEVICE not found, skipping"
        exit 0
    fi
fi

# --- Wait for TPM device ---
if [[ ! -c /dev/tpmrm0 && ! -c /dev/tpm0 ]]; then
    echo "tpm-fido2: Waiting for TPM device..."
    for i in $(seq 1 10); do
        sleep 1
        [[ -c /dev/tpmrm0 || -c /dev/tpm0 ]] && break
    done
    if [[ ! -c /dev/tpmrm0 && ! -c /dev/tpm0 ]]; then
        echo "tpm-fido2: TPM device not found, falling back to passphrase"
        exit 0
    fi
fi

# --- Ensure USB HID modules are loaded ---
modprobe -q usbcore 2>/dev/null
modprobe -q usbhid 2>/dev/null
modprobe -q hid_generic 2>/dev/null
modprobe -q xhci_pci 2>/dev/null
modprobe -q xhci_hcd 2>/dev/null

# Give USB stack a moment to enumerate devices
sleep 2

# --- Find FIDO2 token ---
echo "tpm-fido2: Looking for FIDO2 token..."

FIDO2_TIMEOUT=$(cat "$CONF_DIR/fido2_timeout" 2>/dev/null)
FIDO2_TIMEOUT=${FIDO2_TIMEOUT:-30}
FIDO2_DEVICE=""
ELAPSED=0

while [[ $ELAPSED -lt $FIDO2_TIMEOUT ]]; do
    # Try fido2-token -L first (lists FIDO2-capable devices)
    while IFS=: read -r dev_path dev_info; do
        [[ -z "$dev_path" ]] && continue
        dev_path=$(echo "$dev_path" | tr -d '[:space:]')
        [[ -e "$dev_path" ]] || continue
        FIDO2_DEVICE="$dev_path"
        break
    done < <(fido2-token -L 2>/dev/null)
    [[ -n "$FIDO2_DEVICE" ]] && break
    if [[ $ELAPSED -eq 0 ]]; then
        echo "tpm-fido2: Waiting for FIDO2 token (${FIDO2_TIMEOUT}s timeout)..."
        echo "tpm-fido2: Plug in your FIDO2 token now."
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [[ -z "$FIDO2_DEVICE" ]]; then
    echo "tpm-fido2: No FIDO2 token found after ${FIDO2_TIMEOUT}s, falling back to passphrase"
    exit 0
fi
echo "tpm-fido2: Token found at $FIDO2_DEVICE"

# --- Working space on tmpfs (secrets never touch disk) ---
WORK_DIR=$(mktemp -d /run/tpm-fido2.XXXXXX)
chmod 700 "$WORK_DIR"
cleanup() {
    shred -uzn1 "$WORK_DIR"/* 2>/dev/null
    rmdir "$WORK_DIR" 2>/dev/null
}
trap cleanup EXIT

# --- Extract sealed objects from LUKS2 header token ---
echo "tpm-fido2: Reading sealed objects from LUKS2 header..."

SEAL_PUB_PATH=""
SEAL_PRIV_PATH=""

# Try LUKS2 header token first (preferred: avoids initramfs rebuild on reseal)
for tid in $(seq 0 31); do
    TOKEN_JSON=$(cryptsetup token export "$LUKS_DEVICE" --token-id "$tid" 2>/dev/null) || continue
    TOKEN_TYPE=$(echo "$TOKEN_JSON" | sed 's/.*"type":"\([^"]*\)".*/\1/')
    if [[ "$TOKEN_TYPE" == "tpm-fido2-luks" ]]; then
        echo "$TOKEN_JSON" | sed 's/.*"tpm_seal_pub":"\([^"]*\)".*/\1/' | base64 -d > "$WORK_DIR/seal.pub" 2>/dev/null
        echo "$TOKEN_JSON" | sed 's/.*"tpm_seal_priv":"\([^"]*\)".*/\1/' | base64 -d > "$WORK_DIR/seal.priv" 2>/dev/null
        if [[ -s "$WORK_DIR/seal.pub" && -s "$WORK_DIR/seal.priv" ]]; then
            SEAL_PUB_PATH="$WORK_DIR/seal.pub"
            SEAL_PRIV_PATH="$WORK_DIR/seal.priv"
            echo "tpm-fido2: Sealed objects loaded from LUKS2 token (id=$tid)"
        fi
        break
    fi
done

# Fallback: try initramfs files (backward compat with pre-migration installs)
if [[ -z "$SEAL_PUB_PATH" ]]; then
    if [[ -f "$CONF_DIR/seal.pub" && -f "$CONF_DIR/seal.priv" ]]; then
        SEAL_PUB_PATH="$CONF_DIR/seal.pub"
        SEAL_PRIV_PATH="$CONF_DIR/seal.priv"
        echo "tpm-fido2: Using seal objects from initramfs (legacy)"
    else
        echo "tpm-fido2: No sealed objects found, falling back to passphrase"
        exit 0
    fi
fi

# --- TPM Unseal ---
echo "tpm-fido2: Unsealing salt from TPM..."

# Load the sealed object using the persistent primary
if ! tpm2_load -C "$TPM_HANDLE" \
        -u "$SEAL_PUB_PATH" \
        -r "$SEAL_PRIV_PATH" \
        -c "$WORK_DIR/sealed.ctx" 2>/dev/null; then
    echo "tpm-fido2: TPM load failed, falling back to passphrase"
    exit 0
fi

# Start a policy session and verify PCRs match
if ! tpm2_startauthsession -S "$WORK_DIR/session.ctx" --policy-session 2>/dev/null; then
    echo "tpm-fido2: TPM session failed, falling back to passphrase"
    exit 0
fi

if ! tpm2_policypcr -S "$WORK_DIR/session.ctx" -l "$PCR_BANKS" 2>/dev/null; then
    echo "tpm-fido2: *** PCR MISMATCH: boot chain may be tampered! ***"
    echo "tpm-fido2: Falling back to passphrase. Investigate before trusting this boot."
    tpm2_flushcontext "$WORK_DIR/session.ctx" 2>/dev/null
    exit 0
fi

# Unseal: this is the critical operation. If PCRs don't match the sealed
# policy, this fails and we fall back to passphrase.
if ! tpm2_unseal -c "$WORK_DIR/sealed.ctx" \
        -p "session:$WORK_DIR/session.ctx" \
        -o "$WORK_DIR/salt.bin" 2>/dev/null; then
    echo "tpm-fido2: *** TPM UNSEAL FAILED: possible boot chain tampering! ***"
    echo "tpm-fido2: This can also happen after a kernel/initramfs update."
    echo "tpm-fido2: Falling back to passphrase. Run reseal.sh after booting."
    tpm2_flushcontext "$WORK_DIR/session.ctx" 2>/dev/null
    exit 0
fi
tpm2_flushcontext "$WORK_DIR/session.ctx" 2>/dev/null

SALT_SIZE=$(wc -c < "$WORK_DIR/salt.bin")
if [[ "$SALT_SIZE" -ne 32 ]]; then
    echo "tpm-fido2: Unsealed salt is $SALT_SIZE bytes (expected 32), aborting"
    exit 0
fi
echo "tpm-fido2: Salt unsealed from TPM (PCRs verified)"

# --- FIDO2 HMAC assertion ---
echo "tpm-fido2: Requesting FIDO2 HMAC..."
echo "tpm-fido2: >>> Enter PIN on token and confirm <<<"

# Generate a random client data hash for this assertion
dd if=/dev/urandom bs=32 count=1 of="$WORK_DIR/cdh.bin" 2>/dev/null
CDH_B64=$(base64 -w0 < "$WORK_DIR/cdh.bin")
SALT_B64=$(base64 -w0 < "$WORK_DIR/salt.bin")

# Build assertion input:
#   line 1: client data hash (base64)
#   line 2: relying party ID
#   line 3: credential ID (base64)
#   line 4: hmac salt (base64)
{
    echo "$CDH_B64"
    echo "$RELYING_PARTY"
    echo "$CRED_ID_B64"
    echo "$SALT_B64"
} > "$WORK_DIR/assert_input.txt"

# Get assertion with hmac-secret enabled
# Use stdin/stdout redirection for portability
if ! fido2-assert -G -h "$FIDO2_DEVICE" \
        < "$WORK_DIR/assert_input.txt" \
        > "$WORK_DIR/assert_output.txt" 2>/dev/null; then
    echo "tpm-fido2: FIDO2 assertion failed (timeout or user declined)"
    echo "tpm-fido2: Falling back to passphrase"
    exit 0
fi

# Extract the HMAC secret: it's the last line of the assertion output
# (line 5 for non-resident credentials, line 6 for resident)
HMAC_SECRET_B64=$(tail -1 "$WORK_DIR/assert_output.txt")
echo "$HMAC_SECRET_B64" | base64 -d > "$WORK_DIR/fido2_hmac.bin" 2>/dev/null

HMAC_SIZE=$(wc -c < "$WORK_DIR/fido2_hmac.bin")
if [[ "$HMAC_SIZE" -ne 32 ]]; then
    # Scan all lines; keep last 32-byte match (HMAC is always the final field)
    while IFS= read -r line; do
        decoded_size=$(echo "$line" | base64 -d 2>/dev/null | wc -c)
        if [[ "$decoded_size" -eq 32 ]]; then
            HMAC_SECRET_B64="$line"
            HMAC_SIZE=32
        fi
    done < "$WORK_DIR/assert_output.txt"
    if [[ "$HMAC_SIZE" -eq 32 ]]; then
        echo "$HMAC_SECRET_B64" | base64 -d > "$WORK_DIR/fido2_hmac.bin"
    fi
    if [[ "$HMAC_SIZE" -ne 32 ]]; then
        echo "tpm-fido2: HMAC secret extraction failed, falling back to passphrase"
        exit 0
    fi
fi
echo "tpm-fido2: FIDO2 HMAC obtained"

# --- Derive LUKS key (raw 32 bytes) ---
cat "$WORK_DIR/salt.bin" "$WORK_DIR/fido2_hmac.bin" > "$WORK_DIR/combined.bin"
sha256sum "$WORK_DIR/combined.bin" | cut -d' ' -f1 | xxd -r -p > "$WORK_DIR/luks_key.bin"

# --- Open LUKS volume ---
echo "tpm-fido2: Opening LUKS volume..."
if cryptsetup open "$LUKS_DEVICE" "$LUKS_NAME" --key-file="$WORK_DIR/luks_key.bin"; then
    echo "tpm-fido2: LUKS volume opened successfully"
else
    echo "tpm-fido2: LUKS open failed: derived key may be incorrect"
    echo "tpm-fido2: Falling back to passphrase"
    exit 0
fi

# --- Clean up secrets ---
shred -uzn1 "$WORK_DIR/salt.bin" "$WORK_DIR/fido2_hmac.bin" \
             "$WORK_DIR/combined.bin" "$WORK_DIR/luks_key.bin" \
             "$WORK_DIR/seal.pub" "$WORK_DIR/seal.priv" \
             "$WORK_DIR/assert_output.txt" \
             "$WORK_DIR/assert_input.txt" 2>/dev/null
unset SALT_B64 CDH_B64 HMAC_SECRET_B64

echo "tpm-fido2: Secrets shredded from memory"
