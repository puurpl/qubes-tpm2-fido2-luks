#!/bin/bash
# =============================================================================
# enroll-fido2.sh: FIDO2 enrollment (runs in a USB-capable qube)
#
# Part 1 of split enrollment for Qubes OS, where dom0 cannot access USB.
# Run this in any qube that can see the FIDO2 token (via sys-usb).
#
# This script:
#   1. Generates a random 32-byte salt
#   2. Creates a FIDO2 credential on the token
#   3. Computes HMAC(device_secret, salt) via the hmac-secret extension
#   4. Packages artifacts for transfer to dom0
#
# After this script completes, transfer the output bundle to dom0 and
# run enroll-dom0.sh to finish enrollment (TPM sealing + LUKS keyslot).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/../config/tpm-fido2-luks.conf"

# --- Load configuration ---
if [[ ! -f "$CONF_FILE" ]]; then
    echo "ERROR: Configuration file not found: $CONF_FILE"
    exit 1
fi

# Parse config (safe explicit parsing, no source)
ALLOWED_KEYS="LUKS_DEVICE LUKS_NAME PCR_BANKS TPM_HANDLE RELYING_PARTY FIDO2_USB_VID FIDO2_USB_PID FIDO2_TIMEOUT CONF_DIR"
while IFS='=' read -r key val; do
    [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
    key=$(echo "$key" | tr -d '[:space:]')
    val=$(echo "$val" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^"\(.*\)"$/\1/;s/^'"'"'\(.*\)'"'"'$/\1/')
    if ! echo "$ALLOWED_KEYS" | grep -qw "$key"; then
        echo "WARNING: Ignoring unknown config key: $key"
        continue
    fi
    declare "$key=$val"
done < "$CONF_FILE"

# --- Sanity checks ---
for cmd in fido2-token fido2-cred fido2-assert sha256sum base64 xxd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command not found: $cmd"
        exit 1
    fi
done

# --- Find FIDO2 token ---
echo "=== Looking for FIDO2 token ==="
FIDO2_DEVICE=""
FIDO2_USB_VID_HEX="0x${FIDO2_USB_VID:-1209}"
FIDO2_USB_PID_HEX="0x${FIDO2_USB_PID:-53c1}"

# Try fido2-token -L first (most reliable: lists all FIDO2 devices)
if command -v fido2-token &>/dev/null; then
    while IFS=: read -r dev_path dev_info; do
        [[ -z "$dev_path" ]] && continue
        dev_path=$(echo "$dev_path" | tr -d '[:space:]')
        [[ -e "$dev_path" ]] || continue
        FIDO2_DEVICE="$dev_path"
        break
    done < <(fido2-token -L 2>/dev/null)
fi

if [[ -z "$FIDO2_DEVICE" ]]; then
    echo "ERROR: No FIDO2 token found."
    echo "Make sure the token is attached to this qube via sys-usb."
    echo ""
    echo "Available HID devices:"
    fido2-token -L 2>/dev/null || echo "  (none)"
    exit 1
fi
echo "[OK] FIDO2 token found: $FIDO2_DEVICE"
fido2-token -I "$FIDO2_DEVICE" 2>/dev/null | head -5

# --- Working directory ---
WORK_DIR=$(mktemp -d /tmp/tpm-fido2-enroll.XXXXXX)
chmod 700 "$WORK_DIR"
trap 'shred -uzn3 "$WORK_DIR"/* 2>/dev/null; rmdir "$WORK_DIR" 2>/dev/null' EXIT

# --- Output directory (survives cleanup for transfer to dom0) ---
OUTPUT_DIR="/tmp/tpm-fido2-artifacts"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

echo ""
echo "=== Phase 1: Generate salt ==="
dd if=/dev/urandom bs=32 count=1 of="$WORK_DIR/salt.bin" 2>/dev/null
SALT_B64=$(base64 -w0 < "$WORK_DIR/salt.bin")
echo "[OK] Generated 32-byte random salt"

echo ""
echo "=== Phase 2: Create FIDO2 credential ==="
echo ""
echo ">>> Your FIDO2 token will prompt for PIN + confirmation. <<<"
echo ""

# Generate a random client data hash
dd if=/dev/urandom bs=32 count=1 of="$WORK_DIR/cdh.bin" 2>/dev/null
CDH_B64=$(base64 -w0 < "$WORK_DIR/cdh.bin")

# Generate a user ID
USER_ID_B64=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 -w0)

# Credential input: cdh, rp, username, user_id
{
    echo "$CDH_B64"
    echo "${RELYING_PARTY:-qubes-luks-unlock}"
    echo "qubes-user"
    echo "$USER_ID_B64"
} > "$WORK_DIR/cred_input.txt"

# Make credential with hmac-secret
if ! fido2-cred -M -h "$FIDO2_DEVICE" \
        < "$WORK_DIR/cred_input.txt" \
        > "$WORK_DIR/cred_output.txt"; then
    echo "ERROR: Failed to create FIDO2 credential. Did you confirm on the device?"
    exit 1
fi
echo "[OK] FIDO2 credential created"

# Extract credential ID from fido2-cred output
# Newer libfido2 versions output it directly on line 5.
# Older versions require parsing it from the authenticator data (line 4).
CRED_ID_B64=""

# Try line 5 first (direct credential ID: newer libfido2)
LINE5=$(sed -n '5p' "$WORK_DIR/cred_output.txt")
if [[ -n "$LINE5" ]]; then
    LINE5_SIZE=$(echo "$LINE5" | base64 -d 2>/dev/null | wc -c)
    if [[ "$LINE5_SIZE" -gt 0 && "$LINE5_SIZE" -lt 1024 ]]; then
        CRED_ID_B64="$LINE5"
        echo "[OK] Credential ID from line 5 (${LINE5_SIZE} bytes)"
    fi
fi

# Fallback: parse from authenticator data (lines 4, 3)
if [[ -z "$CRED_ID_B64" ]]; then
    for authdata_line in 4 3; do
        AUTHDATA_B64=$(sed -n "${authdata_line}p" "$WORK_DIR/cred_output.txt")
        echo "$AUTHDATA_B64" | base64 -d > "$WORK_DIR/authdata.bin" 2>/dev/null || continue

        AUTHDATA_SIZE=$(wc -c < "$WORK_DIR/authdata.bin")
        [[ "$AUTHDATA_SIZE" -lt 55 ]] && continue

        FLAGS_BYTE=$(dd if="$WORK_DIR/authdata.bin" bs=1 skip=32 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
        if [[ $((FLAGS_BYTE & 64)) -eq 0 ]]; then
            continue
        fi

        BYTE_HI=$(dd if="$WORK_DIR/authdata.bin" bs=1 skip=53 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
        BYTE_LO=$(dd if="$WORK_DIR/authdata.bin" bs=1 skip=54 count=1 2>/dev/null | od -A n -t u1 | tr -d ' ')
        CRED_ID_LEN=$(( (BYTE_HI << 8) | BYTE_LO ))

        if [[ "$CRED_ID_LEN" -gt 0 && "$CRED_ID_LEN" -lt 1024 && \
              $((55 + CRED_ID_LEN)) -le "$AUTHDATA_SIZE" ]]; then
            CRED_ID_B64=$(dd if="$WORK_DIR/authdata.bin" bs=1 skip=55 count="$CRED_ID_LEN" 2>/dev/null | base64 -w0)
            echo "[OK] Credential ID from authdata line $authdata_line (${CRED_ID_LEN} bytes)"
            break
        fi
    done
fi

if [[ -z "$CRED_ID_B64" ]]; then
    echo "ERROR: Failed to extract credential ID."
    echo "fido2-cred output:"
    cat "$WORK_DIR/cred_output.txt"
    exit 1
fi

echo ""
echo "=== Phase 3: Compute FIDO2 HMAC ==="
echo ""
echo ">>> Token will prompt again: PIN + confirm for assertion. <<<"
echo ""

# New random challenge for the assertion
dd if=/dev/urandom bs=32 count=1 of="$WORK_DIR/assert_cdh.bin" 2>/dev/null
ASSERT_CDH_B64=$(base64 -w0 < "$WORK_DIR/assert_cdh.bin")

# Assertion input: cdh, rp, cred_id, salt
{
    echo "$ASSERT_CDH_B64"
    echo "${RELYING_PARTY:-qubes-luks-unlock}"
    echo "$CRED_ID_B64"
    echo "$SALT_B64"
} > "$WORK_DIR/assert_input.txt"

# Get assertion with hmac-secret
if ! fido2-assert -G -h "$FIDO2_DEVICE" \
        < "$WORK_DIR/assert_input.txt" \
        > "$WORK_DIR/assert_output.txt"; then
    echo "ERROR: FIDO2 assertion failed. Did you confirm on the device?"
    exit 1
fi

# Extract HMAC secret (last 32-byte base64 value)
HMAC_SECRET_B64=$(tail -1 "$WORK_DIR/assert_output.txt")
echo "$HMAC_SECRET_B64" | base64 -d > "$WORK_DIR/fido2_hmac.bin"

HMAC_SIZE=$(wc -c < "$WORK_DIR/fido2_hmac.bin")
if [[ "$HMAC_SIZE" -ne 32 ]]; then
    echo "WARNING: HMAC secret is $HMAC_SIZE bytes (expected 32), scanning all lines..."
    while IFS= read -r line; do
        decoded_size=$(echo "$line" | base64 -d 2>/dev/null | wc -c)
        if [[ "$decoded_size" -eq 32 ]]; then
            HMAC_SECRET_B64="$line"
            HMAC_SIZE=32
        fi
    done < "$WORK_DIR/assert_output.txt"
    if [[ "$HMAC_SIZE" -eq 32 ]]; then
        echo "$HMAC_SECRET_B64" | base64 -d > "$WORK_DIR/fido2_hmac.bin"
        echo "[OK] Found 32-byte value (last match)"
    else
        echo "ERROR: Could not extract 32-byte HMAC secret from assertion."
        exit 1
    fi
fi
echo "[OK] FIDO2 HMAC secret obtained (32 bytes)"

# --- Package artifacts for dom0 ---
echo ""
echo "=== Packaging artifacts ==="

cp "$WORK_DIR/salt.bin" "$OUTPUT_DIR/salt.bin"
cp "$WORK_DIR/fido2_hmac.bin" "$OUTPUT_DIR/fido2_hmac.bin"
echo "$CRED_ID_B64" > "$OUTPUT_DIR/credential_id"
echo "${RELYING_PARTY:-qubes-luks-unlock}" > "$OUTPUT_DIR/relying_party"
chmod 600 "$OUTPUT_DIR"/*

echo ""
echo "=========================================="
echo "  FIDO2 ENROLLMENT COMPLETE"
echo "=========================================="
echo ""
echo "Artifacts saved to: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
echo ""
echo "=== Next: transfer to dom0 ==="
echo ""
echo "In a dom0 terminal, run:"
echo ""
echo "  qvm-run --pass-io $(hostname) 'sudo tar -czf - -C /tmp tpm-fido2-artifacts' \\"
echo "      > /tmp/tpm-fido2-artifacts.tar.gz"
echo "  cd /tmp && tar xzf tpm-fido2-artifacts.tar.gz"
echo ""
echo "Then run enroll-dom0.sh in dom0:"
echo ""
echo "  cd /tmp/tpm-fido2-luks"
echo "  sudo bash scripts/enroll-dom0.sh /tmp/tpm-fido2-artifacts"
echo ""
echo "SECURITY: These artifacts contain secret material (HMAC)."
echo "Transfer promptly and destroy this qube (or wipe $OUTPUT_DIR)."
