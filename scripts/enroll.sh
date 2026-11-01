#!/bin/bash
# =============================================================================
# enroll.sh: One-time enrollment for TPM-sealed FIDO2 LUKS unlock
#
# Run this in dom0 with your FIDO2 token plugged in.
# Requires: tpm2-tools, libfido2, fido2-tools, cryptsetup
#
# This script:
#   1. Generates a random 32-byte salt
#   2. Creates a FIDO2 credential on the token
#   3. Computes HMAC(device_secret, salt) via the FIDO2 hmac-secret extension
#   4. Derives a LUKS key from SHA-256(salt ‖ hmac_result)
#   5. Enrolls the key as a new LUKS keyslot
#   6. Seals the salt in the TPM bound to PCR values
#   7. Creates an encrypted backup of the salt (for kernel update re-sealing)
#   8. Stores metadata needed by the initramfs unlock script
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/../config/tpm-fido2-luks.conf"

# --- Load configuration (explicit parsing, no arbitrary code execution) ---
if [[ ! -f "$CONF_FILE" ]]; then
    echo "ERROR: Configuration file not found: $CONF_FILE"
    echo "Copy config/tpm-fido2-luks.conf and edit it first."
    exit 1
fi

ALLOWED_KEYS="LUKS_DEVICE LUKS_NAME PCR_BANKS TPM_HANDLE RELYING_PARTY FIDO2_USB_VID FIDO2_USB_PID FIDO2_TIMEOUT CONF_DIR"
while IFS='=' read -r key val; do
    # Skip comments and blank lines
    [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
    # Strip leading/trailing whitespace
    key=$(echo "$key" | tr -d '[:space:]')
    # Strip surrounding quotes from value
    val=$(echo "$val" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^"\(.*\)"$/\1/;s/^'"'"'\(.*\)'"'"'$/\1/')
    # Only accept known variable names
    if ! echo "$ALLOWED_KEYS" | grep -qw "$key"; then
        echo "WARNING: Ignoring unknown config key: $key"
        continue
    fi
    declare "$key=$val"
done < "$CONF_FILE"

if [[ "${LUKS_DEVICE:-}" == "/dev/changeme" || -z "${LUKS_DEVICE:-}" ]]; then
    echo "ERROR: Edit $CONF_FILE and set LUKS_DEVICE before running."
    exit 1
fi

# --- Sanity checks ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root in dom0."
    exit 1
fi

for cmd in tpm2_pcrread tpm2_createprimary tpm2_create tpm2_load tpm2_unseal \
           tpm2_evictcontrol tpm2_startauthsession tpm2_policypcr \
           tpm2_flushcontext fido2-token fido2-cred fido2-assert \
           cryptsetup sha256sum base64 xxd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command not found: $cmd"
        exit 1
    fi
done

HAS_OPENSSL=false
if command -v openssl &>/dev/null && openssl version &>/dev/null; then
    HAS_OPENSSL=true
fi

# --- Verify LUKS device ---
if ! cryptsetup isLuks "$LUKS_DEVICE" 2>/dev/null; then
    echo "ERROR: $LUKS_DEVICE is not a LUKS device."
    exit 1
fi

LUKS_VERSION=$(cryptsetup luksDump "$LUKS_DEVICE" | grep "Version:" | awk '{print $2}')
if [[ "$LUKS_VERSION" != "2" ]]; then
    echo "ERROR: LUKS version $LUKS_VERSION detected. LUKS2 is required."
    exit 1
fi
echo "[OK] LUKS2 device: $LUKS_DEVICE"

# --- Verify TPM2 ---
echo ""
echo "=== Verifying TPM2 ==="
if ! tpm2_pcrread "$PCR_BANKS" &>/dev/null; then
    echo "ERROR: Cannot read TPM2 PCRs. Is the TPM available?"
    exit 1
fi
echo "[OK] TPM2 PCR banks readable: $PCR_BANKS"
echo ""
echo "Current PCR values (these will be bound to the sealed salt):"
tpm2_pcrread "$PCR_BANKS"

# --- Find FIDO2 token ---
echo ""
echo "=== Looking for FIDO2 token ==="
FIDO2_DEVICE=""

# Use fido2-token -L (lists all FIDO2-capable devices with their paths)
while IFS=: read -r dev_path dev_info; do
    [[ -z "$dev_path" ]] && continue
    dev_path=$(echo "$dev_path" | tr -d '[:space:]')
    [[ -e "$dev_path" ]] || continue
    FIDO2_DEVICE="$dev_path"
    break
done < <(fido2-token -L 2>/dev/null)

if [[ -z "$FIDO2_DEVICE" ]]; then
    echo "ERROR: No FIDO2 token found. Plug in your FIDO2 security key."
    echo "Available HID devices:"
    fido2-token -L 2>/dev/null || echo "  (none)"
    exit 1
fi
echo "[OK] FIDO2 token found: $FIDO2_DEVICE"
fido2-token -I "$FIDO2_DEVICE" 2>/dev/null | head -5

# --- Working directory (tmpfs for secret material) ---
WORK_DIR=$(mktemp -d -p /dev/shm tpm-fido2-enroll.XXXXXX)
chmod 700 "$WORK_DIR"
trap 'echo "Cleaning up..."; shred -uzn3 "$WORK_DIR"/* 2>/dev/null; rmdir "$WORK_DIR" 2>/dev/null' EXIT

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

# Generate a random client data hash (32 bytes, used as challenge)
dd if=/dev/urandom bs=32 count=1 of="$WORK_DIR/cdh.bin" 2>/dev/null
CDH_B64=$(base64 -w0 < "$WORK_DIR/cdh.bin")

# Generate a user ID
USER_ID_B64=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 -w0)

# Create credential input:
#   line 1: client data hash (base64)
#   line 2: relying party ID
#   line 3: user name
#   line 4: user ID (base64)
{
    echo "$CDH_B64"
    echo "$RELYING_PARTY"
    echo "qubes-user"
    echo "$USER_ID_B64"
} > "$WORK_DIR/cred_input.txt"

# Make credential (-M) with hmac-secret enabled (-h)
# Use stdin/stdout redirection (portable across libfido2 versions)
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

# Assertion input:
#   line 1: client data hash (base64)
#   line 2: relying party ID
#   line 3: credential ID (base64)
#   line 4: hmac salt (base64): our TPM salt
{
    echo "$ASSERT_CDH_B64"
    echo "$RELYING_PARTY"
    echo "$CRED_ID_B64"
    echo "$SALT_B64"
} > "$WORK_DIR/assert_input.txt"

# Get assertion (-G) with hmac-secret (-h)
# Use stdin/stdout redirection (portable across libfido2 versions)
if ! fido2-assert -G -h "$FIDO2_DEVICE" \
        < "$WORK_DIR/assert_input.txt" \
        > "$WORK_DIR/assert_output.txt"; then
    echo "ERROR: FIDO2 assertion failed. Did you confirm on the device?"
    exit 1
fi

# HMAC secret is line 6 of the assertion output (base64)
# Output format: cdh, rp, authdata, sig, [user_id], hmac_secret
# For non-resident credentials, user_id is omitted, so hmac_secret is line 5
HMAC_SECRET_B64=$(tail -1 "$WORK_DIR/assert_output.txt")
echo "$HMAC_SECRET_B64" | base64 -d > "$WORK_DIR/fido2_hmac.bin"

HMAC_SIZE=$(wc -c < "$WORK_DIR/fido2_hmac.bin")
if [[ "$HMAC_SIZE" -ne 32 ]]; then
    echo "WARNING: HMAC secret is $HMAC_SIZE bytes (expected 32)."
    echo "Assertion output:"
    cat "$WORK_DIR/assert_output.txt"
    echo ""
    echo "This may indicate the hmac-secret wasn't returned correctly."
    echo "Attempting to parse all output lines..."
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
        echo "[OK] Found 32-byte value (last match)"
    fi
    if [[ "$HMAC_SIZE" -ne 32 ]]; then
        echo "ERROR: Could not extract 32-byte HMAC secret from assertion."
        exit 1
    fi
fi
echo "[OK] FIDO2 HMAC secret obtained (32 bytes)"

echo ""
echo "=== Phase 4: Derive LUKS key ==="

# LUKS key = SHA-256(salt ‖ hmac_result) as raw 32 bytes
cat "$WORK_DIR/salt.bin" "$WORK_DIR/fido2_hmac.bin" > "$WORK_DIR/combined.bin"
sha256sum "$WORK_DIR/combined.bin" | cut -d' ' -f1 | xxd -r -p > "$WORK_DIR/luks_key.bin"
echo "[OK] LUKS key derived: SHA-256(salt ‖ hmac) (32 bytes raw)"

echo ""
echo "=== Phase 5: Enroll LUKS keyslot ==="
echo ""
echo "You will be prompted for your EXISTING LUKS passphrase to authorize"
echo "adding the new keyslot."
echo ""

cryptsetup luksAddKey "$LUKS_DEVICE" "$WORK_DIR/luks_key.bin"
echo "[OK] New LUKS keyslot enrolled"

# Verify it works
echo ""
echo "Verifying new keyslot can open the device..."
cryptsetup open --test-passphrase "$LUKS_DEVICE" --key-file="$WORK_DIR/luks_key.bin"
echo "[OK] Keyslot verification passed"

echo ""
echo "=== Phase 6: Seal salt in TPM ==="

# Read current PCR values for the policy
tpm2_pcrread -o "$WORK_DIR/pcr_current.bin" "$PCR_BANKS"

# Create primary key under the owner hierarchy
tpm2_createprimary -C o -g sha256 -G rsa -c "$WORK_DIR/primary.ctx"

# Create PCR policy
tpm2_startauthsession -S "$WORK_DIR/session.ctx"
tpm2_policypcr -S "$WORK_DIR/session.ctx" \
    -l "$PCR_BANKS" \
    -L "$WORK_DIR/pcr_policy.bin"
tpm2_flushcontext "$WORK_DIR/session.ctx"

# Seal the salt under the PCR policy
tpm2_create -C "$WORK_DIR/primary.ctx" \
    -i "$WORK_DIR/salt.bin" \
    -L "$WORK_DIR/pcr_policy.bin" \
    -u "$WORK_DIR/seal.pub" \
    -r "$WORK_DIR/seal.priv"

echo "[OK] Salt sealed in TPM with PCR policy"

# Make the primary key persistent (survives reboot)
# Check if handle is already occupied and warn before evicting
if tpm2_readpublic -c "$TPM_HANDLE" &>/dev/null; then
    echo ""
    echo "WARNING: TPM persistent handle $TPM_HANDLE is already occupied."
    echo "Evicting it will break anything that depends on this handle."
    read -rp "Evict existing key and continue? (y/N) " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy] ]]; then
        echo "Aborted. Choose a different TPM_HANDLE in the config file."
        exit 1
    fi
    tpm2_evictcontrol -C o -c "$TPM_HANDLE"
fi
tpm2_evictcontrol -C o -c "$WORK_DIR/primary.ctx" "$TPM_HANDLE"
echo "[OK] Primary key persisted at handle $TPM_HANDLE"

# Verify unseal works with current PCRs
tpm2_load -C "$TPM_HANDLE" \
    -u "$WORK_DIR/seal.pub" \
    -r "$WORK_DIR/seal.priv" \
    -c "$WORK_DIR/sealed.ctx"

tpm2_startauthsession -S "$WORK_DIR/verify_session.ctx" --policy-session
tpm2_policypcr -S "$WORK_DIR/verify_session.ctx" -l "$PCR_BANKS"
UNSEALED_SALT=$(tpm2_unseal -c "$WORK_DIR/sealed.ctx" -p "session:$WORK_DIR/verify_session.ctx" | base64 -w0)
tpm2_flushcontext "$WORK_DIR/verify_session.ctx"

if [[ "$UNSEALED_SALT" == "$SALT_B64" ]]; then
    echo "[OK] TPM unseal verification passed: salt matches"
else
    echo "ERROR: TPM unseal returned different data. Something is wrong."
    echo "This should not happen. Do NOT reboot."
    exit 1
fi

echo ""
echo "=== Phase 7: Store sealed objects in LUKS2 header ==="

# Store seal.pub/seal.priv as a LUKS2 custom token so the initramfs unlock
# script can read them from the LUKS header (unencrypted metadata area).
# This avoids baking them into the initramfs, which would change PCR 9 on
# every reseal and create a chicken-and-egg problem.
SEAL_PUB_B64=$(base64 -w0 < "$WORK_DIR/seal.pub")
SEAL_PRIV_B64=$(base64 -w0 < "$WORK_DIR/seal.priv")
cat > "$WORK_DIR/token.json" <<TOKEOF
{"type":"tpm-fido2-luks","keyslots":[],"tpm_seal_pub":"$SEAL_PUB_B64","tpm_seal_priv":"$SEAL_PRIV_B64"}
TOKEOF

# Remove any existing tpm-fido2-luks token first
for tid in $(seq 0 31); do
    tj=$(cryptsetup token export "$LUKS_DEVICE" --token-id "$tid" 2>/dev/null) || continue
    if echo "$tj" | grep -q '"tpm-fido2-luks"'; then
        cryptsetup token remove "$LUKS_DEVICE" --token-id "$tid"
        echo "[OK] Removed existing tpm-fido2-luks token (id=$tid)"
    fi
done

cryptsetup token import "$LUKS_DEVICE" --json-file "$WORK_DIR/token.json"
echo "[OK] Sealed objects stored as LUKS2 token"

echo ""
echo "=== Phase 8: Store metadata ==="

mkdir -p "$CONF_DIR"

# Sealed object blobs (local copies for debugging/verification)
cp "$WORK_DIR/seal.pub" "$CONF_DIR/seal.pub"
cp "$WORK_DIR/seal.priv" "$CONF_DIR/seal.priv"
chmod 600 "$CONF_DIR/seal.pub" "$CONF_DIR/seal.priv"

# Credential metadata (needed by initramfs for FIDO2 assertion)
echo "$CRED_ID_B64" > "$CONF_DIR/credential_id"
echo "$RELYING_PARTY" > "$CONF_DIR/relying_party"
echo "$PCR_BANKS" > "$CONF_DIR/pcr_banks"
echo "$TPM_HANDLE" > "$CONF_DIR/tpm_handle"
echo "$LUKS_DEVICE" > "$CONF_DIR/luks_device"
echo "$LUKS_NAME" > "$CONF_DIR/luks_name"
echo "${FIDO2_TIMEOUT:-30}" > "$CONF_DIR/fido2_timeout"
echo "${FIDO2_USB_VID:-1209}:${FIDO2_USB_PID:-53c1}" > "$CONF_DIR/fido2_usb_id"
chmod 600 "$CONF_DIR"/*

echo "[OK] Metadata stored in $CONF_DIR"

if [[ "$HAS_OPENSSL" == true ]]; then
    echo ""
    echo "=== Phase 9: Create encrypted salt backup ==="
    echo ""
    echo "Enter your LUKS passphrase again to encrypt the salt backup."
    echo "(This backup is used to re-seal after kernel updates.)"
    echo ""

    read -rs -p "LUKS passphrase: " PASSPHRASE
    echo ""

    echo -n "$PASSPHRASE" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "$WORK_DIR/salt.bin" -out "$CONF_DIR/salt.enc" \
        -pass stdin
    chmod 600 "$CONF_DIR/salt.enc"

    openssl dgst -sha256 -hmac "$PASSPHRASE" -binary "$CONF_DIR/salt.enc" \
        > "$CONF_DIR/salt.enc.mac"
    chmod 600 "$CONF_DIR/salt.enc.mac"
    unset PASSPHRASE

    echo "[OK] Encrypted salt backup stored at $CONF_DIR/salt.enc (with HMAC)"
else
    echo ""
    echo "=== Phase 9: Encrypted salt backup SKIPPED ==="
    echo "openssl is not available. Install it later and create the backup manually."
fi

echo ""
echo "=========================================="
echo "  ENROLLMENT COMPLETE"
echo "=========================================="
echo ""
echo "Files stored in $CONF_DIR/:"
ls -la "$CONF_DIR/"
echo ""
echo "Next steps:"
echo "  1. Run install.sh to install the dracut module"
echo "  2. Rebuild initramfs: dracut -f --add tpm-fido2-luks"
echo "  3. Verify rescue kernel is available in GRUB"
echo "  4. Reboot and test (keep passphrase ready as fallback)"
echo ""
echo "IMPORTANT: Do NOT remove your passphrase LUKS keyslot."
echo "It is your recovery path if the token or TPM fails."
