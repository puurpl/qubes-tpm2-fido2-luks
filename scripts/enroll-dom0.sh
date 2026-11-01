#!/bin/bash
# =============================================================================
# enroll-dom0.sh: TPM sealing + LUKS enrollment (runs in dom0)
#
# Part 2 of split enrollment for Qubes OS.
# Run this in dom0 after enroll-fido2.sh has produced the artifact bundle.
#
# This script:
#   1. Reads salt + HMAC + credential_id from the artifact bundle
#   2. Derives the LUKS key from SHA-256(salt ‖ hmac)
#   3. Enrolls the key as a new LUKS keyslot
#   4. Seals the salt in the TPM bound to PCR values
#   5. Stores sealed objects in the LUKS2 header token
#   6. Stores metadata for initramfs
#   7. Creates an encrypted backup of the salt
#
# Usage: sudo bash enroll-dom0.sh /path/to/tpm-fido2-artifacts
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/../config/tpm-fido2-luks.conf"

# --- Artifact directory (from enroll-fido2.sh) ---
ARTIFACT_DIR="${1:-}"
if [[ -z "$ARTIFACT_DIR" || ! -d "$ARTIFACT_DIR" ]]; then
    echo "Usage: sudo bash $0 /path/to/tpm-fido2-artifacts"
    echo ""
    echo "Run enroll-fido2.sh in a USB-capable qube first to generate the artifacts."
    exit 1
fi

# --- Load configuration ---
if [[ ! -f "$CONF_FILE" ]]; then
    echo "ERROR: Configuration file not found: $CONF_FILE"
    exit 1
fi

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
           tpm2_flushcontext cryptsetup sha256sum base64 xxd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command not found: $cmd"
        exit 1
    fi
done

HAS_OPENSSL=false
if command -v openssl &>/dev/null && openssl version &>/dev/null; then
    HAS_OPENSSL=true
fi

# --- Validate artifacts ---
echo "=== Validating artifacts from FIDO2 enrollment ==="
for f in salt.bin fido2_hmac.bin credential_id relying_party; do
    if [[ ! -f "$ARTIFACT_DIR/$f" ]]; then
        echo "ERROR: Missing artifact: $ARTIFACT_DIR/$f"
        echo "Did enroll-fido2.sh complete successfully?"
        exit 1
    fi
done

SALT_SIZE=$(wc -c < "$ARTIFACT_DIR/salt.bin")
if [[ "$SALT_SIZE" -ne 32 ]]; then
    echo "ERROR: salt.bin is $SALT_SIZE bytes (expected 32)"
    exit 1
fi

HMAC_SIZE=$(wc -c < "$ARTIFACT_DIR/fido2_hmac.bin")
if [[ "$HMAC_SIZE" -ne 32 ]]; then
    echo "ERROR: fido2_hmac.bin is $HMAC_SIZE bytes (expected 32)"
    exit 1
fi

CRED_ID_B64=$(cat "$ARTIFACT_DIR/credential_id")
ARTIFACT_RP=$(cat "$ARTIFACT_DIR/relying_party")
if [[ "$ARTIFACT_RP" != "${RELYING_PARTY:-qubes-luks-unlock}" ]]; then
    echo "WARNING: Relying party mismatch!"
    echo "  Artifact: $ARTIFACT_RP"
    echo "  Config:   ${RELYING_PARTY:-qubes-luks-unlock}"
    echo "Using artifact value (must match what the token was enrolled with)."
    RELYING_PARTY="$ARTIFACT_RP"
fi

echo "[OK] Artifacts validated (salt: 32 bytes, HMAC: 32 bytes, credential ID present)"

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

# --- Working directory (tmpfs) ---
WORK_DIR=$(mktemp -d -p /dev/shm tpm-fido2-enroll.XXXXXX)
chmod 700 "$WORK_DIR"
trap 'echo "Cleaning up..."; shred -uzn3 "$WORK_DIR"/* 2>/dev/null; rmdir "$WORK_DIR" 2>/dev/null' EXIT

# Copy artifacts to working dir
cp "$ARTIFACT_DIR/salt.bin" "$WORK_DIR/salt.bin"
cp "$ARTIFACT_DIR/fido2_hmac.bin" "$WORK_DIR/fido2_hmac.bin"
SALT_B64=$(base64 -w0 < "$WORK_DIR/salt.bin")

echo ""
echo "=== Phase 1: Derive LUKS key ==="

# LUKS key = SHA-256(salt ‖ hmac_result) as raw 32 bytes
cat "$WORK_DIR/salt.bin" "$WORK_DIR/fido2_hmac.bin" > "$WORK_DIR/combined.bin"
sha256sum "$WORK_DIR/combined.bin" | cut -d' ' -f1 | xxd -r -p > "$WORK_DIR/luks_key.bin"
echo "[OK] LUKS key derived: SHA-256(salt || hmac) (32 bytes raw)"

echo ""
echo "=== Phase 2: Enroll LUKS keyslot ==="
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
echo "=== Phase 3: Seal salt in TPM ==="

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

# Make the primary key persistent
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

# Verify unseal works
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
    exit 1
fi

echo ""
echo "=== Phase 4: Store sealed objects in LUKS2 header ==="

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
echo "=== Phase 5: Store metadata ==="

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
    echo "=== Phase 6: Create encrypted salt backup ==="
    echo ""
    echo "Enter your LUKS passphrase to encrypt the salt backup."
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
    echo "=== Phase 6: Encrypted salt backup SKIPPED ==="
    echo "openssl is not available or not working."
    echo "The salt backup (salt.enc + salt.enc.mac) is needed for reseal.sh"
    echo "after kernel updates. Install openssl and create the backup before"
    echo "you depend on token unlock across kernel updates."
    echo "WARNING: Without the backup, you'll need to re-enroll from scratch"
    echo "if a kernel update changes the PCR values."
fi

# --- Wipe the artifact directory ---
echo ""
echo "Wiping artifact bundle..."
shred -uzn3 "$ARTIFACT_DIR"/* 2>/dev/null
rmdir "$ARTIFACT_DIR" 2>/dev/null
echo "[OK] Artifacts destroyed"

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
echo ""
echo "SECURITY: Destroy the enrollment qube if it was a DispVM,"
echo "or wipe /tmp/tpm-fido2-artifacts in the enrollment qube."
