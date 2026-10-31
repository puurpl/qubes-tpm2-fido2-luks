#!/bin/bash
# =============================================================================
# reseal.sh: Re-seal salt in TPM after kernel/initramfs update
#
# When the kernel or initramfs changes, PCR 9 changes, and the TPM can no
# longer unseal the salt. Run this script after booting with your passphrase
# to re-seal the salt with the new PCR values.
#
# Requires: the encrypted salt backup at /etc/tpm-fido2-luks/salt.enc
# =============================================================================

set -euo pipefail

CONF_DIR="/etc/tpm-fido2-luks"

# --- Sanity checks ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root in dom0."
    exit 1
fi

for f in seal.pub seal.priv credential_id relying_party pcr_banks tpm_handle luks_device salt.enc salt.enc.mac; do
    if [[ ! -f "$CONF_DIR/$f" ]]; then
        echo "ERROR: Missing $CONF_DIR/$f: was enrollment completed?"
        exit 1
    fi
done

PCR_BANKS=$(cat "$CONF_DIR/pcr_banks")
TPM_HANDLE=$(cat "$CONF_DIR/tpm_handle")
LUKS_DEVICE=$(cat "$CONF_DIR/luks_device")

echo "=== TPM-FIDO2-LUKS Re-seal ==="
echo ""
echo "Current PCR values (new, after kernel/initramfs update):"
tpm2_pcrread "$PCR_BANKS"
echo ""

# --- Working directory on tmpfs ---
WORK_DIR=$(mktemp -d -p /dev/shm tpm-fido2-reseal.XXXXXX)
chmod 700 "$WORK_DIR"
trap 'shred -uzn3 "$WORK_DIR"/* 2>/dev/null; rmdir "$WORK_DIR" 2>/dev/null' EXIT

# --- Decrypt the salt backup ---
echo "Enter your LUKS passphrase to decrypt the salt backup:"
read -rs -p "LUKS passphrase: " PASSPHRASE
echo ""

# Verify HMAC integrity of the encrypted backup before attempting decryption
openssl dgst -sha256 -hmac "$PASSPHRASE" -binary "$CONF_DIR/salt.enc" \
    > "$WORK_DIR/verify.mac"
if ! diff -q "$CONF_DIR/salt.enc.mac" "$WORK_DIR/verify.mac" >/dev/null 2>&1; then
    unset PASSPHRASE
    shred -uzn1 "$WORK_DIR/verify.mac" 2>/dev/null
    echo "ERROR: Salt backup integrity check failed."
    echo "Either the passphrase is wrong or salt.enc has been tampered with."
    exit 1
fi
shred -uzn1 "$WORK_DIR/verify.mac" 2>/dev/null
echo "[OK] Salt backup integrity verified (HMAC match)"

if ! echo -n "$PASSPHRASE" | openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 \
        -in "$CONF_DIR/salt.enc" -out "$WORK_DIR/salt.bin" \
        -pass stdin 2>/dev/null; then
    unset PASSPHRASE
    echo "ERROR: Failed to decrypt salt backup."
    exit 1
fi
unset PASSPHRASE

SALT_SIZE=$(wc -c < "$WORK_DIR/salt.bin")
if [[ "$SALT_SIZE" -ne 32 ]]; then
    echo "ERROR: Decrypted salt is $SALT_SIZE bytes (expected 32). Backup may be corrupt."
    exit 1
fi
echo "[OK] Salt decrypted (32 bytes)"

# --- Optionally verify the salt still produces the right LUKS key ---
echo ""
echo "Do you want to verify the salt + FIDO2 token can still unlock LUKS?"
echo "This requires your FIDO2 token to be plugged in. (y/N)"
read -r VERIFY
if [[ "$VERIFY" =~ ^[Yy] ]]; then
    FIDO2_DEVICE=""
    while IFS=: read -r dev_path dev_info; do
        [[ -z "$dev_path" ]] && continue
        dev_path=$(echo "$dev_path" | tr -d '[:space:]')
        [[ -e "$dev_path" ]] || continue
        FIDO2_DEVICE="$dev_path"
        break
    done < <(fido2-token -L 2>/dev/null)
    if [[ -z "$FIDO2_DEVICE" ]]; then
        echo "WARNING: No FIDO2 token found. Skipping verification."
    else
        echo ">>> Enter PIN on token and confirm <<<"
        CRED_ID_B64=$(cat "$CONF_DIR/credential_id")
        RELYING_PARTY=$(cat "$CONF_DIR/relying_party")

        dd if=/dev/urandom bs=32 count=1 of="$WORK_DIR/cdh.bin" 2>/dev/null
        CDH_B64=$(base64 -w0 < "$WORK_DIR/cdh.bin")
        SALT_B64=$(base64 -w0 < "$WORK_DIR/salt.bin")

        {
            echo "$CDH_B64"
            echo "$RELYING_PARTY"
            echo "$CRED_ID_B64"
            echo "$SALT_B64"
        } > "$WORK_DIR/assert_input.txt"

        if fido2-assert -G -h "$FIDO2_DEVICE" \
                < "$WORK_DIR/assert_input.txt" \
                > "$WORK_DIR/assert_output.txt" 2>/dev/null; then
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
                else
                    echo "WARNING: Could not extract 32-byte HMAC. Skipping verification."
                fi
            fi
            cat "$WORK_DIR/salt.bin" "$WORK_DIR/fido2_hmac.bin" > "$WORK_DIR/combined.bin"
            sha256sum "$WORK_DIR/combined.bin" | cut -d' ' -f1 | xxd -r -p > "$WORK_DIR/luks_key.bin"

            if cryptsetup open --test-passphrase "$LUKS_DEVICE" --key-file="$WORK_DIR/luks_key.bin"; then
                echo "[OK] Verified: derived key unlocks LUKS"
            else
                echo "ERROR: Derived key does NOT unlock LUKS!"
                echo "The salt may have been corrupted. Do NOT re-seal."
                echo "You may need to re-enroll from scratch with enroll.sh."
                exit 1
            fi
        else
            echo "WARNING: FIDO2 assertion failed. Skipping verification."
        fi
    fi
fi

# --- Re-seal salt with new PCR values ---
echo ""
echo "=== Re-sealing salt in TPM ==="

# Create new PCR policy with CURRENT PCR values
tpm2_startauthsession -S "$WORK_DIR/session.ctx"
tpm2_policypcr -S "$WORK_DIR/session.ctx" \
    -l "$PCR_BANKS" \
    -L "$WORK_DIR/pcr_policy.bin"
tpm2_flushcontext "$WORK_DIR/session.ctx"

# Re-seal salt under the new policy
tpm2_create -C "$TPM_HANDLE" \
    -i "$WORK_DIR/salt.bin" \
    -L "$WORK_DIR/pcr_policy.bin" \
    -u "$WORK_DIR/seal.pub" \
    -r "$WORK_DIR/seal.priv"

echo "[OK] Salt re-sealed with new PCR policy"

# --- Verify unseal works ---
tpm2_load -C "$TPM_HANDLE" \
    -u "$WORK_DIR/seal.pub" \
    -r "$WORK_DIR/seal.priv" \
    -c "$WORK_DIR/sealed.ctx"

tpm2_startauthsession -S "$WORK_DIR/verify_session.ctx" --policy-session
tpm2_policypcr -S "$WORK_DIR/verify_session.ctx" -l "$PCR_BANKS"
tpm2_unseal -c "$WORK_DIR/sealed.ctx" \
    -p "session:$WORK_DIR/verify_session.ctx" \
    -o "$WORK_DIR/unsealed_salt.bin"
tpm2_flushcontext "$WORK_DIR/verify_session.ctx"

if diff -q "$WORK_DIR/salt.bin" "$WORK_DIR/unsealed_salt.bin" >/dev/null 2>&1; then
    echo "[OK] Unseal verification passed: salt matches"
else
    echo "ERROR: Unseal verification FAILED. Do not reboot."
    echo "The sealed object may be corrupt. Try running this script again."
    exit 1
fi

# --- Update LUKS2 header token ---
echo ""
echo "=== Updating LUKS2 header token ==="

SEAL_PUB_B64=$(base64 -w0 < "$WORK_DIR/seal.pub")
SEAL_PRIV_B64=$(base64 -w0 < "$WORK_DIR/seal.priv")
cat > "$WORK_DIR/token.json" <<TOKEOF
{"type":"tpm-fido2-luks","keyslots":[],"tpm_seal_pub":"$SEAL_PUB_B64","tpm_seal_priv":"$SEAL_PRIV_B64"}
TOKEOF

# Find and remove existing tpm-fido2-luks token
for tid in $(seq 0 31); do
    tj=$(cryptsetup token export "$LUKS_DEVICE" --token-id "$tid" 2>/dev/null) || continue
    if echo "$tj" | grep -q '"tpm-fido2-luks"'; then
        cryptsetup token remove "$LUKS_DEVICE" --token-id "$tid"
        echo "[OK] Removed old token (id=$tid)"
    fi
done

cryptsetup token import "$LUKS_DEVICE" --json-file "$WORK_DIR/token.json"
echo "[OK] New sealed objects stored in LUKS2 header token"

# --- Update local copies (for debugging/verification) ---
cp "$WORK_DIR/seal.pub" "$CONF_DIR/seal.pub"
cp "$WORK_DIR/seal.priv" "$CONF_DIR/seal.priv"
chmod 600 "$CONF_DIR/seal.pub" "$CONF_DIR/seal.priv"
echo "[OK] Updated $CONF_DIR/seal.pub and seal.priv"

# --- Re-encrypt salt backup ---
echo ""
echo "Enter your LUKS passphrase again to update the encrypted backup:"
read -rs -p "LUKS passphrase: " PASSPHRASE
echo ""

echo -n "$PASSPHRASE" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$WORK_DIR/salt.bin" -out "$CONF_DIR/salt.enc" \
    -pass stdin
chmod 600 "$CONF_DIR/salt.enc"

# Recompute HMAC for the new ciphertext
openssl dgst -sha256 -hmac "$PASSPHRASE" -binary "$CONF_DIR/salt.enc" \
    > "$CONF_DIR/salt.enc.mac"
chmod 600 "$CONF_DIR/salt.enc.mac"
unset PASSPHRASE
echo "[OK] Updated encrypted salt backup (with HMAC)"

echo ""
echo "=========================================="
echo "  RE-SEAL COMPLETE"
echo "=========================================="
echo ""
echo "The sealed objects are stored in the LUKS2 header (not in the initramfs),"
echo "so no initramfs rebuild is needed and PCR 9 is unchanged."
echo ""
echo "You can reboot now: the token unlock should work immediately."
echo ""
echo "Your passphrase keyslot is still available as a fallback."
