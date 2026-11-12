/*
 * VaultMind Native Cryptographic & Enclave Core (libvaultcrypto)
 *
 * Implements:
 * 1. Constant-time, branchless, table-free arithmetic in GF(2^8)
 *    with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
 * 2. Shamir's (k, n) Threshold Secret Sharing split & Lagrange interpolation at x = 0.
 * 3. Zero-leak Enclave Seal & Verify using Apple CommonCrypto (AES-256-CBC + Encrypt-then-MAC HMAC-SHA256)
 *    where the reconstructed 256-bit Master Key lives strictly on the C stack and is wiped
 *    via C11 memset_s() + volatile compiler memory barrier before returning to Python.
 */

#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>

#define VAULT_KEY_LEN 32
#define VAULT_IV_LEN 16
#define VAULT_HMAC_LEN 32

/* Guaranteed non-elided memory zeroization */
void vault_secure_wipe(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
#ifdef __STDC_LIB_EXT1__
    memset_s(ptr, len, 0, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
#endif
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

/* Constant-time byte buffer equality check (returns 1 if equal, 0 otherwise) */
int vault_ct_memeq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    /* Map diff == 0 -> 1, diff != 0 -> 0 without branches */
    return (int)((1U & ((diff - 1U) >> 8)));
}

/*
 * Constant-time multiplication in GF(2^8) modulo 0x11B.
 * Zero lookup tables (cache-timing immune) and zero secret-dependent branches.
 */
uint8_t vault_gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(-(int8_t)(b & 1U));
        p ^= (a & mask);
        uint8_t hi_mask = (uint8_t)(-(int8_t)((a >> 7) & 1U));
        a = (uint8_t)((a << 1) ^ (0x1BU & hi_mask));
        b >>= 1;
    }
    return p;
}

/*
 * Constant-time multiplicative inverse in GF(2^8): a^(-1) = a^254.
 * Uses fixed addition chain: 254 = 2 + 4 + 8 + 16 + 32 + 64 + 128.
 */
uint8_t vault_gf256_inv(uint8_t a) {
    uint8_t a2   = vault_gf256_mul(a, a);
    uint8_t a4   = vault_gf256_mul(a2, a2);
    uint8_t a8   = vault_gf256_mul(a4, a4);
    uint8_t a16  = vault_gf256_mul(a8, a8);
    uint8_t a32  = vault_gf256_mul(a16, a16);
    uint8_t a64  = vault_gf256_mul(a32, a32);
    uint8_t a128 = vault_gf256_mul(a64, a64);

    uint8_t r = vault_gf256_mul(a2, a4);
    r = vault_gf256_mul(r, a8);
    r = vault_gf256_mul(r, a16);
    r = vault_gf256_mul(r, a32);
    r = vault_gf256_mul(r, a64);
    r = vault_gf256_mul(r, a128);
    return r;
}

/* Horner evaluation of polynomial f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[k-1]*x^(k-1) in GF(2^8) */
uint8_t vault_gf256_eval_poly(const uint8_t *coeffs, size_t k, uint8_t x) {
    uint8_t res = 0;
    for (size_t idx = k; idx > 0; idx--) {
        res = vault_gf256_mul(res, x) ^ coeffs[idx - 1];
    }
    return res;
}

/* Internal Lagrange interpolation at x = 0 over GF(2^8) for byte-slices */
static int reconstruct_bytes_internal(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    size_t secret_len,
    uint8_t *out_secret
) {
    if (k < 1 || secret_len == 0) {
        return -1;
    }
    /* Verify distinct non-zero x coordinates */
    for (size_t i = 0; i < k; i++) {
        if (share_x[i] == 0) return -2;
        for (size_t j = i + 1; j < k; j++) {
            if (share_x[i] == share_x[j]) return -3;
        }
    }

    /* Precompute Lagrange basis coefficients l_j(0) = prod_{m != j} x_m / (x_m ^ x_j) in GF(2^8)
     * Note: In characteristic 2, -x_m == x_m and x_j - x_m == x_j ^ x_m!
     */
    uint8_t lagrange_basis[256];
    for (size_t j = 0; j < k; j++) {
        uint8_t num = 1;
        uint8_t den = 1;
        for (size_t m = 0; m < k; m++) {
            if (m == j) continue;
            num = vault_gf256_mul(num, share_x[m]);
            den = vault_gf256_mul(den, (uint8_t)(share_x[j] ^ share_x[m]));
        }
        lagrange_basis[j] = vault_gf256_mul(num, vault_gf256_inv(den));
    }

    for (size_t b = 0; b < secret_len; b++) {
        uint8_t acc = 0;
        for (size_t j = 0; j < k; j++) {
            uint8_t y_jb = shares_flat[j * secret_len + b];
            acc ^= vault_gf256_mul(y_jb, lagrange_basis[j]);
        }
        out_secret[b] = acc;
    }

    vault_secure_wipe(lagrange_basis, sizeof(lagrange_basis));
    return 0;
}

/* Derive subkeys from 32-byte master key using HMAC-SHA256 domain separation */
static void derive_subkeys(
    const uint8_t master_key[VAULT_KEY_LEN],
    uint8_t enc_key[VAULT_KEY_LEN],
    uint8_t mac_key[VAULT_KEY_LEN],
    uint8_t key_id[VAULT_KEY_LEN]
) {
    const char *lbl_enc = "VAULTMIND_V2_AES256_ENC_KEY";
    const char *lbl_mac = "VAULTMIND_V2_HMAC_SHA256_KEY";
    const char *lbl_id  = "VAULTMIND_V2_MASTER_KEY_COMMITMENT";

    CCHmac(kCCHmacAlgSHA256, master_key, VAULT_KEY_LEN, lbl_enc, strlen(lbl_enc), enc_key);
    CCHmac(kCCHmacAlgSHA256, master_key, VAULT_KEY_LEN, lbl_mac, strlen(lbl_mac), mac_key);
    CCHmac(kCCHmacAlgSHA256, master_key, VAULT_KEY_LEN, lbl_id,  strlen(lbl_id),  key_id);
}

/*
 * Split an arbitrary byte buffer (e.g. 32-byte master key) into n shares with threshold k.
 * Also computes the key_commitment (HMAC-SHA256 identity tag) and wipes temporary polynomial coefficients.
 */
int vault_split_secret(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t threshold_k,
    uint8_t total_n,
    uint8_t *out_shares_flat,      /* size: total_n * secret_len */
    uint8_t *out_key_commitment    /* size: 32 bytes (only if secret_len == 32, may be NULL) */
) {
    if (threshold_k < 1 || threshold_k > total_n || secret_len == 0) {
        return -1;
    }

    uint8_t coeffs[256];
    for (size_t b = 0; b < secret_len; b++) {
        coeffs[0] = secret[b];
        if (threshold_k > 1) {
            arc4random_buf(&coeffs[1], threshold_k - 1);
            /* Ensure leading coefficient is non-zero so degree is strictly k-1 */
            while (coeffs[threshold_k - 1] == 0) {
                arc4random_buf(&coeffs[threshold_k - 1], 1);
            }
        }
        for (uint8_t x = 1; x <= total_n; x++) {
            out_shares_flat[(x - 1) * secret_len + b] = vault_gf256_eval_poly(coeffs, threshold_k, x);
        }
    }
    vault_secure_wipe(coeffs, sizeof(coeffs));

    if (out_key_commitment != NULL && secret_len == VAULT_KEY_LEN) {
        uint8_t dummy_enc[VAULT_KEY_LEN];
        uint8_t dummy_mac[VAULT_KEY_LEN];
        derive_subkeys(secret, dummy_enc, dummy_mac, out_key_commitment);
        vault_secure_wipe(dummy_enc, sizeof(dummy_enc));
        vault_secure_wipe(dummy_mac, sizeof(dummy_mac));
    }

    return 0;
}

/* Public wrapper to reconstruct non-master test/canary bytes when needed for unit testing */
int vault_reconstruct_bytes(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    size_t secret_len,
    uint8_t *out_secret
) {
    return reconstruct_bytes_internal(share_x, shares_flat, k, secret_len, out_secret);
}

/*
 * Enclave Seal Operation (Zero Master Key Exposure to Python):
 * 1. Reconstructs 32-byte master key on the C stack from k shares.
 * 2. Verifies reconstructed key against expected_key_commitment in constant time.
 * 3. Encrypts plaintext with AES-256-CBC (random IV via arc4random_buf).
 * 4. Computes Encrypt-then-MAC HMAC-SHA256 over (aad || iv || ciphertext).
 * 5. Wipes master_key, enc_key, mac_key via memset_s() BEFORE returning.
 */
int vault_enclave_seal(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    const uint8_t *expected_key_commitment, /* 32 bytes */
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out_iv,                        /* 16 bytes */
    uint8_t *out_ciphertext,                /* buffer >= plaintext_len + 16 */
    size_t ciphertext_buf_cap,
    size_t *out_ciphertext_len,
    uint8_t *out_hmac                       /* 32 bytes */
) {
    uint8_t master_key[VAULT_KEY_LEN];
    uint8_t enc_key[VAULT_KEY_LEN];
    uint8_t mac_key[VAULT_KEY_LEN];
    uint8_t actual_id[VAULT_KEY_LEN];
    int rc = 0;

    rc = reconstruct_bytes_internal(share_x, shares_flat, k, VAULT_KEY_LEN, master_key);
    if (rc != 0) {
        goto cleanup;
    }

    derive_subkeys(master_key, enc_key, mac_key, actual_id);
    if (expected_key_commitment != NULL) {
        if (!vault_ct_memeq(actual_id, expected_key_commitment, VAULT_KEY_LEN)) {
            rc = -10; /* Reconstructed key mismatch! */
            goto cleanup;
        }
    }

    arc4random_buf(out_iv, VAULT_IV_LEN);

    size_t moved = 0;
    CCCryptorStatus crypt_status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        enc_key,
        VAULT_KEY_LEN,
        out_iv,
        plaintext,
        plaintext_len,
        out_ciphertext,
        ciphertext_buf_cap,
        &moved
    );
    if (crypt_status != kCCSuccess) {
        rc = -11;
        goto cleanup;
    }
    *out_ciphertext_len = moved;

    /* Encrypt-then-MAC: HMAC-SHA256(mac_key, aad || iv || ciphertext) */
    CCHmacContext hmac_ctx;
    CCHmacInit(&hmac_ctx, kCCHmacAlgSHA256, mac_key, VAULT_KEY_LEN);
    if (aad != NULL && aad_len > 0) {
        CCHmacUpdate(&hmac_ctx, aad, aad_len);
    }
    CCHmacUpdate(&hmac_ctx, out_iv, VAULT_IV_LEN);
    CCHmacUpdate(&hmac_ctx, out_ciphertext, moved);
    CCHmacFinal(&hmac_ctx, out_hmac);
    vault_secure_wipe(&hmac_ctx, sizeof(hmac_ctx));

cleanup:
    vault_secure_wipe(master_key, sizeof(master_key));
    vault_secure_wipe(enc_key, sizeof(enc_key));
    vault_secure_wipe(mac_key, sizeof(mac_key));
    vault_secure_wipe(actual_id, sizeof(actual_id));
    return rc;
}

/*
 * Enclave Verify & Unseal Operation (Zero Master Key Exposure to Python):
 * 1. Reconstructs 32-byte master key on the C stack.
 * 2. Verifies Encrypt-then-MAC HMAC-SHA256 tag in constant time.
 * 3. Decrypts AES-256-CBC ciphertext into out_plaintext.
 * 4. Wipes all key material via memset_s() BEFORE returning.
 */
int vault_enclave_unseal(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *iv,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *expected_hmac,
    uint8_t *out_plaintext,
    size_t plaintext_buf_cap,
    size_t *out_plaintext_len
) {
    uint8_t master_key[VAULT_KEY_LEN];
    uint8_t enc_key[VAULT_KEY_LEN];
    uint8_t mac_key[VAULT_KEY_LEN];
    uint8_t actual_id[VAULT_KEY_LEN];
    uint8_t computed_hmac[VAULT_HMAC_LEN];
    int rc = 0;

    rc = reconstruct_bytes_internal(share_x, shares_flat, k, VAULT_KEY_LEN, master_key);
    if (rc != 0) {
        goto cleanup;
    }

    derive_subkeys(master_key, enc_key, mac_key, actual_id);

    CCHmacContext hmac_ctx;
    CCHmacInit(&hmac_ctx, kCCHmacAlgSHA256, mac_key, VAULT_KEY_LEN);
    if (aad != NULL && aad_len > 0) {
        CCHmacUpdate(&hmac_ctx, aad, aad_len);
    }
    CCHmacUpdate(&hmac_ctx, iv, VAULT_IV_LEN);
    CCHmacUpdate(&hmac_ctx, ciphertext, ciphertext_len);
    CCHmacFinal(&hmac_ctx, computed_hmac);
    vault_secure_wipe(&hmac_ctx, sizeof(hmac_ctx));

    if (!vault_ct_memeq(computed_hmac, expected_hmac, VAULT_HMAC_LEN)) {
        rc = -20; /* Authentication tag verification failed! */
        goto cleanup;
    }

    if (out_plaintext != NULL) {
        size_t moved = 0;
        CCCryptorStatus crypt_status = CCCrypt(
            kCCDecrypt,
            kCCAlgorithmAES,
            kCCOptionPKCS7Padding,
            enc_key,
            VAULT_KEY_LEN,
            iv,
            ciphertext,
            ciphertext_len,
            out_plaintext,
            plaintext_buf_cap,
            &moved
        );
        if (crypt_status != kCCSuccess) {
            rc = -21;
            goto cleanup;
        }
        *out_plaintext_len = moved;
    }

cleanup:
    vault_secure_wipe(master_key, sizeof(master_key));
    vault_secure_wipe(enc_key, sizeof(enc_key));
    vault_secure_wipe(mac_key, sizeof(mac_key));
    vault_secure_wipe(actual_id, sizeof(actual_id));
    vault_secure_wipe(computed_hmac, sizeof(computed_hmac));
    return rc;
}
