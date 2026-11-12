/*
 * VaultMind Native Cryptographic, 128-bit PQ Lattice RLWE-BFV FHE & Enclave Core (libvaultcrypto)
 *
 * Implements in compiled C11:
 * 1. Constant-time, branchless, table-free arithmetic in GF(2^8) (0x11B) for Shamir's Secret Sharing.
 * 2. Dual-Field Hybrid Master Key Derivation binding C-stack GF(2^8) secret shares with
 *    RFC 3526 2048-bit Feldman VSS Z_q shares via HMAC-SHA256, plus Zero-Leak Enclave Seal/Unseal
 *    using Apple CommonCrypto (AES-256-CBC + Encrypt-then-MAC HMAC-SHA256) and C11 memset_s().
 * 3. Standard-Compliant 128-bit Lattice Security Ring-LWE Brakerski-Fan-Vercauteren (BFV) FHE
 *    (HomomorphicEncryption.org Table 1: N = 2048, log2(q) = 54, ternary secret) over
 *    R_q = Z_{2^54}[X]/(X^2048 + 1), supporting E(m1) + E(m2) AND non-linear E(m1) * E(m2)
 *    with 4-limb base-2^14 gadget decomposition relinearization and unbiased rejection sampling.
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

/* HomomorphicEncryption.org 128-bit Lattice Security Parameter Set (Ternary Secret):
 * Ring degree N = 2048: R_q = Z_q[X] / (X^2048 + 1)
 * Ciphertext modulus Q = 2^54 (log2(Q) = 54 <= 54 max for 128-bit security at N = 2048)
 * Plaintext modulus T = 65536 (2^16), Scaling factor Delta = Q / T = 2^38
 * Gadget base B = 2^14 with L = 4 limbs (14 * 4 = 56 >= 54 bits)
 */
#define BFV_N 2048
#define BFV_Q (1LL << 54)
#define BFV_HALF_Q (1LL << 53)
#define BFV_T 65536LL
#define BFV_DELTA (BFV_Q / BFV_T)
#define BFV_GADGET_BITS 14
#define BFV_GADGET_BASE (1LL << BFV_GADGET_BITS)
#define BFV_GADGET_MASK (BFV_GADGET_BASE - 1LL)
#define BFV_LIMBS 4

typedef __int128 int128_t;

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
    return (int)((1U & ((diff - 1U) >> 8)));
}

/* Constant-time multiplication in GF(2^8) modulo 0x11B */
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

/* Constant-time multiplicative inverse in GF(2^8): a^(-1) = a^254 */
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

uint8_t vault_gf256_eval_poly(const uint8_t *coeffs, size_t k, uint8_t x) {
    uint8_t res = 0;
    for (size_t idx = k; idx > 0; idx--) {
        res = vault_gf256_mul(res, x) ^ coeffs[idx - 1];
    }
    return res;
}

static int reconstruct_bytes_internal(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    size_t secret_len,
    uint8_t *out_secret
) {
    if (k < 1 || secret_len == 0) return -1;
    for (size_t i = 0; i < k; i++) {
        if (share_x[i] == 0) return -2;
        for (size_t j = i + 1; j < k; j++) {
            if (share_x[i] == share_x[j]) return -3;
        }
    }

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

/*
 * Dual-field key derivation:
 * Combines C-stack GF(2^8) secret `gf_key` with optional 32-byte RFC 3526 Feldman VSS
 * Z_q secret component `feldman_key` via HMAC-SHA256 so BOTH polynomials are mathematically
 * required to derive the Master Key, while `master_key` never leaves the C stack.
 */
static void derive_subkeys(
    const uint8_t gf_key[VAULT_KEY_LEN],
    const uint8_t *feldman_key,
    uint8_t enc_key[VAULT_KEY_LEN],
    uint8_t mac_key[VAULT_KEY_LEN],
    uint8_t key_id[VAULT_KEY_LEN]
) {
    uint8_t combined_master[VAULT_KEY_LEN];
    if (feldman_key != NULL) {
        CCHmac(kCCHmacAlgSHA256, gf_key, VAULT_KEY_LEN, feldman_key, VAULT_KEY_LEN, combined_master);
    } else {
        memcpy(combined_master, gf_key, VAULT_KEY_LEN);
    }

    const char *lbl_enc = "VAULTMIND_V2_AES256_ENC_KEY";
    const char *lbl_mac = "VAULTMIND_V2_HMAC_SHA256_KEY";
    const char *lbl_id  = "VAULTMIND_V2_MASTER_KEY_COMMITMENT";

    CCHmac(kCCHmacAlgSHA256, combined_master, VAULT_KEY_LEN, lbl_enc, strlen(lbl_enc), enc_key);
    CCHmac(kCCHmacAlgSHA256, combined_master, VAULT_KEY_LEN, lbl_mac, strlen(lbl_mac), mac_key);
    CCHmac(kCCHmacAlgSHA256, combined_master, VAULT_KEY_LEN, lbl_id,  strlen(lbl_id),  key_id);

    vault_secure_wipe(combined_master, sizeof(combined_master));
}

int vault_split_secret(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t threshold_k,
    uint8_t total_n,
    const uint8_t *feldman_component_32,
    uint8_t *out_shares_flat,
    uint8_t *out_key_commitment
) {
    if (threshold_k < 1 || threshold_k > total_n || secret_len == 0) return -1;

    uint8_t coeffs[256];
    for (size_t b = 0; b < secret_len; b++) {
        coeffs[0] = secret[b];
        if (threshold_k > 1) {
            arc4random_buf(&coeffs[1], threshold_k - 1);
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
        derive_subkeys(secret, feldman_component_32, dummy_enc, dummy_mac, out_key_commitment);
        vault_secure_wipe(dummy_enc, sizeof(dummy_enc));
        vault_secure_wipe(dummy_mac, sizeof(dummy_mac));
    }
    return 0;
}

int vault_reconstruct_bytes(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    size_t secret_len,
    uint8_t *out_secret
) {
    return reconstruct_bytes_internal(share_x, shares_flat, k, secret_len, out_secret);
}

int vault_enclave_seal(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    const uint8_t *feldman_component_32,
    const uint8_t *expected_key_commitment,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out_iv,
    uint8_t *out_ciphertext,
    size_t ciphertext_buf_cap,
    size_t *out_ciphertext_len,
    uint8_t *out_hmac
) {
    uint8_t gf_key[VAULT_KEY_LEN];
    uint8_t enc_key[VAULT_KEY_LEN];
    uint8_t mac_key[VAULT_KEY_LEN];
    uint8_t actual_id[VAULT_KEY_LEN];
    int rc = 0;

    rc = reconstruct_bytes_internal(share_x, shares_flat, k, VAULT_KEY_LEN, gf_key);
    if (rc != 0) goto cleanup;

    derive_subkeys(gf_key, feldman_component_32, enc_key, mac_key, actual_id);
    if (expected_key_commitment != NULL) {
        if (!vault_ct_memeq(actual_id, expected_key_commitment, VAULT_KEY_LEN)) {
            rc = -10;
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
    vault_secure_wipe(gf_key, sizeof(gf_key));
    vault_secure_wipe(enc_key, sizeof(enc_key));
    vault_secure_wipe(mac_key, sizeof(mac_key));
    vault_secure_wipe(actual_id, sizeof(actual_id));
    return rc;
}

int vault_enclave_unseal(
    const uint8_t *share_x,
    const uint8_t *shares_flat,
    size_t k,
    const uint8_t *feldman_component_32,
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
    uint8_t gf_key[VAULT_KEY_LEN];
    uint8_t enc_key[VAULT_KEY_LEN];
    uint8_t mac_key[VAULT_KEY_LEN];
    uint8_t actual_id[VAULT_KEY_LEN];
    uint8_t computed_hmac[VAULT_HMAC_LEN];
    int rc = 0;

    rc = reconstruct_bytes_internal(share_x, shares_flat, k, VAULT_KEY_LEN, gf_key);
    if (rc != 0) goto cleanup;

    derive_subkeys(gf_key, feldman_component_32, enc_key, mac_key, actual_id);

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
        rc = -20;
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
    vault_secure_wipe(gf_key, sizeof(gf_key));
    vault_secure_wipe(enc_key, sizeof(enc_key));
    vault_secure_wipe(mac_key, sizeof(mac_key));
    vault_secure_wipe(actual_id, sizeof(actual_id));
    vault_secure_wipe(computed_hmac, sizeof(computed_hmac));
    return rc;
}

/*
 * Local Symmetric Secret Token Seal & Unseal (for arbitrary passwords/phrases in prompts)
 */
int vault_session_seal(
    const uint8_t *session_key_32,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_iv_16,
    uint8_t *out_ct,
    size_t ct_cap,
    size_t *out_ct_len,
    uint8_t *out_hmac_32
) {
    uint8_t enc_key[VAULT_KEY_LEN];
    uint8_t mac_key[VAULT_KEY_LEN];
    uint8_t dummy_id[VAULT_KEY_LEN];
    derive_subkeys(session_key_32, NULL, enc_key, mac_key, dummy_id);
    arc4random_buf(out_iv_16, VAULT_IV_LEN);

    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(
        kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        enc_key, VAULT_KEY_LEN, out_iv_16,
        plaintext, plaintext_len, out_ct, ct_cap, &moved
    );
    if (st != kCCSuccess) {
        vault_secure_wipe(enc_key, sizeof(enc_key));
        vault_secure_wipe(mac_key, sizeof(mac_key));
        vault_secure_wipe(dummy_id, sizeof(dummy_id));
        return -1;
    }
    *out_ct_len = moved;

    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256, mac_key, VAULT_KEY_LEN);
    CCHmacUpdate(&ctx, out_iv_16, VAULT_IV_LEN);
    CCHmacUpdate(&ctx, out_ct, moved);
    CCHmacFinal(&ctx, out_hmac_32);

    vault_secure_wipe(&ctx, sizeof(ctx));
    vault_secure_wipe(enc_key, sizeof(enc_key));
    vault_secure_wipe(mac_key, sizeof(mac_key));
    vault_secure_wipe(dummy_id, sizeof(dummy_id));
    return 0;
}

int vault_session_unseal(
    const uint8_t *session_key_32,
    const uint8_t *iv_16,
    const uint8_t *ct,
    size_t ct_len,
    const uint8_t *expected_hmac_32,
    uint8_t *out_pt,
    size_t pt_cap,
    size_t *out_pt_len
) {
    uint8_t enc_key[VAULT_KEY_LEN];
    uint8_t mac_key[VAULT_KEY_LEN];
    uint8_t dummy_id[VAULT_KEY_LEN];
    uint8_t actual_hmac[VAULT_HMAC_LEN];
    derive_subkeys(session_key_32, NULL, enc_key, mac_key, dummy_id);

    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA256, mac_key, VAULT_KEY_LEN);
    CCHmacUpdate(&ctx, iv_16, VAULT_IV_LEN);
    CCHmacUpdate(&ctx, ct, ct_len);
    CCHmacFinal(&ctx, actual_hmac);
    vault_secure_wipe(&ctx, sizeof(ctx));

    if (!vault_ct_memeq(actual_hmac, expected_hmac_32, VAULT_HMAC_LEN)) {
        vault_secure_wipe(enc_key, sizeof(enc_key));
        vault_secure_wipe(mac_key, sizeof(mac_key));
        vault_secure_wipe(dummy_id, sizeof(dummy_id));
        vault_secure_wipe(actual_hmac, sizeof(actual_hmac));
        return -2;
    }

    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(
        kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        enc_key, VAULT_KEY_LEN, iv_16,
        ct, ct_len, out_pt, pt_cap, &moved
    );
    vault_secure_wipe(enc_key, sizeof(enc_key));
    vault_secure_wipe(mac_key, sizeof(mac_key));
    vault_secure_wipe(dummy_id, sizeof(dummy_id));
    vault_secure_wipe(actual_hmac, sizeof(actual_hmac));
    if (st != kCCSuccess) return -3;
    *out_pt_len = moved;
    return 0;
}

/* =========================================================================
 * NATIVE C 128-BIT LATTICE SECURITY RLWE-BFV HOMOMORPHIC ENCRYPTION ENGINE
 * Ring: R_q = Z_q[X] / (X^2048 + 1), q = 2^54, t = 65536
 * ========================================================================= */

static inline int64_t bfv_cmod(int128_t x) {
    int64_t rem = (int64_t)((uint64_t)x & ((uint64_t)BFV_Q - 1ULL));
    if (rem >= BFV_HALF_Q) {
        rem -= BFV_Q;
    }
    return rem;
}

/* Unbiased rejection-sampled ternary distribution over {-1, 0, 1}^N (255 = 3 * 85) */
static void bfv_sample_ternary(int64_t *out) {
    uint8_t buf[256];
    int idx = 0;
    while (idx < BFV_N) {
        arc4random_buf(buf, sizeof(buf));
        for (size_t k = 0; k < sizeof(buf) && idx < BFV_N; k++) {
            if (buf[k] < 255U) {
                out[idx++] = (int64_t)((int)(buf[k] % 3U) - 1);
            }
        }
    }
    vault_secure_wipe(buf, sizeof(buf));
}

static void bfv_sample_uniform_q(int64_t *out) {
    uint64_t *rnd = (uint64_t *)calloc(BFV_N, sizeof(uint64_t));
    if (rnd == NULL) return;
    arc4random_buf(rnd, sizeof(uint64_t) * BFV_N);
    for (int i = 0; i < BFV_N; i++) {
        int64_t u = (int64_t)(rnd[i] & ((uint64_t)BFV_Q - 1ULL));
        if (u >= BFV_HALF_Q) u -= BFV_Q;
        out[i] = u;
    }
    vault_secure_wipe(rnd, sizeof(uint64_t) * BFV_N);
    free(rnd);
}

/* Exact negacyclic convolution in Z[X]/(X^N + 1) using 128-bit accumulators */
static void bfv_poly_mul_exact(const int64_t *a, const int64_t *b, int128_t *out) {
    memset(out, 0, sizeof(int128_t) * BFV_N);
    for (int i = 0; i < BFV_N; i++) {
        int128_t ai = (int128_t)a[i];
        if (ai == 0) continue;
        int split = BFV_N - i;
        for (int j = 0; j < split; j++) {
            out[i + j] += ai * (int128_t)b[j];
        }
        for (int j = split; j < BFV_N; j++) {
            out[i + j - BFV_N] -= ai * (int128_t)b[j];
        }
    }
}

static void bfv_poly_mul_mod(const int64_t *a, const int64_t *b, int64_t *out) {
    int128_t *tmp = (int128_t *)calloc(BFV_N, sizeof(int128_t));
    if (tmp == NULL) return;
    bfv_poly_mul_exact(a, b, tmp);
    for (int i = 0; i < BFV_N; i++) {
        out[i] = bfv_cmod(tmp[i]);
    }
    vault_secure_wipe(tmp, sizeof(int128_t) * BFV_N);
    free(tmp);
}

static void bfv_scale_down(const int128_t *exact_poly, int64_t *out) {
    for (int i = 0; i < BFV_N; i++) {
        int128_t h = exact_poly[i];
        int128_t sign = (h >= 0) ? 1 : -1;
        int128_t ah = (h >= 0) ? h : -h;
        int128_t q_part = ah / (int128_t)BFV_Q;
        int128_t r_part = ah % (int128_t)BFV_Q;
        int128_t scaled_r = (r_part * (int128_t)BFV_T + (int128_t)BFV_HALF_Q) / (int128_t)BFV_Q;
        int128_t total = sign * (q_part * (int128_t)BFV_T + scaled_r);
        out[i] = bfv_cmod(total);
    }
}

void vault_bfv_keygen(int64_t *out_sk, int64_t *out_pk, int64_t *out_rlk) {
    int64_t *work = (int64_t *)calloc(4 * BFV_N, sizeof(int64_t));
    if (work == NULL) return;
    int64_t *s2 = &work[0];
    int64_t *a_tmp = &work[BFV_N];
    int64_t *e_tmp = &work[2 * BFV_N];
    int64_t *as_prod = &work[3 * BFV_N];

    bfv_sample_ternary(out_sk);
    bfv_poly_mul_mod(out_sk, out_sk, s2);

    bfv_sample_uniform_q(a_tmp);
    bfv_sample_ternary(e_tmp);
    bfv_poly_mul_mod(a_tmp, out_sk, as_prod);
    for (int i = 0; i < BFV_N; i++) {
        out_pk[i] = bfv_cmod(-((int128_t)as_prod[i] + (int128_t)e_tmp[i]));
        out_pk[BFV_N + i] = a_tmp[i];
    }

    for (int l = 0; l < BFV_LIMBS; l++) {
        int128_t scale = ((int128_t)1) << (l * BFV_GADGET_BITS);
        bfv_sample_uniform_q(a_tmp);
        bfv_sample_ternary(e_tmp);
        bfv_poly_mul_mod(a_tmp, out_sk, as_prod);

        int64_t *rlk_b = &out_rlk[(l * 2) * BFV_N];
        int64_t *rlk_a = &out_rlk[(l * 2 + 1) * BFV_N];
        for (int i = 0; i < BFV_N; i++) {
            int128_t term = -((int128_t)as_prod[i] + (int128_t)e_tmp[i]) + scale * (int128_t)s2[i];
            rlk_b[i] = bfv_cmod(term);
            rlk_a[i] = a_tmp[i];
        }
    }

    vault_secure_wipe(work, sizeof(int64_t) * 4 * BFV_N);
    free(work);
}

void vault_bfv_encrypt(const int64_t *pk, int64_t m, int64_t *out_ct) {
    int64_t *work = (int64_t *)calloc(5 * BFV_N, sizeof(int64_t));
    if (work == NULL) return;
    int64_t *u = &work[0];
    int64_t *e1 = &work[BFV_N];
    int64_t *e2 = &work[2 * BFV_N];
    int64_t *p0u = &work[3 * BFV_N];
    int64_t *p1u = &work[4 * BFV_N];

    bfv_sample_ternary(u);
    bfv_sample_ternary(e1);
    bfv_sample_ternary(e2);

    /* Multiply small ternary u as first argument to exploit sparse ai == 0 skip */
    bfv_poly_mul_mod(u, &pk[0], p0u);
    bfv_poly_mul_mod(u, &pk[BFV_N], p1u);

    int64_t m_mod = ((m % BFV_T) + BFV_T) % BFV_T;
    for (int i = 0; i < BFV_N; i++) {
        int128_t msg_scaled = (i == 0) ? ((int128_t)BFV_DELTA * (int128_t)m_mod) : 0;
        out_ct[i] = bfv_cmod((int128_t)p0u[i] + (int128_t)e1[i] + msg_scaled);
        out_ct[BFV_N + i] = bfv_cmod((int128_t)p1u[i] + (int128_t)e2[i]);
    }

    vault_secure_wipe(work, sizeof(int64_t) * 5 * BFV_N);
    free(work);
}

void vault_bfv_add(const int64_t *ct1, const int64_t *ct2, int64_t *out_ct) {
    for (int i = 0; i < 2 * BFV_N; i++) {
        out_ct[i] = bfv_cmod((int128_t)ct1[i] + (int128_t)ct2[i]);
    }
}

void vault_bfv_mul_relin(const int64_t *ct1, const int64_t *ct2, const int64_t *rlk, int64_t *out_ct) {
    const int64_t *c0 = &ct1[0];
    const int64_t *c1 = &ct1[BFV_N];
    const int64_t *d0 = &ct2[0];
    const int64_t *d1 = &ct2[BFV_N];

    int128_t *ex_work = (int128_t *)calloc(4 * BFV_N, sizeof(int128_t));
    int64_t *i64_work = (int64_t *)calloc((7 + BFV_LIMBS) * BFV_N, sizeof(int64_t));
    if (ex_work == NULL || i64_work == NULL) {
        free(ex_work);
        free(i64_work);
        return;
    }

    int128_t *ex0  = &ex_work[0];
    int128_t *ex1a = &ex_work[BFV_N];
    int128_t *ex1b = &ex_work[2 * BFV_N];
    int128_t *ex2  = &ex_work[3 * BFV_N];

    int64_t *h0     = &i64_work[0];
    int64_t *h1     = &i64_work[BFV_N];
    int64_t *h2     = &i64_work[2 * BFV_N];
    int64_t *out0   = &i64_work[3 * BFV_N];
    int64_t *out1   = &i64_work[4 * BFV_N];
    int64_t *prod_b = &i64_work[5 * BFV_N];
    int64_t *prod_a = &i64_work[6 * BFV_N];
    int64_t *digits = &i64_work[7 * BFV_N];

    bfv_poly_mul_exact(c0, d0, ex0);
    bfv_poly_mul_exact(c0, d1, ex1a);
    bfv_poly_mul_exact(c1, d0, ex1b);
    bfv_poly_mul_exact(c1, d1, ex2);

    for (int i = 0; i < BFV_N; i++) {
        ex1a[i] += ex1b[i];
    }

    bfv_scale_down(ex0, h0);
    bfv_scale_down(ex1a, h1);
    bfv_scale_down(ex2, h2);

    for (int i = 0; i < BFV_N; i++) {
        uint64_t rem = (uint64_t)h2[i] & ((uint64_t)BFV_Q - 1ULL);
        for (int l = 0; l < BFV_LIMBS; l++) {
            int64_t d = (int64_t)(rem & (uint64_t)BFV_GADGET_MASK);
            rem >>= BFV_GADGET_BITS;
            if (d >= (BFV_GADGET_BASE / 2)) {
                d -= BFV_GADGET_BASE;
                rem += 1ULL;
            }
            digits[l * BFV_N + i] = d;
        }
    }

    memcpy(out0, h0, sizeof(int64_t) * BFV_N);
    memcpy(out1, h1, sizeof(int64_t) * BFV_N);

    for (int l = 0; l < BFV_LIMBS; l++) {
        const int64_t *digit_l = &digits[l * BFV_N];
        const int64_t *rlk_b = &rlk[(l * 2) * BFV_N];
        const int64_t *rlk_a = &rlk[(l * 2 + 1) * BFV_N];
        bfv_poly_mul_mod(digit_l, rlk_b, prod_b);
        bfv_poly_mul_mod(digit_l, rlk_a, prod_a);
        for (int i = 0; i < BFV_N; i++) {
            out0[i] = bfv_cmod((int128_t)out0[i] + (int128_t)prod_b[i]);
            out1[i] = bfv_cmod((int128_t)out1[i] + (int128_t)prod_a[i]);
        }
    }

    memcpy(&out_ct[0], out0, sizeof(int64_t) * BFV_N);
    memcpy(&out_ct[BFV_N], out1, sizeof(int64_t) * BFV_N);

    free(ex_work);
    free(i64_work);
}

int64_t vault_bfv_decrypt(const int64_t *sk, const int64_t *ct) {
    int64_t *c1s = (int64_t *)calloc(BFV_N, sizeof(int64_t));
    if (c1s == NULL) return 0;

    bfv_poly_mul_mod(sk, &ct[BFV_N], c1s);
    int64_t v0 = bfv_cmod((int128_t)ct[0] + (int128_t)c1s[0]);

    int128_t q_val;
    if (v0 >= 0) {
        q_val = ((int128_t)BFV_T * (int128_t)v0 + (int128_t)BFV_HALF_Q) / (int128_t)BFV_Q;
    } else {
        q_val = -(((int128_t)BFV_T * (int128_t)(-v0) + (int128_t)BFV_HALF_Q) / (int128_t)BFV_Q);
    }
    int64_t res = ((int64_t)(q_val % (int128_t)BFV_T) + BFV_T) % BFV_T;
    vault_secure_wipe(c1s, sizeof(int64_t) * BFV_N);
    free(c1s);
    return res;
}
