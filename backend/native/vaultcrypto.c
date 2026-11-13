/*
 * VaultMind Native Cryptographic Core: RLWE-BFV (leveled, multiplicative depth 1) & Enclave (libvaultcrypto)
 *
 * Implements in compiled C11:
 * 1. Constant-time, branchless, table-free arithmetic in GF(2^8) (0x11B) for Shamir's Secret Sharing.
 *    Shamir coefficients are drawn uniformly (no rejection of a zero leading coefficient).
 * 2. Dual-Field Hybrid Master Key Derivation binding C-stack GF(2^8) secret shares with
 *    RFC 3526 2048-bit Feldman VSS Z_q shares via HMAC-SHA256, plus Enclave Seal/Unseal
 *    using Apple CommonCrypto (AES-256-CBC + Encrypt-then-MAC HMAC-SHA256 over
 *    len64be(aad) || aad || iv || ciphertext). Wiping uses memset_s() (C11 Annex K, provided by
 *    macOS libc) with a volatile-loop fallback on platforms without it.
 * 3. RLWE-BFV (leveled, multiplicative depth 1, no bootstrapping) over
 *    R_q = Z_{2^54}[X]/(X^2048 + 1), supporting E(m1) + E(m2) and one E(m1) * E(m2)
 *    with 4-limb base-2^14 gadget decomposition relinearization and unbiased rejection sampling.
 *    N = 2048 and log q = 54 follow the classical 128-bit row (ternary secret) of the
 *    HomomorphicEncryption.org standard; the error distribution here is uniform ternary
 *    (sigma ~ 0.82) instead of sigma ~ 3.2, so "128 bit" is an approximation.
 *
 * 4. File-backed GF(2^8) shares (vault_*_files, vault_share_file_*): the GF(2^8) shares of the
 *    master key are written to and read from their own 32-byte 0600 files by this library only,
 *    so neither the shares nor K_GF ever pass through Python. Python only passes file paths and
 *    public SHA-256 digests of the shares.
 *
 * Constant-time scope: only the GF(2^8) arithmetic and the MAC/commitment/share-digest
 * comparisons (vault_ct_memeq) are constant-time. The BFV code is NOT constant-time
 * (see bfv_poly_mul_exact).
 */

#define __STDC_WANT_LIB_EXT1__ 1
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

#define VAULT_KEY_LEN 32
#define VAULT_IV_LEN 16
#define VAULT_HMAC_LEN 32

/* RLWE-BFV parameters (leveled, multiplicative depth 1):
 * Ring degree N = 2048: R_q = Z_q[X] / (X^2048 + 1)
 * Ciphertext modulus Q = 2^54. N = 2048 and log q = 54 follow the classical 128-bit row
 * (ternary secret) of the HomomorphicEncryption.org standard; the error distribution is
 * uniform ternary (sigma ~ 0.82) instead of sigma ~ 3.2, so 128 bit is an approximation.
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

/* Guaranteed non-elided memory zeroization.
 * Apple Clang does not define __STDC_LIB_EXT1__, but macOS libc does provide memset_s()
 * (declared in <string.h> when __STDC_WANT_LIB_EXT1__ is set), so it is used there too. */
void vault_secure_wipe(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
#if defined(__STDC_LIB_EXT1__) || defined(__APPLE__)
    (void)memset_s(ptr, (rsize_t)len, 0, (rsize_t)len);
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
    if (k < 1 || k > 255 || secret_len == 0) return -1;
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
            /* All k-1 higher coefficients uniform over GF(2^8), including zero for the leading one:
             * a lower-degree polynomial is allowed and required for perfect secrecy. */
            arc4random_buf(&coeffs[1], threshold_k - 1);
        }
        /* Wider counter: with a uint8_t counter, x <= 255 never becomes false (S3). */
        for (unsigned int x = 1; x <= (unsigned int)total_n; x++) {
            out_shares_flat[(x - 1) * secret_len + b] = vault_gf256_eval_poly(coeffs, threshold_k, (uint8_t)x);
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

/*
 * Generates the 256-bit GF(2^8) key with arc4random_buf on the C stack, splits it into
 * total_n shares of 32 bytes (out_shares_flat: total_n * 32 bytes), computes the key
 * commitment (32 bytes, may be NULL) and wipes the key. The key never reaches Python.
 * Returns 0 on success, the vault_split_secret error code otherwise.
 */
int vault_generate_and_split_key(
    uint8_t threshold_k,
    uint8_t total_n,
    const uint8_t *feldman_component_32,
    uint8_t *out_shares_flat,
    uint8_t *out_key_commitment
) {
    uint8_t gf_key[VAULT_KEY_LEN];
    arc4random_buf(gf_key, sizeof(gf_key));
    int rc = vault_split_secret(gf_key, VAULT_KEY_LEN, threshold_k, total_n,
                                feldman_component_32, out_shares_flat, out_key_commitment);
    vault_secure_wipe(gf_key, sizeof(gf_key));
    return rc;
}

/* Fills out[0..len) with CSPRNG bytes from arc4random_buf (used for session keys). */
int vault_random_bytes(uint8_t *out, size_t len) {
    if (out == NULL || len == 0) return -1;
    arc4random_buf(out, len);
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

/*
 * Feeds len64be(aad) || aad into the HMAC. The fixed 8-byte big-endian length field
 * (always present, also for aad_len == 0) pins the AAD/IV boundary, so bytes cannot be
 * shifted from the AAD into the IV/ciphertext without breaking the tag.
 */
static void hmac_update_aad(CCHmacContext *ctx, const uint8_t *aad, size_t aad_len) {
    uint8_t len_be[8];
    uint64_t l = (aad != NULL) ? (uint64_t)aad_len : 0ULL;
    for (int i = 0; i < 8; i++) {
        len_be[i] = (uint8_t)(l >> (56 - 8 * i));
    }
    CCHmacUpdate(ctx, len_be, sizeof(len_be));
    if (aad != NULL && aad_len > 0) {
        CCHmacUpdate(ctx, aad, aad_len);
    }
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
    hmac_update_aad(&hmac_ctx, aad, aad_len);
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
    hmac_update_aad(&hmac_ctx, aad, aad_len);
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

/* =========================================================================
 * FILE-BACKED GF(2^8) SHARES
 *
 * Each GF(2^8) share of the 32-byte key K_GF lives in its own file of exactly 32 raw bytes
 * (mode 0600) that only this library opens. Python passes paths plus the public SHA-256
 * digest of every share; the share bytes are only ever held in C stack buffers that are
 * wiped with vault_secure_wipe on every return path.
 *
 * Return codes (in addition to the existing ones: -1..-3 reconstruct/split argument errors,
 * -10 key-commitment mismatch, -11/-21 AES failure, -20 HMAC mismatch):
 *   -30 share file missing (ENOENT/ENOTDIR)
 *   -31 share file unreadable (open/fstat/read error other than the cases below)
 *   -32 share path is a symbolic link (refused by O_NOFOLLOW)
 *   -33 not a regular file, or not exactly 32 bytes
 *   -34 SHA-256 of the share does not match the expected digest
 *   -35 writing a share file failed (open/fchmod/write/fsync/close)
 *   -36 invalid argument (NULL pointer, zero xor mask, byte index out of range)
 * ========================================================================= */

#define VAULT_MAX_SHARES 255
#define VAULT_SHARE_ENOENT   (-30)
#define VAULT_SHARE_EIO      (-31)
#define VAULT_SHARE_ESYMLINK (-32)
#define VAULT_SHARE_ESIZE    (-33)
#define VAULT_SHARE_EDIGEST  (-34)
#define VAULT_SHARE_EWRITE   (-35)
#define VAULT_SHARE_EINVAL   (-36)

static int share_open_error(int err) {
    if (err == ENOENT || err == ENOTDIR) return VAULT_SHARE_ENOENT;
    if (err == ELOOP) return VAULT_SHARE_ESYMLINK;
    return VAULT_SHARE_EIO;
}

/* Reads exactly 32 bytes from a regular, non-symlink file into `out`. `out` is wiped on error. */
static int read_share_file(const char *path, uint8_t out[VAULT_KEY_LEN]) {
    struct stat st;
    size_t got = 0;
    ssize_t r = 0;
    uint8_t extra = 0;
    int rc = 0;

    if (path == NULL || out == NULL) return VAULT_SHARE_EINVAL;
    /* O_NONBLOCK: opening a FIFO planted at the path must not block the enclave. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return share_open_error(errno);

    if (fstat(fd, &st) != 0) {
        rc = VAULT_SHARE_EIO;
        goto done;
    }
    if (!S_ISREG(st.st_mode) || st.st_size != (off_t)VAULT_KEY_LEN) {
        rc = VAULT_SHARE_ESIZE;
        goto done;
    }
    while (got < VAULT_KEY_LEN) {
        r = read(fd, out + got, VAULT_KEY_LEN - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            rc = VAULT_SHARE_EIO;
            goto done;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    if (got != VAULT_KEY_LEN) {
        rc = VAULT_SHARE_ESIZE; /* shrank after fstat */
        goto done;
    }
    do {
        r = read(fd, &extra, 1);
    } while (r < 0 && errno == EINTR);
    if (r != 0) {
        rc = (r > 0) ? VAULT_SHARE_ESIZE : VAULT_SHARE_EIO; /* grew after fstat */
    }

done:
    vault_secure_wipe(&extra, sizeof(extra));
    (void)close(fd);
    if (rc != 0) vault_secure_wipe(out, VAULT_KEY_LEN);
    return rc;
}

/* Reads a share file and checks SHA-256(share) == expected_sha256 in constant time. */
static int load_verified_share(const char *path, const uint8_t *expected_sha256, uint8_t out[VAULT_KEY_LEN]) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    if (expected_sha256 == NULL) return VAULT_SHARE_EINVAL;
    int rc = read_share_file(path, out);
    if (rc != 0) return rc;
    CC_SHA256(out, (CC_LONG)VAULT_KEY_LEN, digest);
    int ok = vault_ct_memeq(digest, expected_sha256, CC_SHA256_DIGEST_LENGTH);
    vault_secure_wipe(digest, sizeof(digest));
    if (!ok) {
        vault_secure_wipe(out, VAULT_KEY_LEN);
        return VAULT_SHARE_EDIGEST;
    }
    return 0;
}

/*
 * Stages 32 share bytes into a fresh sibling file `<path>.tmp.<random>` opened with
 * O_CREAT | O_EXCL | O_NOFOLLOW (0600 from birth, never truncating an existing or hard-linked
 * inode) and fsyncs it. Refuses a symlink or directory at `path`. Caller owns `*out_tmp_path`.
 */
static int stage_share_temp_file(
    const char *path,
    const uint8_t share[VAULT_KEY_LEN],
    char **out_tmp_path
) {
    struct stat lst;
    uint8_t rnd[8];
    size_t put = 0;
    int rc = 0;

    if (out_tmp_path != NULL) *out_tmp_path = NULL;
    if (path == NULL || path[0] == '\0' || share == NULL || out_tmp_path == NULL) {
        return VAULT_SHARE_EINVAL;
    }
    if (lstat(path, &lst) == 0) {
        if (S_ISLNK(lst.st_mode)) return VAULT_SHARE_ESYMLINK;
        if (S_ISDIR(lst.st_mode)) return VAULT_SHARE_EWRITE;
    } else if (errno != ENOENT) {
        return (errno == ELOOP) ? VAULT_SHARE_ESYMLINK : VAULT_SHARE_EWRITE;
    }

    size_t plen = strlen(path);
    size_t tcap = plen + 24;
    if (tcap < plen) return VAULT_SHARE_EINVAL;
    char *tmp = (char *)malloc(tcap);
    if (tmp == NULL) return VAULT_SHARE_EWRITE;

    arc4random_buf(rnd, sizeof(rnd));
    int n = snprintf(
        tmp, tcap, "%s.tmp.%02x%02x%02x%02x%02x%02x%02x%02x", path,
        rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]
    );
    vault_secure_wipe(rnd, sizeof(rnd));
    if (n < 0 || (size_t)n >= tcap) {
        free(tmp);
        return VAULT_SHARE_EWRITE;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
    if (fd < 0) {
        int err = errno;
        free(tmp);
        return (err == ELOOP) ? VAULT_SHARE_ESYMLINK : VAULT_SHARE_EWRITE;
    }

    /* Force exact 0600 even if the process umask masked owner bits. */
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        rc = VAULT_SHARE_EWRITE;
        goto fail_fd;
    }
    while (put < VAULT_KEY_LEN) {
        ssize_t w = write(fd, share + put, VAULT_KEY_LEN - put);
        if (w < 0) {
            if (errno == EINTR) continue;
            rc = VAULT_SHARE_EWRITE;
            goto fail_fd;
        }
        if (w == 0) {
            rc = VAULT_SHARE_EWRITE;
            goto fail_fd;
        }
        put += (size_t)w;
    }
    if (fsync(fd) != 0) rc = VAULT_SHARE_EWRITE;

fail_fd:
    if (close(fd) != 0 && rc == 0) rc = VAULT_SHARE_EWRITE;
    if (rc != 0) {
        (void)unlink(tmp);
        free(tmp);
        return rc;
    }
    *out_tmp_path = tmp;
    return 0;
}

/* Atomically writes 32 share bytes to `path` via a fresh 0600 sibling temp file + rename. */
static int write_share_file(const char *path, const uint8_t share[VAULT_KEY_LEN]) {
    char *tmp = NULL;
    int rc = stage_share_temp_file(path, share, &tmp);
    if (rc != 0) return rc;
    if (rename(tmp, path) != 0) {
        int err = errno;
        (void)unlink(tmp);
        free(tmp);
        return (err == ELOOP) ? VAULT_SHARE_ESYMLINK : VAULT_SHARE_EWRITE;
    }
    free(tmp);
    return 0;
}

/*
 * Provisioning: draws K_GF (32 bytes) with arc4random_buf on the C stack, splits it
 * (k, n) over GF(2^8), stages share i (x = i + 1) to a 0600 temp file and renames all n shares
 * into share_paths[i], returning per share SHA-256(share) in out_share_sha256_flat (n * 32 bytes)
 * and the key commitment (32 bytes). No share byte is written to a caller-visible buffer. On
 * staging failure, pre-existing files at share_paths[] are left untouched, staged temp files are
 * unlinked, outputs are wiped, and *out_bad_index (may be NULL) names the failing share.
 */
int vault_generate_split_key_to_files(
    uint8_t threshold_k,
    uint8_t total_n,
    const uint8_t *feldman_component_32,
    const char *const *share_paths,
    uint8_t *out_share_sha256_flat,
    uint8_t *out_key_commitment,
    size_t *out_bad_index
) {
    uint8_t gf_key[VAULT_KEY_LEN];
    uint8_t shares[VAULT_MAX_SHARES * VAULT_KEY_LEN];
    char *tmp_paths[VAULT_MAX_SHARES] = {0};
    size_t committed = 0;
    int rc = 0;

    if (out_bad_index != NULL) *out_bad_index = SIZE_MAX;
    if (share_paths == NULL || out_share_sha256_flat == NULL || out_key_commitment == NULL) {
        return VAULT_SHARE_EINVAL;
    }
    if (threshold_k < 1 || threshold_k > total_n) return -1;
    for (size_t i = 0; i < (size_t)total_n; i++) {
        if (share_paths[i] == NULL || share_paths[i][0] == '\0') {
            if (out_bad_index != NULL) *out_bad_index = i;
            return VAULT_SHARE_EINVAL;
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(share_paths[i], share_paths[j]) == 0) {
                if (out_bad_index != NULL) *out_bad_index = i;
                return VAULT_SHARE_EINVAL;
            }
        }
    }

    arc4random_buf(gf_key, sizeof(gf_key));
    rc = vault_split_secret(gf_key, VAULT_KEY_LEN, threshold_k, total_n,
                            feldman_component_32, shares, out_key_commitment);
    vault_secure_wipe(gf_key, sizeof(gf_key));
    if (rc != 0) goto cleanup;

    for (size_t i = 0; i < (size_t)total_n; i++) {
        const uint8_t *share = &shares[i * VAULT_KEY_LEN];
        rc = stage_share_temp_file(share_paths[i], share, &tmp_paths[i]);
        if (rc != 0) {
            if (out_bad_index != NULL) *out_bad_index = i;
            goto cleanup;
        }
        CC_SHA256(share, (CC_LONG)VAULT_KEY_LEN, &out_share_sha256_flat[i * VAULT_KEY_LEN]);
    }

    for (size_t i = 0; i < (size_t)total_n; i++) {
        if (rename(tmp_paths[i], share_paths[i]) != 0) {
            rc = (errno == ELOOP) ? VAULT_SHARE_ESYMLINK : VAULT_SHARE_EWRITE;
            if (out_bad_index != NULL) *out_bad_index = i;
            goto cleanup;
        }
        free(tmp_paths[i]);
        tmp_paths[i] = NULL;
        committed++;
    }

cleanup:
    for (size_t j = 0; j < (size_t)total_n; j++) {
        if (tmp_paths[j] != NULL) {
            (void)unlink(tmp_paths[j]);
            free(tmp_paths[j]);
            tmp_paths[j] = NULL;
        }
    }
    if (rc != 0) {
        for (size_t j = 0; j < committed; j++) {
            (void)unlink(share_paths[j]);
        }
        vault_secure_wipe(out_share_sha256_flat, (size_t)total_n * VAULT_KEY_LEN);
        vault_secure_wipe(out_key_commitment, VAULT_KEY_LEN);
    }
    vault_secure_wipe(shares, sizeof(shares));
    return rc;
}

/* Loads k verified shares into `shares_out` (k * 32 bytes). */
static int load_quorum_shares(
    const char *const *share_paths,
    const uint8_t *share_x,
    const uint8_t *expected_share_sha256_flat,
    size_t k,
    uint8_t *shares_out,
    size_t *out_bad_index
) {
    if (out_bad_index != NULL) *out_bad_index = SIZE_MAX;
    if (share_paths == NULL || share_x == NULL || expected_share_sha256_flat == NULL) {
        return VAULT_SHARE_EINVAL;
    }
    if (k < 1 || k > VAULT_MAX_SHARES) return -1;
    for (size_t i = 0; i < k; i++) {
        int rc = load_verified_share(share_paths[i], &expected_share_sha256_flat[i * VAULT_KEY_LEN],
                                     &shares_out[i * VAULT_KEY_LEN]);
        if (rc != 0) {
            if (out_bad_index != NULL) *out_bad_index = i;
            return rc;
        }
    }
    return 0;
}

/*
 * vault_enclave_seal with the k GF(2^8) shares read from files by C. share_x[i] and
 * expected_share_sha256_flat[i * 32 ..] belong to share_paths[i]. On a share-file error
 * *out_bad_index (may be NULL) is the quorum position of the offending file.
 */
int vault_enclave_seal_files(
    const char *const *share_paths,
    const uint8_t *share_x,
    const uint8_t *expected_share_sha256_flat,
    size_t k,
    size_t *out_bad_index,
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
    uint8_t shares[VAULT_MAX_SHARES * VAULT_KEY_LEN];
    int rc = load_quorum_shares(share_paths, share_x, expected_share_sha256_flat, k, shares, out_bad_index);
    if (rc == 0) {
        rc = vault_enclave_seal(share_x, shares, k, feldman_component_32, expected_key_commitment,
                                plaintext, plaintext_len, aad, aad_len, out_iv, out_ciphertext,
                                ciphertext_buf_cap, out_ciphertext_len, out_hmac);
    }
    vault_secure_wipe(shares, sizeof(shares));
    return rc;
}

/* vault_enclave_unseal with the k GF(2^8) shares read from files by C (see vault_enclave_seal_files). */
int vault_enclave_unseal_files(
    const char *const *share_paths,
    const uint8_t *share_x,
    const uint8_t *expected_share_sha256_flat,
    size_t k,
    size_t *out_bad_index,
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
    uint8_t shares[VAULT_MAX_SHARES * VAULT_KEY_LEN];
    int rc = load_quorum_shares(share_paths, share_x, expected_share_sha256_flat, k, shares, out_bad_index);
    if (rc == 0) {
        rc = vault_enclave_unseal(share_x, shares, k, feldman_component_32, aad, aad_len, iv,
                                  ciphertext, ciphertext_len, expected_hmac, out_plaintext,
                                  plaintext_buf_cap, out_plaintext_len);
    }
    vault_secure_wipe(shares, sizeof(shares));
    return rc;
}

/* Returns 0 if `path` is a regular non-symlink file of 32 bytes whose SHA-256 equals
 * expected_sha256_32, otherwise a share-file error code. The content is never returned. */
int vault_share_file_check(const char *path, const uint8_t *expected_sha256_32) {
    uint8_t share[VAULT_KEY_LEN];
    int rc = load_verified_share(path, expected_sha256_32, share);
    vault_secure_wipe(share, sizeof(share));
    return rc;
}

/* Copies a share file (must be a valid 32-byte share file) to dst (0600, no symlink follow)
 * through a wiped C stack buffer. Used for the demo backup and restore. */
int vault_share_file_copy(const char *src_path, const char *dst_path) {
    uint8_t share[VAULT_KEY_LEN];
    int rc = read_share_file(src_path, share);
    if (rc == 0) rc = write_share_file(dst_path, share);
    vault_secure_wipe(share, sizeof(share));
    return rc;
}

/* Demo only ("Corrupt" button): XORs byte `byte_index` of a share file with `xor_mask` in place. */
int vault_share_file_flip_byte(const char *path, size_t byte_index, uint8_t xor_mask) {
    struct stat st;
    uint8_t b = 0;
    ssize_t r = 0;
    int rc = 0;

    if (path == NULL || xor_mask == 0) return VAULT_SHARE_EINVAL;
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return share_open_error(errno);

    if (fstat(fd, &st) != 0) {
        rc = VAULT_SHARE_EIO;
        goto done;
    }
    if (!S_ISREG(st.st_mode)) {
        rc = VAULT_SHARE_ESIZE;
        goto done;
    }
    if (st.st_size < 0 || byte_index >= (size_t)st.st_size) {
        rc = VAULT_SHARE_EINVAL;
        goto done;
    }
    do {
        r = pread(fd, &b, 1, (off_t)byte_index);
    } while (r < 0 && errno == EINTR);
    if (r != 1) {
        rc = VAULT_SHARE_EIO;
        goto done;
    }
    b ^= xor_mask;
    do {
        r = pwrite(fd, &b, 1, (off_t)byte_index);
    } while (r < 0 && errno == EINTR);
    if (r != 1 || fsync(fd) != 0) rc = VAULT_SHARE_EWRITE;

done:
    vault_secure_wipe(&b, sizeof(b));
    if (close(fd) != 0 && rc == 0) rc = VAULT_SHARE_EWRITE;
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
 * NATIVE C RLWE-BFV ENGINE (leveled, multiplicative depth 1, no bootstrapping)
 * Ring: R_q = Z_q[X] / (X^2048 + 1), q = 2^54, t = 65536
 * Public BFV functions return int: 0 = ok, VAULT_BFV_ENOMEM = allocation failure.
 * ========================================================================= */

#define VAULT_BFV_ENOMEM (-1)

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

static int bfv_sample_uniform_q(int64_t *out) {
    uint64_t *rnd = (uint64_t *)calloc(BFV_N, sizeof(uint64_t));
    if (rnd == NULL) return VAULT_BFV_ENOMEM;
    arc4random_buf(rnd, sizeof(uint64_t) * BFV_N);
    for (int i = 0; i < BFV_N; i++) {
        int64_t u = (int64_t)(rnd[i] & ((uint64_t)BFV_Q - 1ULL));
        if (u >= BFV_HALF_Q) u -= BFV_Q;
        out[i] = u;
    }
    vault_secure_wipe(rnd, sizeof(uint64_t) * BFV_N);
    free(rnd);
    return 0;
}

/* Exact negacyclic convolution in Z[X]/(X^N + 1) using 128-bit accumulators.
 *
 * NOT CONSTANT-TIME: the `ai == 0` skip below makes the running time depend on the number
 * of zero coefficients of `a`. Callers pass secret polynomials as `a` (the secret key s in
 * keygen and decrypt, the encryption randomness u in encrypt), so timing leaks roughly the
 * Hamming weight of those ternary polynomials. The constant-time claim of this library
 * covers only the GF(2^8) arithmetic and the MAC/commitment comparison (vault_ct_memeq),
 * not the BFV engine. */
static void bfv_poly_mul_exact(const int64_t *a, const int64_t *b, int128_t *out) {
    memset(out, 0, sizeof(int128_t) * BFV_N);
    for (int i = 0; i < BFV_N; i++) {
        int128_t ai = (int128_t)a[i];
        if (ai == 0) continue; /* data-dependent branch, see comment above */
        int split = BFV_N - i;
        for (int j = 0; j < split; j++) {
            out[i + j] += ai * (int128_t)b[j];
        }
        for (int j = split; j < BFV_N; j++) {
            out[i + j - BFV_N] -= ai * (int128_t)b[j];
        }
    }
}

static int bfv_poly_mul_mod(const int64_t *a, const int64_t *b, int64_t *out) {
    int128_t *tmp = (int128_t *)calloc(BFV_N, sizeof(int128_t));
    if (tmp == NULL) return VAULT_BFV_ENOMEM;
    bfv_poly_mul_exact(a, b, tmp);
    for (int i = 0; i < BFV_N; i++) {
        out[i] = bfv_cmod(tmp[i]);
    }
    vault_secure_wipe(tmp, sizeof(int128_t) * BFV_N);
    free(tmp);
    return 0;
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

int vault_bfv_keygen(int64_t *out_sk, int64_t *out_pk, int64_t *out_rlk) {
    int rc = 0;
    int64_t *work = (int64_t *)calloc(4 * BFV_N, sizeof(int64_t));
    if (work == NULL) return VAULT_BFV_ENOMEM;
    int64_t *s2 = &work[0];
    int64_t *a_tmp = &work[BFV_N];
    int64_t *e_tmp = &work[2 * BFV_N];
    int64_t *as_prod = &work[3 * BFV_N];

    bfv_sample_ternary(out_sk);
    if ((rc = bfv_poly_mul_mod(out_sk, out_sk, s2)) != 0) goto fail;

    if ((rc = bfv_sample_uniform_q(a_tmp)) != 0) goto fail;
    bfv_sample_ternary(e_tmp);
    if ((rc = bfv_poly_mul_mod(a_tmp, out_sk, as_prod)) != 0) goto fail;
    for (int i = 0; i < BFV_N; i++) {
        out_pk[i] = bfv_cmod(-((int128_t)as_prod[i] + (int128_t)e_tmp[i]));
        out_pk[BFV_N + i] = a_tmp[i];
    }

    for (int l = 0; l < BFV_LIMBS; l++) {
        int128_t scale = ((int128_t)1) << (l * BFV_GADGET_BITS);
        if ((rc = bfv_sample_uniform_q(a_tmp)) != 0) goto fail;
        bfv_sample_ternary(e_tmp);
        if ((rc = bfv_poly_mul_mod(a_tmp, out_sk, as_prod)) != 0) goto fail;

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
    return 0;

fail:
    /* Never hand back a half-generated (possibly insecure) key set. */
    vault_secure_wipe(out_sk, sizeof(int64_t) * BFV_N);
    vault_secure_wipe(out_pk, sizeof(int64_t) * 2 * BFV_N);
    vault_secure_wipe(out_rlk, sizeof(int64_t) * 2 * BFV_LIMBS * BFV_N);
    vault_secure_wipe(work, sizeof(int64_t) * 4 * BFV_N);
    free(work);
    return rc;
}

int vault_bfv_encrypt(const int64_t *pk, int64_t m, int64_t *out_ct) {
    int rc = 0;
    int64_t *work = (int64_t *)calloc(5 * BFV_N, sizeof(int64_t));
    if (work == NULL) return VAULT_BFV_ENOMEM;
    int64_t *u = &work[0];
    int64_t *e1 = &work[BFV_N];
    int64_t *e2 = &work[2 * BFV_N];
    int64_t *p0u = &work[3 * BFV_N];
    int64_t *p1u = &work[4 * BFV_N];

    bfv_sample_ternary(u);
    bfv_sample_ternary(e1);
    bfv_sample_ternary(e2);

    /* Multiply small ternary u as first argument to exploit the ai == 0 skip
     * (a speed trick; it makes encryption timing depend on u, see bfv_poly_mul_exact). */
    if ((rc = bfv_poly_mul_mod(u, &pk[0], p0u)) != 0 ||
        (rc = bfv_poly_mul_mod(u, &pk[BFV_N], p1u)) != 0) {
        vault_secure_wipe(work, sizeof(int64_t) * 5 * BFV_N);
        free(work);
        return rc;
    }

    int64_t m_mod = ((m % BFV_T) + BFV_T) % BFV_T;
    for (int i = 0; i < BFV_N; i++) {
        int128_t msg_scaled = (i == 0) ? ((int128_t)BFV_DELTA * (int128_t)m_mod) : 0;
        out_ct[i] = bfv_cmod((int128_t)p0u[i] + (int128_t)e1[i] + msg_scaled);
        out_ct[BFV_N + i] = bfv_cmod((int128_t)p1u[i] + (int128_t)e2[i]);
    }

    vault_secure_wipe(work, sizeof(int64_t) * 5 * BFV_N);
    free(work);
    return 0;
}

void vault_bfv_add(const int64_t *ct1, const int64_t *ct2, int64_t *out_ct) {
    for (int i = 0; i < 2 * BFV_N; i++) {
        out_ct[i] = bfv_cmod((int128_t)ct1[i] + (int128_t)ct2[i]);
    }
}

int vault_bfv_mul_relin(const int64_t *ct1, const int64_t *ct2, const int64_t *rlk, int64_t *out_ct) {
    int rc = 0;
    const int64_t *c0 = &ct1[0];
    const int64_t *c1 = &ct1[BFV_N];
    const int64_t *d0 = &ct2[0];
    const int64_t *d1 = &ct2[BFV_N];

    int128_t *ex_work = (int128_t *)calloc(4 * BFV_N, sizeof(int128_t));
    int64_t *i64_work = (int64_t *)calloc((7 + BFV_LIMBS) * BFV_N, sizeof(int64_t));
    if (ex_work == NULL || i64_work == NULL) {
        free(ex_work);
        free(i64_work);
        return VAULT_BFV_ENOMEM;
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
        if ((rc = bfv_poly_mul_mod(digit_l, rlk_b, prod_b)) != 0) goto cleanup;
        if ((rc = bfv_poly_mul_mod(digit_l, rlk_a, prod_a)) != 0) goto cleanup;
        for (int i = 0; i < BFV_N; i++) {
            out0[i] = bfv_cmod((int128_t)out0[i] + (int128_t)prod_b[i]);
            out1[i] = bfv_cmod((int128_t)out1[i] + (int128_t)prod_a[i]);
        }
    }

    memcpy(&out_ct[0], out0, sizeof(int64_t) * BFV_N);
    memcpy(&out_ct[BFV_N], out1, sizeof(int64_t) * BFV_N);

cleanup:
    /* Wipe the tensor-product and relinearization workspace before releasing it. */
    vault_secure_wipe(ex_work, sizeof(int128_t) * 4 * BFV_N);
    vault_secure_wipe(i64_work, sizeof(int64_t) * (7 + BFV_LIMBS) * BFV_N);
    free(ex_work);
    free(i64_work);
    return rc;
}

/* Decrypts ct with sk; writes the plaintext in [0, t) to *out_m. Returns 0 on success. */
int vault_bfv_decrypt(const int64_t *sk, const int64_t *ct, int64_t *out_m) {
    if (out_m == NULL) return -2;
    int64_t *c1s = (int64_t *)calloc(BFV_N, sizeof(int64_t));
    if (c1s == NULL) return VAULT_BFV_ENOMEM;

    if (bfv_poly_mul_mod(sk, &ct[BFV_N], c1s) != 0) {
        vault_secure_wipe(c1s, sizeof(int64_t) * BFV_N);
        free(c1s);
        return VAULT_BFV_ENOMEM;
    }
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
    *out_m = res;
    return 0;
}
