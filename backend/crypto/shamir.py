"""
Shamir's (k, n) Threshold Secret Sharing & Dual-Field 2048-bit Feldman VSS.

Combines:
1. Native C constant-time GF(2^8) Shamir split, Lagrange interpolation, and Zero-Leak
   AES-256-CBC + Encrypt-then-MAC HMAC-SHA256 execution (libvaultcrypto.dylib).
2. Publicly verifiable Feldman VSS over RFC 3526 Group 14 (2048-bit MODP Safe Prime P = 2q + 1),
   mathematically bound into C-stack key derivation via K_master = HMAC-SHA256(K_GF256, SHA256(alpha_0))
   so BOTH the 2048-bit Feldman Z_q shares AND the C-stack GF(2^8) shares are required to unseal.

Key handling, stated precisely: by default the 256-bit GF(2^8) key is generated with
arc4random_buf on the C stack, split and wiped in C (vault_generate_and_split_key); the
reconstructed key and the AES/HMAC subkeys exist only on the C stack. Shares do pass through
Python as bytes/hex, and the Feldman secret alpha_0 is a Python int (generated and re-interpolated
in Python), so a Python heap dump plus k shards is enough to recompute the master key.
"""

import ctypes
import hashlib
import secrets
from typing import Any, Dict, List, Optional, Tuple

from .zeroize import NativeBufferGuard, load_native_lib, secure_zero

RFC3526_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
FELDMAN_P = int(RFC3526_P_HEX, 16)
FELDMAN_Q = (FELDMAN_P - 1) // 2
FELDMAN_G = 4


def _bind_native_functions() -> ctypes.CDLL:
    lib = load_native_lib()

    lib.vault_gf256_mul.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
    lib.vault_gf256_mul.restype = ctypes.c_uint8

    lib.vault_gf256_inv.argtypes = [ctypes.c_uint8]
    lib.vault_gf256_inv.restype = ctypes.c_uint8

    lib.vault_gf256_eval_poly.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.c_uint8,
    ]
    lib.vault_gf256_eval_poly.restype = ctypes.c_uint8

    lib.vault_split_secret.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.c_uint8,
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.vault_split_secret.restype = ctypes.c_int

    lib.vault_generate_and_split_key.argtypes = [
        ctypes.c_uint8,
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.vault_generate_and_split_key.restype = ctypes.c_int

    lib.vault_reconstruct_bytes.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.vault_reconstruct_bytes.restype = ctypes.c_int

    lib.vault_enclave_seal.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.vault_enclave_seal.restype = ctypes.c_int

    lib.vault_enclave_unseal.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.vault_enclave_unseal.restype = ctypes.c_int

    return lib


_CLIB = _bind_native_functions()


class FeldmanVSS:
    def __init__(self, p: int = FELDMAN_P, q: int = FELDMAN_Q, g: int = FELDMAN_G):
        self.p = p
        self.q = q
        self.g = g

    def split_verifiable(self, secret_int: int, threshold_k: int, total_n: int) -> Dict[str, Any]:
        if not (1 <= threshold_k <= total_n):
            raise ValueError("Invalid threshold parameters.")
        a0 = secret_int % self.q
        # Higher coefficients are uniform over all of Z_q (including 0), as Shamir's proof requires.
        coeffs = [a0] + [secrets.randbelow(self.q) for _ in range(threshold_k - 1)]

        commitments = [pow(self.g, c, self.p) for c in coeffs]
        shares: List[Tuple[int, int]] = []
        for x in range(1, total_n + 1):
            val = 0
            for c in reversed(coeffs):
                val = (val * x + c) % self.q
            shares.append((x, val))

        return {
            "shares": shares,
            "commitments_hex": [hex(c) for c in commitments],
        }

    def verify_share(self, x: int, y: int, commitments_hex: List[str]) -> bool:
        if x <= 0 or y < 0 or y >= self.q or not commitments_hex:
            return False

        lhs = pow(self.g, y, self.p)
        rhs = 1
        x_pow = 1
        for c_hex in commitments_hex:
            c_j = int(c_hex, 16)
            term = pow(c_j, x_pow, self.p)
            rhs = (rhs * term) % self.p
            x_pow = (x_pow * x) % self.q

        return lhs == rhs

    def interpolate_zero(self, shares: List[Tuple[int, int]]) -> int:
        """Lagrange interpolation at x = 0 over Z_q."""
        k = len(shares)
        if k == 0:
            raise ValueError("Cannot interpolate empty Feldman share list.")
        acc = 0
        for j in range(k):
            xj, yj = shares[j]
            num = 1
            den = 1
            for m in range(k):
                if m == j:
                    continue
                xm, _ = shares[m]
                num = (num * (-xm)) % self.q
                den = (den * (xj - xm)) % self.q
            basis = (num * pow(den, -1, self.q)) % self.q
            acc = (acc + yj * basis) % self.q
        return acc


class ShamirSecretSharing:
    CANARY_SECRET_BYTE = 0x2A

    def __init__(self):
        self.lib = _CLIB
        self.vss = FeldmanVSS()

    def gf256_mul(self, a: int, b: int) -> int:
        return int(self.lib.vault_gf256_mul(a & 0xFF, b & 0xFF))

    def gf256_inv(self, a: int) -> int:
        if (a & 0xFF) == 0:
            raise ZeroDivisionError("0 has no multiplicative inverse in GF(2^8).")
        return int(self.lib.vault_gf256_inv(a & 0xFF))

    def interpolate_gf256_curve(
        self, valid_canary_points: List[Tuple[int, int]], eval_xs: List[int]
    ) -> List[Dict[str, int]]:
        k = len(valid_canary_points)
        if k == 0:
            return []

        results: List[Dict[str, int]] = []
        for target_x in eval_xs:
            acc = 0
            for j in range(k):
                xj, yj = valid_canary_points[j]
                num = 1
                den = 1
                for m in range(k):
                    if m == j:
                        continue
                    xm, _ = valid_canary_points[m]
                    num = self.gf256_mul(num, target_x ^ xm)
                    den = self.gf256_mul(den, xj ^ xm)
                basis = self.gf256_mul(num, self.gf256_inv(den))
                acc ^= self.gf256_mul(yj, basis)
            results.append({"x": target_x, "y": acc})
        return results

    @staticmethod
    def _fill_feldman_component(alpha_0: int, c_buf) -> None:
        digest = bytearray(hashlib.sha256(alpha_0.to_bytes(256, "big")).digest())
        for i in range(32):
            c_buf[i] = digest[i]
        secure_zero(digest)

    def generate_and_split_master_key(
        self,
        threshold_k: int = 3,
        total_n: int = 5,
        seed_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        if not (1 <= threshold_k <= total_n <= 255):
            raise ValueError("Require 1 <= threshold_k <= total_n <= 255.")

        vss_alpha0 = secrets.randbelow(self.vss.q - 1) + 1
        vss_bundle = self.vss.split_verifiable(vss_alpha0, threshold_k, total_n)
        shares_flat = (ctypes.c_uint8 * (total_n * 32))()
        key_commitment = (ctypes.c_uint8 * 32)()

        with NativeBufferGuard(32) as feldman_buf:
            self._fill_feldman_component(vss_alpha0, feldman_buf)

            if seed_bytes is None:
                # Default path: the 256-bit GF(2^8) key is drawn with arc4random_buf on the
                # C stack, split, committed and wiped inside C; it never enters Python.
                rc = self.lib.vault_generate_and_split_key(
                    threshold_k,
                    total_n,
                    feldman_buf,
                    shares_flat,
                    key_commitment,
                )
                if rc != 0:
                    raise RuntimeError(f"Native vault_generate_and_split_key failed with code {rc}")
            else:
                # Deterministic path (explicit seed, e.g. tests): the seed is caller-supplied.
                with NativeBufferGuard(32) as gf_buf:
                    raw_source = bytearray(seed_bytes)
                    if len(raw_source) != 32:
                        secure_zero(raw_source)
                        raise ValueError("GF(2^8) key share seed must be 32 bytes (256 bits).")

                    for i in range(32):
                        gf_buf[i] = raw_source[i]
                    secure_zero(raw_source)

                    rc = self.lib.vault_split_secret(
                        gf_buf,
                        32,
                        threshold_k,
                        total_n,
                        feldman_buf,
                        shares_flat,
                        key_commitment,
                    )
                    if rc != 0:
                        raise RuntimeError(f"Native vault_split_secret failed with code {rc}")

        canary_in = (ctypes.c_uint8 * 1)(self.CANARY_SECRET_BYTE)
        canary_out = (ctypes.c_uint8 * total_n)()
        rc_c = self.lib.vault_split_secret(canary_in, 1, threshold_k, total_n, None, canary_out, None)
        if rc_c != 0:
            raise RuntimeError(f"Canary vault_split_secret failed with code {rc_c}")

        commitment_hex = bytes(key_commitment).hex()
        shards: List[Dict[str, Any]] = []
        share_digests: Dict[int, str] = {}

        for idx in range(total_n):
            x = idx + 1
            gf_slice = bytes(shares_flat[idx * 32 : (idx + 1) * 32]).hex()
            canary_y = int(canary_out[idx])
            _, feldman_y = vss_bundle["shares"][idx]
            feldman_y_hex = hex(feldman_y)

            digest = hashlib.sha256(
                f"{x}:{gf_slice}:{canary_y}:{feldman_y_hex}:{commitment_hex}".encode("utf-8")
            ).hexdigest()
            share_digests[x] = digest

            shards.append(
                {
                    "node_id": f"vault-node-0{x}",
                    "x": x,
                    "gf256_share_hex": gf_slice,
                    "canary_y": canary_y,
                    "feldman_y_hex": feldman_y_hex,
                }
            )

        secure_zero(shares_flat)

        return {
            "threshold_k": threshold_k,
            "total_n": total_n,
            "key_commitment_hex": commitment_hex,
            "feldman_commitments_hex": vss_bundle["commitments_hex"],
            "share_digests": share_digests,
            "canary_expected_secret": self.CANARY_SECRET_BYTE,
            "shards": shards,
        }

    def verify_shard_integrity(
        self,
        shard: Dict[str, Any],
        feldman_commitments_hex: List[str],
        expected_digest: Optional[str],
        key_commitment_hex: str,
    ) -> Tuple[bool, str]:
        try:
            x = int(shard["x"])
            feldman_y = int(shard["feldman_y_hex"], 16)
            gf_hex = shard["gf256_share_hex"]
            canary_y = int(shard["canary_y"])
            if len(bytes.fromhex(gf_hex)) != 32:
                return False, "Invalid GF(2^8) share byte length"
        except Exception as exc:
            return False, f"Malformed shard structure: {exc}"

        if not self.vss.verify_share(x, feldman_y, feldman_commitments_hex):
            return False, "Feldman 2048-bit VSS equation g^s_i == prod(C_j^(i^j)) mod P FAILED"

        if expected_digest is not None:
            actual_digest = hashlib.sha256(
                f"{x}:{gf_hex}:{canary_y}:{shard['feldman_y_hex']}:{key_commitment_hex}".encode("utf-8")
            ).hexdigest()
            if actual_digest != expected_digest:
                return False, "Shard GF(2^8) cryptographic binding mismatch"

        return True, "VERIFIED_VALID"

    def enclave_seal_record(
        self,
        quorum_shards: List[Dict[str, Any]],
        key_commitment_hex: str,
        plaintext_bytes: bytes,
        aad_bytes: bytes = b"",
    ) -> Dict[str, str]:
        k = len(quorum_shards)
        if k < 1:
            raise ValueError("Quorum cannot be empty.")

        share_x = (ctypes.c_uint8 * k)(*[int(s["x"]) for s in quorum_shards])
        shares_flat = (ctypes.c_uint8 * (k * 32))()

        with NativeBufferGuard(32) as feldman_buf:
            try:
                feld_pts: List[Tuple[int, int]] = []
                for idx, s in enumerate(quorum_shards):
                    raw_share = bytes.fromhex(s["gf256_share_hex"])
                    for b_i in range(32):
                        shares_flat[idx * 32 + b_i] = raw_share[b_i]
                    feld_pts.append((int(s["x"]), int(s["feldman_y_hex"], 16)))

                alpha_0 = self.vss.interpolate_zero(feld_pts)
                self._fill_feldman_component(alpha_0, feldman_buf)

                comm_bytes = bytes.fromhex(key_commitment_hex)
                c_comm = (ctypes.c_uint8 * 32)(*comm_bytes)

                c_pt = (ctypes.c_uint8 * max(1, len(plaintext_bytes)))(*plaintext_bytes)
                c_aad = (ctypes.c_uint8 * max(1, len(aad_bytes)))(*aad_bytes)

                c_iv = (ctypes.c_uint8 * 16)()
                ct_cap = len(plaintext_bytes) + 32
                c_ct = (ctypes.c_uint8 * ct_cap)()
                c_ct_len = ctypes.c_size_t(0)
                c_hmac = (ctypes.c_uint8 * 32)()

                rc = self.lib.vault_enclave_seal(
                    share_x,
                    shares_flat,
                    k,
                    feldman_buf,
                    c_comm,
                    c_pt,
                    len(plaintext_bytes),
                    c_aad if len(aad_bytes) > 0 else None,
                    len(aad_bytes),
                    c_iv,
                    c_ct,
                    ct_cap,
                    ctypes.byref(c_ct_len),
                    c_hmac,
                )
                if rc == -10:
                    raise ValueError("Native C Enclave aborted: reconstructed dual-field key failed commitment check!")
                if rc != 0:
                    raise RuntimeError(f"Native C vault_enclave_seal error: {rc}")

                return {
                    "iv_hex": bytes(c_iv).hex(),
                    "ciphertext_hex": bytes(c_ct[: c_ct_len.value]).hex(),
                    "hmac_hex": bytes(c_hmac).hex(),
                }
            finally:
                secure_zero(shares_flat)

    def enclave_unseal_record(
        self,
        quorum_shards: List[Dict[str, Any]],
        iv_hex: str,
        ciphertext_hex: str,
        hmac_hex: str,
        aad_bytes: bytes = b"",
    ) -> bytes:
        k = len(quorum_shards)
        share_x = (ctypes.c_uint8 * k)(*[int(s["x"]) for s in quorum_shards])
        shares_flat = (ctypes.c_uint8 * (k * 32))()

        with NativeBufferGuard(32) as feldman_buf:
            try:
                feld_pts: List[Tuple[int, int]] = []
                for idx, s in enumerate(quorum_shards):
                    raw_share = bytes.fromhex(s["gf256_share_hex"])
                    for b_i in range(32):
                        shares_flat[idx * 32 + b_i] = raw_share[b_i]
                    feld_pts.append((int(s["x"]), int(s["feldman_y_hex"], 16)))

                alpha_0 = self.vss.interpolate_zero(feld_pts)
                self._fill_feldman_component(alpha_0, feldman_buf)

                if not (
                    isinstance(iv_hex, str)
                    and isinstance(ciphertext_hex, str)
                    and isinstance(hmac_hex, str)
                ):
                    raise ValueError("Ledger hex fields (iv_hex, ciphertext_hex, hmac_hex) must be strings.")
                hex_chars = frozenset("0123456789abcdefABCDEF")
                if len(iv_hex) != 32 or not all(ch in hex_chars for ch in iv_hex):
                    raise ValueError("Invalid AES-CBC IV hex: expected exactly 32 hexadecimal characters (16 bytes).")
                if len(hmac_hex) != 64 or not all(ch in hex_chars for ch in hmac_hex):
                    raise ValueError("Invalid HMAC-SHA256 hex: expected exactly 64 hexadecimal characters (32 bytes).")
                if (
                    len(ciphertext_hex) < 32
                    or len(ciphertext_hex) % 32 != 0
                    or not all(ch in hex_chars for ch in ciphertext_hex)
                ):
                    raise ValueError(
                        "Invalid AES-CBC ciphertext hex: expected a non-empty multiple of 32 hexadecimal characters."
                    )

                iv_b = bytes.fromhex(iv_hex)
                ct_b = bytes.fromhex(ciphertext_hex)
                mac_b = bytes.fromhex(hmac_hex)

                c_iv = (ctypes.c_uint8 * 16)(*iv_b)
                c_ct = (ctypes.c_uint8 * max(1, len(ct_b)))(*ct_b)
                c_mac = (ctypes.c_uint8 * 32)(*mac_b)
                c_aad = (ctypes.c_uint8 * max(1, len(aad_bytes)))(*aad_bytes)

                pt_cap = len(ct_b) + 16
                c_pt = (ctypes.c_uint8 * pt_cap)()
                c_pt_len = ctypes.c_size_t(0)

                rc = self.lib.vault_enclave_unseal(
                    share_x,
                    shares_flat,
                    k,
                    feldman_buf,
                    c_aad if len(aad_bytes) > 0 else None,
                    len(aad_bytes),
                    c_iv,
                    c_ct,
                    len(ct_b),
                    c_mac,
                    c_pt,
                    pt_cap,
                    ctypes.byref(c_pt_len),
                )
                if rc == -20:
                    raise ValueError("HMAC-SHA256 authentication tag verification failed (tampered ciphertext)!")
                if rc != 0:
                    raise RuntimeError(f"Native C vault_enclave_unseal error: {rc}")

                out = bytes(c_pt[: c_pt_len.value])
                secure_zero(c_pt)
                return out
            finally:
                secure_zero(shares_flat)
