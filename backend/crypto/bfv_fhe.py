"""
Native C Lattice RLWE-BFV Homomorphic Encryption & Ephemeral Session Secret Vault.

1. RLWE-BFV Scheme (Brakerski-Fan-Vercauteren) over cyclotomic ring R_q = Z_q[X]/(X^64 + 1):
   - Ciphertext modulus q = 2^60, plaintext modulus t = 65536 (2^16), scaling factor Delta = 2^44.
   - Supports BOTH homomorphic addition E(m1) + E(m2) AND non-linear ciphertext-ciphertext
     multiplication E(m1) * E(m2) with 4-limb base-2^15 gadget decomposition relinearization
     executed in compiled C using 128-bit integer arithmetic (__int128).
2. SessionSecretVault:
   - Seals arbitrary free-text passwords, passphrases, and <secret>...</secret> spans locally
     via C CommonCrypto AES-256-CBC + HMAC-SHA256 so raw secrets are not left in plaintext dicts.
"""

import ctypes
import os
from typing import Any, Dict, List

from .zeroize import load_native_lib, secure_zero

BFV_N = 64
BFV_PK_LEN = 2 * BFV_N
BFV_CT_LEN = 2 * BFV_N
BFV_RLK_LEN = 4 * 2 * BFV_N
BFV_T = 65536


def _bind_bfv_and_session_functions() -> ctypes.CDLL:
    lib = load_native_lib()

    lib.vault_session_seal.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.vault_session_seal.restype = ctypes.c_int

    lib.vault_session_unseal.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.vault_session_unseal.restype = ctypes.c_int

    lib.vault_bfv_keygen.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.vault_bfv_keygen.restype = None

    lib.vault_bfv_encrypt.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.c_int64,
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.vault_bfv_encrypt.restype = None

    lib.vault_bfv_add.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.vault_bfv_add.restype = None

    lib.vault_bfv_mul_relin.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.vault_bfv_mul_relin.restype = None

    lib.vault_bfv_decrypt.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.vault_bfv_decrypt.restype = ctypes.c_int64

    return lib


_LIB = _bind_bfv_and_session_functions()


class SessionSecretVault:
    """
    Encrypts arbitrary prompt secrets (passwords, JWTs, <secret>...</secret>) inside native C
    using AES-256-CBC + HMAC-SHA256 under a mutable ctypes session buffer wiped via memset_s().
    """

    def __init__(self):
        self._key = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))

    def seal(self, raw_secret: str) -> Dict[str, str]:
        pt_bytes = raw_secret.encode("utf-8")
        pt_len = max(1, len(pt_bytes))
        c_pt = (ctypes.c_uint8 * pt_len)()
        for idx, b in enumerate(pt_bytes):
            c_pt[idx] = b

        c_iv = (ctypes.c_uint8 * 16)()
        ct_cap = len(pt_bytes) + 32
        c_ct = (ctypes.c_uint8 * ct_cap)()
        c_ct_len = ctypes.c_size_t(0)
        c_hmac = (ctypes.c_uint8 * 32)()

        try:
            rc = _LIB.vault_session_seal(
                self._key,
                c_pt,
                len(pt_bytes),
                c_iv,
                c_ct,
                ct_cap,
                ctypes.byref(c_ct_len),
                c_hmac,
            )
            if rc != 0:
                raise RuntimeError(f"vault_session_seal failed with code {rc}")
            ct_hex = bytes(c_ct[: c_ct_len.value]).hex()
            return {
                "iv_hex": bytes(c_iv).hex(),
                "ct_hex": ct_hex,
                "hmac_hex": bytes(c_hmac).hex(),
                "preview": f"0x{ct_hex[:16]}...",
            }
        finally:
            secure_zero(c_pt)

    def unseal(self, blob: Dict[str, str]) -> str:
        iv_b = bytes.fromhex(blob["iv_hex"])
        ct_b = bytes.fromhex(blob["ct_hex"])
        hmac_b = bytes.fromhex(blob["hmac_hex"])

        c_iv = (ctypes.c_uint8 * 16).from_buffer_copy(iv_b)
        c_ct = (ctypes.c_uint8 * len(ct_b)).from_buffer_copy(ct_b)
        c_hmac = (ctypes.c_uint8 * 32).from_buffer_copy(hmac_b)
        pt_cap = len(ct_b) + 32
        c_pt = (ctypes.c_uint8 * pt_cap)()
        c_pt_len = ctypes.c_size_t(0)

        try:
            rc = _LIB.vault_session_unseal(
                self._key,
                c_iv,
                c_ct,
                len(ct_b),
                c_hmac,
                c_pt,
                pt_cap,
                ctypes.byref(c_pt_len),
            )
            if rc != 0:
                raise RuntimeError(f"vault_session_unseal integrity check failed (rc={rc})")
            return bytes(c_pt[: c_pt_len.value]).decode("utf-8")
        finally:
            secure_zero(c_pt)

    def close(self) -> None:
        if getattr(self, "_key", None) is not None:
            secure_zero(self._key)


class BFVEvaluator:
    """
    Untrusted Cloud / Blind Evaluator for RLWE-BFV ciphertexts.
    Holds ONLY the public relinearization key `rlk` — ZERO access to ternary secret key `s`.
    """

    def __init__(self, rlk_coeffs: List[int]):
        if len(rlk_coeffs) != BFV_RLK_LEN:
            raise ValueError(f"Invalid BFV relinearization key length: {len(rlk_coeffs)}")
        self._rlk = (ctypes.c_int64 * BFV_RLK_LEN)(*rlk_coeffs)

    @staticmethod
    def _to_c_ct(ct: List[int]):
        if len(ct) != BFV_CT_LEN:
            raise ValueError(f"Invalid BFV ciphertext length: {len(ct)}")
        return (ctypes.c_int64 * BFV_CT_LEN)(*ct)

    def add(self, ct1: List[int], ct2: List[int]) -> List[int]:
        """Compute E(m1 + m2 mod 65536) in R_q."""
        c1 = self._to_c_ct(ct1)
        c2 = self._to_c_ct(ct2)
        out = (ctypes.c_int64 * BFV_CT_LEN)()
        _LIB.vault_bfv_add(c1, c2, out)
        return list(out)

    def multiply(self, ct1: List[int], ct2: List[int]) -> List[int]:
        """
        Compute non-linear ciphertext × ciphertext product E(m1 * m2 mod 65536)
        using tensor product scaling round((t/q) * (c1 (x) c2)) + 4-limb gadget relinearization.
        """
        c1 = self._to_c_ct(ct1)
        c2 = self._to_c_ct(ct2)
        out = (ctypes.c_int64 * BFV_CT_LEN)()
        _LIB.vault_bfv_mul_relin(c1, c2, self._rlk, out)
        return list(out)


class BFVContext:
    """
    Trusted Local Client Context for Ring-LWE BFV Homomorphic Encryption.
    Ring: R_q = Z_{2^60}[X] / (X^64 + 1), Plaintext space Z_{65536}.
    """

    def __init__(self):
        self._sk = (ctypes.c_int64 * BFV_N)()
        self._pk = (ctypes.c_int64 * BFV_PK_LEN)()
        self._rlk = (ctypes.c_int64 * BFV_RLK_LEN)()
        _LIB.vault_bfv_keygen(self._sk, self._pk, self._rlk)
        self.evaluator = BFVEvaluator(list(self._rlk))

    def encrypt_int(self, m: int) -> List[int]:
        if not (0 <= m < BFV_T):
            raise ValueError(f"BFV integer plaintext must be in [0, {BFV_T - 1}], got {m}.")
        out = (ctypes.c_int64 * BFV_CT_LEN)()
        _LIB.vault_bfv_encrypt(self._pk, ctypes.c_int64(m), out)
        return list(out)

    def decrypt_int(self, ct: List[int]) -> int:
        c_ct = (ctypes.c_int64 * BFV_CT_LEN)(*ct)
        return int(_LIB.vault_bfv_decrypt(self._sk, c_ct))

    @staticmethod
    def ciphertext_preview(ct: List[int]) -> str:
        c0_hex = hex(ct[0] & ((1 << 64) - 1))
        c1_hex = hex(ct[BFV_N] & ((1 << 64) - 1))
        return f"R_q[{c0_hex[:10]}..,{c1_hex[:10]}..]"

    @property
    def parameters_dict(self) -> Dict[str, Any]:
        return {
            "scheme": "RLWE-BFV (Brakerski-Fan-Vercauteren)",
            "ring": "Z_{2^60}[X] / (X^64 + 1)",
            "ring_degree_n": BFV_N,
            "ciphertext_modulus_bits": 60,
            "plaintext_modulus_t": BFV_T,
            "gadget_limbs": 4,
            "gadget_base_bits": 15,
            "execution": "Compiled C11 (__int128 negacyclic convolution)",
        }

    def close(self) -> None:
        if getattr(self, "_sk", None) is not None:
            secure_zero(self._sk)
