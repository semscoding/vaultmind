"""
Native C RLWE-BFV Homomorphic Encryption (leveled, multiplicative depth 1) & Session Secret Vault.

1. RLWE-BFV Scheme (Brakerski-Fan-Vercauteren) over cyclotomic ring R_q = Z_q[X]/(X^2048 + 1):
   - Leveled, multiplicative depth 1, no bootstrapping: one ciphertext-ciphertext multiplication
     (with relinearization) followed by additions; depth 2 is not supported.
   - Ring degree N = 2048, ciphertext modulus q = 2^54, plaintext modulus t = 65536,
     scaling factor Delta = 2^38, 4-limb base-2^14 gadget relinearization, unbiased rejection sampling.
   - N=2048 and log q=54 follow the classical 128-bit row (ternary secret) of the
     HomomorphicEncryption.org standard; the error distribution is uniform ternary (sigma ~ 0.82)
     instead of sigma ~ 3.2, so 128 bit is an approximation.
   - 32-bit products: the 16 base-256 limb products are each a homomorphic depth-1 product;
     they are decrypted separately and recombined with powers of 256 in plaintext.
2. SessionSecretVault:
   - Seals arbitrary free-text passwords, passphrases, and <secret>...</secret> spans locally
     via C CommonCrypto AES-256-CBC + HMAC-SHA256 so raw secrets never sit in plaintext dicts.
     The 32-byte session key is generated in C with arc4random_buf (vault_random_bytes).
"""

import ctypes
from typing import Any, Dict, List, Tuple

from .zeroize import load_native_lib, secure_zero

BFV_N = 2048
BFV_PK_LEN = 2 * BFV_N
BFV_CT_LEN = 2 * BFV_N
BFV_RLK_LEN = 4 * 2 * BFV_N
BFV_T = 65536
BFV_LIMB_BASE = 256


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
    lib.vault_bfv_keygen.restype = ctypes.c_int

    lib.vault_bfv_encrypt.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.c_int64,
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.vault_bfv_encrypt.restype = ctypes.c_int

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
    lib.vault_bfv_mul_relin.restype = ctypes.c_int

    lib.vault_bfv_decrypt.argtypes = [
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.vault_bfv_decrypt.restype = ctypes.c_int

    lib.vault_random_bytes.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
    lib.vault_random_bytes.restype = ctypes.c_int

    return lib


_LIB = _bind_bfv_and_session_functions()


def _check_rc(rc: int, fn_name: str) -> None:
    if rc != 0:
        raise RuntimeError(f"Native C {fn_name} failed with code {rc} (allocation failure)")


class SessionSecretVault:
    def __init__(self):
        # Session key is drawn in C (arc4random_buf) directly into this mutable buffer.
        self._key = (ctypes.c_uint8 * 32)()
        rc = _LIB.vault_random_bytes(self._key, 32)
        if rc != 0:
            raise RuntimeError(f"vault_random_bytes failed with code {rc}")

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
    Untrusted Cloud / Blind Evaluator for N=2048 RLWE-BFV ciphertexts.
    Holds ONLY the public relinearization key `rlk` — ZERO access to ternary secret key `s`.
    """

    def __init__(self, rlk_array):
        if len(rlk_array) != BFV_RLK_LEN:
            raise ValueError(f"Invalid BFV relinearization key length: {len(rlk_array)}")
        if isinstance(rlk_array, ctypes.Array):
            self._rlk = (ctypes.c_int64 * BFV_RLK_LEN).from_buffer_copy(rlk_array)
        else:
            self._rlk = (ctypes.c_int64 * BFV_RLK_LEN)(*rlk_array)

    @staticmethod
    def _as_c_ct(ct):
        if isinstance(ct, ctypes.Array) and len(ct) == BFV_CT_LEN:
            return ct
        if len(ct) != BFV_CT_LEN:
            raise ValueError(f"Invalid BFV ciphertext length: {len(ct)}")
        return (ctypes.c_int64 * BFV_CT_LEN)(*ct)

    def add(self, ct1, ct2):
        c1 = self._as_c_ct(ct1)
        c2 = self._as_c_ct(ct2)
        out = (ctypes.c_int64 * BFV_CT_LEN)()
        _LIB.vault_bfv_add(c1, c2, out)
        return out

    def multiply(self, ct1, ct2):
        c1 = self._as_c_ct(ct1)
        c2 = self._as_c_ct(ct2)
        out = (ctypes.c_int64 * BFV_CT_LEN)()
        _check_rc(_LIB.vault_bfv_mul_relin(c1, c2, self._rlk, out), "vault_bfv_mul_relin")
        return out

    def multiply_limbs(self, limbs_a: List[Any], limbs_b: List[Any]) -> List[Tuple[int, Any]]:
        """
        Overflow-free homomorphic schoolbook multiplication over base-256 limbs!
        Each limb m_i in [0, 255] satisfies m_i * m_j <= 65025 < 65536 = t, guaranteeing
        ZERO modular wraparound for arbitrary 32-bit / 64-bit integer products!
        """
        terms: List[Tuple[int, Any]] = []
        for i, ca in enumerate(limbs_a):
            for j, cb in enumerate(limbs_b):
                terms.append((i + j, self.multiply(ca, cb)))
        return terms


class BFVContext:
    """
    Trusted Local Client Context for RLWE-BFV (leveled, multiplicative depth 1).
    Ring: R_q = Z_{2^54}[X] / (X^2048 + 1), Plaintext space Z_{65536}.
    """

    def __init__(self):
        self._sk = (ctypes.c_int64 * BFV_N)()
        self._pk = (ctypes.c_int64 * BFV_PK_LEN)()
        self._rlk = (ctypes.c_int64 * BFV_RLK_LEN)()
        _check_rc(_LIB.vault_bfv_keygen(self._sk, self._pk, self._rlk), "vault_bfv_keygen")
        self.evaluator = BFVEvaluator(self._rlk)

    def encrypt_int(self, m: int):
        if not (0 <= m < BFV_T):
            raise ValueError(f"BFV single-ring plaintext must be in [0, {BFV_T - 1}], got {m}.")
        out = (ctypes.c_int64 * BFV_CT_LEN)()
        _check_rc(_LIB.vault_bfv_encrypt(self._pk, ctypes.c_int64(m), out), "vault_bfv_encrypt")
        return out

    def decrypt_int(self, ct) -> int:
        c_ct = BFVEvaluator._as_c_ct(ct)
        out_m = ctypes.c_int64(0)
        _check_rc(_LIB.vault_bfv_decrypt(self._sk, c_ct, ctypes.byref(out_m)), "vault_bfv_decrypt")
        return int(out_m.value)

    def encrypt_limbs_u32(self, value: int) -> List[Any]:
        """Decompose non-negative integer into base-256 limbs in [0, 255] and BFV-encrypt each limb."""
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError(f"BFV u32 value must be in [0, 2^32 - 1], got {value}.")
        if value == 0:
            return [self.encrypt_int(0)]
        limbs = []
        rem = value
        while rem > 0:
            limbs.append(self.encrypt_int(rem & 0xFF))
            rem >>= 8
        return limbs

    def decrypt_limbs_product(self, product_terms: List[Tuple[int, Any]]) -> int:
        total = 0
        for deg, ct in product_terms:
            limb_prod = self.decrypt_int(ct)
            total += limb_prod * (BFV_LIMB_BASE ** deg)
        return total

    @staticmethod
    def ciphertext_preview(ct) -> str:
        c0_hex = hex(int(ct[0]) & ((1 << 64) - 1))
        c1_hex = hex(int(ct[BFV_N]) & ((1 << 64) - 1))
        return f"R_q[{c0_hex[:10]}..,{c1_hex[:10]}..]"

    @property
    def parameters_dict(self) -> Dict[str, Any]:
        return {
            "scheme": "RLWE-BFV (leveled, multiplicative depth 1)",
            "ring": "Z_{2^54}[X] / (X^2048 + 1)",
            "ring_degree_n": BFV_N,
            "ciphertext_modulus_bits": 54,
            "plaintext_modulus_t": BFV_T,
            "gadget_limbs": 4,
            "gadget_base_bits": 14,
            "secret_distribution": "uniform ternary {-1, 0, 1}",
            "error_distribution": "uniform ternary {-1, 0, 1} (sigma ~ 0.82)",
            "security_standard": (
                "N=2048 and log q=54 follow the classical 128-bit row (ternary secret) of the "
                "HomomorphicEncryption.org standard; the error distribution is uniform ternary "
                "(sigma ~ 0.82) instead of sigma ~ 3.2, so 128 bit is an approximation"
            ),
        }

    def close(self) -> None:
        if getattr(self, "_sk", None) is not None:
            secure_zero(self._sk)
