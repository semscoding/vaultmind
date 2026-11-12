"""
Paillier Additive Homomorphic Cryptosystem (1024-bit PHE) & Blind Evaluator.

Mathematical properties over Z_{n^2}^*:
- Additive Homomorphism (PHE): D(E(m1) * E(m2) mod n^2) = (m1 + m2) mod n
- Scalar Multiplication (PHE): D(E(m1)^k mod n^2) = (k * m1) mod n

For non-linear ciphertext × ciphertext multiplication E(m1) * E(m2), VaultMind pairs
Paillier with Native C 128-bit Lattice Security Ring-LWE BFV FHE in `bfv_fhe.py`.
"""

import math
import re
import secrets
from typing import Any, Dict, Tuple
from sympy import isprime


def normalize_fhe_handle(raw_ref: Any) -> str:
    """
    Strip inline `(ENC:0x...)` previews that live LLMs (Gemini / OpenAI / Bedrock)
    occasionally include when copying `[FHE_NUM_1](ENC:0x...)` from the wire prompt.
    """
    text = str(raw_ref or "").strip()
    return re.sub(r"\(ENC:0x[0-9a-fA-F\.]+\)", "", text)


def generate_prime(bits: int = 512) -> int:
    """Generate a cryptographically random prime of `bits` bit-length."""
    if bits < 64:
        raise ValueError("Prime bit-length must be >= 64.")
    while True:
        candidate = secrets.randbits(bits)
        # Set top two bits (guarantees p * q is strictly `2 * bits` bits long) and LSB (odd)
        candidate |= (3 << (bits - 2)) | 1
        if isprime(candidate):
            return candidate


def lcm(a: int, b: int) -> int:
    return abs(a * b) // math.gcd(a, b)


class PaillierKeypair:
    DEFAULT_SCALE = 100  # 2 decimal places of exact fixed-point precision

    def __init__(self, p: int, q: int, bits: int = 1024):
        if p == q:
            raise ValueError("Primes p and q must be distinct.")
        self.p = p
        self.q = q
        self.bits = bits
        self.n = p * q
        self.n_sq = self.n * self.n
        self.lambd = lcm(p - 1, q - 1)
        self.g = self.n + 1
        self.mu = pow(self.lambd % self.n, -1, self.n)

    @classmethod
    def generate(cls, bits: int = 1024) -> "PaillierKeypair":
        if bits < 512:
            raise ValueError("Minimum secure Paillier modulus size is 512 bits (1024+ recommended).")
        half = bits // 2
        p = generate_prime(half)
        q = generate_prime(half)
        while p == q:
            q = generate_prime(half)
        return cls(p, q, bits=bits)

    def encrypt_int(self, m: int) -> int:
        if abs(m) >= self.n // 2:
            raise ValueError("Plaintext magnitude exceeds 1024-bit Paillier message space.")
        m_mod = m % self.n

        while True:
            r = secrets.randbelow(self.n - 1) + 1
            if math.gcd(r, self.n) == 1:
                break

        gm = (1 + m_mod * self.n) % self.n_sq
        rn = pow(r, self.n, self.n_sq)
        return (gm * rn) % self.n_sq

    def decrypt_int(self, c: int) -> int:
        u = pow(c, self.lambd, self.n_sq)
        l_u = (u - 1) // self.n
        m = (l_u * self.mu) % self.n
        if m > self.n // 2:
            m -= self.n
        return m

    def encrypt_fixed(self, value: float, scale: int = DEFAULT_SCALE) -> Tuple[int, int]:
        if math.isnan(value) or math.isinf(value):
            raise ValueError("Numeric value cannot be NaN or Infinity.")
        scaled_int = int(round(value * scale))
        return self.encrypt_int(scaled_int), scale

    def decrypt_fixed(self, ciphertext: int, scale: int = DEFAULT_SCALE) -> float:
        raw_int = self.decrypt_int(ciphertext)
        return raw_int / float(scale)

    def homomorphic_add(self, c1: int, c2: int) -> int:
        return (c1 * c2) % self.n_sq

    def homomorphic_multiply_scalar(self, c: int, scalar: int) -> int:
        if scalar < 0:
            c_inv = pow(c, -1, self.n_sq)
            return pow(c_inv, -scalar, self.n_sq)
        return pow(c, scalar, self.n_sq)

    @property
    def public_key_dict(self) -> Dict[str, Any]:
        return {
            "scheme": "Paillier Additive Homomorphic (1024-bit PHE)",
            "modulus_bits": self.n.bit_length(),
            "n_preview": hex(self.n)[:22] + "..." + hex(self.n)[-10:],
            "n_squared_bits": self.n_sq.bit_length(),
            "g_formula": "n + 1",
        }


class HomomorphicEvaluator:
    """
    Executes algebraic expressions on Paillier ciphertexts using ONLY the public key (n, n^2).
    """

    def __init__(self, n: int):
        self.n = n
        self.n_sq = n * n

    def add_scaled(self, c1: int, scale1: int, c2: int, scale2: int) -> Tuple[int, int]:
        target_scale = lcm(scale1, scale2)
        if scale1 != target_scale:
            factor1 = target_scale // scale1
            c1 = pow(c1, factor1, self.n_sq)
        if scale2 != target_scale:
            factor2 = target_scale // scale2
            c2 = pow(c2, factor2, self.n_sq)
        return (c1 * c2) % self.n_sq, target_scale

    def percentage_of(self, c: int, scale: int, percent_int: int) -> Tuple[int, int]:
        if percent_int < 0:
            raise ValueError("Percentage must be non-negative.")
        c_out = pow(c, percent_int, self.n_sq)
        return c_out, scale * 100

    def evaluate_operation(
        self, op_spec: Dict[str, Any], encrypted_handles: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        op = op_spec.get("op", "").upper()

        if op == "PERCENT_BONUS":
            ref = normalize_fhe_handle(op_spec.get("ref", ""))
            pct = int(op_spec.get("percent", 15))
            if ref not in encrypted_handles:
                raise KeyError(f"Unknown homomorphic handle: {ref}")
            entry = encrypted_handles[ref]
            c_bonus, scale_bonus = self.percentage_of(entry["ciphertext"], entry["scale"], pct)
            c_total, scale_total = self.percentage_of(entry["ciphertext"], entry["scale"], 100 + pct)
            return {
                "engine": "1024-bit Paillier PHE",
                "op": op,
                "label": f"{pct}% Bonus & Adjusted Compensation on {ref}",
                "formula": f"c_bonus = {ref}^{pct} mod n², c_total = {ref}^{100 + pct} mod n²",
                "outputs": {
                    "[FHE_COMPUTED_BONUS]": {"ciphertext": c_bonus, "scale": scale_bonus},
                    "[FHE_COMPUTED_TOTAL]": {"ciphertext": c_total, "scale": scale_total},
                },
            }

        if op == "ADD":
            ref_a = normalize_fhe_handle(op_spec.get("ref_a", ""))
            ref_b = normalize_fhe_handle(op_spec.get("ref_b", ""))
            if ref_a not in encrypted_handles or ref_b not in encrypted_handles:
                raise KeyError(f"Unknown homomorphic handles for ADD: {ref_a}, {ref_b}")
            ea = encrypted_handles[ref_a]
            eb = encrypted_handles[ref_b]
            c_sum, scale_sum = self.add_scaled(ea["ciphertext"], ea["scale"], eb["ciphertext"], eb["scale"])
            return {
                "engine": "1024-bit Paillier PHE",
                "op": op,
                "label": f"Homomorphic Sum ({ref_a} + {ref_b})",
                "formula": f"c_sum = ({ref_a} · {ref_b}) mod n²",
                "outputs": {
                    "[FHE_COMPUTED_SUM]": {"ciphertext": c_sum, "scale": scale_sum},
                },
            }

        if op == "MUL_SCALAR":
            ref = normalize_fhe_handle(op_spec.get("ref", ""))
            scalar = int(op_spec.get("scalar", 1))
            if ref not in encrypted_handles:
                raise KeyError(f"Unknown homomorphic handle: {ref}")
            entry = encrypted_handles[ref]
            c_mul = pow(entry["ciphertext"], scalar, self.n_sq)
            return {
                "engine": "1024-bit Paillier PHE",
                "op": op,
                "label": f"Homomorphic Scalar Product ({scalar} × {ref})",
                "formula": f"c_prod = {ref}^{scalar} mod n²",
                "outputs": {
                    "[FHE_COMPUTED_PROD]": {"ciphertext": c_mul, "scale": entry["scale"]},
                },
            }

        raise ValueError(f"Unsupported Paillier operation: {op}")
