"""
Paillier Additive Homomorphic Cryptosystem (PHE, 2048-bit modulus by default) & Blind Evaluator.

Mathematical properties over Z_{n^2}^*:
- Additive Homomorphism (PHE): D(E(m1) * E(m2) mod n^2) = (m1 + m2) mod n
- Scalar Multiplication (PHE): D(E(m1)^k mod n^2) = (k * m1) mod n

For non-linear ciphertext × ciphertext multiplication E(m1) * E(m2), VaultMind pairs
Paillier with the native C RLWE-BFV scheme (leveled, depth 1) in `bfv_fhe.py`.

Fixed-point amounts are converted with `decimal.Decimal` (never via binary float rounding),
and LLM-supplied operands (percent, scalar) are range-checked before exponentiation.
"""

import math
import re
import secrets
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from typing import Any, Dict, Tuple, Union
from sympy import isprime


def normalize_fhe_handle(raw_ref: Any) -> str:
    """
    Strip inline `(ENC:0x...)` previews that live LLMs (Gemini / OpenAI / Bedrock)
    occasionally include when copying `[FHE_NUM_1](ENC:0x...)` from the wire prompt.
    """
    text = str(raw_ref or "").strip()
    return re.sub(r"\(ENC:0x[0-9a-fA-F\.]+\)", "", text)


# Bounds for operands that come from an (untrusted) LLM response (S14).
MAX_ABS_SCALAR = 10**6
MAX_PERCENT = Decimal(1000)
MAX_OPERAND_DECIMALS = 4

NumberLike = Union[int, float, str, Decimal]


def to_decimal(value: Any, what: str = "value") -> Decimal:
    """Convert int/float/str/Decimal to a finite Decimal. Floats go via repr() so 4.9 stays 4.9."""
    if isinstance(value, bool):
        raise ValueError(f"{what} must be a number, not a boolean.")
    try:
        if isinstance(value, Decimal):
            dec = value
        elif isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                raise ValueError(f"{what} cannot be NaN or Infinity.")
            dec = Decimal(repr(value))
        elif isinstance(value, (int, str)):
            dec = Decimal(str(value).strip())
        else:
            raise ValueError(f"{what} must be a number, got {type(value).__name__}.")
    except InvalidOperation:
        raise ValueError(f"{what} is not a valid number: {value!r}") from None
    if not dec.is_finite():
        raise ValueError(f"{what} cannot be NaN or Infinity.")
    return dec


def decimal_to_scaled_int(dec: Decimal, what: str) -> Tuple[int, int]:
    """Represent a Decimal exactly as (integer numerator, power-of-ten factor); max 4 decimals."""
    exp = int(dec.normalize().as_tuple().exponent)
    places = max(0, -exp)
    if places > MAX_OPERAND_DECIMALS:
        raise ValueError(f"{what} {dec} has more than {MAX_OPERAND_DECIMALS} decimal places.")
    factor = 10**places
    return int(dec * factor), factor


def generate_prime(bits: int = 1024) -> int:
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

    def __init__(self, p: int, q: int, bits: int = 2048):
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
    def generate(cls, bits: int = 2048) -> "PaillierKeypair":
        if bits < 512:
            raise ValueError("Minimum Paillier modulus size is 512 bits (2048 recommended, ~112-bit security).")
        half = bits // 2
        p = generate_prime(half)
        q = generate_prime(half)
        while p == q:
            q = generate_prime(half)
        return cls(p, q, bits=bits)

    def encrypt_int(self, m: int) -> int:
        if abs(m) >= self.n // 2:
            raise ValueError(
                f"Plaintext magnitude exceeds {self.n.bit_length()}-bit Paillier message space."
            )
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

    def encrypt_fixed(self, value: NumberLike, scale: int = DEFAULT_SCALE) -> Tuple[int, int]:
        """Encrypt int/float/str/Decimal as round_half_even(value * scale), e.g. cents (S7)."""
        dec = to_decimal(value, "Numeric value")
        scaled_int = int((dec * scale).to_integral_value(rounding=ROUND_HALF_EVEN))
        return self.encrypt_int(scaled_int), scale

    def decrypt_fixed(self, ciphertext: int, scale: int = DEFAULT_SCALE) -> float:
        raw_int = self.decrypt_int(ciphertext)
        return raw_int / float(scale)

    def decrypt_fixed_decimal(self, ciphertext: int, scale: int = DEFAULT_SCALE) -> Decimal:
        """Exact fixed-point decryption (no float rounding), used for display formatting."""
        return Decimal(self.decrypt_int(ciphertext)) / Decimal(scale)

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
            "scheme": f"Paillier Additive Homomorphic ({self.n.bit_length()}-bit PHE)",
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

    @property
    def engine_label(self) -> str:
        return f"{self.n.bit_length()}-bit Paillier PHE"

    def add_scaled(self, c1: int, scale1: int, c2: int, scale2: int) -> Tuple[int, int]:
        target_scale = lcm(scale1, scale2)
        if scale1 != target_scale:
            factor1 = target_scale // scale1
            c1 = pow(c1, factor1, self.n_sq)
        if scale2 != target_scale:
            factor2 = target_scale // scale2
            c2 = pow(c2, factor2, self.n_sq)
        return (c1 * c2) % self.n_sq, target_scale

    def percentage_of(self, c: int, scale: int, percent_int: int, percent_factor: int = 1) -> Tuple[int, int]:
        """E(m)^(p) with result scale `scale * 100 * percent_factor` (p = percent * percent_factor)."""
        if percent_int < 0:
            raise ValueError("Percentage must be non-negative.")
        c_out = pow(c, percent_int, self.n_sq)
        return c_out, scale * 100 * percent_factor

    @staticmethod
    def parse_percent(raw: Any) -> Tuple[Decimal, int, int]:
        """Validate an LLM-supplied percent (S6/S14): 0 <= p <= 1000, max 4 decimals, no truncation."""
        pct = to_decimal(raw, "percent")
        if pct < 0 or pct > MAX_PERCENT:
            raise ValueError(f"percent {pct} out of range [0, {MAX_PERCENT}].")
        pct_int, factor = decimal_to_scaled_int(pct, "percent")
        return pct.normalize(), pct_int, factor

    @staticmethod
    def parse_scalar(raw: Any) -> int:
        """Validate an LLM-supplied scalar (S14): an integer with |scalar| <= 10^6."""
        dec = to_decimal(raw, "scalar")
        if dec != dec.to_integral_value():
            raise ValueError(f"scalar {dec} must be an integer.")
        scalar = int(dec)
        if abs(scalar) > MAX_ABS_SCALAR:
            raise ValueError(f"scalar {scalar} out of range [-{MAX_ABS_SCALAR}, {MAX_ABS_SCALAR}].")
        return scalar

    def evaluate_operation(
        self, op_spec: Dict[str, Any], encrypted_handles: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        op = str(op_spec.get("op", "")).upper()

        if op == "PERCENT_BONUS":
            ref = normalize_fhe_handle(op_spec.get("ref", ""))
            pct_dec, pct_int, factor = self.parse_percent(op_spec.get("percent", 15))
            if ref not in encrypted_handles:
                raise KeyError(f"Unknown homomorphic handle: {ref}")
            entry = encrypted_handles[ref]
            pct_label = format(pct_dec, "f")
            hundred = 100 * factor
            c_bonus, scale_bonus = self.percentage_of(entry["ciphertext"], entry["scale"], pct_int, factor)
            c_total, scale_total = self.percentage_of(
                entry["ciphertext"], entry["scale"], hundred + pct_int, factor
            )
            if factor == 1:
                formula = f"c_bonus = {ref}^{pct_int} mod n², c_total = {ref}^{hundred + pct_int} mod n²"
            else:
                formula = (
                    f"c_bonus = {ref}^{pct_int} mod n², c_total = {ref}^{hundred + pct_int} mod n² "
                    f"(percent scaled by {factor}, decrypted / {100 * factor})"
                )
            return {
                "engine": self.engine_label,
                "op": op,
                "label": f"{pct_label}% Bonus & Adjusted Compensation on {ref}",
                "formula": formula,
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
                "engine": self.engine_label,
                "op": op,
                "label": f"Homomorphic Sum ({ref_a} + {ref_b})",
                "formula": f"c_sum = ({ref_a} · {ref_b}) mod n²",
                "outputs": {
                    "[FHE_COMPUTED_SUM]": {"ciphertext": c_sum, "scale": scale_sum},
                },
            }

        if op == "MUL_SCALAR":
            ref = normalize_fhe_handle(op_spec.get("ref", ""))
            scalar = self.parse_scalar(op_spec.get("scalar", 1))
            if ref not in encrypted_handles:
                raise KeyError(f"Unknown homomorphic handle: {ref}")
            entry = encrypted_handles[ref]
            c_mul = pow(entry["ciphertext"], scalar, self.n_sq)
            return {
                "engine": self.engine_label,
                "op": op,
                "label": f"Homomorphic Scalar Product ({scalar} × {ref})",
                "formula": f"c_prod = {ref}^{scalar} mod n²",
                "outputs": {
                    "[FHE_COMPUTED_PROD]": {"ciphertext": c_mul, "scale": entry["scale"]},
                },
            }

        raise ValueError(f"Unsupported Paillier operation: {op}")
