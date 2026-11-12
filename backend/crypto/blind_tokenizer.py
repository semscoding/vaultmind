"""
Span-Based Cryptographic Blind Tokenizer & 1024-bit Paillier Number Encryptor.

Eliminates substring replacement bugs and regex false positives by:
1. Scanning candidate PII, Secret, Banking, Government ID, Entity, and Numeric spans.
2. Resolving overlaps deterministically by cryptographic priority and span length.
3. Rebuilding the blinded prompt in a single linear pass using exact character offsets.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from .homomorphic import HomomorphicEvaluator, PaillierKeypair


STOPWORD_CAPITALS = {
    "Evaluate",
    "Process",
    "Authorize",
    "Analyze",
    "Approve",
    "Update",
    "Calculate",
    "Compute",
    "Transfer",
    "Commit",
    "Grant",
    "Execute",
    "Please",
    "Review",
    "Check",
    "Send",
    "Verify",
    "Query",
    "Store",
    "Create",
    "Delete",
    "Select",
    "Insert",
}

CURRENCY_CODES = {"USD", "EUR", "GBP", "CHF", "JPY", "CAD", "AUD"}


@dataclass
class SpanMatch:
    start: int
    end: int
    category: str
    raw_text: str
    priority: int
    numeric_value: float = 0.0
    prefix_symbol: str = ""


class BlindContext:
    def __init__(self, session_key: bytes, paillier: PaillierKeypair):
        self.session_key = session_key
        self.paillier = paillier
        self.token_to_plaintext: Dict[str, str] = {}
        self.plaintext_to_token: Dict[str, str] = {}
        self.encrypted_numbers: Dict[str, Dict[str, Any]] = {}
        self.computed_numbers: Dict[str, Dict[str, Any]] = {}
        self.primary_subject_token: str = ""
        self.logs: List[str] = []

    def log(self, message: str) -> None:
        self.logs.append(message)


class BlindTokenizer:
    def __init__(self, paillier_bits: int = 1024):
        self.session_key = secrets.token_bytes(32)
        self.paillier = PaillierKeypair.generate(bits=paillier_bits)
        self.evaluator = HomomorphicEvaluator(n=self.paillier.n)

    def _hmac_token(self, raw_value: str, prefix: str) -> str:
        normalized = " ".join(raw_value.strip().split())
        digest = hmac.new(
            self.session_key,
            f"{prefix}:{normalized}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"[{prefix}_{digest[:8].upper()}]"

    @staticmethod
    def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
        return max(a_start, b_start) < min(a_end, b_end)

    def _collect_spans(self, prompt: str) -> List[SpanMatch]:
        candidates: List[SpanMatch] = []

        # Priority 1: Raw API Keys / Bearer Tokens
        for m in re.finditer(
            r"\b(?:sk_[A-Za-z0-9_-]{6,}|sk-[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{10,}|AKIA[0-9A-Z]{10,}|ghp_[A-Za-z0-9]{10,})\b",
            prompt,
        ):
            candidates.append(SpanMatch(m.start(), m.end(), "SECRET", m.group(0), priority=1))

        # Priority 2: International Bank Account Numbers (IBAN)
        for m in re.finditer(
            r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b",
            prompt,
        ):
            candidates.append(SpanMatch(m.start(), m.end(), "IBAN", m.group(0), priority=2))

        # Priority 3: Email addresses
        for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", prompt):
            candidates.append(SpanMatch(m.start(), m.end(), "EMAIL", m.group(0), priority=3))

        # Priority 4: Labeled Government / Medical IDs (BSN, SSN, MRN, Account ID) & SSN patterns
        for m in re.finditer(
            r"(?i:(?<=\bBSN:\s)|(?<=\bSSN:\s)|(?<=\bMRN:\s))([0-9A-Z-]{6,16})\b",
            prompt,
        ):
            candidates.append(SpanMatch(m.start(1), m.end(1), "GOV_ID", m.group(1), priority=4))

        for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", prompt):
            candidates.append(SpanMatch(m.start(), m.end(), "GOV_ID", m.group(0), priority=4))

        # Priority 5: Multi-word Capitalized Names / Organizations / Locations
        # Strict case sensitivity on capitalized words prevents matching "record for"
        for m in re.finditer(
            r"\b([A-Z][a-z]{1,25}(?:\s+[A-Z][a-z]{1,25})+(?:\s+(?:Corp|Inc|Ltd|BV|NV|LLC|Group|Bank|Central|Hospital))?)\b",
            prompt,
        ):
            phrase = m.group(1)
            words = phrase.split()
            # Strip leading command verb if at start of sentence (e.g., "Evaluate Marcus Vance" -> "Marcus Vance")
            start_offset = m.start(1)
            while words and words[0] in STOPWORD_CAPITALS:
                removed = words.pop(0)
                start_offset += len(removed) + 1
            if len(words) >= 2:
                clean_phrase = " ".join(words)
                # Distinguish locations/clinics vs person/company entities by preceding context
                prefix_ctx = prompt[max(0, start_offset - 16) : start_offset].lower()
                cat = "LOC" if ("clinic" in prefix_ctx or "city" in prefix_ctx) else "ID"
                candidates.append(SpanMatch(start_offset, m.end(1), cat, clean_phrase, priority=5))

        # Single capitalized proper name explicitly preceded by role noun (strictly Case-Sensitive on group 1!)
        for m in re.finditer(
            r"(?:employee|patient|client|vendor|recipient|user)\s+([A-Z][a-z]{2,25})\b",
            prompt,
        ):
            word = m.group(1)
            if word not in STOPWORD_CAPITALS and word.upper() not in CURRENCY_CODES:
                candidates.append(SpanMatch(m.start(1), m.end(1), "ID", word, priority=6))

        # Priority 7: Sensitive Financial & Numerical Values (Paillier Fixed-Point Encrypted)
        # Note: Public percentage rates (e.g., "15%") are left as plaintext scalars so the cloud
        # agent can apply Paillier scalar exponentiation c^k mod n^2 without needing multiplicative FHE!
        for m in re.finditer(
            r"(?<![A-Za-z0-9_])([\$€£])?(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?(?![A-Za-z0-9_])",
            prompt,
        ):
            # Skip percentages like "15%" which serve as public policy scalars in E(m)^k
            trailing_char = prompt[m.end() : m.end() + 1]
            if trailing_char == "%":
                continue

            sym = m.group(1) or ""
            int_part = m.group(2).replace(",", "")
            dec_part = m.group(3)
            raw_num_str = f"{int_part}.{dec_part}" if dec_part is not None else int_part
            val = float(raw_num_str)

            # Encrypt all decimals (e.g. ratings 4.9, lab results 14.2), currency amounts, or numbers >= 10
            if dec_part is None and not sym and val < 10:
                continue

            candidates.append(
                SpanMatch(
                    start=m.start(),
                    end=m.end(),
                    category="FHE_NUM",
                    raw_text=m.group(0),
                    priority=7,
                    numeric_value=val,
                    prefix_symbol=sym,
                )
            )

        # Resolve overlaps: sort by priority ascending, then length descending, then start ascending
        candidates.sort(key=lambda s: (s.priority, -(s.end - s.start), s.start))
        accepted: List[SpanMatch] = []
        for cand in candidates:
            if any(self._overlaps(cand.start, cand.end, ex.start, ex.end) for ex in accepted):
                continue
            accepted.append(cand)

        accepted.sort(key=lambda s: s.start)
        return accepted

    @staticmethod
    def _format_number(val: float, has_decimals: bool, prefix_symbol: str = "") -> str:
        if has_decimals or abs(val - round(val)) > 1e-6:
            formatted = f"{val:,.2f}".rstrip("0").rstrip(".")
            # Keep at least 2 decimals for large currency-like values if non-integer
            if "." in formatted and val >= 100 and len(formatted.split(".")[1]) == 1:
                formatted = f"{val:,.2f}"
        else:
            formatted = f"{int(round(val)):,}" if val >= 10000 else str(int(round(val)))
        return f"{prefix_symbol}{formatted}"

    def blind_prompt(self, prompt: str) -> Tuple[str, BlindContext]:
        ctx = BlindContext(self.session_key, self.paillier)
        spans = self._collect_spans(prompt)

        out_parts: List[str] = []
        cursor = 0
        fhe_idx = 1

        for sp in spans:
            out_parts.append(prompt[cursor : sp.start])

            if sp.category == "FHE_NUM":
                token = f"[FHE_NUM_{fhe_idx}]"
                fhe_idx += 1

                ciphertext, scale = self.paillier.encrypt_fixed(sp.numeric_value)
                c_hex = hex(ciphertext)
                preview = f"{c_hex[:14]}...{c_hex[-8:]}"
                has_dec = "." in sp.raw_text

                ctx.encrypted_numbers[token] = {
                    "plaintext_val": sp.numeric_value,
                    "raw_text": sp.raw_text,
                    "has_decimals": has_dec,
                    "prefix_symbol": sp.prefix_symbol,
                    "ciphertext": ciphertext,
                    "scale": scale,
                    "hex_preview": preview,
                }
                ctx.token_to_plaintext[token] = sp.raw_text
                out_parts.append(f"{token}(ENC:{preview})")
                ctx.log(
                    f"1024-bit Paillier Encrypted '{sp.raw_text}' (scaled ×{scale}) -> {token} ({preview})"
                )
            else:
                if sp.raw_text in ctx.plaintext_to_token:
                    token = ctx.plaintext_to_token[sp.raw_text]
                else:
                    token = self._hmac_token(sp.raw_text, prefix=sp.category)
                    ctx.plaintext_to_token[sp.raw_text] = token
                    ctx.token_to_plaintext[token] = sp.raw_text

                if sp.category == "ID" and not ctx.primary_subject_token:
                    ctx.primary_subject_token = token

                out_parts.append(token)
                ctx.log(f"HMAC-SHA256 Blinded {sp.category}: '{sp.raw_text}' -> {token}")

            cursor = sp.end

        out_parts.append(prompt[cursor:])
        return "".join(out_parts), ctx

    def execute_and_decrypt_fhe(self, op_spec: Dict[str, Any], ctx: BlindContext) -> Dict[str, Any]:
        """
        Run homomorphic evaluation on ciphertexts (using public key n ONLY),
        then decrypt the resulting ciphertexts locally on the client to register
        computed tokens like [FHE_COMPUTED_BONUS] and [FHE_COMPUTED_TOTAL].
        """
        eval_res = self.evaluator.evaluate_operation(op_spec, ctx.encrypted_numbers)
        decrypted_summary: Dict[str, str] = {}

        # Inherit currency symbol if input had one
        ref_key = op_spec.get("ref") or op_spec.get("ref_a") or ""
        sym = ""
        if ref_key in ctx.encrypted_numbers:
            sym = ctx.encrypted_numbers[ref_key].get("prefix_symbol", "")

        for out_token, meta in eval_res["outputs"].items():
            dec_val = self.paillier.decrypt_fixed(meta["ciphertext"], meta["scale"])
            formatted = f"{sym}{dec_val:,.2f}"
            c_hex = hex(meta["ciphertext"])
            preview = f"{c_hex[:14]}...{c_hex[-8:]}"

            ctx.computed_numbers[out_token] = {
                "decrypted_value": dec_val,
                "formatted": formatted,
                "hex_preview": preview,
                "scale": meta["scale"],
            }
            ctx.token_to_plaintext[out_token] = formatted
            decrypted_summary[out_token] = formatted
            ctx.log(
                f"Homomorphic Result {out_token}: D({preview}) / {meta['scale']} = {formatted}"
            )

        return {
            "op": eval_res["op"],
            "label": eval_res["label"],
            "formula": eval_res["formula"],
            "decrypted_outputs": decrypted_summary,
            "ciphertext_previews": {
                k: v["hex_preview"] for k, v in ctx.computed_numbers.items()
            },
        }

    def unblind_response(self, response_text: str, ctx: BlindContext) -> str:
        """Restore local tokens and decrypted FHE computation handles for client display."""
        # Strip inline ciphertext previews attached to FHE handles first
        cleaned = re.sub(r"(\[FHE_NUM_\d+\])\(ENC:0x[0-9a-fA-F\.]+\)", r"\1", response_text)

        # Replace tokens longest-first
        for token in sorted(ctx.token_to_plaintext.keys(), key=len, reverse=True):
            cleaned = cleaned.replace(token, ctx.token_to_plaintext[token])

        return cleaned
