"""
Span-Based Cryptographic Blind Tokenizer, Native C AES-256 Secret Sealer,
1024-bit Paillier PHE & 128-bit PQ Lattice RLWE-BFV FHE Encryptor.

Capabilities:
1. Zero-Retention Arbitrary Secret & Credential Blinding:
   - Explicit `<secret>...</secret>` tags (including empty-tag sanitization)
   - Free-text passwords/passphrases/PINs (`password is ...`, `passphrase: ...`, `pin = ...`)
   - Compound key labels (`secret key is ...`, `master key: ...`, `api_key=...`) & Bearer/JWT/Hex keys
   All `SECRET` spans are sealed in C memory via AES-256-CBC + HMAC-SHA256 (`SessionSecretVault`)
   and NEVER stored as keys or values in plaintext Python dictionaries, nor echoed in JSON audit logs.
2. PII / Banking / Medical / Dutch & International Name Blinding:
   - IBANs, Emails, BSN/SSN/MRN IDs, plus names with Dutch/European particles (`Jan van Dijk`,
     `Maria de Vries`, `Pieter van der Berg`), hyphens (`Jean-Luc Picard`), and apostrophes (`O'Connor`).
3. Dual Homomorphic Encryption:
   - 1024-bit Fixed-Point Paillier PHE for large currency sums & public percentage policy scalars.
   - Compiled C 128-bit Lattice Security Ring-LWE BFV FHE (N=2048, q=2^54) with overflow-free
     base-256 limb multiplication for arbitrary 32-bit products (e.g. 300 * 300 = 90,000).
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .bfv_fhe import BFVContext, SessionSecretVault
from .homomorphic import HomomorphicEvaluator, PaillierKeypair, normalize_fhe_handle


STOPWORD_CAPITALS = {
    "Evaluate",
    "Process",
    "Authorize",
    "Analyze",
    "Approve",
    "Update",
    "Calculate",
    "Compute",
    "Multiply",
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

# Capitalized name token supporting apostrophes (O'Connor) and hyphens (Jean-Luc)
NAME_WORD = r"[A-Z](?:[a-z]{1,24}|'[A-Z][a-z]{1,24})(?:-[A-Z][a-z]{1,24})?"
# Dutch & European surname particles (only matched between strictly capitalized name words)
NAME_PARTICLE = r"(?:van\s+der|van\s+den|van\s+de|in\s+'t|van|de|den|der|ter|ten|von|zu|du|la|le|da|di|del)"


@dataclass
class SpanMatch:
    start: int
    end: int
    category: str
    raw_text: str
    priority: int
    numeric_value: float = 0.0
    prefix_symbol: str = ""
    unseal_value: Optional[str] = None


class BlindContext:
    def __init__(self, session_key: bytes, paillier: PaillierKeypair, bfv: BFVContext):
        self.session_key = session_key
        self.paillier = paillier
        self.bfv = bfv
        self.token_to_plaintext: Dict[str, str] = {}
        self.plaintext_to_token: Dict[str, str] = {}
        self.sealed_secrets: Dict[str, Dict[str, str]] = {}
        self.encrypted_numbers: Dict[str, Dict[str, Any]] = {}
        self.computed_numbers: Dict[str, Dict[str, Any]] = {}
        self.primary_subject_token: str = ""
        self.redacted_prompt: str = ""
        self.logs: List[str] = []

    def log(self, message: str) -> None:
        self.logs.append(message)


class BlindTokenizer:
    def __init__(self, paillier_bits: int = 1024):
        self.session_key = secrets.token_bytes(32)
        self.paillier = PaillierKeypair.generate(bits=paillier_bits)
        self.evaluator = HomomorphicEvaluator(n=self.paillier.n)
        self.bfv = BFVContext()
        self.secret_vault = SessionSecretVault()

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

        # Priority 0: Explicit <secret>...</secret> tags (handles empty tags safely too)
        for m in re.finditer(r"<secret>(.*?)</secret>", prompt, flags=re.DOTALL | re.IGNORECASE):
            inner = m.group(1)
            candidates.append(
                SpanMatch(
                    start=m.start(),
                    end=m.end(),
                    category="SECRET",
                    raw_text=m.group(0),
                    priority=0,
                    unseal_value=inner,
                )
            )

        # Priority 1A: Labeled passwords, passphrases, PINs, and compound key phrases (supports 'is', '=', ':')
        for m in re.finditer(
            r"""(?i:\b(?:password|passwd|pwd|passphrase|pin|secret[_\s-]+key|master[_\s-]+key|root[_\s-]+key|private[_\s-]+key|api[_\s-]+key|access[_\s-]+token|auth[_\s-]+token|secret[_\s-]+token)\s*(?:is|=|:)\s*)(?:"([^"]+)"|'([^']+)'|([^\s,;)\]"']+))""",
            prompt,
        ):
            grp_idx = 1 if m.group(1) is not None else (2 if m.group(2) is not None else 3)
            val_str = m.group(grp_idx)
            end_pos = m.end(grp_idx)
            if grp_idx == 3 and val_str.endswith(".") and len(val_str) > 1:
                val_str = val_str[:-1]
                end_pos -= 1
            candidates.append(
                SpanMatch(
                    start=m.start(grp_idx) - (1 if grp_idx in (1, 2) else 0),
                    end=end_pos + (1 if grp_idx in (1, 2) else 0),
                    category="SECRET",
                    raw_text=val_str,
                    priority=1,
                    unseal_value=val_str,
                )
            )

        # Priority 1B: Single-word generic secret/token/key/seed labels with ':' or '='
        for m in re.finditer(
            r"""(?i:\b(?:secret|token|key|seed)\s*(?:=|:)\s*)(?:"([^"]+)"|'([^']+)'|([^\s,;)\]"']+))""",
            prompt,
        ):
            grp_idx = 1 if m.group(1) is not None else (2 if m.group(2) is not None else 3)
            val_str = m.group(grp_idx)
            end_pos = m.end(grp_idx)
            if grp_idx == 3 and val_str.endswith(".") and len(val_str) > 1:
                val_str = val_str[:-1]
                end_pos -= 1
            candidates.append(
                SpanMatch(
                    start=m.start(grp_idx) - (1 if grp_idx in (1, 2) else 0),
                    end=end_pos + (1 if grp_idx in (1, 2) else 0),
                    category="SECRET",
                    raw_text=val_str,
                    priority=1,
                    unseal_value=val_str,
                )
            )

        # Priority 1C: HTTP Bearer tokens, JWTs, known Cloud API key prefixes, and raw 128/256-bit hex keys
        for m in re.finditer(r"\bBearer\s+([A-Za-z0-9._~+/=-]{8,})", prompt):
            candidates.append(
                SpanMatch(m.start(1), m.end(1), "SECRET", m.group(1), priority=1, unseal_value=m.group(1))
            )

        for m in re.finditer(
            r"\b(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|sk_[A-Za-z0-9_-]{6,}|sk-[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{10,}|AKIA[0-9A-Z]{10,}|ghp_[A-Za-z0-9]{10,}|(?:0x)?[0-9a-fA-F]{32,128})\b",
            prompt,
        ):
            candidates.append(
                SpanMatch(m.start(), m.end(), "SECRET", m.group(0), priority=1, unseal_value=m.group(0))
            )

        # Priority 2: International Bank Account Numbers (IBAN)
        for m in re.finditer(
            r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b",
            prompt,
        ):
            candidates.append(SpanMatch(m.start(), m.end(), "IBAN", m.group(0), priority=2))

        # Priority 3: Email addresses
        for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", prompt):
            candidates.append(SpanMatch(m.start(), m.end(), "EMAIL", m.group(0), priority=3))

        # Priority 4: Labeled Government / Medical IDs (BSN, SSN, MRN) & SSN patterns
        for m in re.finditer(
            r"(?i:(?<=\bBSN:\s)|(?<=\bSSN:\s)|(?<=\bMRN:\s))([0-9A-Z-]{6,16})\b",
            prompt,
        ):
            candidates.append(SpanMatch(m.start(1), m.end(1), "GOV_ID", m.group(1), priority=4))

        for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", prompt):
            candidates.append(SpanMatch(m.start(), m.end(), "GOV_ID", m.group(0), priority=4))

        # Priority 5: Multi-word Capitalized Names / Dutch & European Particles / Organizations / Locations
        full_name_pattern = (
            rf"\b({NAME_WORD}(?:\s+(?:{NAME_PARTICLE}\s+)?{NAME_WORD})+"
            rf"(?:\s+(?:Corp|Inc|Ltd|BV|NV|LLC|Group|Bank|Central|Hospital|Labs))?)\b"
        )
        for m in re.finditer(full_name_pattern, prompt):
            phrase = m.group(1)
            words = phrase.split()
            start_offset = m.start(1)
            while words and words[0] in STOPWORD_CAPITALS:
                removed = words.pop(0)
                start_offset += len(removed) + 1
            if len(words) >= 2:
                clean_phrase = " ".join(words)
                prefix_ctx = prompt[max(0, start_offset - 16) : start_offset].lower()
                cat = "LOC" if ("clinic" in prefix_ctx or "city" in prefix_ctx) else "ID"
                candidates.append(SpanMatch(start_offset, m.end(1), cat, clean_phrase, priority=5))

        # Priority 5B: Single hyphenated or apostrophe proper name (e.g. "Patient O'Connor") or role-prefixed name
        for m in re.finditer(
            rf"(?i:\b(?:employee|patient|client|vendor|recipient|user)\s+)({NAME_WORD})\b",
            prompt,
        ):
            word = m.group(1)
            if word not in STOPWORD_CAPITALS and word.upper() not in CURRENCY_CODES:
                candidates.append(SpanMatch(m.start(1), m.end(1), "ID", word, priority=6))

        # Priority 7: Sensitive Financial & Numerical Values (Paillier PHE + 128-bit PQ RLWE-BFV FHE)
        for m in re.finditer(
            r"(?<![A-Za-z0-9_])([\$€£])?(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?(?![A-Za-z0-9_])",
            prompt,
        ):
            trailing_char = prompt[m.end() : m.end() + 1]
            if trailing_char == "%":
                continue

            sym = m.group(1) or ""
            int_part = m.group(2).replace(",", "")
            dec_part = m.group(3)
            raw_num_str = f"{int_part}.{dec_part}" if dec_part is not None else int_part
            val = float(raw_num_str)

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

        candidates.sort(key=lambda s: (s.priority, -(s.end - s.start), s.start))
        accepted: List[SpanMatch] = []
        for cand in candidates:
            if any(self._overlaps(cand.start, cand.end, ex.start, ex.end) for ex in accepted):
                continue
            accepted.append(cand)

        accepted.sort(key=lambda s: s.start)
        return accepted

    def blind_prompt(self, prompt: str) -> Tuple[str, BlindContext]:
        ctx = BlindContext(self.session_key, self.paillier, self.bfv)
        spans = self._collect_spans(prompt)

        out_parts: List[str] = []
        redacted_parts: List[str] = []
        cursor = 0
        fhe_idx = 1

        for sp in spans:
            prefix_slice = prompt[cursor : sp.start]
            out_parts.append(prefix_slice)
            redacted_parts.append(prefix_slice)

            if sp.category == "FHE_NUM":
                token = f"[FHE_NUM_{fhe_idx}]"
                fhe_idx += 1

                ciphertext, scale = self.paillier.encrypt_fixed(sp.numeric_value)
                c_hex = hex(ciphertext)
                preview = f"{c_hex[:14]}...{c_hex[-8:]}"
                has_dec = "." in sp.raw_text

                # Encrypt non-negative 32-bit integers into N=2048 base-256 RLWE-BFV limbs (overflow-free!)
                bfv_limbs: Optional[List[Any]] = None
                bfv_preview: Optional[str] = None
                rounded_int = int(round(sp.numeric_value))
                if not has_dec and 0 <= rounded_int <= 0xFFFFFFFF:
                    bfv_limbs = self.bfv.encrypt_limbs_u32(rounded_int)
                    bfv_preview = self.bfv.ciphertext_preview(bfv_limbs[0])

                ctx.encrypted_numbers[token] = {
                    "plaintext_val": sp.numeric_value,
                    "raw_text": sp.raw_text,
                    "has_decimals": has_dec,
                    "prefix_symbol": sp.prefix_symbol,
                    "ciphertext": ciphertext,
                    "scale": scale,
                    "hex_preview": preview,
                    "bfv_limbs": bfv_limbs,
                    "bfv_preview": bfv_preview,
                }
                ctx.token_to_plaintext[token] = sp.raw_text
                out_parts.append(f"{token}(ENC:{preview})")
                redacted_parts.append(sp.raw_text)
                scheme_note = (
                    "1024-bit Paillier PHE + N=2048 RLWE-BFV FHE"
                    if bfv_limbs is not None
                    else "1024-bit Paillier PHE"
                )
                ctx.log(f"{scheme_note} Encrypted '{sp.raw_text}' -> {token} ({preview})")

            elif sp.category == "SECRET":
                secret_plain = sp.unseal_value if sp.unseal_value is not None else sp.raw_text
                # Deterministic HMAC token — NEVER store `secret_plain` in `plaintext_to_token` or `token_to_plaintext`!
                token = self._hmac_token(secret_plain or "<EMPTY>", prefix="SECRET")
                if token not in ctx.sealed_secrets:
                    ctx.sealed_secrets[token] = self.secret_vault.seal(secret_plain)
                out_parts.append(token)
                redacted_parts.append(f"[REDACTED:{token}]")
                ctx.log(
                    f"C-Enclave AES-256-CBC + HMAC Sealed SECRET -> {token} ({ctx.sealed_secrets[token]['preview']})"
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
                redacted_parts.append(sp.raw_text)
                ctx.log(f"HMAC-SHA256 Blinded {sp.category}: '{sp.raw_text}' -> {token}")

            cursor = sp.end

        tail = prompt[cursor:]
        out_parts.append(tail)
        redacted_parts.append(tail)
        ctx.redacted_prompt = "".join(redacted_parts)
        return "".join(out_parts), ctx

    def execute_and_decrypt_fhe(self, op_spec: Dict[str, Any], ctx: BlindContext) -> Dict[str, Any]:
        op = op_spec.get("op", "").upper()

        if op in ("BFV_MULTIPLY", "MULTIPLY"):
            ref_a = normalize_fhe_handle(op_spec.get("ref_a", ""))
            ref_b = normalize_fhe_handle(op_spec.get("ref_b", ""))
            if ref_a not in ctx.encrypted_numbers or ref_b not in ctx.encrypted_numbers:
                raise KeyError(f"Unknown FHE handles for BFV_MULTIPLY: {ref_a}, {ref_b}")
            ea = ctx.encrypted_numbers[ref_a]
            eb = ctx.encrypted_numbers[ref_b]
            if ea.get("bfv_limbs") is None or eb.get("bfv_limbs") is None:
                raise ValueError("Selected operands are non-integers or exceed 32-bit unsigned BFV limb domain.")

            prod_terms = self.bfv.evaluator.multiply_limbs(ea["bfv_limbs"], eb["bfv_limbs"])
            dec_int = self.bfv.decrypt_limbs_product(prod_terms)
            sym = ea.get("prefix_symbol") or eb.get("prefix_symbol") or ""
            formatted = f"{sym}{dec_int:,}"
            preview = self.bfv.ciphertext_preview(prod_terms[0][1])

            out_token = "[FHE_COMPUTED_PRODUCT]"
            ctx.computed_numbers[out_token] = {
                "decrypted_value": dec_int,
                "formatted": formatted,
                "hex_preview": preview,
                "scale": 1,
            }
            ctx.token_to_plaintext[out_token] = formatted
            ctx.log(
                f"Native C 128-bit PQ RLWE-BFV (N=2048) Product {out_token}: D(Relin({ref_a} ⊗ {ref_b})) = {formatted}"
            )
            return {
                "engine": "Native C RLWE-BFV 128-bit Lattice FHE (R_q = Z_{2^54}[X]/(X^2048+1))",
                "op": "BFV_MULTIPLY",
                "label": f"128-bit Lattice RLWE-BFV Ciphertext × Ciphertext Product ({ref_a} × {ref_b})",
                "formula": f"c_prod = Relin(round((t/q) · ({ref_a} ⊗ {ref_b}))) in R_q (N=2048)",
                "decrypted_outputs": {out_token: formatted},
                "ciphertext_previews": {out_token: preview},
            }

        eval_res = self.evaluator.evaluate_operation(op_spec, ctx.encrypted_numbers)
        decrypted_summary: Dict[str, str] = {}

        ref_key = normalize_fhe_handle(op_spec.get("ref") or op_spec.get("ref_a") or "")
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
                f"1024-bit Paillier PHE Result {out_token}: D({preview}) / {meta['scale']} = {formatted}"
            )

        return {
            "engine": eval_res.get("engine", "1024-bit Paillier PHE"),
            "op": eval_res["op"],
            "label": eval_res["label"],
            "formula": eval_res["formula"],
            "decrypted_outputs": decrypted_summary,
            "ciphertext_previews": {
                k: v["hex_preview"] for k, v in ctx.computed_numbers.items()
            },
        }

    def unblind_response(self, response_text: str, ctx: BlindContext) -> str:
        """Restore local tokens, C-sealed secrets, and decrypted homomorphic handles for client display."""
        cleaned = re.sub(r"(\[FHE_NUM_\d+\])\(ENC:0x[0-9a-fA-F\.]+\)", r"\1", response_text)

        for sec_token, blob in ctx.sealed_secrets.items():
            if sec_token in cleaned:
                unsealed_val = self.secret_vault.unseal(blob)
                cleaned = cleaned.replace(sec_token, unsealed_val)

        for token in sorted(ctx.token_to_plaintext.keys(), key=len, reverse=True):
            cleaned = cleaned.replace(token, ctx.token_to_plaintext[token])

        return cleaned
