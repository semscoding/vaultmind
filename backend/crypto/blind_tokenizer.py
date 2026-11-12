"""
Span-Based Blind Tokenizer, Native C AES-256 Secret Sealer, Paillier PHE (2048-bit default)
and RLWE-BFV (leveled, depth 1) Encryptor.

Capabilities:
1. Secret & Credential Blinding (zero-retention for the SECRET category):
   - Explicit `<secret>...</secret>` tags (empty tags too; an UNCLOSED `<secret>` seals everything
     up to the end of the prompt)
   - Labelled passwords/PINs/keys in English and Dutch (`password is ...`, `wachtwoord: ...`,
     `pincode = ...`, `password for the database is ...`, `aws_secret_access_key = ...`)
   - Bearer tokens, JWTs, `sk_`/`AKIA`/`AIza`/`ghp_`/Slack `xox?-` keys, hex keys and PEM blocks
   SECRET spans are sealed in C memory via AES-256-CBC + HMAC-SHA256 (`SessionSecretVault`)
   and are never stored as keys or values in plaintext Python dictionaries or in the logs.
2. PII Blinding: IBANs (case-insensitive), e-mail (Unicode), phone numbers, dates, labelled and
   mixed alphanumeric IDs (passport/customer numbers, Dutch postcodes), and capitalised multi-word
   names with Unicode letters, Mc/Mac forms and Dutch/European particles.
3. Numbers: Paillier PHE (fixed-point cents via `Decimal`) for amounts; non-negative 32-bit integers
   are additionally encrypted as RLWE-BFV limbs (N=2048, log q=54) for one ciphertext×ciphertext product.

KNOWN LIMITATIONS (heuristic, regex-based blinding):
- A secret without a label or recognisable pattern is NOT detected: wrap it in <secret>...</secret>.
- Single first names without context ("Sem", "Maria"), lower-case names ("jan jansen"),
  street names and cities without a clinic/city label are not detected.
- Percentages and bare integers below 10 stay in clear text (they are public policy parameters).
- `1.234` (one dot group, no comma) is ambiguous and is read as the English decimal 1.234.
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from decimal import Decimal
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
_CUR_ALT = "|".join(sorted(CURRENCY_CODES))

# Technical identifiers, standards and fiscal/version codes that look like mixed alphanumeric IDs
# but are public domain terminology rather than personal identifiers (M-R1).
ALNUM_STOPLIST = {
    "AES128", "AES192", "AES256", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3", "X25519", "ED25519",
    "RSA1024", "RSA2048", "RSA3072", "RSA4096", "HMACSHA256", "UTF8", "UTF16", "UTF32", "BASE64",
    "IPV4", "IPV6", "H264", "H265", "PKCS1", "PKCS7", "PKCS8", "PKCS11", "PKCS12",
    "CHACHA20", "POLY1305", "GF256", "BFV2048", "CRC32", "INT32", "INT64", "INT128",
    "UINT32", "UINT64", "UINT128", "FLOAT32", "FLOAT64", "ARM64", "X8664", "AMD64",
}
_TECH_CODE_RE = re.compile(
    r"^(?:ISO\d+|SOC\d[A-Z0-9]*|RFC\d+|IEEE\d+[A-Z0-9]*|NIST[A-Z0-9]*|GDPR\d*|HIPAA\d*"
    r"|PCI[A-Z0-9]*|WCAG\d*[A-Z0-9]*|OWASP\d*|CVE\d+|CWE\d+|TLS\d+|SSL\d+|SSH\d*|HTTP\d+"
    r"|OAUTH\d*|COVID\d+|ICD\d+[A-Z0-9]*|DSM\d+[A-Z0-9]*|Q[1-4](?:FY)?\d{2,4}|H[12](?:FY)?\d{2,4}"
    r"|FY\d{2,4}|ERC\d+|BIP\d+|EIP\d+|[A-Z]{4,}\d{1,2})$"
)

# Two-letter suffixes after 4 digits that denote units, eras, timezones or country/IT codes rather
# than Dutch postcodes (1000 AA .. 9999 ZZ; SA/SD/SS are also invalid NL postcodes).
POSTCODE_UNIT_STOPLIST = {
    "AM", "PM", "AD", "BC", "CE", "KB", "MB", "GB", "TB", "PB", "EB", "KI", "MI", "GI",
    "KW", "MW", "GW", "TW", "WH", "HZ", "DB", "PX", "PT", "EM", "MS", "NS", "US", "PS",
    "SA", "SD", "SS", "EU", "UK", "NL", "DE", "FR", "BE", "ES", "IT", "CH", "AT", "SE",
    "NO", "DK", "FI", "PL", "JP", "CN", "CA", "AU", "HR", "PR", "AI", "ML", "QA", "UI",
    "UX", "ID", "IP", "OS", "VM", "IO", "TV", "PC",
}

# Capitalised business/document nouns: a Title-Case phrase made ONLY of these words (e.g.
# "Annual Bonus", "Balance Sheet") is business terminology, not a person's name (M-R1).
BUSINESS_CAPITAL_NOUNS = {
    "Annual", "Bonus", "Balance", "Sheet", "Executive", "Summary", "Retention", "Quarterly",
    "Monthly", "Weekly", "Daily", "Report", "Financial", "Statement", "Operating", "Income",
    "Cash", "Flow", "Service", "Level", "Agreement", "Master", "Root", "Key", "Credentials",
    "Clinical", "Trial", "Budget", "Cloud", "Reserve", "Target", "Earnout", "Pool", "Project",
    "Audit", "Ledger", "Database", "System", "Security", "Policy", "Compliance", "Invoice",
    "Product", "Salary", "Contract", "Subsidy", "Adjustment", "Escalation", "Notice",
    "Confidential", "Patient", "Record", "Transfer", "Authorization", "Account", " Fiscal",
    "Quarter", "Year", "Revenue", "Profit", "Margin", "Tax", "Credit", "Debit", "Total", "Cost",
}


def _char_class(pred) -> str:
    """Escaped character class body for Latin/Latin-1/Latin Extended/Greek/Cyrillic letters."""
    return "".join(re.escape(chr(c)) for c in range(0x41, 0x530) if pred(chr(c)))


_UP = _char_class(str.isupper)
_LO = _char_class(str.islower)

# Capitalised name token: Unicode letters (Renée, Müller, García), Mc/Mac forms (McDonald,
# MacArthur), apostrophes (O'Connor) and hyphens (Jean-Luc, Boer-Jansen).
NAME_WORD = (
    rf"(?:(?:Mc|Mac)[{_UP}][{_LO}]{{1,24}}"
    rf"|[{_UP}](?:[{_LO}]{{1,24}}|'[{_UP}][{_LO}]{{1,24}}))"
    rf"(?:-[{_UP}][{_LO}]{{1,24}})?"
)
# Dutch & European surname particles (only matched between strictly capitalized name words)
NAME_PARTICLE = r"(?:van\s+der|van\s+den|van\s+de|in\s+'t|van|de|den|der|ter|ten|von|zu|du|la|le|da|di|del)"

# Labels that introduce a secret value (English + Dutch) with "is"/"was"/"luidt"/"="/":".
# Generic prose words like "sleutel", "geheim" and "pin" are handled in Priority 1B (`=`/`:`)
# or dedicated numeric-PIN pattern so ordinary Dutch/English prose ("De sleutel tot succes is...",
# "Het geheim van groei is...", "The pin on the map is red") is not sealed as a secret (M-R1).
SECRET_LABELS = (
    r"(?:aws[_\s-]+secret[_\s-]+access[_\s-]+key|secret[_\s-]+access[_\s-]+key|"
    r"secret[_\s-]+key|master[_\s-]+key|root[_\s-]+key|private[_\s-]+key|api[_\s-]+key|"
    r"access[_\s-]+key|access[_\s-]+token|auth[_\s-]+token|secret[_\s-]+token|client[_\s-]+secret|"
    r"password|passwd|pwd|passphrase|pass\s?code|pincode|"
    r"wachtwoord|wachtzin|toegangscode|geheime\s+(?:code|sleutel)|"
    r"(?:api|master|root|priv[eé])[_\s-]+sleutel)"
)
# Words immediately after "password"/"wachtwoord" that describe policy/metadata rather than a secret.
_META_NOUN_GUARD = (
    r"(?!(?:\s+(?:policy|policies|reset|rotation|rules?|requirements?|strength|complexity|"
    r"length|manager|field|fields|prompt|hash|hashes|aging|expiration|expiry|history|"
    r"beleid|regels|eisen|lengte|verloop|wijziging|herstel|veld))\b)"
)
# Up to four words between label and separator: "password for the database is X".
_GAP = r"(?:\s+[^\s,;:=.!?()\[\]\"'<>]{1,30}){0,4}?"
_SEP_EQ = r"\s*(?:=|:)\s*"
_SEP_PROSE = r"\s*(?:\bis\b|\bwas\b|\bluidt\b)\s*"
# Prose auxiliaries/adjectives that follow "a password is ..." in policy reminders rather than values.
_PROSE_PREDICATE_GUARD = (
    r"(?!(?:never|not|always|required|mandatory|optional|updated|changed|expired|reset|"
    r"needed|missing|empty|recommended|enforced|stored|hashed|encrypted|"
    r"nooit|niet|altijd|verplicht|optioneel|gewijzigd|verlopen|nodig|leeg|versleuteld)\b)"
)
# Value rule (documented choice): a quoted value is taken exactly. An UNQUOTED value runs to the end
# of its clause: the next `,` `;` `)` `]` or newline, or a `.`/`!`/`?` followed by whitespace or the
# end of the prompt. This over-blinds ("password is abc and commit" seals "abc and commit") rather
# than leaking the tail of a multi-word passphrase; quote the value for an exact span.
_VALUE = (
    r"(?:\"([^\"\n]+)\"|'([^'\n]+)'"
    r"|([^\s,;)\]\"'][^,;)\]\n]*?)(?=\s*(?:[,;)\]\n]|[.!?](?:\s|$)|$)))"
)
_PROSE_VALUE = (
    r"(?:\"([^\"\n]+)\"|'([^'\n]+)'"
    r"|" + _PROSE_PREDICATE_GUARD + r"([^\s,;)\]\"'][^,;)\]\n]*?)(?=\s*(?:[,;)\]\n]|[.!?](?:\s|$)|$)))"
)
# Digits in the NL format "1.234,56", multiple dot groups "1.234.567", EN "130,000.50",
# NL decimal "14,2", or plain "4.9". `1.234` alone is ambiguous and parsed as EN decimal.
_NUM_BODY = (
    r"(?:\d{1,3}(?:\.\d{3})+,\d{1,2}(?!\d)"
    r"|\d{1,3}(?:\.\d{3}){2,}(?![\d,])"
    r"|\d{1,3}(?:,\d{3})+(?:\.\d+)?"
    r"|\d+,\d{1,2}(?!\d)"
    r"|\d+(?:\.\d+)?)"
)
NUM_RE = re.compile(
    rf"(?<![\w.,])(?P<neg>-)?(?:(?P<sym>[\$€£])\s?|(?P<code1>{_CUR_ALT})\s?)?(?P<neg2>-)?"
    rf"(?P<num>{_NUM_BODY})(?P<mult>[kK])?(?:\s?(?P<code2>{_CUR_ALT})\b)?(?![\w%]|[.,]\d)"
)
_TOKEN_STRIP_RE = re.compile(r"\[[A-Z_]+_[0-9A-F]{8}\]|\[FHE_NUM_\d+\](?:\(ENC:[^)]*\))?")


@dataclass
class SpanMatch:
    start: int
    end: int
    category: str
    raw_text: str
    priority: int
    numeric_value: Any = 0.0
    prefix_symbol: str = ""
    unseal_value: Optional[str] = None
    has_decimals: bool = False
    is_role_subject: bool = False


class BlindContext:
    def __init__(self, session_key: bytes, paillier: PaillierKeypair, bfv: BFVContext):
        # Fresh random HMAC key per blind_prompt() call (S9): tokens are not linkable across requests.
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
        # Leak-check bookkeeping (B1). Non-secret raw values are kept locally (they are already in
        # token_to_plaintext); SECRET values are only compared at blinding time, never stored.
        self.detected_span_count: int = 0
        self.detected_pii_values: List[str] = []
        self.residual_secret_matches: int = 0

    def log(self, message: str) -> None:
        self.logs.append(message)


def _value_occurs(value: str, text: str) -> bool:
    """Case-insensitive occurrence with word boundaries on word-character edges."""
    v = value.strip()
    if not v:
        return False
    pat = re.escape(v)
    if re.match(r"\w", v[0]):
        pat = r"(?<!\w)" + pat
    if re.match(r"\w", v[-1]):
        pat = pat + r"(?!\w)"
    return re.search(pat, text, flags=re.IGNORECASE) is not None


def _format_amount(sym: str, value: Any, fmt: str) -> str:
    """'-$390,000.00' rather than '$-390,000.00'."""
    sign = "-" if value < 0 else ""
    return f"{sign}{sym}{fmt.format(abs(value))}"


class BlindTokenizer:
    def __init__(self, paillier_bits: int = 2048):
        self.paillier = PaillierKeypair.generate(bits=paillier_bits)
        self.evaluator = HomomorphicEvaluator(n=self.paillier.n)
        self.bfv = BFVContext()
        self.secret_vault = SessionSecretVault()

    @property
    def phe_label(self) -> str:
        return f"{self.paillier.n.bit_length()}-bit Paillier PHE"

    @staticmethod
    def _hmac_token(raw_value: str, prefix: str, key: bytes) -> str:
        normalized = " ".join(raw_value.strip().split())
        digest = hmac.new(
            key,
            f"{prefix}:{normalized}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        # 8 hex characters (32 bit) on purpose: frontend regexes and tests rely on this form.
        # Linkability across requests is prevented by the per-request key, not by digest length.
        return f"[{prefix}_{digest[:8].upper()}]"

    @staticmethod
    def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
        return max(a_start, b_start) < min(a_end, b_end)

    @staticmethod
    def _labelled_value_span(m: "re.Match", base: int, priority: int) -> SpanMatch:
        """SpanMatch for a `_VALUE` match whose groups start at index `base` (quoted keeps quotes)."""
        for offset in range(3):
            idx = base + offset
            if m.group(idx) is not None:
                val = m.group(idx)
                quoted = offset < 2
                start = m.start(idx) - (1 if quoted else 0)
                end = m.end(idx) + (1 if quoted else 0)
                return SpanMatch(start, end, "SECRET", val, priority=priority, unseal_value=val)
        raise ValueError("no value group matched")

    @staticmethod
    def _parse_number(m: "re.Match") -> Tuple[Decimal, bool]:
        body = m.group("num")
        if "," in body and "." in body and body.index(".") < body.index(","):
            norm = body.replace(".", "").replace(",", ".")  # NL 1.234,56
        elif body.count(".") >= 2:
            norm = body.replace(".", "")  # NL 1.234.567
        elif "," in body:
            if re.fullmatch(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?", body):
                norm = body.replace(",", "")  # EN 130,000(.50)
            else:
                norm = body.replace(",", ".")  # NL decimal 14,2
        else:
            norm = body
        val = Decimal(norm)
        has_dec = "." in norm
        if m.group("mult"):
            val *= 1000
            has_dec = val != val.to_integral_value()
        if m.group("neg") or m.group("neg2"):
            val = -val
        return val, has_dec

    def _collect_spans(self, prompt: str) -> List[SpanMatch]:
        candidates: List[SpanMatch] = []

        # Priority 0: Explicit <secret>...</secret> tags. An unclosed <secret> runs to the end of the
        # prompt (S8/B1b), so "<secret>alpha-bravo-99" can never leak a remainder.
        for m in re.finditer(r"<secret>(.*?)(?:</secret>|\Z)", prompt, flags=re.DOTALL | re.IGNORECASE):
            candidates.append(
                SpanMatch(m.start(), m.end(), "SECRET", m.group(0), priority=0, unseal_value=m.group(1))
            )

        # Priority 0: PEM blocks (-----BEGIN ... KEY----- through END, or to end of prompt)
        for m in re.finditer(
            r"-----BEGIN [A-Z0-9 ]{0,40}-----[\s\S]*?(?:-----END [A-Z0-9 ]{0,40}-----|\Z)", prompt
        ):
            candidates.append(SpanMatch(m.start(), m.end(), "SECRET", m.group(0), priority=0, unseal_value=m.group(0)))

        # Priority 1A: Labelled passwords/PINs/keys (EN + NL):
        #   - Explicit '=' or ':' accepts any value up to end of clause.
        #   - Natural-language 'is'/'was'/'luidt' rejects indefinite articles ("a password is never...")
        #     and policy nouns ("password policy was updated...") to avoid sealing normal prose (M-R1).
        for m in re.finditer(rf"(?i:\b{SECRET_LABELS}{_META_NOUN_GUARD}{_GAP}{_SEP_EQ})" + _VALUE, prompt):
            candidates.append(self._labelled_value_span(m, 1, priority=1))
        for m in re.finditer(
            rf"(?i:(?<!\ba\s)(?<!\ban\s)(?<!\been\s)\b{SECRET_LABELS}{_META_NOUN_GUARD}{_GAP}{_SEP_PROSE})"
            + _PROSE_VALUE,
            prompt,
        ):
            candidates.append(self._labelled_value_span(m, 1, priority=1))

        # Priority 1B: Single-word generic labels with ':' or '=', plus numeric/quoted PIN in prose
        for m in re.finditer(r"(?i:\b(?:secret|token|key|seed|pin|geheim|sleutel)\s*(?:=|:)\s*)" + _VALUE, prompt):
            candidates.append(self._labelled_value_span(m, 1, priority=1))
        for m in re.finditer(
            rf"(?i:\bpin(?:\s+(?:code|number|nr|(?:for|van|voor)(?:\s+[\w-]+){{1,3}}))?{_SEP_PROSE})"
            r"(?:\"([^\"\n]+)\"|'([^'\n]+)'|(\d{3,12})\b)",
            prompt,
        ):
            candidates.append(self._labelled_value_span(m, 1, priority=1))

        # Priority 1C: "password X" without separator, when X contains a digit or symbol
        for m in re.finditer(
            r"(?i:\b(?:password|passwd|wachtwoord|pincode|pin)\s+)(?![:=])"
            r"([^\s,;)\]\"']*?[\d!@#$%^&*_+~][^\s,;)\]\"']*)",
            prompt,
        ):
            val, end = m.group(1), m.end(1)
            while len(val) > 1 and val[-1] in ".!?" and (end >= len(prompt) or prompt[end].isspace()):
                val, end = val[:-1], end - 1
            candidates.append(SpanMatch(m.start(1), end, "SECRET", val, priority=1, unseal_value=val))

        # Priority 1D: HTTP Bearer tokens, JWTs, known cloud API key prefixes, Slack tokens, hex keys
        for m in re.finditer(r"\bBearer\s+([A-Za-z0-9._~+/=-]{8,})", prompt):
            candidates.append(
                SpanMatch(m.start(1), m.end(1), "SECRET", m.group(1), priority=1, unseal_value=m.group(1))
            )

        for m in re.finditer(
            r"\b(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|sk_[A-Za-z0-9_-]{6,}|sk-[A-Za-z0-9_-]{8,}"
            r"|AIza[0-9A-Za-z_-]{10,}|AKIA[0-9A-Z]{10,}|ghp_[A-Za-z0-9]{10,}|xox[abposr]-[A-Za-z0-9-]{10,}"
            r"|(?:0x)?[0-9a-fA-F]{32,128})\b",
            prompt,
        ):
            candidates.append(
                SpanMatch(m.start(), m.end(), "SECRET", m.group(0), priority=1, unseal_value=m.group(0))
            )

        # Priority 2: IBAN (case-insensitive; at least 8 digits to avoid matching ordinary words)
        for m in re.finditer(
            r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b", prompt, flags=re.IGNORECASE
        ):
            if sum(ch.isdigit() for ch in m.group(0)) >= 8:
                candidates.append(SpanMatch(m.start(), m.end(), "IBAN", m.group(0), priority=2))

        # Priority 3: Email addresses (Unicode local part and domain, e.g. jörg@müller.de)
        for m in re.finditer(r"(?<![\w.%+-])[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[^\W\d_]{2,}\b", prompt):
            candidates.append(SpanMatch(m.start(), m.end(), "EMAIL", m.group(0), priority=3))

        # Priority 4: Labelled Government / Medical / customer IDs, and SSN pattern
        for m in re.finditer(
            r"(?i:\b(?:BSN|SSN|MRN|passport(?:\s*(?:no|nr|number))?|paspoort(?:nummer)?|"
            r"klantnummer|customer\s*(?:id|no|nr|number)|account\s*(?:id|no|nr|number))"
            r"\.?\s*(?:[:#]|\bis\b)?\s*)([0-9A-Za-z-]{5,20})\b",
            prompt,
        ):
            if any(ch.isdigit() for ch in m.group(1)):
                candidates.append(SpanMatch(m.start(1), m.end(1), "GOV_ID", m.group(1), priority=4))

        for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", prompt):
            candidates.append(SpanMatch(m.start(), m.end(), "GOV_ID", m.group(0), priority=4))

        # Priority 4: Phone numbers (+31 6 12345678, 0031..., 06-12345678, 020 1234567)
        for m in re.finditer(
            r"(?<![\w+])(?:(?:\+|00)[1-9]\d{0,2}[\s.-]?(?:\(0\)[\s.-]?)?\d{1,4}(?:[\s.-]?\d{2,4}){1,4}"
            r"|0\d{1,3}[\s-]?\d{6,8})(?!\w)",
            prompt,
        ):
            if sum(ch.isdigit() for ch in m.group(0)) >= 9:
                candidates.append(SpanMatch(m.start(), m.end(), "PHONE", m.group(0), priority=4))

        # Priority 4: Dates (2026-11-12, 12-11-2026, 12/11/26, 12.11.2026)
        for m in re.finditer(r"\b(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})\b", prompt):
            candidates.append(SpanMatch(m.start(), m.end(), "GOV_ID", m.group(0), priority=4))

        # Priority 4: Dutch postcode (2511AB / 2511 AB), excluding storage/power/date units (M-R1)
        for m in re.finditer(r"\b[1-9]\d{3}\s?[A-Z]{2}\b", prompt):
            if m.group(0)[-2:] not in POSTCODE_UNIT_STOPLIST:
                candidates.append(SpanMatch(m.start(), m.end(), "LOC", m.group(0), priority=4))

        # Priority 5: Mixed alphanumeric IDs (passport NX4K2P881, A123456): upper-case letters + digits
        for m in re.finditer(
            r"(?<![\w-])(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{6,20}(?![\w-])", prompt
        ):
            tok = m.group(0)
            if tok in ALNUM_STOPLIST or _TECH_CODE_RE.fullmatch(tok):
                continue
            if re.fullmatch(rf"\d+(?:{_CUR_ALT})|(?:{_CUR_ALT})\d+", tok):
                continue  # 5000EUR / EUR5000: handled as an encrypted amount below
            candidates.append(SpanMatch(m.start(), m.end(), "GOV_ID", tok, priority=5))

        # Priority 5: Multi-word Capitalized Names / Dutch & European Particles / Organizations / Locations
        role_prefix_re = re.compile(
            r"(?i:\b(?:employee|patient|patiënt|client|klant|vendor|customer|lead|recipient|user|"
            r"medewerker|werknemer|leverancier|subject|mr\.?|mrs\.?|ms\.?|dr\.?|dhr\.?|mevr\.?)\s+)$"
        )
        org_suffixes = {"Corp", "Inc", "Ltd", "BV", "NV", "LLC", "Group", "Bank", "Central", "Hospital", "Labs"}
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
                start_offset = prompt.index(words[0], start_offset + len(removed)) if words else start_offset
            if len(words) >= 2:
                clean_phrase = prompt[start_offset : m.end(1)]
                prefix_window = prompt[max(0, start_offset - 24) : start_offset]
                prefix_ctx = prefix_window.lower()
                has_role = role_prefix_re.search(prefix_window) is not None
                has_org = words[-1] in org_suffixes
                if not has_role and not has_org and all(w in BUSINESS_CAPITAL_NOUNS for w in words):
                    continue
                cat = "LOC" if ("clinic" in prefix_ctx or "city" in prefix_ctx) else "ID"
                candidates.append(
                    SpanMatch(
                        start_offset,
                        m.end(1),
                        cat,
                        clean_phrase,
                        priority=5,
                        is_role_subject=(cat == "ID" and has_role),
                    )
                )

        # Priority 6: Single proper name after a role/title word (e.g. "patient O'Connor", "dhr. Müller")
        for m in re.finditer(
            rf"(?i:\b(?:employee|patient|patiënt|client|klant|vendor|customer|lead|recipient|user|medewerker|werknemer|"
            rf"leverancier|mr\.?|mrs\.?|ms\.?|dr\.?|dhr\.?|mevr\.?)\s+)({NAME_WORD})\b",
            prompt,
        ):
            word = m.group(1)
            if (
                word not in STOPWORD_CAPITALS
                and word not in BUSINESS_CAPITAL_NOUNS
                and word.upper() not in CURRENCY_CODES
            ):
                candidates.append(SpanMatch(m.start(1), m.end(1), "ID", word, priority=6, is_role_subject=True))

        # Priority 7: Sensitive amounts (Paillier PHE; non-negative 32-bit integers also RLWE-BFV)
        for m in NUM_RE.finditer(prompt):
            val, has_dec = self._parse_number(m)
            sym = m.group("sym") or ""
            code = m.group("code1") or m.group("code2")
            if not sym and code:
                sym = f"{code} "
            if not has_dec and not sym and not m.group("mult") and abs(val) < 10:
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
                    has_decimals=has_dec,
                )
            )

        return self._merge_overlaps(prompt, candidates)

    @staticmethod
    def _merge_overlaps(prompt: str, candidates: List[SpanMatch]) -> List[SpanMatch]:
        """
        S8: overlapping candidates are merged into the UNION of their spans, blinded under the
        highest-priority category in the group, so a partially overlapping lower-priority span can
        never leave its non-overlapping remainder in clear text.
        """
        if not candidates:
            return []
        candidates = sorted(candidates, key=lambda s: (s.start, -s.end))
        groups: List[List[SpanMatch]] = []
        group_end = -1
        for cand in candidates:
            if groups and cand.start < group_end:
                groups[-1].append(cand)
                group_end = max(group_end, cand.end)
            else:
                groups.append([cand])
                group_end = cand.end

        merged: List[SpanMatch] = []
        for grp in groups:
            start = min(s.start for s in grp)
            end = max(s.end for s in grp)
            rep = min(grp, key=lambda s: (s.priority, -(s.end - s.start), s.start))
            if rep.start == start and rep.end == end:
                merged.append(rep)
                continue
            union_text = prompt[start:end]
            if rep.category == "SECRET":
                inner = re.sub(r"</?secret>", "", union_text, flags=re.IGNORECASE)
                merged.append(SpanMatch(start, end, "SECRET", union_text, rep.priority, unseal_value=inner))
            else:
                merged.append(
                    SpanMatch(
                        start,
                        end,
                        rep.category,
                        union_text,
                        rep.priority,
                        is_role_subject=any(s.is_role_subject for s in grp),
                    )
                )
        return merged

    def blind_prompt(self, prompt: str) -> Tuple[str, BlindContext]:
        ctx = BlindContext(secrets.token_bytes(32), self.paillier, self.bfv)
        spans = self._collect_spans(prompt)
        ctx.detected_span_count = len(spans)

        out_parts: List[str] = []
        redacted_parts: List[str] = []
        secret_values_for_scan: List[str] = []  # local only; discarded when this call returns
        primary_role_selected = False
        cursor = 0
        fhe_idx = 1

        for sp in spans:
            prefix_slice = prompt[cursor : sp.start]
            out_parts.append(prefix_slice)
            redacted_parts.append(prefix_slice)

            if sp.category == "FHE_NUM":
                token = f"[FHE_NUM_{fhe_idx}]"
                fhe_idx += 1

                value = sp.numeric_value if isinstance(sp.numeric_value, Decimal) else Decimal(str(sp.numeric_value))
                ciphertext, scale = self.paillier.encrypt_fixed(value)
                c_hex = hex(ciphertext)
                preview = f"{c_hex[:14]}...{c_hex[-8:]}"
                has_dec = sp.has_decimals

                # Encrypt non-negative 32-bit integers into N=2048 base-256 RLWE-BFV limbs
                bfv_limbs: Optional[List[Any]] = None
                bfv_preview: Optional[str] = None
                if not has_dec and value == value.to_integral_value() and 0 <= value <= 0xFFFFFFFF:
                    bfv_limbs = self.bfv.encrypt_limbs_u32(int(value))
                    bfv_preview = self.bfv.ciphertext_preview(bfv_limbs[0])

                ctx.encrypted_numbers[token] = {
                    "plaintext_val": float(value),
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
                ctx.detected_pii_values.append(sp.raw_text)
                out_parts.append(f"{token}(ENC:{preview})")
                redacted_parts.append(sp.raw_text)
                scheme_note = (
                    f"{self.phe_label} + RLWE-BFV (N=2048, leveled depth 1)"
                    if bfv_limbs is not None
                    else self.phe_label
                )
                # S10: no clear-text amount in the log, only category + token + ciphertext preview.
                ctx.log(f"{scheme_note} encrypted FHE_NUM -> {token} ({preview})")

            elif sp.category == "SECRET":
                secret_plain = sp.unseal_value if sp.unseal_value is not None else sp.raw_text
                # NEVER store `secret_plain` in `plaintext_to_token` or `token_to_plaintext`!
                token = self._hmac_token(secret_plain or "<EMPTY>", prefix="SECRET", key=ctx.session_key)
                if token not in ctx.sealed_secrets:
                    ctx.sealed_secrets[token] = self.secret_vault.seal(secret_plain)
                if secret_plain:
                    secret_values_for_scan.append(secret_plain)
                out_parts.append(token)
                redacted_parts.append(f"[REDACTED:{token}]")
                ctx.log(
                    f"C-Enclave AES-256-CBC + HMAC Sealed SECRET -> {token} ({ctx.sealed_secrets[token]['preview']})"
                )

            else:
                if sp.raw_text in ctx.plaintext_to_token:
                    token = ctx.plaintext_to_token[sp.raw_text]
                else:
                    token = self._hmac_token(sp.raw_text, prefix=sp.category, key=ctx.session_key)
                    ctx.plaintext_to_token[sp.raw_text] = token
                    ctx.token_to_plaintext[token] = sp.raw_text

                if sp.category == "ID":
                    if sp.is_role_subject and not primary_role_selected:
                        ctx.primary_subject_token = token
                        primary_role_selected = True
                    elif not ctx.primary_subject_token:
                        ctx.primary_subject_token = token

                ctx.detected_pii_values.append(sp.raw_text)
                out_parts.append(token)
                redacted_parts.append(sp.raw_text)
                # S10: log category + token only, never the raw value.
                ctx.log(f"HMAC-SHA256 Blinded {sp.category} -> {token}")

            cursor = sp.end

        tail = prompt[cursor:]
        out_parts.append(tail)
        redacted_parts.append(tail)
        ctx.redacted_prompt = "".join(redacted_parts)
        blinded = "".join(out_parts)

        # B1: secrets are compared NOW (at blinding time) and only the count is kept.
        scan_text = _TOKEN_STRIP_RE.sub(" ", blinded)
        ctx.residual_secret_matches = sum(1 for v in secret_values_for_scan if _value_occurs(v, scan_text))
        secret_values_for_scan.clear()
        return blinded, ctx

    def residual_scan(self, blinded_text: str, ctx: BlindContext) -> Dict[str, Any]:
        """
        B1: post-blinding scan. Checks whether any detected raw value still appears in the text that
        leaves the machine (tokens and ciphertext previews are stripped first). Heuristic: it can only
        find values the tokenizer detected in the first place.
        """
        scan_text = _TOKEN_STRIP_RE.sub(" ", blinded_text)
        residual_pii = sum(1 for v in set(ctx.detected_pii_values) if _value_occurs(v, scan_text))
        return {
            "detected_spans": ctx.detected_span_count,
            "residual_pii_matches": residual_pii,
            "residual_secret_matches": ctx.residual_secret_matches,
            "residual_matches": residual_pii + ctx.residual_secret_matches,
        }

    def execute_and_decrypt_fhe(self, op_spec: Dict[str, Any], ctx: BlindContext) -> Dict[str, Any]:
        op = str(op_spec.get("op", "")).upper()

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
            formatted = _format_amount(sym, dec_int, "{:,}")
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
                f"Native C RLWE-BFV (leveled, depth 1, N=2048) product {out_token}: "
                f"D(Relin({ref_a} ⊗ {ref_b})) decrypted locally"
            )
            return {
                "engine": "Native C RLWE-BFV (leveled, depth 1; R_q = Z_{2^54}[X]/(X^2048+1))",
                "op": "BFV_MULTIPLY",
                "label": f"RLWE-BFV (leveled, depth 1) Ciphertext × Ciphertext Product ({ref_a} × {ref_b})",
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
            dec_val = self.paillier.decrypt_fixed_decimal(meta["ciphertext"], meta["scale"])
            formatted = _format_amount(sym, dec_val, "{:,.2f}")
            c_hex = hex(meta["ciphertext"])
            preview = f"{c_hex[:14]}...{c_hex[-8:]}"

            ctx.computed_numbers[out_token] = {
                "decrypted_value": float(dec_val),
                "formatted": formatted,
                "hex_preview": preview,
                "scale": meta["scale"],
            }
            ctx.token_to_plaintext[out_token] = formatted
            decrypted_summary[out_token] = formatted
            ctx.log(f"{self.phe_label} result {out_token}: D({preview}) / {meta['scale']} decrypted locally")

        return {
            "engine": eval_res.get("engine", self.phe_label),
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
