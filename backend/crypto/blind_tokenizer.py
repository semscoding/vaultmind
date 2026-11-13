"""
Span-Based Blind Tokenizer, Native C AES-256 Secret Sealer, Paillier PHE (2048-bit default)
and RLWE-BFV (leveled, depth 1) Encryptor.

Capabilities:
1. Secret & Credential Blinding (non-retained in Python token maps, logs, or responses):
   - Explicit `<secret>...</secret>` tags (including `< secret >`, nested tags, and empty tags;
     an UNCLOSED `<secret>` seals everything up to the end of the prompt)
   - Labelled passwords/PINs/keys in English and Dutch (`password is ...`, `wachtwoord: ...`,
     `pincode = ...`, `password for the database is ...`, `aws_secret_access_key = ...`)
   - Bearer tokens, JWTs, `sk_`/`AKIA`/`AIza`/`ghp_`/Slack `xox?-` keys, hex keys and PEM blocks
   SECRET spans are sealed in C memory via AES-256-CBC + HMAC-SHA256 (`SessionSecretVault`)
   and are never stored in `token_to_plaintext`, `plaintext_to_token`, logs, or `unblind_response`
   output by default (note: the caller's immutable input `prompt: str` and transient regex slices
   still reside briefly on the Python heap until garbage-collected).
2. PII Blinding: IBANs (case-insensitive), e-mail (Unicode), phone numbers, dates, labelled and
   mixed alphanumeric IDs (passport/customer numbers, Dutch postcodes), and capitalised multi-word
   names with Unicode letters, Mc/Mac forms and Dutch/European particles.
3. Numbers: Paillier PHE (fixed-point cents via `Decimal`) for amounts; non-negative 32-bit integers
   are additionally encrypted as RLWE-BFV limbs (N=2048, log q=54) for one ciphertext×ciphertext product.

KNOWN LIMITATIONS (heuristic, regex-based blinding):
- A secret without a label or recognisable pattern is NOT detected: wrap it in <secret>...</secret>.
- Names, places and streets are matched against a bundled offline gazetteer (`gazetteer.py`).
  Names/places outside those lists, lower-case names without a person cue in front of them
  ("renée müller confirmed"), ambiguous names/places without context ("Will", "Best") and street
  names without a house number or address cue are not detected.
- Percentages and bare integers below 10 stay in clear text (they are public policy parameters).
- `1.234` (one dot group, no comma) is ambiguous and is read as the English decimal 1.234.
"""

import hashlib
import hmac
import re
import secrets
import unicodedata
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from .bfv_fhe import BFVContext, SessionSecretVault
from .gazetteer import (
    AMBIGUOUS_FIRST_NAMES,
    AMBIGUOUS_PLACES,
    CALENDAR_WORDS,
    FIRST_NAMES,
    NAME_PARTICLE_PAIRS,
    NAME_PARTICLES,
    NAME_STOP,
    ORG_CUE_PATTERN,
    PERSON_CUES,
    PLACE_INDEX,
    PLACE_PREPOSITIONS,
    ROLE_WORDS,
    STREET_SUFFIX_STOPLIST,
    STREET_SUFFIXES_NL,
    STREET_WORDS_EN,
)
from .homomorphic import HomomorphicEvaluator, PaillierKeypair, normalize_fhe_handle

MAX_PROMPT_CHARS = 65_536
_SECRET_TAG_RE = re.compile(r"<\s*(/)?\s*secret\s*>", re.IGNORECASE)


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
    "PYTHON2", "PYTHON3", "OAUTH2", "HTTP11", "WEB3", "COVID19", "PCIDSS", "TLS12", "TLS13",
    "LOG4J", "LOG4J2", "ARGON2", "ARGON2ID", "BCRYPT2", "SCRYPT2", "ECDSA256", "ECDSA384",
}
# Only explicit, well-known shapes are exempt (M-R4). A generic "letters + 1-2 digits" rule would
# also exempt real identifiers such as POLICY12, SMITH42 or KLANT07, so there is none.
_TECH_CODE_RE = re.compile(
    r"^(?:ISO\d{3,6}|SOC[123](?:TYPE[12])?|RFC\d{3,5}|IEEE\d{3,5}[A-Z]{0,3}|NIST(?:SP)?\d{3}(?:R\d)?"
    r"|GDPR\d{0,4}|HIPAA\d{0,4}|PCIDSS\d{0,2}|WCAG2[012]?A{0,3}|OWASP\d{0,4}|CVE\d{4,}|CWE\d{1,4}"
    r"|TLS\d{1,2}|SSL\d{1,2}|SSH\d?|HTTP\d{1,2}|OAUTH\d?|ICD(?:9|10|11)(?:CM|PCS)?|DSM[45](?:TR)?"
    r"|Q[1-4](?:FY)?(?:\d{2}|20\d{2})|H[12](?:FY)?(?:\d{2}|20\d{2})|FY(?:\d{2}|20\d{2})"
    r"|ERC\d{2,4}|BIP\d{1,3}|EIP\d{1,4})$"
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
    "Confidential", "Patient", "Record", "Transfer", "Authorization", "Account", "Fiscal",
    "Quarter", "Year", "Revenue", "Profit", "Margin", "Tax", "Credit", "Debit", "Total", "Cost",
}


# Words from the list above that are also common surnames. After a role word ("patient Cash",
# "employee Key") they are treated as a name, not as business terminology (M-R4).
SURNAME_CAPABLE_NOUNS = {"Cash", "Key", "Pool", "Root"}
_TITLE_PREFIX_RE = re.compile(r"(?i:\b(?:mr|mrs|ms|dr|dhr|mevr)\.?\s+)$")


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
# Value rule (documented choice): a quoted value is taken exactly (supporting backslash escapes and
# mid-token apostrophes inside single quotes, e.g. 'p@ss'word99'). An UNQUOTED value (including a
# value with an unclosed leading quote) runs to the end of its clause: `,` or `;` followed by
# whitespace/end-of-line, `)` `]` or newline, or `.`/`!`/`?` followed by whitespace/end-of-prompt.
# Mid-token `,`/`;` (e.g. `p@ss,word123`, `My;Pass123`) stay inside the credential span.
_DBL_QUOTED = r'"((?:\\.|[^"\\\n])*)"'
_SGL_QUOTED = r"'((?:\\.|'(?=\w[^'\s\n]*')|[^'\\\n])*)'"
_UNQUOTED_CHAR = r"(?:[^,;)\]\n]|[,;](?!\s|$))"
_CLAUSE_END = r"(?=\s*(?:[,;](?:\s|$)|[)\]\n]|[.!?](?:\s|$)|$))"
_VALUE = (
    rf"(?:{_DBL_QUOTED}|{_SGL_QUOTED}"
    rf"|([^\s,;)\]]{_UNQUOTED_CHAR}*?){_CLAUSE_END})"
)
_PROSE_VALUE = (
    rf"(?:{_DBL_QUOTED}|{_SGL_QUOTED}"
    rf"|{_PROSE_PREDICATE_GUARD}([^\s,;)\]]{_UNQUOTED_CHAR}*?){_CLAUSE_END})"
)
# Fail-closed override (B-R4): a value whose FIRST token looks like a credential rather than a word
# is always sealed, whatever the prose guards above say. Every branch below uses partitioned/disjoint
# character classes so scanning an arbitrary-length non-matching token is strictly O(L) (zero ReDoS).
_TOK = r"(?:[^\s,;)\]\"']|[,;](?!\s|$))"
_STRONG_FIRST = (
    r"(?=(?:[\"'])?(?:"
    r"(?=[^\s\d,;)\]\"']*\d)(?=[\d.!?]*[^\s\d,;)\]\"'.!?])"
    r"|[^\s,;)\]\"'@#$%^&*_+~=/\\|]*[@#$%^&*_+~=/\\|]"
    r"|[^\s,;)\]\"']*[,;](?!\s|$)"
    r"|(?=[^\s,;)\]\"'!?]*[!?]+(?![\s,;)\]\"']|$))(?=(?:_|[^\w\s,;)\]\"'])*[^\W_])"
    r"|[^\s,;)\]\"'-]+(?:-[^\s,;)\]\"'-]+){2,}"
    r"))"
)
_STRONG_VALUE = (
    rf"(?:{_DBL_QUOTED}|{_SGL_QUOTED}"
    rf"|{_STRONG_FIRST}([^\s,;)\]]{_UNQUOTED_CHAR}*?){_CLAUSE_END})"
)
# One credential-like token after a generic word in prose ("De sleutel van de kluis is Kluis#4815"):
# at least 4 characters and either digit+letter mixed or a credential symbol (strictly O(L)).
_GENERIC_STRONG_TOKEN = (
    rf"((?=(?:(?=[^\s\d,;)\]\"']*\d)(?=(?:[\d_]|[^\w\s,;)\]\"'])*[^\W\d_])"
    rf"|[^\s,;)\]\"'@#$%^&*_+~=/\\|]*[@#$%^&*_+~=/\\|]"
    rf"|[^\s,;)\]\"']*[,;](?!\s|$)))"
    rf"{_TOK}{{4,}})"
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

# ---- Gazetteer-based detectors (names, places, addresses, cued organisations) ----------------
# Word tokens: letters with inner hyphen/apostrophe parts of 2+ letters (O'Connor, Jean-Luc,
# s-Hertogenbosch) but not a possessive "'s" (Maria's -> Maria). Strictly linear.
_WORD_RE = re.compile(r"[^\W\d_]+(?:[-'’][^\W\d_]{2,})*")
# Leading capitalised verbs that cue an organisation; never part of the blinded name itself.
_LEADING_CUE_CAPITALS = {"Pay", "Betaal"}
# Gap between a cue word and the next word: optional "." (dr.) or ":" (to:) plus 1-3 spaces/tabs.
_CUE_GAP_RE = re.compile(r"[.:]?[ \t]{1,3}")
# House number with addition: 12, 4b, 12-14, 12 bis, 12-hs, 12 A (no decimals, no percentages).
_HOUSE_NO_RE = re.compile(
    r"[ \t]{1,3}(\d{1,4}(?:[a-z]|[ \t]?[A-Z])?(?:[ \t]?-[ \t]?\d{1,4}[a-zA-Z]?|-(?:hs|bis|[IV]{1,3}))?"
    r"(?:[ \t]+bis)?)(?![\w%]|[.,]\d)"
)
_EN_STREET_ALT = "|".join(sorted(STREET_WORDS_EN, key=len, reverse=True))
# Number-first English address: "12 Baker Street", "221B Baker Street", "12-14 Old Kent Road".
_EN_ADDRESS_NUM_RE = re.compile(
    rf"(?<![\w.,-])(\d{{1,5}}[A-Za-z]?(?:-\d{{1,5}})?)[ \t]+((?:{NAME_WORD}[ \t]+){{1,3}}(?:{_EN_STREET_ALT}))\b\.?"
)
# Street words without a number are only blinded after an address cue.
_EN_STREET_RE = re.compile(rf"\b((?:{NAME_WORD}[ \t]+){{1,3}}(?:{_EN_STREET_ALT}))\b")
_ADDRESS_CUE_RE = re.compile(
    r"(?i:\b(?:lives?|living|located|based|resides?|residing|woont|wonend|gevestigd|verhuisd)"
    r"\s+(?:at|on|in|aan|op|in|naar)(?:\s+(?:de|het|the))?\s*$"
    r"|\b(?:adres|address|straat|street|bezorgadres|afleveradres)\b\s*(?:is\s+|:\s*)?$)"
)
_ADDRESS_TAIL_RE = re.compile(r"(?:\d[A-Za-z]?|\b[1-9]\d{3}[ \t]?[A-Z]{2}),?[ \t]*$")
_ORG_CUE_RE = re.compile(
    rf"(?i:\b(?:{ORG_CUE_PATTERN}))[ \t]+"
    rf"({NAME_WORD}(?:[ \t]+{NAME_WORD}){{1,3}}(?:[ \t]+(?:Corp|Inc|Ltd|BV|NV|LLC|B\.V\.|N\.V\.))?)\b"
)
_ORG_CONTINUE_RE = re.compile(
    rf"(?:[ \t]*,[ \t]*|[ \t]+(?:and|en|&)[ \t]+)"
    rf"({NAME_WORD}(?:[ \t]+{NAME_WORD}){{1,3}}(?:[ \t]+(?:Corp|Inc|Ltd|BV|NV|LLC))?)\b"
)
# Word endings that mark an everyday EN/NL word rather than a surname; only consulted after an
# ambiguous lower-case first name ("to max capacity" vs "to max verstappen").
_COMMON_WORD_SUFFIXES = (
    "ity", "tion", "sion", "ing", "ment", "ness", "ance", "ence", "able", "ible", "ize", "ise",
    "ful", "less", "ous", "ive", "ly", "ed", "heid", "eren", "elen", "ggen", "kken", "nnen", "llen",
)
_ORG_ROLE_CUES = {"vendor", "client", "customer", "leverancier", "klant", "supplier"}


def _is_cap(tok: str) -> bool:
    """Title-case word (Maria, McDonald, IJmuiden, O'Connor); not ALL-CAPS and not lower case."""
    return tok[0].isupper() and any(ch.islower() for ch in tok[1:])


def _gazetteer_spans(prompt: str) -> List["SpanMatch"]:
    """
    Deterministic, offline detectors on top of the regex rules (O(N): one tokenisation pass plus
    set/dict lookups per token, bounded look-ahead):
      1. Full names from the first-name list, case-insensitive ("jan jansen", "maria de vries").
      2. Single capitalised first names ("about Maria"); ambiguous names only after a person cue.
      3. Street addresses with house number ("Keizersgracht 12", "12 Baker Street"); a street
         without number only after an address cue ("woont aan de Keizersgracht").
      4. Capitalised place names ("Amsterdam", "Den Haag"); ambiguous ones only after a place
         preposition or inside an address ("in Best", "12, Best").
      5. Title-Case organisation groups directly after a cue word ("Pay Total Security and
         Cloud Reserve"), even when made only of business nouns. The cue word stays in clear.
    """
    toks = [(m.start(), m.end(), m.group(0)) for m in _WORD_RE.finditer(prompt)]
    lows = [t[2].lower() for t in toks]
    n = len(toks)
    out: List[SpanMatch] = []

    def adjacent(i: int, j: int) -> bool:
        gap_start, gap_end = toks[i][1], toks[j][0]
        return 0 < gap_end - gap_start <= 3 and prompt[gap_start:gap_end] in (" ", "  ", "   ", "\t")

    def prev_in(i: int, words) -> bool:
        if i == 0 or lows[i - 1] not in words:
            return False
        return _CUE_GAP_RE.fullmatch(prompt[toks[i - 1][1] : toks[i][0]]) is not None

    def surname_ok(k: int, want_cap: bool) -> bool:
        tok = toks[k][2]
        if len(tok) < 2 or lows[k] in NAME_STOP or tok in STOPWORD_CAPITALS:
            return False
        return _is_cap(tok) if want_cap else tok.islower() or _is_cap(tok)

    # 1 + 2: names -------------------------------------------------------------------------
    skip_until = -1
    for i in range(n):
        if i <= skip_until or lows[i] not in FIRST_NAMES:
            continue
        tok = toks[i][2]
        cap = _is_cap(tok)
        if not (cap or tok.islower()):
            continue
        low = lows[i]
        amb = low in AMBIGUOUS_FIRST_NAMES
        cued = prev_in(i, PERSON_CUES)

        # optional particle(s), then one surname word (two when both are capitalised)
        k = i + 1
        if k < n and adjacent(i, k) and lows[k] in NAME_PARTICLES:
            if k + 1 < n and adjacent(k, k + 1) and (lows[k], lows[k + 1]) in NAME_PARTICLE_PAIRS:
                k += 1
            k += 1
        last = None
        if k < n and adjacent(k - 1, k) and surname_ok(k, want_cap=cap):
            last = k
            if (
                cap
                and _is_cap(toks[k][2])
                and k + 1 < n
                and adjacent(k, k + 1)
                and lows[k + 1] not in FIRST_NAMES
                and surname_ok(k + 1, want_cap=True)
            ):
                last = k + 1

        if (
            last is not None
            and amb
            and not cap
            and not _is_cap(toks[last][2])
            and lows[last].endswith(_COMMON_WORD_SUFFIXES)
        ):
            last = None  # "to max capacity", "met mark overleggen": an everyday word, not a surname
        if last is not None and (cued or cap and not amb):
            # "to jan jansen", "mail maria de vries", "for will smith". A lower-case name needs a
            # person cue in front of it (preposition, role or contact word): without one, "mark the
            # invoice", "the emma project" or a bare "renée müller confirmed" are too weak evidence
            # (documented limitation). An ambiguous capitalised first name without a cue ("Will
            # Smith" at sentence start) is left to the capitalised multi-word rule.
            out.append(
                SpanMatch(toks[i][0], toks[last][1], "ID", prompt[toks[i][0] : toks[last][1]], priority=5,
                          is_role_subject=prev_in(i, ROLE_WORDS))
            )
            skip_until = last
            continue

        if not cap:
            # A lower-case first name alone counts only right after a person cue ("ask lisa",
            # "stuur naar sem"), and never when it is also an everyday word ("to mark", "met max").
            if cued and not amb:
                out.append(SpanMatch(toks[i][0], toks[i][1], "ID", tok, priority=6,
                                     is_role_subject=prev_in(i, ROLE_WORDS)))
            continue
        if amb and (not cued or low in CALENDAR_WORDS):
            continue
        if low == "jan" and re.match(r"[ \t]?\d", prompt[toks[i][1] : toks[i][1] + 2]):
            continue  # "Jan 15": English month abbreviation
        out.append(SpanMatch(toks[i][0], toks[i][1], "ID", tok, priority=6, is_role_subject=prev_in(i, ROLE_WORDS)))

    # 3: addresses ---------------------------------------------------------------------------
    for i in range(n):
        tok = toks[i][2]
        low = lows[i]
        if not _is_cap(tok) or low in STREET_SUFFIX_STOPLIST:
            continue
        suffix = next((s for s in STREET_SUFFIXES_NL if low.endswith(s) and len(low) >= len(s) + 3), None)
        if suffix is None:
            continue
        # Multi-word street names: "Prins Hendrikkade", "Van Baerlestraat", "Oudezijds Voorburgwal".
        first = i
        while first > 0 and i - first < 2 and adjacent(first - 1, first):
            prev_tok = toks[first - 1][2]
            if _is_cap(prev_tok) and prev_tok not in STOPWORD_CAPITALS and lows[first - 1] not in NAME_STOP:
                first -= 1
            elif lows[first - 1] in NAME_PARTICLES and first >= 2 and _is_cap(toks[first - 2][2]):
                first -= 1
            else:
                break
        while first < i and lows[first] in NAME_PARTICLES and not _is_cap(toks[first][2]):
            first += 1
        start = toks[first][0]
        hm = _HOUSE_NO_RE.match(prompt, toks[i][1])
        if hm:
            num = hm.group(1)
            digits = re.match(r"\d+", num).group(0)
            if len(digits) == 4 and num == digits and 1900 <= int(digits) <= 2099:
                hm = None  # "Woningmarkt 2025" is a year, not a house number
        if hm:
            out.append(SpanMatch(start, hm.end(1), "LOC", prompt[start : hm.end(1)], priority=4))
        elif _ADDRESS_CUE_RE.search(prompt[max(0, start - 40) : start]):
            out.append(SpanMatch(start, toks[i][1], "LOC", prompt[start : toks[i][1]], priority=4))

    for m in _EN_ADDRESS_NUM_RE.finditer(prompt):
        out.append(SpanMatch(m.start(), m.end(2), "LOC", prompt[m.start() : m.end(2)], priority=4))
    for m in _EN_STREET_RE.finditer(prompt):
        if _ADDRESS_CUE_RE.search(prompt[max(0, m.start() - 40) : m.start()]):
            out.append(SpanMatch(m.start(1), m.end(1), "LOC", m.group(1), priority=4))

    # 4: places --------------------------------------------------------------------------------
    i = 0
    while i < n:
        key = lows[i]
        tok = toks[i][2]
        start_off = toks[i][0]
        if key.startswith("s-") and start_off > 0 and prompt[start_off - 1] in "'’":
            capital_ok = len(tok) > 2 and tok[2].isupper()  # 's-Hertogenbosch
            start_off -= 1
        else:
            capital_ok = tok[0].isupper() and not tok.isupper()
        entries = PLACE_INDEX.get(key) if capital_ok else None
        matched = None
        if entries:
            for words in entries:
                last = i + len(words) - 1
                if last >= n:
                    continue
                if all(lows[i + w] == words[w] and adjacent(i + w - 1, i + w) for w in range(1, len(words))):
                    matched = (words, last)
                    break
        if matched is None:
            i += 1
            continue
        words, last = matched
        name = " ".join(words)
        if name in AMBIGUOUS_PLACES:
            in_address = _ADDRESS_TAIL_RE.search(prompt[max(0, start_off - 12) : start_off]) is not None
            if not (prev_in(i, PLACE_PREPOSITIONS) or in_address):
                i = last + 1
                continue
        out.append(SpanMatch(start_off, toks[last][1], "LOC", prompt[start_off : toks[last][1]], priority=5))
        i = last + 1

    # 5: organisations after a cue word --------------------------------------------------------
    for m in _ORG_CUE_RE.finditer(prompt):
        cue = prompt[m.start() : m.start(1)].split()[0].lower()
        role = cue in _ORG_ROLE_CUES
        out.append(SpanMatch(m.start(1), m.end(1), "ID", m.group(1), priority=5, is_role_subject=role))
        pos, extra = m.end(1), 0
        while extra < 4:
            cm = _ORG_CONTINUE_RE.match(prompt, pos)
            if not cm:
                break
            out.append(SpanMatch(cm.start(1), cm.end(1), "ID", cm.group(1), priority=5))
            pos, extra = cm.end(1), extra + 1

    return out


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
    """Case-insensitive, NFC-normalized occurrence with word boundaries on word-character edges."""
    v = unicodedata.normalize("NFC", value).strip()
    if not v:
        return False
    norm_text = text if unicodedata.is_normalized("NFC", text) else unicodedata.normalize("NFC", text)
    pat = re.escape(v)
    if re.match(r"\w", v[0]):
        pat = r"(?<!\w)" + pat
    if re.match(r"\w", v[-1]):
        pat = pat + r"(?!\w)"
    return re.search(pat, norm_text, flags=re.IGNORECASE) is not None


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
                if not quoted:
                    # A "!" glued to an unquoted value is far more often the last character of the
                    # password than sentence punctuation, so it is sealed with it (fail closed).
                    while end < len(m.string) and m.string[end] == "!":
                        val, end = val + "!", end + 1
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

    @staticmethod
    def _find_secret_tag_spans(prompt: str) -> List[SpanMatch]:
        """
        Linear O(N) scanner for `<secret>...</secret>` tags (including whitespace variants `< secret >`,
        nested `<secret>...<secret>...</secret>...</secret>`, stray `</secret>`, and unclosed `<secret>`).
        """
        spans: List[SpanMatch] = []
        depth = 0
        outer_start = 0
        inner_open_end = 0
        last_emitted_end = 0

        for m in _SECRET_TAG_RE.finditer(prompt):
            is_close = m.group(1) is not None
            if not is_close:
                if depth == 0:
                    outer_start = m.start()
                    inner_open_end = m.end()
                depth += 1
            else:
                if depth > 0:
                    depth -= 1
                    if depth == 0:
                        raw = prompt[outer_start : m.end()]
                        inner = _SECRET_TAG_RE.sub("", prompt[inner_open_end : m.start()])
                        spans.append(SpanMatch(outer_start, m.end(), "SECRET", raw, priority=0, unseal_value=inner))
                        last_emitted_end = m.end()
                else:
                    # Stray closing tag (e.g. malformed `secret>val</secret>`): seal preceding token + tag.
                    tok_start = m.start()
                    while tok_start > last_emitted_end and not prompt[tok_start - 1].isspace():
                        tok_start -= 1
                    raw = prompt[tok_start : m.end()]
                    inner = _SECRET_TAG_RE.sub("", prompt[tok_start : m.start()])
                    spans.append(SpanMatch(tok_start, m.end(), "SECRET", raw, priority=0, unseal_value=inner))
                    last_emitted_end = m.end()

        if depth > 0:
            raw = prompt[outer_start:]
            inner = _SECRET_TAG_RE.sub("", prompt[inner_open_end:])
            spans.append(SpanMatch(outer_start, len(prompt), "SECRET", raw, priority=0, unseal_value=inner))

        return spans

    def _collect_spans(self, prompt: str) -> List[SpanMatch]:
        candidates: List[SpanMatch] = []

        # Priority 0: Explicit <secret>...</secret> tags (handles whitespace, nesting, and unclosed tags).
        candidates.extend(self._find_secret_tag_spans(prompt))

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

        # Fail-closed overrides (B-R4): a credential-like value is sealed even after a policy noun
        # ("Password reset: TempPass123!"), a prose predicate ("password is not-my-real-one!") or an
        # indefinite article ("a password is Zomer2026x").
        for m in re.finditer(
            rf"(?i:\b{SECRET_LABELS}{_GAP}(?:{_SEP_EQ}|{_SEP_PROSE}))" + _STRONG_VALUE, prompt
        ):
            candidates.append(self._labelled_value_span(m, 1, priority=1))
        for m in re.finditer(
            rf"(?i:\b(?:sleutel|geheim|pin|secret|key|token|seed){_GAP}{_SEP_PROSE})" + _GENERIC_STRONG_TOKEN,
            prompt,
        ):
            val, end = m.group(1), m.end(1)
            while len(val) > 1 and val[-1] in ".?" and (end >= len(prompt) or prompt[end].isspace()):
                val, end = val[:-1], end - 1
            if val.upper() in ALNUM_STOPLIST or _TECH_CODE_RE.fullmatch(val.upper()):
                continue
            candidates.append(SpanMatch(m.start(1), end, "SECRET", val, priority=1, unseal_value=val))

        # Priority 1B: Single-word generic labels with ':' or '=', plus numeric/quoted PIN in prose
        for m in re.finditer(r"(?i:\b(?:secret|token|key|seed|pin|geheim|sleutel)\s*(?:=|:)\s*)" + _VALUE, prompt):
            candidates.append(self._labelled_value_span(m, 1, priority=1))
        for m in re.finditer(
            rf"(?i:\bpin(?:\s+(?:code|number|nr|(?:for|van|voor)(?:\s+[\w-]+){{1,3}}))?{_SEP_PROSE})"
            rf"(?:{_DBL_QUOTED}|{_SGL_QUOTED}|(\d{{3,12}})\b)",
            prompt,
        ):
            candidates.append(self._labelled_value_span(m, 1, priority=1))

        # Priority 1C: "password X" without separator, when X contains a digit or symbol (strictly O(L))
        for m in re.finditer(
            r"(?i:\b(?:password|passwd|wachtwoord|pincode|pin)\s+)(?![:=])"
            rf"([^\s,;)\]\"'\d!@#$%^&*_+~]*[\d!@#$%^&*_+~]{_TOK}*)",
            prompt,
        ):
            val, end = m.group(1), m.end(1)
            while len(val) > 1 and val[-1] in ".?" and (end >= len(prompt) or prompt[end].isspace()):
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
        # A unit-like suffix is still a postcode when a capitalised place name follows ("3011 AD
        # Rotterdam") or an address word precedes it ("adres ... 2595 BE") (S-R7).
        for m in re.finditer(r"\b[1-9]\d{3}\s?[A-Z]{2}\b", prompt):
            is_unit = m.group(0)[-2:] in POSTCODE_UNIT_STOPLIST
            if is_unit:
                followed_by_place = re.match(rf"\s+[{_UP}][{_LO}]{{2,}}", prompt[m.end():]) is not None
                address_cue = re.search(
                    r"(?i:\b(?:postcode|zip|adres|address|straat|street|woont|lives)\b)",
                    prompt[max(0, m.start() - 40) : m.start()],
                ) is not None
                if not (followed_by_place or address_cue):
                    continue
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

        # Priority 4-6: gazetteer names, addresses, places and cued organisations (offline lists).
        # Added before the capitalised-phrase rule so a place ("Den Haag") wins a tie with it.
        candidates.extend(_gazetteer_spans(prompt))

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
            while words and (words[0] in STOPWORD_CAPITALS or words[0] in _LEADING_CUE_CAPITALS):
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
            # After a personal title (mr/dr/dhr/mevr) the next capitalised word is always a name.
            # After a role noun, business nouns are skipped unless they are also common surnames.
            after_title = _TITLE_PREFIX_RE.search(prompt[: m.start(1)]) is not None
            is_business_noun = word in BUSINESS_CAPITAL_NOUNS and word not in SURNAME_CAPABLE_NOUNS
            if (
                word not in STOPWORD_CAPITALS
                and (after_title or not is_business_noun)
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
                inner = _SECRET_TAG_RE.sub("", union_text)
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
        if not isinstance(prompt, str):
            raise ValueError("Prompt must be a string.")
        if len(prompt) > MAX_PROMPT_CHARS:
            raise ValueError(f"Prompt exceeds maximum length ({MAX_PROMPT_CHARS} characters).")
        prompt = unicodedata.normalize("NFC", prompt)
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
        scan_text = unicodedata.normalize("NFC", scan_text)
        occurs = {v: _value_occurs(v, scan_text) for v in set(secret_values_for_scan)}
        ctx.residual_secret_matches = sum(1 for v in secret_values_for_scan if occurs[v])
        occurs.clear()
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
        """
        Validate the LLM's op_spec here, send ONLY public material (Paillier n / BFV rlk) plus the
        ciphertexts to the separate evaluator process, then decrypt the returned ciphertexts locally.
        Same machine: a process boundary with public material only, not a network/hardware boundary.
        """
        # Lazy import: services/ imports this module (avoids an import cycle).
        from services import evaluator_worker as ew

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

            req = ew.build_bfv_request(ref_a, ref_b, ea["bfv_limbs"], eb["bfv_limbs"], self.bfv.evaluator.public_rlk)
            res = ew.run_evaluation(req, lambda resp, pid: ew.decode_bfv_response(resp, req, pid))
            prod_terms = res["terms"]
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
            ctx.log(f"RLWE-BFV product evaluated by {res['evaluated_by']}")
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
                **ew.provenance(res),
            }

        req, expected_scales = ew.build_paillier_request(op_spec, ctx.encrypted_numbers, self.paillier.n)
        eval_res = ew.run_evaluation(
            req, lambda resp, pid: ew.decode_paillier_response(resp, req, self.paillier.n, expected_scales, pid)
        )
        ctx.log(f"{self.phe_label} {eval_res['op']} evaluated by {eval_res['evaluated_by']}")
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
            **ew.provenance(eval_res),
        }

    def unblind_response(self, response_text: str, ctx: BlindContext, include_secrets: bool = False) -> str:
        """
        Restore local PII tokens and decrypted homomorphic handles for client display.
        Echoed `[SECRET_XXXX]` tokens stay redacted by default so cloud/prompt-injected
        echoes cannot exfiltrate sealed credentials into plaintext JSON responses or UI views.
        """
        cleaned = re.sub(r"(\[FHE_NUM_\d+\])\(ENC:0x[0-9a-fA-F\.]+\)", r"\1", response_text)

        for sec_token, blob in ctx.sealed_secrets.items():
            if sec_token in cleaned:
                if include_secrets:
                    replacement = self.secret_vault.unseal(blob)
                else:
                    # Redaction never decrypts: the plaintext must not be recreated on the Python heap.
                    replacement = f"[REDACTED:{sec_token}]"
                cleaned = cleaned.replace(sec_token, replacement)

        for token in sorted(ctx.token_to_plaintext.keys(), key=len, reverse=True):
            cleaned = cleaned.replace(token, ctx.token_to_plaintext[token])

        return cleaned
