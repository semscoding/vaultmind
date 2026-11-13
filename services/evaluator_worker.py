"""
Untrusted homomorphic evaluator process for VaultMind.

What this is (and what it is not)
---------------------------------
The homomorphic evaluation (Paillier PERCENT_BONUS / ADD / MUL_SCALAR and RLWE-BFV ciphertext ×
ciphertext multiplication) runs in a SEPARATE OS PROCESS that only ever receives public material:

* Paillier: the public modulus ``n`` plus the ciphertexts (and their fixed-point scales).
* RLWE-BFV: the public relinearization key ``rlk`` plus the limb ciphertexts.

It never receives ``p``, ``q``, ``lambda``, ``mu`` (Paillier) or the ternary secret key ``sk``
(BFV), never constructs a ``PaillierKeypair`` or ``BFVContext``, and has no decryption code
path. It returns result ciphertexts only; the main process decrypts them locally.

Honest scope: the worker runs on the SAME machine, as a child process of the main process. The
separation is a process boundary carrying only public material, not a network or hardware
boundary (no enclave, no remote attestation). Its value is that it demonstrates, and the tests
check, that the evaluator can compute without any secret key, so the same worker could just as
well run on another host.

Wire format (both directions, over the child's stdin/stdout pipes)
------------------------------------------------------------------
Each message is a frame: a 4-byte big-endian length followed by that many bytes of UTF-8 JSON.
No pickle and no other code-carrying format ever crosses the boundary. Big Paillier integers are
lowercase hex strings; BFV ciphertexts / rlk are little-endian int64 arrays, hex-encoded.
Both sides validate types, lengths and ranges; the main process does not trust the response.

Request::

    {"v": 1, "id": 1, "kind": "paillier", "op": "PERCENT_BONUS" | "ADD" | "MUL_SCALAR",
     "public": {"n": "<hex>"},
     "params": {"ref": "[FHE_NUM_1]", "percent": "12.5"} | {"ref_a", "ref_b"} | {"ref", "scalar": int},
     "ciphertexts": {"[FHE_NUM_1]": {"c": "<hex>", "scale": 100}, ...}}

    {"v": 1, "id": 2, "kind": "bfv", "op": "BFV_MULTIPLY",
     "public": {"rlk": "<hex of 16384 int64>"},
     "params": {"ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"},
     "ciphertexts": {"limbs_a": ["<hex of 4096 int64>", ...], "limbs_b": [...]}}

Response::

    {"v": 1, "id": 1, "ok": true, "pid": 1234, "engine": str, "op": str, "label": str, "formula": str,
     "outputs": {"[FHE_COMPUTED_BONUS]": {"c": "<hex>", "scale": 10000}, ...}}   # Paillier
     "terms": [{"deg": 0, "c": "<hex>"}, ...]                                    # BFV
    {"v": 1, "id": 1, "ok": false, "pid": 1234, "error": "..."}

The first frame the worker sends is a handshake: ``{"v": 1, "hello": "vaultmind-evaluator", "pid": ...}``.
"""

import atexit
import itertools
import json
import math
import os
import re
import selectors
import signal
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

PROTOCOL_VERSION = 1
HELLO_TAG = "vaultmind-evaluator"
MAX_FRAME_BYTES = 8 * 1024 * 1024

# Must match backend/crypto/bfv_fhe.py (checked when the crypto modules are loaded).
BFV_N = 2048
BFV_CT_LEN = 2 * BFV_N
BFV_RLK_LEN = 4 * 2 * BFV_N
BFV_COEFF_BOUND = 1 << 54  # ciphertext modulus q; coefficients are kept centred in (-q, q)
BFV_MAX_LIMBS = 4  # u32 values -> at most 4 base-256 limbs

PAILLIER_MIN_N_BITS = 512
PAILLIER_MAX_N_BITS = 8192
MAX_SCALE = 10**12
MAX_TEXT_CHARS = 512

PAILLIER_OPS = ("PERCENT_BONUS", "ADD", "MUL_SCALAR")
BFV_OPS = ("BFV_MULTIPLY",)

_REF_RE = re.compile(r"^\[FHE_NUM_\d{1,6}\]$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_OUT_TOKEN_RE = re.compile(r"^\[FHE_COMPUTED_[A-Z]{1,16}\]$")

REQUEST_KEYS = {"v", "id", "kind", "op", "public", "params", "ciphertexts"}
_LEGACY_REQUEST_KEYS = REQUEST_KEYS - {"id"}
_REQ_IDS = itertools.count(1)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKER_PATH = os.path.abspath(__file__)


class FrameError(ValueError):
    """A frame or JSON message that does not follow the protocol."""


# --------------------------------------------------------------------------------------------
# Codec helpers (shared by both sides)
# --------------------------------------------------------------------------------------------


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise FrameError(msg)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def int_to_hex(value: int) -> str:
    return format(value, "x")


def hex_to_int(raw: Any, what: str, max_bits: int) -> int:
    _require(isinstance(raw, str), f"{what} must be a hex string")
    _require(0 < len(raw) <= (max_bits + 3) // 4, f"{what} has an invalid length")
    _require(_HEX_RE.match(raw) is not None, f"{what} is not lowercase hex")
    return int(raw, 16)


def i64_to_hex(values: Any, length: int) -> str:
    _require(len(values) == length, f"int64 array must have {length} entries, got {len(values)}")
    return struct.pack(f"<{length}q", *values).hex()


def hex_to_i64(raw: Any, length: int, what: str) -> Tuple[int, ...]:
    _require(isinstance(raw, str), f"{what} must be a hex string")
    _require(len(raw) == 16 * length, f"{what} must encode exactly {length} int64 values")
    _require(_HEX_RE.match(raw) is not None, f"{what} is not lowercase hex")
    values = struct.unpack(f"<{length}q", bytes.fromhex(raw))
    _require(
        all(-BFV_COEFF_BOUND < x < BFV_COEFF_BOUND for x in values),
        f"{what} has coefficients outside (-q, q)",
    )
    return values


def safe_text(raw: Any, what: str) -> str:
    _require(isinstance(raw, str), f"{what} must be a string")
    _require(len(raw) <= MAX_TEXT_CHARS, f"{what} is too long")
    _require(not any(ord(ch) < 32 or ord(ch) == 127 for ch in raw), f"{what} contains control characters")
    return raw


def encode_message(msg: Dict[str, Any]) -> bytes:
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def decode_message(payload: bytes) -> Dict[str, Any]:
    """Parse one frame payload. JSON only: nothing in here can execute code."""
    _require(isinstance(payload, (bytes, bytearray)), "frame payload must be bytes")
    _require(len(payload) <= MAX_FRAME_BYTES, "frame too large")
    try:
        msg = json.loads(bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FrameError(f"frame is not valid UTF-8 JSON ({type(exc).__name__})") from None
    _require(isinstance(msg, dict), "message must be a JSON object")
    return msg


# --------------------------------------------------------------------------------------------
# Worker side: evaluation using only the public-key evaluator classes
# --------------------------------------------------------------------------------------------


def _evaluator_classes():
    """Load ONLY the evaluator classes (public material). Lazy so the client side stays light."""
    from backend.crypto import bfv_fhe, homomorphic

    if (bfv_fhe.BFV_CT_LEN, bfv_fhe.BFV_RLK_LEN) != (BFV_CT_LEN, BFV_RLK_LEN):
        raise RuntimeError("BFV parameter mismatch between evaluator worker and bfv_fhe.py")
    return bfv_fhe.BFVEvaluator, homomorphic.HomomorphicEvaluator


def _check_ref(raw: Any, what: str) -> str:
    _require(isinstance(raw, str) and _REF_RE.match(raw) is not None, f"{what} is not a valid FHE handle")
    return raw


def _evaluate_paillier(req: Dict[str, Any]) -> Dict[str, Any]:
    _, HomomorphicEvaluator = _evaluator_classes()
    op = req["op"]
    public = req["public"]
    _require(isinstance(public, dict) and set(public) == {"n"}, "public must contain exactly 'n'")
    n = hex_to_int(public["n"], "public.n", PAILLIER_MAX_N_BITS)
    _require(PAILLIER_MIN_N_BITS <= n.bit_length() <= PAILLIER_MAX_N_BITS, "public.n has an invalid size")
    _require(n % 2 == 1, "public.n must be odd")
    n_sq = n * n

    params = req["params"]
    _require(isinstance(params, dict), "params must be an object")
    if op == "PERCENT_BONUS":
        _require(set(params) == {"ref", "percent"}, "PERCENT_BONUS expects params ref, percent")
        _require(isinstance(params["percent"], str) and len(params["percent"]) <= 64, "percent must be a short string")
        refs = [_check_ref(params["ref"], "params.ref")]
    elif op == "ADD":
        _require(set(params) == {"ref_a", "ref_b"}, "ADD expects params ref_a, ref_b")
        refs = [_check_ref(params["ref_a"], "params.ref_a"), _check_ref(params["ref_b"], "params.ref_b")]
    else:  # MUL_SCALAR
        _require(set(params) == {"ref", "scalar"}, "MUL_SCALAR expects params ref, scalar")
        _require(_is_int(params["scalar"]), "scalar must be an integer")
        refs = [_check_ref(params["ref"], "params.ref")]

    cts = req["ciphertexts"]
    _require(isinstance(cts, dict) and set(cts) == set(refs), "ciphertexts must match the referenced handles")
    handles: Dict[str, Dict[str, int]] = {}
    for ref, entry in cts.items():
        _require(isinstance(entry, dict) and set(entry) == {"c", "scale"}, f"ciphertext {ref} must have c, scale")
        c = hex_to_int(entry["c"], f"ciphertext {ref}", 2 * PAILLIER_MAX_N_BITS)
        _require(0 < c < n_sq, f"ciphertext {ref} is outside Z_(n^2)")
        scale = entry["scale"]
        _require(_is_int(scale) and 0 < scale <= MAX_SCALE, f"scale of {ref} is invalid")
        handles[ref] = {"ciphertext": c, "scale": scale}

    # The evaluator re-validates the LLM operands itself (parse_percent / parse_scalar bounds).
    res = HomomorphicEvaluator(n).evaluate_operation(dict(params, op=op), handles)
    return {
        "engine": res["engine"],
        "op": res["op"],
        "label": res["label"],
        "formula": res["formula"],
        "outputs": {
            tok: {"c": int_to_hex(meta["ciphertext"]), "scale": meta["scale"]}
            for tok, meta in res["outputs"].items()
        },
    }


def _evaluate_bfv(req: Dict[str, Any]) -> Dict[str, Any]:
    BFVEvaluator, _ = _evaluator_classes()
    public = req["public"]
    _require(isinstance(public, dict) and set(public) == {"rlk"}, "public must contain exactly 'rlk'")
    rlk = hex_to_i64(public["rlk"], BFV_RLK_LEN, "public.rlk")

    params = req["params"]
    _require(isinstance(params, dict) and set(params) == {"ref_a", "ref_b"}, "BFV_MULTIPLY expects params ref_a, ref_b")
    ref_a = _check_ref(params["ref_a"], "params.ref_a")
    ref_b = _check_ref(params["ref_b"], "params.ref_b")

    cts = req["ciphertexts"]
    _require(isinstance(cts, dict) and set(cts) == {"limbs_a", "limbs_b"}, "ciphertexts must be limbs_a, limbs_b")
    limbs: Dict[str, List[Tuple[int, ...]]] = {}
    for side in ("limbs_a", "limbs_b"):
        raw = cts[side]
        _require(isinstance(raw, list) and 1 <= len(raw) <= BFV_MAX_LIMBS, f"{side} must hold 1..{BFV_MAX_LIMBS} limbs")
        limbs[side] = [hex_to_i64(x, BFV_CT_LEN, f"{side}[{i}]") for i, x in enumerate(raw)]

    terms = BFVEvaluator(rlk).multiply_limbs(limbs["limbs_a"], limbs["limbs_b"])
    return {
        "engine": "Native C RLWE-BFV (leveled, depth 1; R_q = Z_{2^54}[X]/(X^2048+1))",
        "op": "BFV_MULTIPLY",
        "label": f"RLWE-BFV (leveled, depth 1) Ciphertext × Ciphertext Product ({ref_a} × {ref_b})",
        "formula": f"c_prod = Relin(round((t/q) · ({ref_a} ⊗ {ref_b}))) in R_q (N=2048)",
        "terms": [{"deg": deg, "c": i64_to_hex(ct, BFV_CT_LEN)} for deg, ct in terms],
    }


def evaluate_request(req: Any) -> Dict[str, Any]:
    """
    Validate and evaluate one request. Pure function of the (public) request: used by the worker
    process, and by the main process only for the explicitly labelled in-process fallback.
    Never raises; failures become {"ok": false, "error": ...}.
    """
    pid = os.getpid()
    has_id = isinstance(req, dict) and "id" in req and _is_int(req["id"]) and 0 < req["id"] < (1 << 53)
    id_field = {"id": req["id"]} if has_id else {}
    try:
        _require(isinstance(req, dict), "request must be a JSON object")
        keys = set(req)
        _require(
            keys == REQUEST_KEYS or keys == _LEGACY_REQUEST_KEYS,
            f"request fields must be {sorted(REQUEST_KEYS)}",
        )
        if "id" in req:
            _require(has_id, "request id must be a positive integer")
        _require(req["v"] == PROTOCOL_VERSION, "unsupported protocol version")
        kind, op = req["kind"], req["op"]
        if kind == "paillier" and op in PAILLIER_OPS:
            body = _evaluate_paillier(req)
        elif kind == "bfv" and op in BFV_OPS:
            body = _evaluate_bfv(req)
        else:
            raise FrameError(f"unsupported operation: {str(kind)[:32]}/{str(op)[:32]}")
    except Exception as exc:  # noqa: BLE001 - the worker must answer, not crash
        return dict(
            id_field,
            v=PROTOCOL_VERSION,
            ok=False,
            pid=pid,
            error=f"{type(exc).__name__}: {exc}"[:MAX_TEXT_CHARS],
        )
    return dict(body, **id_field, v=PROTOCOL_VERSION, ok=True, pid=pid)


def _read_exact_blocking(stream, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _write_frame_blocking(stream, payload: bytes) -> None:
    stream.write(struct.pack(">I", len(payload)) + payload)
    stream.flush()


def worker_main() -> int:
    """Serve requests on stdin/stdout until EOF (the parent closing the pipe or exiting)."""
    # Ctrl-C in the parent's terminal also reaches this process group; shutdown is driven by EOF.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr  # stray prints must never corrupt the framed protocol
    _evaluator_classes()  # load the evaluator once, before the handshake
    _write_frame_blocking(stdout, encode_message({"v": PROTOCOL_VERSION, "hello": HELLO_TAG, "pid": os.getpid()}))
    while True:
        header = _read_exact_blocking(stdin, 4)
        if header is None:
            return 0
        (length,) = struct.unpack(">I", header)
        if length > MAX_FRAME_BYTES:
            return 2  # cannot resynchronise safely; the parent restarts us
        payload = _read_exact_blocking(stdin, length)
        if payload is None:
            return 0
        try:
            req = decode_message(payload)
        except FrameError as exc:
            resp = {"v": PROTOCOL_VERSION, "ok": False, "pid": os.getpid(), "error": f"FrameError: {exc}"}
        else:
            resp = evaluate_request(req)
        _write_frame_blocking(stdout, encode_message(resp))


def _install_minimal_crypto_package(root: str) -> None:
    """
    Make `backend.crypto.bfv_fhe` / `.homomorphic` importable WITHOUT running
    backend/crypto/__init__.py, which would also load the tokenizer and Shamir modules.
    The worker thus loads only the two modules that hold the evaluator classes.
    """
    import types

    if root not in sys.path:
        sys.path.insert(0, root)
    import backend  # noqa: F401  (docstring-only package)

    pkg = types.ModuleType("backend.crypto")
    pkg.__path__ = [os.path.join(root, "backend", "crypto")]
    pkg.__package__ = "backend.crypto"
    sys.modules["backend.crypto"] = pkg


# --------------------------------------------------------------------------------------------
# Main-process side: request builders, response validation, process client
# --------------------------------------------------------------------------------------------


class EvaluatorUnavailable(RuntimeError):
    """The worker could not be started or did not answer (crash, EOF, timeout)."""


class EvaluatorProtocolError(ValueError):
    """The worker answered, but the answer is malformed or fails validation."""


class EvaluatorRejected(ValueError):
    """The worker refused the request (ok: false)."""


def build_paillier_request(
    op_spec: Dict[str, Any], encrypted_numbers: Dict[str, Dict[str, Any]], n: int
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """
    Validate an (untrusted, LLM-produced) Paillier op_spec in the main process and build the
    request. Returns (request, expected output scales). Error types/messages mirror
    HomomorphicEvaluator.evaluate_operation so existing callers see the same behaviour.
    """
    from backend.crypto.homomorphic import HomomorphicEvaluator, lcm, normalize_fhe_handle

    op = str(op_spec.get("op", "")).upper()

    def entry(ref: str) -> Dict[str, Any]:
        e = encrypted_numbers[ref]
        return {"c": int_to_hex(e["ciphertext"]), "scale": int(e["scale"])}

    if op == "PERCENT_BONUS":
        ref = normalize_fhe_handle(op_spec.get("ref", ""))
        pct_dec, _pct_int, factor = HomomorphicEvaluator.parse_percent(op_spec.get("percent", 15))
        if ref not in encrypted_numbers:
            raise KeyError(f"Unknown homomorphic handle: {ref}")
        params = {"ref": ref, "percent": format(pct_dec, "f")}
        cts = {ref: entry(ref)}
        out_scale = int(encrypted_numbers[ref]["scale"]) * 100 * factor
        expected = {"[FHE_COMPUTED_BONUS]": out_scale, "[FHE_COMPUTED_TOTAL]": out_scale}
    elif op == "ADD":
        ref_a = normalize_fhe_handle(op_spec.get("ref_a", ""))
        ref_b = normalize_fhe_handle(op_spec.get("ref_b", ""))
        if ref_a not in encrypted_numbers or ref_b not in encrypted_numbers:
            raise KeyError(f"Unknown homomorphic handles for ADD: {ref_a}, {ref_b}")
        params = {"ref_a": ref_a, "ref_b": ref_b}
        cts = {ref_a: entry(ref_a), ref_b: entry(ref_b)}
        expected = {
            "[FHE_COMPUTED_SUM]": lcm(int(encrypted_numbers[ref_a]["scale"]), int(encrypted_numbers[ref_b]["scale"]))
        }
    elif op == "MUL_SCALAR":
        ref = normalize_fhe_handle(op_spec.get("ref", ""))
        scalar = HomomorphicEvaluator.parse_scalar(op_spec.get("scalar", 1))
        if ref not in encrypted_numbers:
            raise KeyError(f"Unknown homomorphic handle: {ref}")
        params = {"ref": ref, "scalar": scalar}
        cts = {ref: entry(ref)}
        expected = {"[FHE_COMPUTED_PROD]": int(encrypted_numbers[ref]["scale"])}
    else:
        raise ValueError(f"Unsupported Paillier operation: {op}")

    req = {
        "v": PROTOCOL_VERSION,
        "id": next(_REQ_IDS),
        "kind": "paillier",
        "op": op,
        "public": {"n": int_to_hex(n)},
        "params": params,
        "ciphertexts": cts,
    }
    return req, expected


def build_bfv_request(ref_a: str, ref_b: str, limbs_a: List[Any], limbs_b: List[Any], rlk: Any) -> Dict[str, Any]:
    return {
        "v": PROTOCOL_VERSION,
        "id": next(_REQ_IDS),
        "kind": "bfv",
        "op": "BFV_MULTIPLY",
        "public": {"rlk": i64_to_hex(rlk, BFV_RLK_LEN)},
        "params": {"ref_a": ref_a, "ref_b": ref_b},
        "ciphertexts": {
            "limbs_a": [i64_to_hex(ct, BFV_CT_LEN) for ct in limbs_a],
            "limbs_b": [i64_to_hex(ct, BFV_CT_LEN) for ct in limbs_b],
        },
    }


def describe_inputs(req: Dict[str, Any], request_bytes: int) -> Dict[str, Any]:
    """Field names and sizes of what crossed the boundary. No values."""
    sizes: Dict[str, str] = {}
    if req["kind"] == "paillier":
        sizes["public.n"] = f"{int(req['public']['n'], 16).bit_length()}-bit Paillier modulus"
        for ref, e in req["ciphertexts"].items():
            sizes[f"ciphertexts.{ref}"] = f"{int(e['c'], 16).bit_length()}-bit Paillier ciphertext + scale"
    else:
        sizes["public.rlk"] = f"{BFV_RLK_LEN} int64 BFV relinearization key"
        for side in ("limbs_a", "limbs_b"):
            sizes[f"ciphertexts.{side}"] = f"{len(req['ciphertexts'][side])} × {BFV_CT_LEN} int64 BFV ciphertexts"
    return {
        "fields": (["id"] if "id" in req else []) + ["op"] + [f"params.{k}" for k in req["params"]] + list(sizes),
        "sizes": sizes,
        "request_bytes": request_bytes,
        "never_sent": "p, q, lambda, mu (Paillier); sk (BFV)",
    }


def _check_response_header(resp: Dict[str, Any], req: Dict[str, Any], expected_pid: int) -> None:
    if resp.get("v") != PROTOCOL_VERSION:
        raise EvaluatorProtocolError("evaluator response has a wrong protocol version")
    if resp.get("pid") != expected_pid:
        raise EvaluatorProtocolError("evaluator response pid does not match the worker process")
    ok = resp.get("ok")
    if ok is False:
        if "id" in req and resp.get("id") != req["id"]:
            raise EvaluatorProtocolError("evaluator response id does not match the request")
        raise EvaluatorRejected(f"evaluator rejected the request: {safe_text(str(resp.get('error'))[:MAX_TEXT_CHARS], 'error')}")
    if ok is not True:
        raise EvaluatorProtocolError("evaluator response has no ok flag")
    if "id" in req and resp.get("id") != req["id"]:
        raise EvaluatorProtocolError("evaluator response id does not match the request")


def decode_paillier_response(
    resp: Dict[str, Any], req: Dict[str, Any], n: int, expected_scales: Dict[str, int], expected_pid: int
) -> Dict[str, Any]:
    try:
        _check_response_header(resp, req, expected_pid)
        expected_fields = {"v", "ok", "pid", "engine", "op", "label", "formula", "outputs"} | (
            {"id"} if "id" in req else set()
        )
        _require(set(resp) == expected_fields, "unexpected response fields")
        _require(resp["op"] == req["op"], "response op does not match the request")
        outputs = resp["outputs"]
        _require(isinstance(outputs, dict) and set(outputs) == set(expected_scales), "unexpected output handles")
        n_sq = n * n
        decoded = {}
        for tok, meta in outputs.items():
            _require(_OUT_TOKEN_RE.match(tok) is not None, "invalid output handle")
            _require(isinstance(meta, dict) and set(meta) == {"c", "scale"}, f"output {tok} must have c, scale")
            c = hex_to_int(meta["c"], f"output {tok}", 2 * n.bit_length())
            _require(0 < c < n_sq, f"output {tok} is outside Z_(n^2)")
            _require(_is_int(meta["scale"]) and meta["scale"] == expected_scales[tok], f"output {tok} has a wrong scale")
            decoded[tok] = {"ciphertext": c, "scale": meta["scale"]}
        return {
            "engine": safe_text(resp["engine"], "engine"),
            "op": resp["op"],
            "label": safe_text(resp["label"], "label"),
            "formula": safe_text(resp["formula"], "formula"),
            "outputs": decoded,
        }
    except FrameError as exc:
        raise EvaluatorProtocolError(f"invalid evaluator response: {exc}") from None


def decode_bfv_response(resp: Dict[str, Any], req: Dict[str, Any], expected_pid: int) -> Dict[str, Any]:
    import ctypes

    try:
        _check_response_header(resp, req, expected_pid)
        expected_fields = {"v", "ok", "pid", "engine", "op", "label", "formula", "terms"} | (
            {"id"} if "id" in req else set()
        )
        _require(set(resp) == expected_fields, "unexpected response fields")
        _require(resp["op"] == "BFV_MULTIPLY", "response op does not match the request")
        la, lb = len(req["ciphertexts"]["limbs_a"]), len(req["ciphertexts"]["limbs_b"])
        expected_degs = [i + j for i in range(la) for j in range(lb)]
        terms = resp["terms"]
        _require(isinstance(terms, list) and len(terms) == len(expected_degs), "wrong number of product terms")
        decoded = []
        for idx, (term, deg) in enumerate(zip(terms, expected_degs)):
            _require(isinstance(term, dict) and set(term) == {"deg", "c"}, f"term {idx} must have deg, c")
            _require(_is_int(term["deg"]) and term["deg"] == deg, f"term {idx} has a wrong degree")
            values = hex_to_i64(term["c"], BFV_CT_LEN, f"term {idx}")
            decoded.append((deg, (ctypes.c_int64 * BFV_CT_LEN)(*values)))
        return {
            "engine": safe_text(resp["engine"], "engine"),
            "op": resp["op"],
            "label": safe_text(resp["label"], "label"),
            "formula": safe_text(resp["formula"], "formula"),
            "terms": decoded,
        }
    except FrameError as exc:
        raise EvaluatorProtocolError(f"invalid evaluator response: {exc}") from None


class _TransportError(Exception):
    pass


def _validated_timeout(raw: Any, default: float = 20.0, strict: bool = False) -> float:
    if raw is None:
        return default
    try:
        val = float(raw)
    except (TypeError, ValueError):
        if strict:
            raise ValueError(f"invalid evaluator timeout: {raw!r}") from None
        return default
    if not math.isfinite(val) or val <= 0:
        if strict:
            raise ValueError(f"evaluator timeout must be positive and finite, got {raw!r}")
        return default
    return val


class EvaluatorClient:
    """
    One long-lived worker process, started lazily on first use and shared by every pipeline in
    this Python process. Requests are serialised by a lock; each has a deadline. On a crash,
    EOF or time-out the worker is killed and restarted once for the same request.
    """

    def __init__(
        self,
        argv: Optional[List[str]] = None,
        request_timeout: Optional[float] = None,
        start_timeout: float = 15.0,
    ):
        self._argv = list(argv) if argv else [sys.executable, WORKER_PATH]
        self.request_timeout = (
            _validated_timeout(request_timeout, strict=True)
            if request_timeout is not None
            else _validated_timeout(os.environ.get("VAULTMIND_EVALUATOR_TIMEOUT"), default=20.0, strict=False)
        )
        self.start_timeout = _validated_timeout(start_timeout, default=15.0, strict=True)
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        # Optional observer for every frame crossing the boundary: tap(direction, payload_bytes).
        self.tap: Optional[Callable[[str, bytes], None]] = None
        self.starts = 0  # number of worker processes started by this client

    # -- process management --------------------------------------------------------------

    @property
    def pid(self) -> Optional[int]:
        proc = self._proc
        return proc.pid if proc is not None and proc.poll() is None else None

    def _start(self) -> None:
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            proc = subprocess.Popen(
                self._argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,
                cwd=_PROJECT_ROOT,
                env=env,
                close_fds=True,
                bufsize=0,
            )
        except OSError as exc:
            raise _TransportError(f"could not start evaluator process: {exc}") from None
        self._proc = proc
        handshake_ok = False
        try:
            os.set_blocking(proc.stdin.fileno(), False)
            os.set_blocking(proc.stdout.fileno(), False)
            hello = decode_message(self._recv_frame(time.monotonic() + self.start_timeout))
            if hello.get("hello") != HELLO_TAG or hello.get("pid") != proc.pid or hello.get("v") != PROTOCOL_VERSION:
                raise _TransportError("evaluator handshake failed: unexpected hello")
            handshake_ok = True
        except FrameError as exc:
            raise _TransportError(f"evaluator handshake failed: {exc}") from None
        except OSError as exc:
            raise _TransportError(f"evaluator pipe setup failed: {exc}") from None
        finally:
            if not handshake_ok:
                self._kill()

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        for stream in (proc.stdin, proc.stdout):
            try:
                stream.close()
            except OSError:
                pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)  # reap: no zombie left behind
        except subprocess.TimeoutExpired:
            pass

    def invalidate(self, expected_pid: Optional[int] = None) -> None:
        """Kill the worker if it is still the active process (e.g. after a protocol violation)."""
        with self._lock:
            if self._proc is not None and (expected_pid is None or self._proc.pid == expected_pid):
                self._kill()

    def close(self) -> None:
        """Graceful shutdown: close stdin (worker exits on EOF), then make sure it is gone."""
        with self._lock:
            proc, self._proc = self._proc, None
            if proc is None:
                return
            try:
                proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            try:
                proc.stdout.close()
            except OSError:
                pass

    # -- framed I/O with deadlines ---------------------------------------------------------

    def _send_frame(self, payload: bytes, deadline: float) -> None:
        fd = self._proc.stdin.fileno()
        view = memoryview(struct.pack(">I", len(payload)) + payload)
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(fd, selectors.EVENT_WRITE)
                while view:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _TransportError("timed out writing to the evaluator process")
                    if not sel.select(remaining):
                        continue
                    try:
                        written = os.write(fd, view)
                    except BlockingIOError:
                        continue
                    except OSError as exc:  # BrokenPipeError when the worker died
                        raise _TransportError(f"evaluator process pipe closed: {exc}") from None
                    view = view[written:]
        except _TransportError:
            raise
        except (OSError, ValueError) as exc:
            raise _TransportError(f"evaluator selector error: {exc}") from None

    def _recv_exact(self, n: int, deadline: float) -> bytes:
        fd = self._proc.stdout.fileno()
        buf = bytearray()
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(fd, selectors.EVENT_READ)
                while len(buf) < n:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _TransportError("timed out waiting for the evaluator process")
                    if not sel.select(remaining):
                        continue
                    try:
                        chunk = os.read(fd, min(n - len(buf), 1 << 20))
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        raise _TransportError(f"evaluator process pipe error: {exc}") from None
                    if not chunk:
                        raise _TransportError("evaluator process exited (EOF)")
                    buf.extend(chunk)
        except _TransportError:
            raise
        except (OSError, ValueError) as exc:
            raise _TransportError(f"evaluator selector error: {exc}") from None
        return bytes(buf)

    def _recv_frame(self, deadline: float) -> bytes:
        (length,) = struct.unpack(">I", self._recv_exact(4, deadline))
        if length > MAX_FRAME_BYTES:
            raise _TransportError("evaluator frame exceeds the size limit")
        return self._recv_exact(length, deadline)

    # -- request / response ----------------------------------------------------------------

    def request_bytes(self, payload: bytes) -> Tuple[bytes, int]:
        """Send one raw frame, return (raw response frame, worker pid). Restarts once on failure."""
        with self._lock:
            last_error: Optional[Exception] = None
            for attempt in range(2):
                completed = False
                try:
                    if self._proc is None or self._proc.poll() is not None:
                        self._kill()
                        self._start()
                        self.starts += 1
                    pid = self._proc.pid
                    deadline = time.monotonic() + self.request_timeout
                    if self.tap:
                        self.tap("request", payload)
                    self._send_frame(payload, deadline)
                    raw = self._recv_frame(deadline)
                    completed = True
                    if self.tap:
                        self.tap("response", raw)
                    return raw, pid
                except _TransportError as exc:
                    last_error = exc
                finally:
                    # Never leave a half-written request or unread response buffered in the pipe.
                    if not completed:
                        self._kill()
            raise EvaluatorUnavailable(str(last_error))

    def call(self, req: Dict[str, Any]) -> Tuple[Dict[str, Any], int, int]:
        """Send a request dict; return (parsed response, worker pid, request size in bytes)."""
        payload = encode_message(req)
        raw, pid = self.request_bytes(payload)
        try:
            resp = decode_message(raw)
        except FrameError as exc:
            with self._lock:
                self._kill()  # a worker that sends garbage is not reused
            raise EvaluatorProtocolError(f"invalid evaluator response: {exc}") from None
        return resp, pid, len(payload)


_CLIENT: Optional[EvaluatorClient] = None
_CLIENT_LOCK = threading.Lock()


def get_evaluator_client() -> EvaluatorClient:
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT is None:
            _CLIENT = EvaluatorClient()
        return _CLIENT


def set_evaluator_client(client: Optional[EvaluatorClient]) -> Optional[EvaluatorClient]:
    """Swap the shared client (tests). Returns the previous one; the caller closes it if needed."""
    global _CLIENT
    with _CLIENT_LOCK:
        previous, _CLIENT = _CLIENT, client
        return previous


@atexit.register
def _shutdown_shared_client() -> None:
    client = _CLIENT
    if client is not None:
        client.close()


FALLBACK_LABEL = "in-process fallback"
PROVENANCE_KEYS = ("evaluated_by", "evaluator_pid", "evaluator_inputs", "evaluator_warning")


def provenance(result: Dict[str, Any]) -> Dict[str, Any]:
    """The keys that say where the homomorphic evaluation ran (added to the FHE result)."""
    return {k: result[k] for k in PROVENANCE_KEYS if k in result}


def run_evaluation(req: Dict[str, Any], decode: Callable[[Dict[str, Any], int], Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluate `req` in the worker process and decode/validate the answer with `decode(resp, pid)`.
    If the worker cannot be started or keeps failing (after one restart), evaluate in this
    process instead and say so explicitly in the result.
    """
    holder = "n" if req["kind"] == "paillier" else "rlk"
    client = get_evaluator_client()
    try:
        resp, pid, req_bytes = client.call(req)
    except EvaluatorUnavailable as exc:
        local_pid = os.getpid()
        payload = encode_message(req)
        result = decode(decode_message(encode_message(evaluate_request(decode_message(payload)))), local_pid)
        result.update(
            evaluated_by=FALLBACK_LABEL,
            evaluator_pid=local_pid,
            evaluator_warning=(
                "Evaluator process unavailable "
                f"({str(exc)[:200]}); the homomorphic evaluation ran in the main process, which also "
                "holds the secret keys. The result is correct but this run does NOT demonstrate key separation."
            ),
            evaluator_inputs=describe_inputs(req, len(payload)),
        )
        return result
    try:
        result = decode(resp, pid)
    except EvaluatorProtocolError:
        client.invalidate(pid)
        raise
    result.update(
        evaluated_by=f"untrusted evaluator process (pid {pid}; holds only {holder})",
        evaluator_pid=pid,
        evaluator_inputs=describe_inputs(req, req_bytes),
    )
    return result


if __name__ == "__main__":
    # Run as a script (not `-m services...`) so services/__init__.py (pipeline, enclave) is never imported.
    _here = os.path.dirname(WORKER_PATH)
    sys.path[:] = [entry for entry in sys.path if os.path.abspath(entry or ".") != _here]
    _install_minimal_crypto_package(_PROJECT_ROOT)
    sys.exit(worker_main())
