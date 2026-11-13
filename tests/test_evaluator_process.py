"""
Tests for the untrusted evaluator process (services/evaluator_worker.py).

The worker is a child process on the same machine that receives only public material
(Paillier n / BFV rlk) and ciphertexts; the main process decrypts. These tests check the
process boundary, the absence of secret material on the wire, correctness, robustness
(restart, fallback, time-out) and that a manipulated response is rejected cleanly.
"""

import ast
import json
import os
import pickle
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from backend.crypto.blind_tokenizer import BlindTokenizer
from services import evaluator_worker as ew

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A fake "worker" that completes the handshake and then misbehaves according to argv[1].
FAKE_WORKER = r"""
import json, os, struct, sys, time
inp, out = sys.stdin.buffer, sys.stdout.buffer
def send(b):
    out.write(struct.pack(">I", len(b)) + b); out.flush()
send(json.dumps({"v": 1, "hello": "vaultmind-evaluator", "pid": os.getpid()}).encode())
mode = sys.argv[1]
while True:
    h = inp.read(4)
    if len(h) < 4:
        break
    req = json.loads(inp.read(struct.unpack(">I", h)[0]))
    pid = os.getpid()
    meta = {"v": 1, "ok": True, "pid": pid, "engine": "e", "op": req["op"], "label": "l", "formula": "f"}
    if mode == "notjson":
        send(b"\x80\x04 definitely not json")
    elif mode == "pickle":
        send(bytes.fromhex(sys.argv[2]))
    elif mode == "hang":
        time.sleep(60)
    elif mode == "short_bfv":
        la, lb = len(req["ciphertexts"]["limbs_a"]), len(req["ciphertexts"]["limbs_b"])
        terms = [{"deg": i + j, "c": "00" * 8 * 100} for i in range(la) for j in range(lb)]
        send(json.dumps(dict(meta, terms=terms)).encode())
    elif mode == "big_paillier":
        n = int(req["public"]["n"], 16)
        outs = {"[FHE_COMPUTED_BONUS]": {"c": format(n * n + 5, "x"), "scale": 10000},
                "[FHE_COMPUTED_TOTAL]": {"c": format(n * n + 7, "x"), "scale": 10000}}
        send(json.dumps(dict(meta, outputs=outs)).encode())
    elif mode == "wrong_scale":
        outs = {"[FHE_COMPUTED_BONUS]": {"c": "2", "scale": 1}, "[FHE_COMPUTED_TOTAL]": {"c": "3", "scale": 1}}
        send(json.dumps(dict(meta, outputs=outs)).encode())
    elif mode == "wrong_pid":
        send(json.dumps(dict(meta, pid=1, outputs={})).encode())
"""


class _PickleBomb:
    """Unpickling this would create a marker file. JSON decoding must never do that."""

    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (open, (self.path, "w"))


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class _SwapClient:
    """Context manager: temporarily replace the shared evaluator client."""

    def __init__(self, client):
        self.client = client

    def __enter__(self):
        self.previous = ew.set_evaluator_client(self.client)
        return self.client

    def __exit__(self, *exc):
        ew.set_evaluator_client(self.previous)
        self.client.close()
        return False


class EvaluatorProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tok = BlindTokenizer(paillier_bits=1024)

    def _ctx(self, prompt):
        _, ctx = self.tok.blind_prompt(prompt)
        return ctx

    # -- process boundary ------------------------------------------------------------------

    def test_evaluation_runs_in_a_separate_live_process(self):
        ctx = self._ctx("Evaluate a 15% bonus for salary $130,000 this year.")
        res = self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15}, ctx)
        pid = res["evaluator_pid"]
        self.assertIsInstance(pid, int)
        self.assertNotEqual(pid, os.getpid())
        self.assertTrue(_pid_alive(pid))
        self.assertTrue(res["evaluated_by"].startswith(f"untrusted evaluator process (pid {pid}"))
        self.assertNotIn("evaluator_warning", res)
        cmd = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout
        self.assertIn("evaluator_worker", cmd)
        # Same keys as before, plus the provenance keys.
        for key in ("engine", "op", "label", "formula", "decrypted_outputs", "ciphertext_previews",
                    "evaluated_by", "evaluator_pid", "evaluator_inputs"):
            self.assertIn(key, res)
        self.assertIn("public.n", res["evaluator_inputs"]["sizes"])

    def test_boundary_carries_no_secret_material(self):
        frames = []
        client = ew.get_evaluator_client()
        client.tap = lambda direction, payload: frames.append((direction, payload))
        try:
            ctx = self._ctx("Multiply invoice units 300 and price $300 for salary $130,000 today.")
            self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": "[FHE_NUM_3]", "percent": "12.5"}, ctx)
            self.tok.execute_and_decrypt_fhe({"op": "ADD", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_3]"}, ctx)
            self.tok.execute_and_decrypt_fhe({"op": "MUL_SCALAR", "ref": "[FHE_NUM_3]", "scalar": -2}, ctx)
            self.tok.execute_and_decrypt_fhe({"op": "BFV_MULTIPLY", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"}, ctx)
        finally:
            client.tap = None
        self.assertEqual(len(frames), 8)

        pk = self.tok.paillier
        secret_strings = []
        for value in (pk.p, pk.q, pk.lambd, pk.mu):
            secret_strings += [str(value), format(value, "x"), format(value, "X")]
        sk = self.tok.bfv._sk
        sk_raw = bytes(sk)
        secret_strings += [struct.pack(f"<{len(sk)}q", *sk).hex(), sk_raw.hex()]

        for direction, payload in frames:
            text = payload.decode("ascii")
            for s in secret_strings:
                self.assertNotIn(s, text, f"secret material found in {direction} frame")
            self.assertNotIn(sk_raw, payload)
            msg = json.loads(text)
            if direction == "request":
                self.assertEqual(set(msg), ew.REQUEST_KEYS)
                if msg["kind"] == "paillier":
                    self.assertEqual(set(msg["public"]), {"n"})
                    self.assertEqual(int(msg["public"]["n"], 16), pk.n)
                    for entry in msg["ciphertexts"].values():
                        self.assertEqual(set(entry), {"c", "scale"})
                else:
                    self.assertEqual(set(msg["public"]), {"rlk"})
                    self.assertEqual(set(msg["ciphertexts"]), {"limbs_a", "limbs_b"})
                self.assertLessEqual(set(msg["params"]), {"ref", "ref_a", "ref_b", "percent", "scalar"})
            else:
                self.assertTrue(msg["ok"])
                self.assertLessEqual(
                    set(msg), {"v", "ok", "pid", "engine", "op", "label", "formula", "outputs", "terms"}
                )

    def test_worker_module_has_no_decryption_or_secret_key_code(self):
        path = os.path.join(ROOT, "services", "evaluator_worker.py")
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names, attrs, imported = set(), set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                attrs.add(node.attr)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names.add(node.name)
        identifiers = names | attrs | imported
        self.assertFalse([i for i in identifiers if "decrypt" in i.lower()])
        for forbidden in ("BFVContext", "PaillierKeypair", "SessionSecretVault", "BlindTokenizer"):
            self.assertNotIn(forbidden, identifiers)
        for forbidden_attr in ("_sk", "p", "q", "lambd", "mu", "paillier"):
            self.assertNotIn(forbidden_attr, attrs)

    def test_worker_rejects_bad_requests_without_crashing(self):
        client = ew.get_evaluator_client()
        ctx = self._ctx("Evaluate a 15% bonus for salary $130,000 this year.")
        good, _ = ew.build_paillier_request(
            {"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15}, ctx.encrypted_numbers, self.tok.paillier.n
        )
        resp, pid, _ = client.call(good)
        self.assertTrue(resp["ok"])

        bad_requests = [
            dict(good, op="DECRYPT"),
            dict(good, kind="secret"),
            dict(good, sk="00"),
            dict(good, params={"ref": "[FHE_NUM_1]", "percent": "5000"}),  # worker re-validates bounds
            dict(good, params={"ref": "[FHE_NUM_1]; import os", "percent": "15"}),
            dict(good, public={"n": "zz"}),
            dict(good, ciphertexts={"[FHE_NUM_1]": {"c": "0", "scale": 100}}),
            {"v": 1, "kind": "bfv", "op": "BFV_MULTIPLY", "public": {"rlk": "00"},
             "params": {"ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"},
             "ciphertexts": {"limbs_a": ["00"], "limbs_b": ["00"]}},
            [1, 2, 3],
        ]
        for bad in bad_requests:
            resp, bad_pid, _ = client.call(bad) if isinstance(bad, dict) else (
                json.loads(client.request_bytes(json.dumps(bad).encode())[0]), client.pid, 0
            )
            self.assertFalse(resp["ok"], bad)
            self.assertIn("error", resp)
            self.assertEqual(bad_pid, pid)

        raw, raw_pid = client.request_bytes(b"\xff\xfe not json at all")
        self.assertFalse(json.loads(raw)["ok"])
        self.assertEqual(raw_pid, pid)

        resp, pid_after, _ = client.call(good)
        self.assertTrue(resp["ok"])
        self.assertEqual(pid_after, pid, "worker must survive malformed input")

    # -- correctness after local decryption -----------------------------------------------

    def test_paillier_operations_are_correct(self):
        ctx = self._ctx("Evaluate salary $130,000 with base $1,200.50 and fee $300.25 and price $100.00 today.")
        handles = {v["raw_text"]: k for k, v in ctx.encrypted_numbers.items()}
        salary, base, fee, price = (handles[x] for x in ("$130,000", "$1,200.50", "$300.25", "$100.00"))

        res = self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": salary, "percent": 15}, ctx)
        self.assertEqual(res["decrypted_outputs"], {"[FHE_COMPUTED_BONUS]": "$19,500.00", "[FHE_COMPUTED_TOTAL]": "$149,500.00"})
        res = self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": salary, "percent": "12.5"}, ctx)
        self.assertEqual(res["decrypted_outputs"], {"[FHE_COMPUTED_BONUS]": "$16,250.00", "[FHE_COMPUTED_TOTAL]": "$146,250.00"})
        self.assertIn("12.5% Bonus", res["label"])
        res = self.tok.execute_and_decrypt_fhe({"op": "ADD", "ref_a": base, "ref_b": fee}, ctx)
        self.assertEqual(res["decrypted_outputs"], {"[FHE_COMPUTED_SUM]": "$1,500.75"})
        res = self.tok.execute_and_decrypt_fhe({"op": "MUL_SCALAR", "ref": price, "scalar": -3}, ctx)
        self.assertEqual(res["decrypted_outputs"], {"[FHE_COMPUTED_PROD]": "-$300.00"})
        res = self.tok.execute_and_decrypt_fhe({"op": "mul_scalar", "ref": price, "scalar": "7"}, ctx)
        self.assertEqual(res["decrypted_outputs"], {"[FHE_COMPUTED_PROD]": "$700.00"})
        self.assertNotEqual(res["evaluator_pid"], os.getpid())

    def test_bfv_multiply_is_correct(self):
        ctx = self._ctx("Multiply invoice units 300 and price $300 today.")
        res = self.tok.execute_and_decrypt_fhe(
            {"op": "BFV_MULTIPLY", "ref_a": "[FHE_NUM_1](ENC:0xdead...beef)", "ref_b": "[FHE_NUM_2]"}, ctx
        )
        self.assertEqual(res["decrypted_outputs"], {"[FHE_COMPUTED_PRODUCT]": "$90,000"})
        self.assertIn("holds only rlk", res["evaluated_by"])

        ctx = self._ctx("Multiply units 4294967295 and count 4294967295 for the report.")
        res = self.tok.execute_and_decrypt_fhe({"op": "MULTIPLY", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"}, ctx)
        self.assertEqual(res["decrypted_outputs"]["[FHE_COMPUTED_PRODUCT]"], f"{(2**32 - 1) ** 2:,}")
        self.assertEqual(res["evaluator_inputs"]["sizes"]["ciphertexts.limbs_a"], "4 × 4096 int64 BFV ciphertexts")

    def test_invalid_llm_operands_are_rejected_before_sending(self):
        frames = []
        client = ew.get_evaluator_client()
        client.tap = lambda d, p: frames.append(d)
        try:
            ctx = self._ctx("Evaluate a bonus for salary $130,000 this year.")
            with self.assertRaises(ValueError):
                self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": "abc"}, ctx)
            with self.assertRaises(ValueError):
                self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 5000}, ctx)
            with self.assertRaises(ValueError):
                self.tok.execute_and_decrypt_fhe({"op": "MUL_SCALAR", "ref": "[FHE_NUM_1]", "scalar": 10**7}, ctx)
            with self.assertRaises(ValueError):
                self.tok.execute_and_decrypt_fhe({"op": "DIVIDE", "ref": "[FHE_NUM_1]"}, ctx)
            with self.assertRaises(KeyError):
                self.tok.execute_and_decrypt_fhe({"op": "ADD", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_9]"}, ctx)
        finally:
            client.tap = None
        self.assertEqual(frames, [], "invalid operands must not reach the evaluator process")

    # -- robustness ---------------------------------------------------------------------------

    def test_killed_worker_is_restarted(self):
        ctx = self._ctx("Evaluate a 15% bonus for salary $130,000 this year.")
        spec = {"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15}
        old_pid = self.tok.execute_and_decrypt_fhe(spec, ctx)["evaluator_pid"]
        os.kill(old_pid, signal.SIGKILL)
        res = self.tok.execute_and_decrypt_fhe(spec, ctx)
        self.assertEqual(res["decrypted_outputs"]["[FHE_COMPUTED_TOTAL]"], "$149,500.00")
        self.assertNotEqual(res["evaluator_pid"], old_pid)
        self.assertNotEqual(res["evaluator_pid"], os.getpid())
        self.assertNotIn("evaluator_warning", res)
        self.assertFalse(_pid_alive(old_pid), "killed worker must be reaped")

    def test_fallback_when_worker_cannot_start(self):
        ctx = self._ctx("Multiply invoice units 300 and price $300 for salary $130,000 today.")
        for argv in (["/nonexistent/evaluator_worker"], [sys.executable, "-c", "import sys; sys.exit(3)"]):
            with _SwapClient(ew.EvaluatorClient(argv=argv, start_timeout=5)):
                res = self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": "[FHE_NUM_3]", "percent": 15}, ctx)
                self.assertEqual(res["evaluated_by"], "in-process fallback")
                self.assertEqual(res["evaluator_pid"], os.getpid())
                self.assertIn("does NOT demonstrate key separation", res["evaluator_warning"])
                self.assertEqual(res["decrypted_outputs"]["[FHE_COMPUTED_BONUS]"], "$19,500.00")
                res = self.tok.execute_and_decrypt_fhe({"op": "BFV_MULTIPLY", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"}, ctx)
                self.assertEqual(res["evaluated_by"], "in-process fallback")
                self.assertEqual(res["decrypted_outputs"]["[FHE_COMPUTED_PRODUCT]"], "$90,000")

    def test_hanging_worker_times_out_and_falls_back(self):
        ctx = self._ctx("Evaluate a 15% bonus for salary $130,000 this year.")
        client = ew.EvaluatorClient(argv=[sys.executable, "-c", FAKE_WORKER, "hang"], request_timeout=0.5)
        with _SwapClient(client):
            t0 = time.monotonic()
            res = self.tok.execute_and_decrypt_fhe({"op": "PERCENT_BONUS", "ref": "[FHE_NUM_1]", "percent": 15}, ctx)
            self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual(res["evaluated_by"], "in-process fallback")
        self.assertIn("timed out", res["evaluator_warning"])
        self.assertEqual(res["decrypted_outputs"]["[FHE_COMPUTED_TOTAL]"], "$149,500.00")

    def test_manipulated_responses_fail_cleanly(self):
        ctx = self._ctx("Multiply invoice units 300 and price $300 for salary $130,000 today.")
        bonus = {"op": "PERCENT_BONUS", "ref": "[FHE_NUM_3]", "percent": 15}
        mult = {"op": "BFV_MULTIPLY", "ref_a": "[FHE_NUM_1]", "ref_b": "[FHE_NUM_2]"}
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "pwned")
            bomb = pickle.dumps(_PickleBomb(marker)).hex()
            cases = [("notjson", bonus), ("pickle", bonus), ("short_bfv", mult),
                     ("big_paillier", bonus), ("wrong_scale", bonus), ("wrong_pid", bonus)]
            for mode, spec in cases:
                with self.subTest(mode=mode):
                    with _SwapClient(ew.EvaluatorClient(argv=[sys.executable, "-c", FAKE_WORKER, mode, bomb])):
                        with self.assertRaises(ew.EvaluatorProtocolError):
                            self.tok.execute_and_decrypt_fhe(spec, ctx)
            self.assertFalse(os.path.exists(marker), "response bytes must never be unpickled")

    def test_no_worker_left_after_interpreter_exit(self):
        script = (
            "from backend.crypto.blind_tokenizer import BlindTokenizer\n"
            "t = BlindTokenizer(paillier_bits=1024)\n"
            "_, ctx = t.blind_prompt('Evaluate a 15% bonus for salary $130,000 this year.')\n"
            "r = t.execute_and_decrypt_fhe({'op': 'PERCENT_BONUS', 'ref': '[FHE_NUM_1]'}, ctx)\n"
            "print(r['evaluator_pid'], flush=True)\n"
        )
        env = dict(os.environ, PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1")
        # 1) normal exit: atexit closes the worker; the interpreter must not hang.
        out = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=env, capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        pid = int(out.stdout.split()[-1])
        self.assertFalse(_pid_alive(pid))

        # 2) parent killed hard (no atexit): the worker sees EOF on stdin and exits by itself.
        proc = subprocess.Popen([sys.executable, "-c", script + "import time; time.sleep(60)\n"], cwd=ROOT,
                                env=env, stdout=subprocess.PIPE, text=True)
        try:
            pid = int(proc.stdout.readline().split()[-1])
            self.assertTrue(_pid_alive(pid))
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()
        deadline = time.monotonic() + 10
        while _pid_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(_pid_alive(pid), "orphaned worker must exit on EOF")


if __name__ == "__main__":
    unittest.main()
