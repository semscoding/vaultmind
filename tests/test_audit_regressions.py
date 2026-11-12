"""
Regression tests for the findings of the Victory Audit (12 Nov 2026) and audit round 3.

Every test that touches storage uses its own temporary directory. No test performs a real
cloud call: provider failures are simulated by patching httpx, and only dummy (non-key)
strings are passed where an API key is expected.
"""

import asyncio
import ctypes
import json
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import httpx
from fastapi.testclient import TestClient

from apis.llm_client import LLMClient, LLMProviderError
from backend.crypto.bfv_fhe import BFV_T, BFVContext
from backend.crypto.blind_tokenizer import BlindTokenizer
from backend.crypto.shamir import ShamirSecretSharing
from services.enclave_service import SecureEnclave
from services.pipeline_service import AgentPipeline

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DUMMY_KEY = "dummy-test-value-not-an-api-key"


def _intent(target: str = "[ID_TEST1234]", action: str = "DB_WRITE_RECORD"):
    return {"action": action, "target": target, "params": {}}


class TestNativeCoreRegressions(unittest.TestCase):
    def test_aad_boundary_shift_attack_is_rejected(self):
        """M1: moving the last 16 AAD bytes into the IV (and the IV into the ciphertext) must fail."""
        sss = ShamirSecretSharing()
        bundle = sss.generate_and_split_master_key(threshold_k=3, total_n=5)
        quorum = bundle["shards"][:3]
        aad = b"1:" + b"0" * 64 + b":DB_WRITE_RECORD:[GOV_ID_AABBCCDD]"
        sealed = sss.enclave_seal_record(quorum, bundle["key_commitment_hex"], b"payload-123", aad)

        # Control: the genuine row verifies and decrypts.
        self.assertEqual(
            sss.enclave_unseal_record(quorum, sealed["iv_hex"], sealed["ciphertext_hex"], sealed["hmac_hex"], aad),
            b"payload-123",
        )

        # Attack: aad' = aad[:-16], iv' = aad[-16:], ct' = iv || ct  (same byte stream into a length-free HMAC)
        shifted_aad = aad[:-16]
        shifted_iv = aad[-16:].hex()
        shifted_ct = sealed["iv_hex"] + sealed["ciphertext_hex"]
        with self.assertRaises(ValueError):
            sss.enclave_unseal_record(quorum, shifted_iv, shifted_ct, sealed["hmac_hex"], shifted_aad)

    def test_shamir_split_coefficients_are_uniform(self):
        """
        M5: with k=2 the share at x=1 is s XOR a_1. With uniform a_1 it equals the secret with
        probability 1/256 per byte and takes all 256 values. 65,536 bytes are split in one call:
        expected 256 hits, and P(some value never occurs) <= 256 * (255/256)^65536 ~ 2^-361.
        """
        lib = ShamirSecretSharing().lib
        n_bytes = 65536
        secret = os.urandom(n_bytes)
        c_secret = (ctypes.c_uint8 * n_bytes).from_buffer_copy(secret)
        shares = (ctypes.c_uint8 * (2 * n_bytes))()
        rc = lib.vault_split_secret(c_secret, n_bytes, 2, 2, None, shares, None)
        self.assertEqual(rc, 0)

        share_x1 = bytes(shares[:n_bytes])
        a1_values = {s ^ y for s, y in zip(secret, share_x1)}
        equal_hits = sum(1 for s, y in zip(secret, share_x1) if s == y)
        self.assertGreaterEqual(equal_hits, 1, "share at x=1 never equals the secret: a_1 = 0 is excluded")
        self.assertEqual(len(a1_values), 256, "leading coefficient does not take all 256 values")

    def test_total_n_255_returns(self):
        """S3: total_n = 255 used to loop forever (uint8_t counter). Run it in a subprocess with a time-out."""
        code = (
            "from backend.crypto.shamir import ShamirSecretSharing\n"
            "sss = ShamirSecretSharing()\n"
            "b = sss.generate_and_split_master_key(threshold_k=3, total_n=255)\n"
            "assert len(b['shards']) == 255\n"
            "q = [s for s in b['shards'] if s['x'] in (1, 128, 255)]\n"
            "sss.enclave_seal_record(q, b['key_commitment_hex'], b'x')\n"
            "print('OK')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, timeout=120
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        self.assertIn("OK", proc.stdout)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("nm"), "macOS + nm required")
    def test_memset_s_is_linked_into_the_dylib(self):
        """B2: the compiled library really imports memset_s (not only the volatile-loop fallback)."""
        lib_path = os.path.join(REPO_ROOT, "backend", "native", "libvaultcrypto.dylib")
        out = subprocess.run(["nm", "-u", lib_path], capture_output=True, text=True, check=True).stdout
        self.assertIn("_memset_s", out.split())


class TestBFVDepth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bfv = BFVContext()

    @classmethod
    def tearDownClass(cls):
        cls.bfv.close()

    def test_depth_1_multiplication_then_addition_is_exact(self):
        rng = random.Random(311)
        ev = self.bfv.evaluator
        for _ in range(10):
            a, b, c, d = (rng.randint(0, 65535) for _ in range(4))
            p1 = ev.multiply(self.bfv.encrypt_int(a), self.bfv.encrypt_int(b))
            p2 = ev.multiply(self.bfv.encrypt_int(c), self.bfv.encrypt_int(d))
            self.assertEqual(self.bfv.decrypt_int(p1), (a * b) % BFV_T)
            self.assertEqual(self.bfv.decrypt_int(ev.add(p1, p2)), (a * b + c * d) % BFV_T)

    def test_depth_2_is_not_guaranteed(self):
        """
        Documentation test: the parameters are sized for multiplicative depth 1 only. A second
        multiplication (depth 2) is NOT guaranteed to decrypt correctly; the audit measured 40/40
        failures. Only that the call completes is checked here, never its correctness.
        """
        ev = self.bfv.evaluator
        ct = ev.multiply(self.bfv.encrypt_int(3), self.bfv.encrypt_int(5))
        ct2 = ev.multiply(ct, self.bfv.encrypt_int(7))
        value = self.bfv.decrypt_int(ct2)
        self.assertTrue(0 <= value < BFV_T)


class TestEnclaveRegressions(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.enclave = SecureEnclave(storage_dir=self.tmp, reset_on_init=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_raw(self, x: int, raw: str) -> None:
        with open(os.path.join(self.tmp, "shards", f"node_0{x}.json"), "w", encoding="utf-8") as f:
            f.write(raw)

    def _read_raw(self, x: int) -> str:
        with open(os.path.join(self.tmp, "shards", f"node_0{x}.json"), encoding="utf-8") as f:
            return f.read()

    def test_shard_files_are_owner_only(self):
        for x in range(1, 6):
            mode = os.stat(os.path.join(self.tmp, "shards", f"node_0{x}.json")).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_empty_and_truncated_shard_files_fail_over(self):
        """M2: an empty and a truncated shard file are TAMPER_REJECTED, not a crash."""
        self._write_raw(1, "")
        self._write_raw(2, self._read_raw(2)[:40])
        status = self.enclave.get_public_vault_status()
        self.assertTrue(status["quorum_healthy"])
        res = self.enclave.execute_privileged_intent(_intent())
        self.assertTrue(res["success"], res.get("error"))
        self.assertEqual(res["receipt"]["quorum_nodes"], ["vault-node-03", "vault-node-04", "vault-node-05"])
        self.assertEqual(res["receipt"]["rejected_tampered_nodes"], ["vault-node-01", "vault-node-02"])

    def test_json_list_and_non_numeric_canary_fail_over(self):
        """M2: a JSON list and a non-numeric canary_y are TAMPER_REJECTED, not a crash."""
        self._write_raw(1, "[1, 2, 3]")
        shard2 = json.loads(self._read_raw(2))
        shard2["canary_y"] = "not-a-number"
        self._write_raw(2, json.dumps(shard2))
        res = self.enclave.execute_privileged_intent(_intent())
        self.assertTrue(res["success"], res.get("error"))
        self.assertEqual(res["receipt"]["quorum_nodes"], ["vault-node-03", "vault-node-04", "vault-node-05"])
        nodes = {n["node_id"]: n for n in self.enclave.get_public_vault_status()["nodes"]}
        self.assertEqual(nodes["vault-node-01"]["status"], "TAMPER_REJECTED")
        self.assertEqual(nodes["vault-node-02"]["status"], "TAMPER_REJECTED")

    def test_three_broken_shards_block_the_enclave(self):
        """Below k=3 valid shards the enclave refuses to seal."""
        self._write_raw(1, "")
        self.enclave.tamper_shard_for_demo(2)
        self.enclave.tamper_shard_for_demo(3)
        res = self.enclave.execute_privileged_intent(_intent())
        self.assertFalse(res["success"])
        self.assertIn("Threshold Quorum Failed", res["error"])
        self.assertEqual(self.enclave.ledger.count_entries(), 0)

    # ---------------- ledger hash chain (S5) ----------------
    def _seal_rows(self, n: int = 3) -> str:
        for i in range(n):
            res = self.enclave.execute_privileged_intent(_intent(target=f"[ID_ROW{i:05d}]"))
            self.assertTrue(res["success"], res.get("error"))
        self.assertTrue(self.enclave.verify_ledger_entries()["verified"])
        return os.path.join(self.tmp, "vault_ledger.db")

    def test_ledger_row_deletion_is_detected(self):
        db = self._seal_rows()
        with sqlite3.connect(db) as conn:
            conn.execute("DELETE FROM sealed_transactions WHERE id = 2")
            conn.commit()
        ver = self.enclave.verify_ledger_entries()
        self.assertFalse(ver["verified"])
        self.assertTrue(any(e["id"] == 3 for e in ver["chain_errors"]))

    def test_ledger_row_duplication_is_detected(self):
        db = self._seal_rows()
        with sqlite3.connect(db) as conn:
            conn.execute(
                "INSERT INTO sealed_transactions "
                "(id, created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex, prev_hash) "
                "SELECT 4, created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex, prev_hash "
                "FROM sealed_transactions WHERE id = 3"
            )
            conn.commit()
        ver = self.enclave.verify_ledger_entries()
        self.assertFalse(ver["verified"])
        bad = {e["id"] for e in ver["chain_errors"]}
        self.assertIn(4, bad)

    def test_ledger_row_swap_is_detected(self):
        db = self._seal_rows()
        cols = "created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex, prev_hash"
        with sqlite3.connect(db) as conn:
            r1 = conn.execute(f"SELECT {cols} FROM sealed_transactions WHERE id = 1").fetchone()
            r2 = conn.execute(f"SELECT {cols} FROM sealed_transactions WHERE id = 2").fetchone()
            setter = ", ".join(f"{c.strip()} = ?" for c in cols.split(","))
            conn.execute(f"UPDATE sealed_transactions SET {setter} WHERE id = 1", (*r2,))
            conn.execute(f"UPDATE sealed_transactions SET {setter} WHERE id = 2", (*r1,))
            conn.commit()
        ver = self.enclave.verify_ledger_entries()
        self.assertFalse(ver["verified"])
        reasons = [r for e in ver["entries"] for r in [e.get("verification_reason")] if r and r != "OK"]
        self.assertTrue(reasons, "failed rows must carry a verification_reason")


class TestLLMProviderErrors(unittest.TestCase):
    def _post_returning(self, response=None, exc=None):
        async def fake_post(self_client, url, *args, **kwargs):
            if exc is not None:
                raise exc
            return response

        return mock.patch.object(httpx.AsyncClient, "post", new=fake_post)

    def test_gemini_without_candidates_raises_provider_error(self):
        resp = httpx.Response(200, json={"candidates": []})
        with self._post_returning(response=resp):
            with self.assertRaises(LLMProviderError) as cm:
                asyncio.run(LLMClient()._call_gemini("blinded prompt", DUMMY_KEY))
        self.assertNotIn(DUMMY_KEY, str(cm.exception))
        self.assertIsNotNone(cm.exception.wire_request)

    def test_gemini_timeout_raises_provider_error(self):
        with self._post_returning(exc=httpx.ReadTimeout("timed out")):
            with self.assertRaises(LLMProviderError):
                asyncio.run(LLMClient()._call_gemini("blinded prompt", DUMMY_KEY))

    def test_process_route_returns_502_on_provider_failure(self):
        from main import app

        client = TestClient(app)
        resp = httpx.Response(200, json={"candidates": []})
        with self._post_returning(response=resp):
            r = client.post(
                "/api/process",
                json={"prompt": "Summarise invoice for Nova Labs", "provider": "gemini", "api_key": DUMMY_KEY},
            )
        self.assertEqual(r.status_code, 502)
        body = r.json()
        self.assertEqual(body["error"], "LLM_PROVIDER_ERROR")
        self.assertNotIn(DUMMY_KEY, json.dumps(body))
        with self._post_returning(exc=httpx.ReadTimeout("timed out")):
            r2 = client.post(
                "/api/process",
                json={"prompt": "Summarise invoice for Nova Labs", "provider": "gemini", "api_key": DUMMY_KEY},
            )
        self.assertEqual(r2.status_code, 502)

    def test_action_intent_as_string_does_not_raise(self):
        text = 'Plan.\n```json\n{"fhe_compute": null, "action_intent": "TRANSFER_EXECUTE"}\n```'
        parsed = LLMClient()._parse_structured_output(text, provider_label="test", is_live=True)
        self.assertIsNone(parsed["action_intent"])
        self.assertIn("action_intent", parsed["parse_warning"])


class TestPipelineRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.pipe = AgentPipeline(storage_dir=cls._tmp.name, paillier_bits=1024, reset_vault=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run(self, prompt: str):
        return asyncio.run(self.pipe.process_prompt(prompt, provider="simulation"))

    def test_leak_flags_are_computed(self):
        leaky = self._run("Pay employee Renée Müller today; renée müller confirmed the amount by phone.")
        self.assertTrue(leaky["cloud_wire_payload"]["contains_raw_pii"])
        self.assertGreater(leaky["cloud_wire_payload"]["leak_check"]["residual_matches"], 0)

        clean = self._run(
            "Evaluate a 15% annual bonus for employee Marcus Vance (salary: $130,000) and commit to database."
        )
        self.assertFalse(clean["cloud_wire_payload"]["contains_raw_pii"])
        self.assertFalse(clean["cloud_wire_payload"]["contains_raw_secrets"])
        self.assertEqual(clean["cloud_wire_payload"]["leak_check"]["residual_matches"], 0)

    def test_previously_leaking_prompts_are_blinded(self):
        cases = [
            ("Het wachtwoord is Welkom2026!", ["Welkom2026"]),
            ("The password for the database is Hunter2!Geheim", ["Hunter2", "Geheim"]),
            ("Pay employee Renée Müller and José García today", ["Renée", "Müller", "José", "García"]),
            ("pay nl91abna0417164300 now", ["nl91abna0417164300"]),
            ("passport NX4K2P881", ["NX4K2P881"]),
        ]
        tok: BlindTokenizer = self.pipe.tokenizer
        for prompt, pieces in cases:
            with self.subTest(prompt=prompt):
                blinded, ctx = tok.blind_prompt(prompt)
                for piece in pieces:
                    self.assertNotIn(piece.lower(), blinded.lower())
                self.assertEqual(tok.residual_scan(blinded, ctx)["residual_matches"], 0)

    def test_action_intent_string_from_llm_is_ignored_with_warning(self):
        fake = {
            "provider": "fake",
            "is_live_cloud": False,
            "raw_response": "ok",
            "fhe_compute": None,
            "action_intent": "TRANSFER_EXECUTE",
            "wire_request": None,
        }

        async def fake_reasoning(*args, **kwargs):
            return dict(fake)

        with mock.patch.object(self.pipe.llm, "generate_blind_reasoning", new=fake_reasoning):
            res = self._run("Authorize transfer for Nova Labs")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIsNone(res["enclave_receipt"])
        self.assertTrue(any("action_intent" in w for w in res["llm_output_warnings"]))
        # The enclave itself also refuses a non-object intent.
        self.assertFalse(self.pipe.enclave.execute_privileged_intent("TRANSFER_EXECUTE")["success"])

    def test_offline_engine_keeps_decimal_percent(self):
        res = self._run("Evaluate a 12.5% annual bonus for employee Marcus Vance (salary: $130,000) and commit.")
        outs = res["fhe_computation"]["decrypted_outputs"]
        self.assertEqual(outs["[FHE_COMPUTED_BONUS]"], "$16,250.00")
        self.assertEqual(outs["[FHE_COMPUTED_TOTAL]"], "$146,250.00")


if __name__ == "__main__":
    unittest.main(verbosity=2)
