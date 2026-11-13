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

    def test_ordinary_business_prose_avoids_false_positives(self):
        """M-R1: ordinary business/technical prose must not seal clauses as SECRET or misclassify units/standards."""
        tok: BlindTokenizer = self.pipe.tokenizer

        prose_cases = [
            "De sleutel tot succes is goede samenwerking met onze klanten.",
            "Het geheim van ons kwartaalresultaat is focus op kwaliteit, en niet op korting.",
            "The pin on the map is red, while the badge on the door is green.",
            "The password policy was updated last Tuesday; please check the handbook.",
            "Remember that a password is never requested by support staff.",
            "Our platform completed ISO27001 and SOC2TYPE2 audits in Q4FY2026.",
        ]
        for sentence in prose_cases:
            with self.subTest(sentence=sentence):
                blinded, ctx = tok.blind_prompt(sentence)
                self.assertEqual(blinded, sentence)
                self.assertEqual(len(ctx.sealed_secrets), 0)

        # Storage/power/era suffixes must not be mistaken for Dutch postcodes
        tech_blinded, tech_ctx = tok.blind_prompt(
            "Upgrade protocol to OAUTH2 and RFC3526 using PYTHON3 with 2048 MB of RAM and 1024 GB disk."
        )
        self.assertNotIn("[LOC_", tech_blinded)
        self.assertNotIn("[GOV_ID_", tech_blinded)
        self.assertEqual(len(tech_ctx.sealed_secrets), 0)

        # Real Dutch postcodes and real PINs/sleutel= still get blinded/sealed
        nl_blinded, nl_ctx = tok.blind_prompt("Ship to 2511 AB; pin for the card is 4829, sleutel: TopGeheim99.")
        self.assertNotIn("2511 AB", nl_blinded)
        self.assertNotIn("4829", nl_blinded)
        self.assertNotIn("TopGeheim99", nl_blinded)
        self.assertEqual(len(nl_ctx.sealed_secrets), 2)

        # Role-prefixed subject wins over Title-Case business nouns
        _, subj_ctx = tok.blind_prompt("Review Annual Bonus and Balance Sheet for employee Marcus Vance today.")
        self.assertEqual(subj_ctx.token_to_plaintext[subj_ctx.primary_subject_token], "Marcus Vance")
        self.assertNotIn("Annual Bonus", subj_ctx.plaintext_to_token)
        self.assertNotIn("Balance Sheet", subj_ctx.plaintext_to_token)

    def test_credential_like_values_are_sealed_despite_prose_guards(self):
        """B-R4: the prose guards must never let a credential-like value through (fail closed)."""
        tok: BlindTokenizer = self.pipe.tokenizer
        cases = [
            ("Password reset: TempPass123!", ["TempPass123"]),
            ("Password field: hunter2x", ["hunter2x"]),
            ("wachtwoord veld = Geheim!23", ["Geheim"]),
            ("The password is never-gonna-give-you-up", ["never-gonna", "give-you-up"]),
            ("password is not-my-real-one!", ["not-my-real-one"]),
            ("Het wachtwoord is niet-te-raden-99", ["niet-te-raden"]),
            ("password hash is $2b$12$KIXQ4f8zR9vW", ["KIXQ4f8zR9vW", "$2b$"]),
            ("Create the account; a password is Zomer2026x", ["Zomer2026x"]),
            ("Er is een wachtwoord is Zomer2026x ingesteld", ["Zomer2026x"]),
            ("De sleutel van de kluis is Kluis#4815", ["Kluis#", "4815"]),
            ("Het geheim is Tulp-Molen-88", ["Tulp-Molen"]),
            ("The pin is AB12CD", ["AB12CD"]),
        ]
        for prompt, forbidden in cases:
            with self.subTest(prompt=prompt):
                blinded, ctx = tok.blind_prompt(prompt)
                for piece in forbidden:
                    self.assertNotIn(piece, blinded)
                self.assertGreaterEqual(len(ctx.sealed_secrets), 1)

    def test_identifiers_and_surnames_are_not_exempted_as_business_terms(self):
        """M-R4: only explicit standard codes are exempt; IDs and surnames after a role word are blinded."""
        tok: BlindTokenizer = self.pipe.tokenizer
        cases = [
            ("policy number POLICY12 for the claim", ["POLICY12"]),
            ("login SMITH42 and badge KLANT07", ["SMITH42", "KLANT07"]),
            ("customer Q12345 and member H21987", ["Q12345", "H21987"]),
            ("reference NISTX99812 and PCI4471902", ["NISTX99812", "PCI4471902"]),
            ("ABCD12 arrived", ["ABCD12"]),
            ("patient Cash and dr. Pool met employee Key", ["Cash", "Pool", "Key"]),
            ("Send the file to Mr. Root", ["Root"]),
            ("Stuur naar 3011 AD Rotterdam", ["3011 AD"]),
        ]
        for prompt, forbidden in cases:
            with self.subTest(prompt=prompt):
                blinded, _ = tok.blind_prompt(prompt)
                for piece in forbidden:
                    self.assertNotIn(piece, blinded)

        # The explicit standard codes and business phrases stay untouched.
        for sentence in [
            "Our platform completed ISO27001 and SOC2TYPE2 audits in Q4FY2026.",
            "Review Fiscal Year and Fiscal Quarter results.",
            "We need 2048 MB of RAM for the build.",
        ]:
            with self.subTest(sentence=sentence):
                blinded, ctx = tok.blind_prompt(sentence)
                self.assertNotIn("[GOV_ID_", blinded)
                self.assertNotIn("[ID_", blinded)
                self.assertNotIn("[LOC_", blinded)
                self.assertEqual(len(ctx.sealed_secrets), 0)

    def test_trailing_exclamation_mark_is_sealed_with_the_password(self):
        """S-6c: "Welkom2026!" must not leave the "!" outside the token."""
        tok: BlindTokenizer = self.pipe.tokenizer
        for prompt in [
            "Het wachtwoord is Welkom2026!",
            "Password reset: TempPass123!",
            "password is not-my-real-one!",
            "login with password Hunter2Geheim! now",
        ]:
            with self.subTest(prompt=prompt):
                blinded, ctx = tok.blind_prompt(prompt)
                self.assertNotIn("]!", blinded)
                self.assertTrue(any(tok.secret_vault.unseal(b).endswith("!") for b in ctx.sealed_secrets.values()))

    def test_redacted_echo_never_decrypts_the_secret(self):
        """S-6b: redacting an echoed [SECRET_…] token must not call unseal()."""
        tok: BlindTokenizer = self.pipe.tokenizer
        blinded, ctx = tok.blind_prompt("password is Tr0ub4dor&3")
        token = next(iter(ctx.sealed_secrets))
        with mock.patch.object(tok.secret_vault, "unseal", side_effect=AssertionError("unseal called")):
            out = tok.unblind_response(f"echo {token}", ctx)
        self.assertEqual(out, f"echo [REDACTED:{token}]")

    def test_large_prompt_with_many_secrets_stays_fast(self):
        """S-6d: the residual scan is linear in the number of distinct secret values."""
        import time as _time

        tok: BlindTokenizer = self.pipe.tokenizer
        prompt = ("password: 'x' " * 4700)[:65536]
        started = _time.perf_counter()
        tok.blind_prompt(prompt)
        self.assertLess(_time.perf_counter() - started, 1.5)


class TestConcurrencyAndMigrationRegressions(unittest.TestCase):
    def test_concurrent_enclave_seals_succeed_with_valid_hash_chain(self):
        """S-R3: concurrent threads sealing intents retry cleanly on LedgerChainConflict."""
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            enclave = SecureEnclave(storage_dir=tmp, threshold=3, total_shares=5)
            barrier = threading.Barrier(4)
            results = []

            def worker(idx: int):
                barrier.wait()
                results.append(
                    enclave.execute_privileged_intent({"action": "DB_WRITE_RECORD", "target": f"[ID_{idx:08X}]"})
                )

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(results), 4)
            self.assertTrue(all(r.get("success") for r in results), results)
            ver = enclave.verify_ledger_entries()
            self.assertTrue(ver["verified"], ver)
            self.assertEqual(ver["chain_length"], 4)

    def test_legacy_ledger_double_migration_never_collides(self):
        """S-R3: migrating a pre-chain table twice within the same millisecond uses distinct ns names."""
        import sqlite3
        from database.ledger import EncryptedLedger

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "legacy.db")
            for round_idx in range(2):
                conn = sqlite3.connect(db_path)
                conn.execute("DROP TABLE IF EXISTS sealed_transactions")
                conn.execute(
                    "CREATE TABLE sealed_transactions (id INTEGER PRIMARY KEY, action TEXT, target_token TEXT)"
                )
                conn.execute(
                    "INSERT INTO sealed_transactions (action, target_token) VALUES (?, ?)",
                    (f"OLD_{round_idx}", "SUBJ"),
                )
                conn.commit()
                conn.close()
                EncryptedLedger(db_path)

            conn = sqlite3.connect(db_path)
            legacy_tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'sealed_transactions_legacy_%'"
                ).fetchall()
            ]
            conn.close()
            self.assertEqual(len(legacy_tables), 2)


class TestAuditRound5Regressions(unittest.TestCase):
    """Regression tests for Audit Round 5 (13 Nov 2026)."""

    def test_decimal_dos_and_underflow_guards(self):
        import time
        from backend.crypto.homomorphic import HomomorphicEvaluator, PaillierKeypair
        from main import app

        t0 = time.perf_counter()
        for bad_scalar in ["1e2000000", "-1e2000000", "1e1000000", "1e-2000000", "1.5", "9" * 2000]:
            with self.subTest(bad_scalar=bad_scalar[:24]):
                with self.assertRaises(ValueError):
                    HomomorphicEvaluator.parse_scalar(bad_scalar)

        for bad_pct in ["1e2000000", "1e1000000", "1e-2000000", "-0.01", "1000.01", "0.00001"]:
            with self.subTest(bad_pct=bad_pct):
                with self.assertRaises(ValueError):
                    HomomorphicEvaluator.parse_percent(bad_pct)

        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.2, f"Decimal bounds validation took too long: {elapsed:.3f}s")

        # Valid scientific-notation integers & percents still work accurately
        self.assertEqual(HomomorphicEvaluator.parse_scalar("1e3"), 1000)
        self.assertEqual(HomomorphicEvaluator.parse_scalar("-100.00"), -100)
        pct_dec, pct_int, factor = HomomorphicEvaluator.parse_percent("12.5000")
        self.assertEqual((str(pct_dec), pct_int, factor), ("12.5", 125, 10))

        kp = PaillierKeypair.generate(bits=512)
        for huge_val in ["1e1000000", "1e2000", "-1e2000"]:
            with self.assertRaises(ValueError):
                kp.encrypt_fixed(huge_val)

        client = TestClient(app)
        res = client.post("/api/homomorphic-calc", json={"val1": 1e308, "val2": 1.0})
        self.assertEqual(res.status_code, 400)

    def test_echoed_secret_token_is_redacted_in_unblinded_response(self):
        from apis.llm_client import SYSTEM_PROMPT

        self.assertIn("NEVER echo [SECRET_XXXX]", SYSTEM_PROMPT)

        with tempfile.TemporaryDirectory() as tmp:
            pipe = AgentPipeline(storage_dir=tmp, paillier_bits=1024, reset_vault=True)
            prompt = (
                "Authorize payment for client Nova Labs where password is correct-horse-battery-staple, "
                "seed: <secret>root-seed-9988</secret>."
            )
            blinded, ctx = pipe.tokenizer.blind_prompt(prompt)
            sec_tokens = list(ctx.sealed_secrets.keys())
            self.assertEqual(len(sec_tokens), 2)

            # Default unblind_response keeps echoed [SECRET_...] redacted; opt-in unseals
            echo_text = f"Processed {ctx.primary_subject_token} using {sec_tokens[0]} and {sec_tokens[1]}."
            redacted_out = pipe.tokenizer.unblind_response(echo_text, ctx)
            self.assertNotIn("correct-horse-battery-staple", redacted_out)
            self.assertNotIn("root-seed-9988", redacted_out)
            self.assertIn(f"[REDACTED:{sec_tokens[0]}]", redacted_out)
            self.assertIn("Nova Labs", redacted_out)

            explicit_out = pipe.tokenizer.unblind_response(echo_text, ctx, include_secrets=True)
            self.assertIn("correct-horse-battery-staple", explicit_out)

            # Full pipeline run with mocked live LLM echoing every [SECRET_...] token
            async def malicious_live_echo(blinded_prompt: str, *args, **kwargs):
                found_sec = [tok for tok in blinded_prompt.split() if tok.startswith("[SECRET_")]
                joined = " ".join(found_sec)
                return {
                    "provider": "Mocked Live Cloud Echo",
                    "is_live_cloud": True,
                    "raw_response": f"Echoing credentials back: {joined} for {blinded_prompt}",
                    "fhe_compute": None,
                    "action_intent": None,
                    "wire_request": {"method": "POST", "url": "https://example.test", "headers_redacted": {}, "body": {}},
                }

            with mock.patch.object(pipe.llm, "generate_blind_reasoning", new=malicious_live_echo):
                res = asyncio.run(pipe.process_prompt(prompt, provider="gemini", api_key=DUMMY_KEY))

            serialized = json.dumps(res)
            self.assertNotIn("correct-horse-battery-staple", res["unblinded_result"])
            self.assertNotIn("root-seed-9988", res["unblinded_result"])
            self.assertNotIn("correct-horse-battery-staple", serialized)
            self.assertNotIn("root-seed-9988", serialized)

    def test_ledger_aad_colon_shift_and_hex_truncation_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            enclave = SecureEnclave(storage_dir=tmp, reset_on_init=True)
            res = enclave.execute_privileged_intent(
                {"action": "DB_WRITE_RECORD", "target": "URGENT:[ID_AABBCCDD]", "params": {}}
            )
            self.assertTrue(res["success"], res)
            self.assertTrue(enclave.verify_ledger_entries()["verified"])

            db_path = os.path.join(tmp, "vault_ledger.db")
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "UPDATE sealed_transactions SET action = ?, target_token = ? WHERE id = 1",
                    ("DB_WRITE_RECORD:URGENT", "[ID_AABBCCDD]"),
                )
                conn.commit()

            ver = enclave.verify_ledger_entries()
            self.assertFalse(ver["verified"], "Colon-shifted action/target must fail canonical JSON AAD + policy check")

        # Hex length & format validation in enclave_unseal_record (prevents ctypes zero-padding of truncated "00")
        sss = ShamirSecretSharing()
        bundle = sss.generate_and_split_master_key(threshold_k=3, total_n=5)
        quorum = bundle["shards"][:3]
        sealed = sss.enclave_seal_record(quorum, bundle["key_commitment_hex"], b"record", b'[1,"0","A","B"]')

        for bad_iv, bad_ct, bad_mac in [
            (sealed["iv_hex"][:-2], sealed["ciphertext_hex"], sealed["hmac_hex"]),
            (sealed["iv_hex"], sealed["ciphertext_hex"], sealed["hmac_hex"][:-2]),
            (sealed["iv_hex"], sealed["ciphertext_hex"][:-2], sealed["hmac_hex"]),
            (" " + sealed["iv_hex"][:-1], sealed["ciphertext_hex"], sealed["hmac_hex"]),
            (sealed["iv_hex"], "", sealed["hmac_hex"]),
        ]:
            with self.assertRaises(ValueError):
                sss.enclave_unseal_record(quorum, bad_iv, bad_ct, bad_mac, b'[1,"0","A","B"]')

    def test_tokenizer_unicode_nfd_secret_tag_variants_quotes_and_delimiters(self):
        tok = BlindTokenizer(paillier_bits=512)

        # 1. Unicode NFD decomposed names + residual_scan NFD awareness
        nfd_prompt = "Pay employee Rene\u0301e Mu\u0308ller today"
        blinded_nfd, ctx_nfd = tok.blind_prompt(nfd_prompt)
        self.assertIn("[ID_", blinded_nfd)
        self.assertNotIn("Ren", blinded_nfd)
        self.assertNotIn("ller", blinded_nfd)
        self.assertEqual(tok.residual_scan(blinded_nfd, ctx_nfd)["residual_matches"], 0)
        # If an NFD-decomposed copy leaked into wire text, residual_scan must catch it
        self.assertGreater(
            tok.residual_scan(blinded_nfd + " rene\u0301e mu\u0308ller", ctx_nfd)["residual_matches"], 0
        )

        # 2. <secret> tag whitespace, nesting, and stray closing tag
        tag_cases = [
            ("Token < secret >ws-secret-99</ secret > done", ["ws-secret-99", "<", ">"]),
            ("Token <secret >trail-space-88</secret > done", ["trail-space-88", "<", ">"]),
            ("Nested <secret>outer <secret>inner-77</secret> tail-66</secret> end", ["outer", "inner-77", "tail-66", "<", ">"]),
            ("Malformed secret>stray-leak-55</secret> end", ["stray-leak-55", "<", ">"]),
        ]
        for p, forbidden in tag_cases:
            with self.subTest(prompt=p):
                b, c = tok.blind_prompt(p)
                for piece in forbidden:
                    self.assertNotIn(piece, b.lower())
                self.assertGreaterEqual(len(c.sealed_secrets), 1)

        # 3. Escaped quotes, mid-word apostrophes in single quotes, unclosed quotes, and mid-token ',' / ';'
        esc_prompt = 'Login where password is "say \\"hi\\" topsecret42" now'
        sgl_prompt = "Login where password is 'p@ss'word99'! Please don't share."
        sgl_plain_excl = "Login where password is 'hunter'! Please don't share."
        unclosed_dbl = 'Login where password: "unclosed_secret_123'
        unclosed_sgl = "Login where password: 'unclosed_secret_456"
        comma_prompt = "Login where password is p@ss,word123 for staging"
        semi_prompt = "Config secret = My;Pass123; pin = 4821"

        for p, forbidden in [
            (esc_prompt, ["topsecret42", "hi"]),
            (sgl_prompt, ["p@ss", "word99"]),
            (sgl_plain_excl, ["hunter"]),
            (unclosed_dbl, ["unclosed_secret_123"]),
            (unclosed_sgl, ["unclosed_secret_456"]),
            (comma_prompt, ["p@ss", "word123"]),
            (semi_prompt, ["My", "Pass123", "4821"]),
        ]:
            with self.subTest(prompt=p):
                b, c = tok.blind_prompt(p)
                for piece in forbidden:
                    self.assertNotIn(piece, b)
                self.assertGreaterEqual(len(c.sealed_secrets), 1)

        # Contraction after single-quoted secret must remain intact, and exclamation in prose must not false-positive
        b_sgl, _ = tok.blind_prompt(sgl_plain_excl)
        self.assertIn("! Please don't share.", b_sgl)
        prose_excl = "Remember that a password is required! Please check the handbook."
        b_prose, c_prose = tok.blind_prompt(prose_excl)
        self.assertEqual(b_prose, prose_excl)
        self.assertEqual(len(c_prose.sealed_secrets), 0)

    def test_tokenizer_linear_time_no_redos_and_prompt_length_bound(self):
        import time
        from main import app

        tok = BlindTokenizer(paillier_bits=512)
        long_word = "a" * 20_000
        t0 = time.perf_counter()
        tok.blind_prompt(f"password is {long_word} ")
        tok.blind_prompt(f"De sleutel is {long_word} ")
        tok.blind_prompt(f"password {long_word} ")
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.35, f"Tokenizer exhibited superlinear backtracking: {elapsed:.3f}s")

        with self.assertRaises(ValueError):
            tok.blind_prompt("x" * 70_000)

        client = TestClient(app)
        res = client.post("/api/process", json={"prompt": "x" * 70_000, "provider": "simulation"})
        self.assertEqual(res.status_code, 400)

    def test_stale_native_lib_mtime_triggers_rebuild(self):
        import backend.crypto.zeroize as zeroize_mod

        fake_lib = mock.MagicMock()
        with (
            mock.patch.object(zeroize_mod.os.path, "exists", return_value=True),
            mock.patch.object(
                zeroize_mod.os.path,
                "getmtime",
                side_effect=lambda p: 200.0 if p.endswith("vaultcrypto.c") else 100.0,
            ),
            mock.patch.object(zeroize_mod, "build_native_library", return_value="/tmp/rebuilt.dylib") as mock_build,
            mock.patch.object(zeroize_mod.ctypes, "CDLL", return_value=fake_lib) as mock_cdll,
        ):
            zeroize_mod.load_native_lib()
            mock_build.assert_called_once()
            mock_cdll.assert_called_once_with("/tmp/rebuilt.dylib")

    def test_loopback_csrf_middleware_blocks_cross_origin_posts(self):
        from main import app

        client = TestClient(app)
        for bad_headers in [
            {"Origin": "https://evil.example"},
            {"Origin": "http://evil.example:8000"},
            {"Origin": "null"},
            {"Origin": "http://[::1"},
            {"Origin": "http://localhost:3000"},
            {"Origin": "http://127.0.0.1:8000"},
            {"Sec-Fetch-Site": "cross-site"},
        ]:
            with self.subTest(headers=bad_headers):
                r = client.post("/api/restore-nodes", headers=bad_headers)
                self.assertEqual(r.status_code, 403)

        ok = client.post(
            "/api/restore-nodes",
            headers={"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(ok.status_code, 200)

    def test_native_c_reconstruct_rejects_k_above_255(self):
        lib = ShamirSecretSharing().lib
        dummy_x = (ctypes.c_uint8 * 256)(*([1] * 256))
        dummy_shares = (ctypes.c_uint8 * (256 * 32))()
        dummy_feld = (ctypes.c_uint8 * 32)()
        dummy_iv = (ctypes.c_uint8 * 16)()
        dummy_ct = (ctypes.c_uint8 * 16)()
        dummy_mac = (ctypes.c_uint8 * 32)()
        dummy_pt = (ctypes.c_uint8 * 32)()
        pt_len = ctypes.c_size_t(0)
        rc = lib.vault_enclave_unseal(
            dummy_x, dummy_shares, 256, dummy_feld, None, 0, dummy_iv, dummy_ct, 16, dummy_mac, dummy_pt, 32, ctypes.byref(pt_len)
        )
        self.assertEqual(rc, -1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
