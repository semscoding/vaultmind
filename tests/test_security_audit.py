"""
Comprehensive Security, Cryptographic & Red-Team Verification Suite for VaultMind v2.
Tests all 6 architectural layers: frontend, backend, database, apis, services, and monitoring,
including N=2048 128-bit Lattice RLWE-BFV FHE, Dual-Field Feldman VSS, and Zero-Retention Secret Sealing.
"""

import json
import os
import random
import sqlite3
import tempfile
import unittest
from fastapi.testclient import TestClient

from apis.llm_client import LLMClient, load_dotenv_if_present
from backend.crypto.bfv_fhe import BFVContext, SessionSecretVault
from backend.crypto.homomorphic import PaillierKeypair
from backend.crypto.shamir import ShamirSecretSharing
from backend.crypto.zeroize import NativeBufferGuard, secure_zero
from main import app
from services.pipeline_service import AgentPipeline


class VaultMindSecurityAuditTests(unittest.TestCase):
    def test_01_native_c_gf256_field_axioms(self):
        sss = ShamirSecretSharing()
        for a in range(1, 256):
            inv_a = sss.gf256_inv(a)
            self.assertEqual(sss.gf256_mul(a, inv_a), 1, f"Failed inverse for {a}")

        for a, b, c in [(0x57, 0x83, 0x13), (0xFF, 0xAA, 0x55), (0x01, 0x9E, 0x4C)]:
            lhs = sss.gf256_mul(a, b ^ c)
            rhs = sss.gf256_mul(a, b) ^ sss.gf256_mul(a, c)
            self.assertEqual(lhs, rhs)

    def test_02_real_c_memset_s_zeroize_and_no_secrets_in_python_state(self):
        buf = bytearray(b"TOP_SECRET_MASTER_MATERIAL_32BYT")
        secure_zero(buf)
        self.assertEqual(buf, bytearray(32))

        with NativeBufferGuard(16) as cbuf:
            for i in range(16):
                cbuf[i] = 0xAB
            ptr_ref = cbuf
        self.assertEqual(bytes(ptr_ref), b"\x00" * 16)

        with self.assertRaises(TypeError):
            secure_zero("immutable_python_string")
        with self.assertRaises(TypeError):
            secure_zero(b"immutable_python_bytes")

        with tempfile.TemporaryDirectory() as tmp:
            pipe = AgentPipeline(storage_dir=tmp, paillier_bits=1024, reset_vault=True)
            state_keys = set(pipe.enclave.__dict__.keys())
            self.assertNotIn("vault_nodes", state_keys)
            self.assertNotIn("master_secret", state_keys)
            for x in range(1, 6):
                with open(os.path.join(tmp, "shards", f"node_0{x}.json")) as f:
                    shard_text = f.read()
                self.assertNotIn(shard_text, str(pipe.enclave.__dict__))

    def test_03_feldman_2048_vss_tamper_failover_and_quorum_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipe = AgentPipeline(storage_dir=tmp, paillier_bits=1024, reset_vault=True)

            pipe.enclave.tamper_shard_for_demo(1)
            pipe.enclave.tamper_shard_for_demo(2)

            res_ok = pipe.enclave.execute_privileged_intent(
                {"action": "TRANSFER_EXECUTE", "target": "[ID_TEST1234]", "params": {}}
            )
            self.assertTrue(res_ok["success"])
            self.assertEqual(
                res_ok["receipt"]["quorum_nodes"],
                ["vault-node-03", "vault-node-04", "vault-node-05"],
            )
            self.assertEqual(
                res_ok["receipt"]["rejected_tampered_nodes"],
                ["vault-node-01", "vault-node-02"],
            )

            pipe.enclave.tamper_shard_for_demo(3)
            res_blocked = pipe.enclave.execute_privileged_intent(
                {"action": "TRANSFER_EXECUTE", "target": "[ID_TEST1234]", "params": {}}
            )
            self.assertFalse(res_blocked["success"])
            self.assertIn("Threshold Quorum Failed", res_blocked["error"])

            restored = pipe.enclave.restore_all_shards()
            self.assertTrue(restored["quorum_healthy"])

    def test_04_paillier_1024_phe_fixed_point_math(self):
        kp = PaillierKeypair.generate(bits=1024)
        self.assertGreaterEqual(kp.n.bit_length(), 1024)

        c_dec, scale_dec = kp.encrypt_fixed(4.9)
        self.assertAlmostEqual(kp.decrypt_fixed(c_dec, scale_dec), 4.9, places=5)

    def test_05_all_scenarios_zero_leaks_and_encrypted_sqlite_hmac_tamper(self):
        import asyncio

        async def _run():
            with tempfile.TemporaryDirectory() as tmp:
                pipe = AgentPipeline(storage_dir=tmp, paillier_bits=1024, reset_vault=True)

                r_sal = await pipe.process_prompt(
                    "Evaluate a 15% annual bonus for employee Marcus Vance (salary: $130,000, rating: 4.9) and commit to database.",
                    provider="simulation",
                )
                self.assertEqual(r_sal["status"], "SUCCESS")
                self.assertNotIn("Marcus Vance", r_sal["blinded_prompt"])
                self.assertNotIn("130,000", r_sal["blinded_prompt"])
                self.assertNotIn("4.9", r_sal["blinded_prompt"])
                self.assertIn("$19,500.00", r_sal["unblinded_result"])
                self.assertIn("$149,500.00", r_sal["unblinded_result"])

                r_hlth = await pipe.process_prompt(
                    "Process confidential patient record for Sophia Laurent (BSN: 94820194, hemoglobin: 14.2, clinic: Amsterdam Central) and update secure EHR ledger.",
                    provider="simulation",
                )
                self.assertEqual(r_hlth["status"], "SUCCESS")
                self.assertIn("record for [ID_", r_hlth["blinded_prompt"])
                for secret_piece in ["Sophia Laurent", "94820194", "14.2", "Amsterdam Central"]:
                    self.assertNotIn(secret_piece, r_hlth["blinded_prompt"])
                self.assertEqual(r_hlth["enclave_receipt"]["action"], "UPDATE_EHR_LEDGER")

                r_fin = await pipe.process_prompt(
                    "Authorize executive transfer of €50,000 to vendor Acronis Corp (IBAN: NL91ABNA041289) and sign with root credentials.",
                    provider="simulation",
                )
                self.assertEqual(r_fin["status"], "SUCCESS")
                for secret_piece in ["NL91ABNA041289", "Acronis Corp", "50,000"]:
                    self.assertNotIn(secret_piece, r_fin["blinded_prompt"])
                self.assertIsNotNone(r_fin["enclave_receipt"])
                self.assertEqual(r_fin["enclave_receipt"]["action"], "TRANSFER_EXECUTE")

                ver_ok = pipe.enclave.verify_ledger_entries()
                self.assertTrue(ver_ok["verified"])
                self.assertEqual(len(ver_ok["entries"]), 3)

                db_path = os.path.join(tmp, "vault_ledger.db")
                with sqlite3.connect(db_path) as conn:
                    row = conn.execute("SELECT id, ciphertext_hex FROM sealed_transactions LIMIT 1").fetchone()
                    flipped = ("00" if not row[1].startswith("00") else "ff") + row[1][2:]
                    conn.execute("UPDATE sealed_transactions SET ciphertext_hex = ? WHERE id = ?", (flipped, row[0]))
                    conn.commit()

                ver_bad = pipe.enclave.verify_ledger_entries()
                self.assertFalse(ver_bad["verified"])

        asyncio.run(_run())

    def test_06_api_monitoring_and_real_polynomial_curve(self):
        client = TestClient(app)
        client.post("/api/restore-nodes")

        if not os.getenv("GEMINI_API_KEY"):
            res_err = client.post(
                "/api/process",
                json={"prompt": "Analyze Marcus Vance salary $100,000", "provider": "gemini"},
            )
            self.assertEqual(res_err.status_code, 400)

        res_st = client.get("/api/vault-status")
        self.assertEqual(res_st.status_code, 200)
        pts = res_st.json()["polynomial_curve"]["interpolated_points"]
        self.assertEqual(pts[0], {"x": 0, "y": 42})

        res_xss = client.post(
            "/api/process",
            json={
                "prompt": "Evaluate 20% bonus for employee Elena Rostova (<img src=x onerror=alert(1)>, key: sk_live_9988776655, salary: $150,000) and commit.",
                "provider": "simulation",
            },
        )
        self.assertEqual(res_xss.status_code, 200)
        body = res_xss.json()
        self.assertNotIn("sk_live_9988776655", body["blinded_prompt"])
        self.assertNotIn("sk_live_9988776655", json.dumps(body))
        self.assertIn("$30,000.00", body["unblinded_result"])

        res_health = client.get("/api/monitoring/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.json()["status"], "HEALTHY")

        res_metrics = client.get("/api/monitoring/metrics")
        self.assertEqual(res_metrics.status_code, 200)
        self.assertGreaterEqual(res_metrics.json()["counters"]["total_requests"], 1)

    def test_07_native_c_128bit_pq_rlwe_bfv_n2048_multiplication(self):
        import asyncio

        bfv = BFVContext()
        self.assertEqual(bfv.parameters_dict["ring_degree_n"], 2048)
        self.assertEqual(bfv.parameters_dict["ciphertext_modulus_bits"], 54)

        rng = random.Random(2026)
        for _ in range(25):
            a = rng.randint(0, 65535)
            b = rng.randint(0, 65535)
            ct_a = bfv.encrypt_int(a)
            ct_b = bfv.encrypt_int(b)
            ct_prod = bfv.evaluator.multiply(ct_a, ct_b)
            ct_sum = bfv.evaluator.add(ct_a, ct_b)
            self.assertEqual(bfv.decrypt_int(ct_prod), (a * b) % 65536)
            self.assertEqual(bfv.decrypt_int(ct_sum), (a + b) % 65536)
        bfv.close()

        async def _run_pipeline_bfv():
            with tempfile.TemporaryDirectory() as tmp:
                pipe = AgentPipeline(storage_dir=tmp, paillier_bits=1024, reset_vault=True)
                res = await pipe.process_prompt(
                    "Compute invoice product for client Nova Labs (hours: 160, rate: $225, password is correct-horse-battery-staple, seed: <secret>master-seed-alpha-99</secret>) and commit to database.",
                    provider="simulation",
                )
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["fhe_computation"]["op"], "BFV_MULTIPLY")
                self.assertEqual(
                    res["fhe_computation"]["decrypted_outputs"]["[FHE_COMPUTED_PRODUCT]"],
                    "$36,000",
                )
                self.assertIn("$36,000", res["unblinded_result"])
                serialized = json.dumps(res)
                for secret_piece in ["correct-horse-battery-staple", "master-seed-alpha-99", "<secret>"]:
                    self.assertNotIn(secret_piece, res["blinded_prompt"])
                    self.assertNotIn(secret_piece, serialized)

        asyncio.run(_run_pipeline_bfv())

    def test_08_free_text_passwords_secret_tags_jwts_hex_keys_and_c_session_seal(self):
        sv = SessionSecretVault()
        sealed = sv.seal("ultra-confidential-root-passphrase")
        self.assertEqual(sv.unseal(sealed), "ultra-confidential-root-passphrase")

        bad_blob = dict(sealed)
        bad_blob["ct_hex"] = ("00" if not sealed["ct_hex"].startswith("00") else "ff") + sealed["ct_hex"][2:]
        with self.assertRaises(RuntimeError):
            sv.unseal(bad_blob)
        sv.close()

        with tempfile.TemporaryDirectory() as tmp:
            pipe = AgentPipeline(storage_dir=tmp, paillier_bits=1024, reset_vault=True)
            complex_secret_prompt = (
                "Verify credentials where password is my_custom_password_42!, "
                'passphrase: "winter-nebula-quantum", pin = 8492, '
                "secret key is abcdef1234567890, "
                "Bearer tok_live_abc987xyz654, "
                "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U, "
                "raw hex 0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08, "
                "empty <secret></secret> and <secret>arbitrary freeform secret phrase</secret>."
            )
            blinded, ctx = pipe.tokenizer.blind_prompt(complex_secret_prompt)

            must_not_appear = [
                "my_custom_password_42!",
                "winter-nebula-quantum",
                "8492",
                "abcdef1234567890",
                "tok_live_abc987xyz654",
                "eyJhbGciOiJIUzI1NiJ9",
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "arbitrary freeform secret phrase",
                "<secret>",
            ]
            for s in must_not_appear:
                self.assertNotIn(s, blinded, f"Secret '{s}' leaked into blinded wire prompt!")
                self.assertNotIn(s, ctx.token_to_plaintext.values())
                self.assertNotIn(s, ctx.token_to_plaintext.keys())
                self.assertNotIn(s, ctx.plaintext_to_token.keys())
                self.assertNotIn(s, ctx.plaintext_to_token.values())
                self.assertNotIn(s, ctx.redacted_prompt)

            self.assertEqual(len(ctx.sealed_secrets), 9)

    def test_09_dotenv_llm_config_and_bfv_api_endpoints(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tf:
            tf.write("AWS_BEARER_TOKEN_BEDROCK=ABSK_test_dummy_key_do_not_leak\n")
            tmp_env_path = tf.name

        old_val = os.environ.pop("AWS_BEARER_TOKEN_BEDROCK", None)
        try:
            load_dotenv_if_present(tmp_env_path)
            cfg = LLMClient.get_env_config()
            self.assertTrue(cfg["bedrock_configured"])
            self.assertNotIn("ABSK_test_dummy_key_do_not_leak", str(cfg))
        finally:
            os.environ.pop("AWS_BEARER_TOKEN_BEDROCK", None)
            if old_val is not None:
                os.environ["AWS_BEARER_TOKEN_BEDROCK"] = old_val
            os.unlink(tmp_env_path)

        client = TestClient(app)
        res_cfg = client.get("/api/llm-config")
        self.assertEqual(res_cfg.status_code, 200)
        self.assertIn("recommended_default", res_cfg.json())

        res_bfv = client.post("/api/bfv-fhe-calc", json={"m1": 160, "m2": 225})
        self.assertEqual(res_bfv.status_code, 200)
        bfv_data = res_bfv.json()
        self.assertEqual(bfv_data["decrypted_product_exact"], 36000)
        self.assertEqual(bfv_data["decrypted_sum_mod_t"], 385)

    def test_10_redteam_audit_v2_regressions(self):
        """
        Verifies all 6 Red-Team Audit v2 fixes:
        1) Overflow-free multi-limb BFV (300 * 300 = 90,000 > 65,536 without wraparound!)
        2) Dutch/European/apostrophe/hyphenated names (Jan van Dijk, Maria de Vries, O'Connor, Jean-Luc Picard)
        3) Live LLM handle-suffix normalization ([FHE_NUM_1](ENC:0x...))
        4) Dual-field cryptographic binding (tampering Feldman Z_q OR GF(2^8) aborts C key commitment!)
        5) HTTP 400 on oversized Paillier input (> n/2)
        """
        import asyncio

        # 1 & 2 & 3: Overflow-free 300 * 300 = 90,000 + Dutch names + Live LLM handle normalization
        async def _check_dutch_and_overflow():
            with tempfile.TemporaryDirectory() as tmp:
                pipe = AgentPipeline(storage_dir=tmp, paillier_bits=1024, reset_vault=True)
                blinded, ctx = pipe.tokenizer.blind_prompt(
                    "Multiply invoice units 300 and price $300 for Jan van Dijk, Maria de Vries, Jean-Luc Picard, and patient O'Connor."
                )
                for name in ["Jan van Dijk", "Maria de Vries", "Jean-Luc Picard", "O'Connor"]:
                    self.assertNotIn(name, blinded, f"Name '{name}' was not blinded!")

                # Simulate live Gemini/OpenAI copying inline (ENC:0x...) handle suffix
                fhe_res = pipe.tokenizer.execute_and_decrypt_fhe(
                    {
                        "op": "BFV_MULTIPLY",
                        "ref_a": "[FHE_NUM_1](ENC:0xdeadbeef...12345678)",
                        "ref_b": "[FHE_NUM_2](ENC:0xfeedface...87654321)",
                    },
                    ctx,
                )
                self.assertEqual(fhe_res["decrypted_outputs"]["[FHE_COMPUTED_PRODUCT]"], "$90,000")

        asyncio.run(_check_dutch_and_overflow())

        # 4: Dual-field cryptographic binding inside C enclave
        sss = ShamirSecretSharing()
        bundle = sss.generate_and_split_master_key(threshold_k=3, total_n=5)
        quorum = [dict(s) for s in bundle["shards"][:3]]

        # Corrupt ONLY Feldman Z_q scalar (leaving GF(2^8) untouched) -> C commitment MUST abort!
        bad_feldman_quorum = [dict(s) for s in quorum]
        bad_feldman_quorum[0]["feldman_y_hex"] = hex(int(bad_feldman_quorum[0]["feldman_y_hex"], 16) ^ 1)
        with self.assertRaises(ValueError):
            sss.enclave_seal_record(bad_feldman_quorum, bundle["key_commitment_hex"], b"test")

        # Corrupt ONLY GF(2^8) share (leaving Feldman Z_q untouched) -> C commitment MUST abort!
        bad_gf_quorum = [dict(s) for s in quorum]
        raw_gf = bytearray(bytes.fromhex(bad_gf_quorum[0]["gf256_share_hex"]))
        raw_gf[0] ^= 0x01
        bad_gf_quorum[0]["gf256_share_hex"] = bytes(raw_gf).hex()
        with self.assertRaises(ValueError):
            sss.enclave_seal_record(bad_gf_quorum, bundle["key_commitment_hex"], b"test")

        # 5: HTTP 400 on out-of-range Paillier number (> n/2) and multi-limb BFV API check
        client = TestClient(app)
        res_huge = client.post("/api/homomorphic-calc", json={"val1": 1e308, "val2": 1.0})
        self.assertEqual(res_huge.status_code, 400)

        res_bfv_big = client.post("/api/bfv-fhe-calc", json={"m1": 300, "m2": 300})
        self.assertEqual(res_bfv_big.status_code, 200)
        self.assertEqual(res_bfv_big.json()["decrypted_product_exact"], 90000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
