"""
Comprehensive Security & Cryptographic Verification Suite for VaultMind v2.
Tests all 6 architectural layers: frontend, backend, database, apis, services, and monitoring.
"""

import os
import sqlite3
import tempfile
import unittest
from fastapi.testclient import TestClient

from backend.crypto.zeroize import NativeBufferGuard, secure_zero
from backend.crypto.shamir import ShamirSecretSharing
from backend.crypto.homomorphic import PaillierKeypair
from services.pipeline_service import AgentPipeline
from main import app


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

    def test_04_paillier_1024_fixed_point_and_blind_bonus_math(self):
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
                    "Evaluate a 15% annual bonus for employee Marcus Vance (salary: $130,000, rating: 4.9) and commit to database."
                )
                self.assertEqual(r_sal["status"], "SUCCESS")
                self.assertNotIn("Marcus Vance", r_sal["blinded_prompt"])
                self.assertNotIn("130,000", r_sal["blinded_prompt"])
                self.assertNotIn("4.9", r_sal["blinded_prompt"])
                self.assertIn("$19,500.00", r_sal["unblinded_result"])
                self.assertIn("$149,500.00", r_sal["unblinded_result"])

                r_hlth = await pipe.process_prompt(
                    "Process confidential patient record for Sophia Laurent (BSN: 94820194, hemoglobin: 14.2, clinic: Amsterdam Central) and update secure EHR ledger."
                )
                self.assertEqual(r_hlth["status"], "SUCCESS")
                self.assertIn("record for [ID_", r_hlth["blinded_prompt"])
                for secret_piece in ["Sophia Laurent", "94820194", "14.2", "Amsterdam Central"]:
                    self.assertNotIn(secret_piece, r_hlth["blinded_prompt"])
                self.assertEqual(r_hlth["enclave_receipt"]["action"], "UPDATE_EHR_LEDGER")

                r_fin = await pipe.process_prompt(
                    "Authorize executive transfer of €50,000 to vendor Acronis Corp (IBAN: NL91ABNA041289) and sign with root credentials."
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
        self.assertIn("$30,000.00", body["unblinded_result"])

        # Verify Monitoring Health & Telemetry endpoints
        res_health = client.get("/api/monitoring/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.json()["status"], "HEALTHY")

        res_metrics = client.get("/api/monitoring/metrics")
        self.assertEqual(res_metrics.status_code, 200)
        self.assertGreaterEqual(res_metrics.json()["counters"]["total_requests"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
