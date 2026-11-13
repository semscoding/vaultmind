"""
GF(2^8) shares live in C-only `.gfshare` files (manifest format v2).

Checks that the share bytes never sit in shard JSON or the manifest, that Python never opens a
`.gfshare` file during seal / ledger verification / status / corrupt / restore, that broken share
files are TAMPER_REJECTED with failover, and that a legacy (v1) runtime is re-provisioned.
Test code itself reads `.gfshare` files only outside the guarded blocks, to cross-check digests.
"""

import builtins
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from backend.crypto.shamir import ShamirSecretSharing, ShareFileError
from database.ledger import EncryptedLedger
from services.enclave_service import SecureEnclave


def _intent(target: str = "[ID_TEST1234]"):
    return {"action": "DB_WRITE_RECORD", "target": target, "params": {}}


def _is_share_path(path) -> bool:
    if isinstance(path, int):
        return False
    try:
        p = os.fsdecode(path)
    except TypeError:
        return False
    return p.endswith(".gfshare") or p.endswith(".gfshare.bak")


class GuardPythonShareAccess:
    """Patch builtins.open / io.open / os.open so a Python open of a share file raises and is recorded."""

    def __init__(self):
        self.hits = []
        self._patches = []

    def _wrap(self, real):
        def guarded(path, *args, **kwargs):
            if _is_share_path(path):
                self.hits.append(os.fsdecode(path))
                raise AssertionError(f"Python opened a GF(2^8) share file: {path}")
            return real(path, *args, **kwargs)

        return guarded

    def __enter__(self):
        self._patches = [
            mock.patch.object(builtins, "open", self._wrap(builtins.open)),
            mock.patch.object(io, "open", self._wrap(io.open)),
            mock.patch.object(os, "open", self._wrap(os.open)),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


class TestCShareFiles(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.enclave = SecureEnclave(storage_dir=self.tmp, reset_on_init=True)

    def tearDown(self):
        self._tmp.cleanup()

    # helpers (test-side reads, never inside a GuardPythonShareAccess block)
    def _share(self, x: int) -> str:
        return os.path.join(self.tmp, "shards", f"node_0{x}.gfshare")

    def _json(self, x: int) -> dict:
        with open(os.path.join(self.tmp, "shards", f"node_0{x}.json"), encoding="utf-8") as f:
            return json.load(f)

    def _read_share(self, x: int) -> bytes:
        with open(self._share(x), "rb") as f:
            return f.read()

    def _write_share(self, x: int, data: bytes) -> None:
        with open(self._share(x), "wb") as f:
            f.write(data)

    def _nodes(self):
        return {n["node_id"]: n for n in self.enclave.get_public_vault_status()["nodes"]}

    def _assert_failover_without_node1(self, reason_fragment: str):
        node1 = self._nodes()["vault-node-01"]
        self.assertEqual(node1["status"], "TAMPER_REJECTED")
        self.assertIn(reason_fragment, node1["reason"])
        res = self.enclave.execute_privileged_intent(_intent())
        self.assertTrue(res["success"], res.get("error"))
        self.assertEqual(res["receipt"]["quorum_nodes"], ["vault-node-02", "vault-node-03", "vault-node-04"])
        self.assertEqual(res["receipt"]["rejected_tampered_nodes"], ["vault-node-01"])
        self.assertTrue(self.enclave.verify_ledger_entries()["verified"])

    # ---------------- format ----------------
    def test_provisioned_layout_holds_no_share_bytes_in_json(self):
        with open(os.path.join(self.tmp, "manifest.json"), encoding="utf-8") as f:
            manifest_text = f.read()
        manifest = json.loads(manifest_text)
        self.assertEqual(manifest["format_version"], 2)
        for x in range(1, 6):
            share = self._read_share(x)
            self.assertEqual(len(share), 32)
            for path in (self._share(x), os.path.join(self.tmp, ".demo_clean_shards", f"node_0{x}.gfshare.bak")):
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600, path)
            shard = self._json(x)
            self.assertNotIn("gf256_share_hex", shard)
            self.assertEqual(set(shard), {"node_id", "x", "gf_share_sha256", "canary_y", "feldman_y_hex"})
            self.assertEqual(shard["gf_share_sha256"], hashlib.sha256(share).hexdigest())
            with open(os.path.join(self.tmp, "shards", f"node_0{x}.json"), encoding="utf-8") as f:
                shard_text = f.read()
            with open(os.path.join(self.tmp, ".demo_clean_shards", f"node_0{x}.json.bak"), encoding="utf-8") as f:
                backup_text = f.read()
            for text in (shard_text, backup_text, manifest_text):
                self.assertNotIn(share.hex(), text.lower())
                self.assertNotIn("gf256_share_hex", text)
            self.assertEqual(
                manifest["share_digests"][str(x)],
                ShamirSecretSharing.shard_binding_digest(
                    x, shard["gf_share_sha256"], shard["canary_y"], shard["feldman_y_hex"], manifest["key_commitment_hex"]
                ),
            )
        # Public fingerprint comes from the digest, not the share.
        for x, node in enumerate(self.enclave.get_public_vault_status()["nodes"], start=1):
            self.assertEqual(node["fingerprint"], self._json(x)["gf_share_sha256"][:8])

    # ---------------- Python never opens a share file ----------------
    def test_python_never_opens_share_files(self):
        with GuardPythonShareAccess() as guard:
            # Negative control: the guard really fires for every Python open path.
            for opener in (lambda p: open(p, "rb"), lambda p: io.open(p, "rb"), lambda p: os.open(p, os.O_RDONLY)):
                with self.assertRaises(AssertionError):
                    opener(self._share(1))
            self.assertEqual(len(guard.hits), 3)
            guard.hits.clear()

            res = self.enclave.execute_privileged_intent(_intent())
            self.assertTrue(res["success"], res.get("error"))
            ver = self.enclave.verify_ledger_entries()
            self.assertTrue(ver["verified"], ver)
            status = self.enclave.get_public_vault_status()
            self.assertTrue(status["quorum_healthy"])
            self.enclave.tamper_shard_for_demo(4)
            restored = self.enclave.restore_all_shards()
            self.assertTrue(all(n["status"] == "SECURE_VERIFIED" for n in restored["nodes"]))
            res2 = self.enclave.execute_privileged_intent(_intent("[ID_SECOND]"))
            self.assertTrue(res2["success"], res2.get("error"))
            # Fresh provisioning, too.
            SecureEnclave(storage_dir=os.path.join(self.tmp, "second"), reset_on_init=True)
        self.assertEqual(guard.hits, [])

    # ---------------- broken share files ----------------
    def test_missing_share_file_fails_over(self):
        os.unlink(self._share(1))
        self._assert_failover_without_node1("missing")

    def test_short_share_file_fails_over(self):
        self._write_share(1, self._read_share(1)[:31])
        self._assert_failover_without_node1("exactly 32 bytes")

    def test_long_share_file_fails_over(self):
        self._write_share(1, self._read_share(1) + b"\x00")
        self._assert_failover_without_node1("exactly 32 bytes")

    def test_symlinked_share_file_is_refused_and_restore_repairs_it(self):
        good = self._read_share(1)
        decoy = os.path.join(self.tmp, "decoy.bin")
        with open(decoy, "wb") as f:
            f.write(good)  # identical bytes: only O_NOFOLLOW rejects it
        os.unlink(self._share(1))
        os.symlink(decoy, self._share(1))
        self._assert_failover_without_node1("symbolic link")
        self.enclave.restore_all_shards()
        self.assertFalse(os.path.islink(self._share(1)))
        self.assertEqual(self._nodes()["vault-node-01"]["status"], "SECURE_VERIFIED")

    def test_single_bit_flip_fails_over(self):
        raw = bytearray(self._read_share(1))
        raw[17] ^= 0x04
        self._write_share(1, bytes(raw))
        self._assert_failover_without_node1("SHA-256 does not match")

    def test_three_broken_share_files_block_the_enclave(self):
        os.unlink(self._share(1))
        self._write_share(2, self._read_share(2)[:31])
        raw = bytearray(self._read_share(3))
        raw[0] ^= 0x80
        self._write_share(3, bytes(raw))
        status = self.enclave.get_public_vault_status()
        self.assertFalse(status["quorum_healthy"])
        res = self.enclave.execute_privileged_intent(_intent())
        self.assertFalse(res["success"])
        self.assertIn("Threshold Quorum Failed", res["error"])
        self.assertEqual(self.enclave.ledger.count_entries(), 0)

    def test_share_changed_after_inspection_triggers_failover(self):
        """TOCTOU: C re-checks the digest at seal time; ShareFileError makes failover try the next combo."""
        valid, _, _, _ = self.enclave._inspect_shards_on_disk()
        self.assertEqual(len(valid), 5)
        raw = bytearray(self._read_share(1))
        raw[5] ^= 0x01
        self._write_share(1, bytes(raw))
        _, quorum, rejected = self.enclave._seal_with_quorum_failover(valid, b"payload", b"aad")
        self.assertNotIn("vault-node-01", [s["node_id"] for s in quorum])
        self.assertTrue(rejected and all("vault-node-01" in combo for combo in rejected))

    # ---------------- Corrupt / Restore ----------------
    def test_corrupt_and_restore_via_service(self):
        expected = self._json(2)["gf_share_sha256"]
        status = self.enclave.tamper_shard_for_demo(2)
        node2 = {n["node_id"]: n for n in status["nodes"]}["vault-node-02"]
        self.assertEqual(node2["status"], "TAMPER_REJECTED")
        self.assertNotEqual(hashlib.sha256(self._read_share(2)).hexdigest(), expected)
        self.assertEqual(len(self._read_share(2)), 32)

        restored = self.enclave.restore_all_shards()
        self.assertTrue(restored["quorum_healthy"])
        self.assertTrue(all(n["status"] == "SECURE_VERIFIED" for n in restored["nodes"]))
        self.assertEqual(hashlib.sha256(self._read_share(2)).hexdigest(), expected)
        self.assertEqual(os.stat(self._share(2)).st_mode & 0o777, 0o600)
        res = self.enclave.execute_privileged_intent(_intent())
        self.assertTrue(res["success"], res.get("error"))
        self.assertEqual(res["receipt"]["quorum_nodes"], ["vault-node-01", "vault-node-02", "vault-node-03"])

    def test_restore_brings_back_a_deleted_share_file(self):
        os.unlink(self._share(5))
        self.assertEqual(self._nodes()["vault-node-05"]["status"], "TAMPER_REJECTED")
        self.enclave.restore_all_shards()
        self.assertEqual(self._nodes()["vault-node-05"]["status"], "SECURE_VERIFIED")

    def test_atomic_share_writes_use_fresh_inode_and_preserve_existing_on_failure(self):
        orig_share1 = self._read_share(1)
        spy_link = os.path.join(self.tmp, "hardlink_spy.bin")
        os.link(self._share(1), spy_link)

        # Re-provisioning must stage to a fresh inode + rename, never truncating/overwriting spy_link.
        SecureEnclave(storage_dir=self.tmp, reset_on_init=True)
        new_shares = [self._read_share(x) for x in range(1, 6)]
        self.assertNotEqual(new_shares[0], orig_share1)
        with open(spy_link, "rb") as f:
            self.assertEqual(f.read(), orig_share1, "hard-linked old inode must not receive new share bytes")

        # If staging fails on share 4 (symlink target), existing shares 1..5 must remain untouched.
        decoy = os.path.join(self.tmp, "decoy_target.bin")
        with open(decoy, "wb") as f:
            f.write(b"A" * 32)
        bad_symlink = os.path.join(self.tmp, "planted_link.gfshare")
        os.symlink(decoy, bad_symlink)
        paths = [self._share(1), self._share(2), self._share(3), bad_symlink, self._share(5)]
        with self.assertRaises(ShareFileError) as ctx:
            self.enclave.sss.generate_and_split_master_key_to_files(paths, threshold_k=3)
        self.assertEqual(ctx.exception.bad_index, 3)
        for idx, x in enumerate([1, 2, 3, 5]):
            self.assertEqual(self._read_share(x), new_shares[x - 1], f"share {x} clobbered on failed provision")

    def test_planted_symlinks_refused_in_status_and_tamper_and_cleared_on_reset(self):
        decoy_json = os.path.join(self.tmp, "decoy_shard.json")
        with open(decoy_json, "w", encoding="utf-8") as f:
            json.dump(self._json(1), f)
        os.unlink(os.path.join(self.tmp, "shards", "node_01.json"))
        os.symlink(decoy_json, os.path.join(self.tmp, "shards", "node_01.json"))

        node1 = self._nodes()["vault-node-01"]
        self.assertEqual(node1["status"], "TAMPER_REJECTED")
        self.assertIn("symbolic link", node1["reason"])

        with open(decoy_json, "r", encoding="utf-8") as f:
            before_decoy = f.read()
        with self.assertRaises(ValueError):
            self.enclave.tamper_shard_for_demo(1)
        with open(decoy_json, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), before_decoy, "tamper_shard_for_demo must not follow symlinked JSON")

        # Plant symlinks on .gfshare and manifest.json too: reset_on_init=True must replace them cleanly.
        decoy_manifest = os.path.join(self.tmp, "decoy_manifest.json")
        with open(decoy_manifest, "w", encoding="utf-8") as f:
            f.write('{"decoy": true}')
        os.unlink(self._share(2))
        os.symlink(decoy_manifest, self._share(2))
        os.unlink(os.path.join(self.tmp, "manifest.json"))
        os.symlink(decoy_manifest, os.path.join(self.tmp, "manifest.json"))

        fresh = SecureEnclave(storage_dir=self.tmp, reset_on_init=True)
        self.assertTrue(fresh.get_public_vault_status()["quorum_healthy"])
        self.assertFalse(os.path.islink(self._share(2)))
        self.assertFalse(os.path.islink(os.path.join(self.tmp, "manifest.json")))
        with open(decoy_manifest, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), '{"decoy": true}')


class TestLegacyRuntimeMigration(unittest.TestCase):
    def test_legacy_runtime_is_reprovisioned_without_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            shards_dir = os.path.join(tmp, "shards")
            backup_dir = os.path.join(tmp, ".demo_clean_shards")
            os.makedirs(shards_dir)
            os.makedirs(backup_dir)

            # v1 layout: share bytes as gf256_share_hex in JSON, manifest without format_version.
            sss = ShamirSecretSharing()
            bundle = sss.generate_and_split_master_key(threshold_k=3, total_n=5)
            for shard in bundle["shards"]:
                for path in (
                    os.path.join(shards_dir, f"node_0{shard['x']}.json"),
                    os.path.join(backup_dir, f"node_0{shard['x']}.json.bak"),
                ):
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(shard, f)
            with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "threshold_k": 3,
                        "total_n": 5,
                        "key_commitment_hex": bundle["key_commitment_hex"],
                        "feldman_commitments_hex": bundle["feldman_commitments_hex"],
                        "share_digests": {str(k): v for k, v in bundle["share_digests"].items()},
                        "canary_expected_secret": bundle["canary_expected_secret"],
                    },
                    f,
                )
            # One genuine old-key row in the ledger.
            ledger = EncryptedLedger(os.path.join(tmp, "vault_ledger.db"))
            seq, prev = ledger.next_chain_position()
            aad = SecureEnclave._ledger_aad(seq, prev, "DB_WRITE_RECORD", "[ID_OLD]")
            sealed = sss.enclave_seal_record(bundle["shards"][:3], bundle["key_commitment_hex"], b"old", aad)
            ledger.append_sealed_entry(
                action="DB_WRITE_RECORD", target_token="[ID_OLD]",
                quorum_nodes=["vault-node-01", "vault-node-02", "vault-node-03"],
                iv_hex=sealed["iv_hex"], ciphertext_hex=sealed["ciphertext_hex"], hmac_hex=sealed["hmac_hex"],
                seq=seq, prev_hash=prev,
            )
            self.assertEqual(ledger.count_entries(), 1)

            with self.assertLogs("services.enclave_service", level="WARNING"):
                enclave = SecureEnclave(storage_dir=tmp)

            self.assertIn("Legacy runtime vault", enclave.vault_migration_note)
            self.assertIn("Legacy ledger moved", enclave.vault_migration_note)
            status = enclave.get_public_vault_status()
            self.assertEqual(status["vault_migration_note"], enclave.vault_migration_note)
            self.assertTrue(all(n["status"] == "SECURE_VERIFIED" for n in status["nodes"]))
            self.assertEqual(status["audit_log_count"], 0)

            with open(os.path.join(tmp, "manifest.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["format_version"], 2)
            for x in range(1, 6):
                for path in (
                    os.path.join(shards_dir, f"node_0{x}.json"),
                    os.path.join(backup_dir, f"node_0{x}.json.bak"),
                ):
                    with open(path, encoding="utf-8") as f:
                        self.assertNotIn("gf256_share_hex", f.read())
                self.assertEqual(os.path.getsize(os.path.join(shards_dir, f"node_0{x}.gfshare")), 32)

            with sqlite3.connect(os.path.join(tmp, "vault_ledger.db")) as conn:
                legacy_tables = [
                    r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'sealed_transactions_legacy_%'"
                    )
                ]
                self.assertEqual(len(legacy_tables), 1)
                self.assertEqual(conn.execute(f"SELECT COUNT(*) FROM {legacy_tables[0]}").fetchone()[0], 1)

            res = enclave.execute_privileged_intent(_intent())
            self.assertTrue(res["success"], res.get("error"))
            self.assertTrue(enclave.verify_ledger_entries()["verified"])

            # A second start sees format v2 and does not re-provision again.
            again = SecureEnclave(storage_dir=tmp)
            self.assertIsNone(again.vault_migration_note)
            self.assertEqual(again.key_commitment_hex, enclave.key_commitment_hex)

    def test_unparseable_manifest_is_not_silently_rekeyed(self):
        with tempfile.TemporaryDirectory() as tmp:
            SecureEnclave(storage_dir=tmp, reset_on_init=True)
            with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as f:
                f.write("{not json")
            with self.assertRaises(ValueError):
                SecureEnclave(storage_dir=tmp)

    def test_legacy_migration_preserves_custom_quorum_and_removes_extra_legacy_shards(self):
        with tempfile.TemporaryDirectory() as tmp:
            shards_dir = os.path.join(tmp, "shards")
            backup_dir = os.path.join(tmp, ".demo_clean_shards")
            os.makedirs(shards_dir)
            os.makedirs(backup_dir)

            sss = ShamirSecretSharing()
            bundle = sss.generate_and_split_master_key(threshold_k=2, total_n=4)
            for shard in bundle["shards"]:
                with open(os.path.join(shards_dir, f"node_0{shard['x']}.json"), "w", encoding="utf-8") as f:
                    json.dump(shard, f)
            # Stale extra v1 shard with raw hex share that must not linger after migration.
            with open(os.path.join(shards_dir, "node_05.json"), "w", encoding="utf-8") as f:
                json.dump({"x": 5, "gf256_share_hex": "aa" * 32}, f)
            with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "threshold_k": 2,
                        "total_n": 4,
                        "key_commitment_hex": bundle["key_commitment_hex"],
                        "feldman_commitments_hex": bundle["feldman_commitments_hex"],
                        "share_digests": {str(k): v for k, v in bundle["share_digests"].items()},
                        "canary_expected_secret": bundle["canary_expected_secret"],
                    },
                    f,
                )

            with self.assertLogs("services.enclave_service", level="WARNING"):
                enclave = SecureEnclave(storage_dir=tmp)
            self.assertEqual(enclave.threshold, 2)
            self.assertEqual(enclave.total_shares, 4)
            self.assertFalse(os.path.exists(os.path.join(shards_dir, "node_05.json")))
            res = enclave.execute_privileged_intent(_intent())
            self.assertTrue(res["success"], res.get("error"))
            self.assertEqual(len(res["receipt"]["quorum_nodes"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
