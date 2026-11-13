"""
Enclave Service: Local Loopback Secure Enclave (v2).
Manages isolated 0600 disk shards, 2048-bit RFC 3526 Feldman VSS verification,
and C-stack AES-256-CBC + HMAC-SHA256 sealing into the encrypted SQLite ledger.
"""

import hashlib
import itertools
import json
import os
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.crypto.shamir import ShamirSecretSharing
from database.ledger import EncryptedLedger, LedgerChainConflict


ALLOWED_ACTIONS = {
    "GRANT_COMPLIANCE_BONUS",
    "UPDATE_EHR_LEDGER",
    "TRANSFER_EXECUTE",
    "DB_WRITE_RECORD",
    "QUERY_SECURE_LEDGER",
}


class SecureEnclave:
    def __init__(
        self,
        storage_dir: Optional[str] = None,
        threshold: int = 3,
        total_shares: int = 5,
        reset_on_init: bool = False,
    ):
        base_dir = storage_dir or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "database", "runtime")
        )
        self.shards_dir = os.path.join(base_dir, "shards")
        self.backup_dir = os.path.join(base_dir, ".demo_clean_shards")
        self.manifest_path = os.path.join(base_dir, "manifest.json")
        self.ledger = EncryptedLedger(os.path.join(base_dir, "vault_ledger.db"))

        self.sss = ShamirSecretSharing()
        self.threshold = threshold
        self.total_shares = total_shares

        os.makedirs(self.shards_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

        if reset_on_init or not os.path.exists(self.manifest_path):
            self._provision_fresh_vault()

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        self.threshold = int(manifest["threshold_k"])
        self.total_shares = int(manifest["total_n"])
        self.key_commitment_hex: str = manifest["key_commitment_hex"]
        self.feldman_commitments_hex: List[str] = manifest["feldman_commitments_hex"]
        self.share_digests: Dict[int, str] = {
            int(k): v for k, v in manifest["share_digests"].items()
        }

    def _shard_file(self, x: int) -> str:
        return os.path.join(self.shards_dir, f"node_0{x}.json")

    def _backup_file(self, x: int) -> str:
        return os.path.join(self.backup_dir, f"node_0{x}.json.bak")

    @staticmethod
    def _write_private_json(path: str, obj: Any) -> None:
        """Write JSON to `path` with owner-only (0600) permissions from the first byte."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
        os.chmod(path, 0o600)

    def _provision_fresh_vault(self) -> None:
        bundle = self.sss.generate_and_split_master_key(
            threshold_k=self.threshold,
            total_n=self.total_shares,
        )

        for shard in bundle["shards"]:
            x = int(shard["x"])
            s_path = self._shard_file(x)
            b_path = self._backup_file(x)
            self._write_private_json(s_path, shard)
            self._write_private_json(b_path, shard)

        public_manifest = {
            "threshold_k": bundle["threshold_k"],
            "total_n": bundle["total_n"],
            "key_commitment_hex": bundle["key_commitment_hex"],
            "feldman_commitments_hex": bundle["feldman_commitments_hex"],
            "share_digests": {str(k): v for k, v in bundle["share_digests"].items()},
            "canary_expected_secret": bundle["canary_expected_secret"],
        }
        self._write_private_json(self.manifest_path, public_manifest)

        bundle["shards"].clear()

    def _inspect_shards_on_disk(
        self,
    ) -> Tuple[
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
    ]:
        valid_shards: List[Dict[str, Any]] = []
        rejected_nodes: List[Dict[str, Any]] = []
        node_summaries: List[Dict[str, Any]] = []
        observed_canary_points: List[Dict[str, Any]] = []

        for x in range(1, self.total_shares + 1):
            path = self._shard_file(x)
            node_id = f"vault-node-0{x}"
            if not os.path.exists(path):
                rejected_nodes.append({"node_id": node_id, "x": x, "reason": "Missing shard file"})
                node_summaries.append(
                    {
                        "node_id": node_id,
                        "index": x,
                        "status": "TAMPER_REJECTED",
                        "vss_valid": False,
                        "reason": "Missing shard file on disk",
                        "fingerprint": "MISSING",
                        "canary_y": 0,
                    }
                )
                continue

            # M2: every read and field access of an on-disk shard sits inside one try.
            # Any malformed file (empty, truncated, JSON list, non-numeric fields) is
            # treated exactly like a cryptographic tamper: TAMPER_REJECTED + failover.
            shard: Any = None
            fp = "UNREADABLE"
            c_y = 0
            try:
                with open(path, "r", encoding="utf-8") as f:
                    shard = json.load(f)
                if not isinstance(shard, dict):
                    raise TypeError(f"shard file holds a JSON {type(shard).__name__}, expected an object")
                ok, reason = self.sss.verify_shard_integrity(
                    shard,
                    self.feldman_commitments_hex,
                    self.share_digests.get(x),
                    self.key_commitment_hex,
                )
                gf_hex = shard.get("gf256_share_hex", "")
                if not isinstance(gf_hex, str):
                    raise TypeError("gf256_share_hex is not a string")
                fp = hashlib.sha256(gf_hex.encode("utf-8")).hexdigest()[:8]
                c_y = int(shard.get("canary_y", 0))
                if ok and int(shard.get("x", -1)) != x:
                    ok, reason = False, f"Shard index mismatch (file node_0{x} claims x={shard.get('x')})"
            except Exception as exc:  # noqa: BLE001 - any parse failure == tamper
                ok = False
                reason = f"Unreadable or malformed shard file ({type(exc).__name__}: {exc})"[:240]
                shard = None
                c_y = 0
            observed_canary_points.append({"x": x, "y": c_y, "valid": ok, "node_id": node_id})

            if ok:
                valid_shards.append(shard)
                node_summaries.append(
                    {
                        "node_id": node_id,
                        "index": x,
                        "status": "SECURE_VERIFIED",
                        "vss_valid": True,
                        "reason": "2048-bit Feldman VSS Verified",
                        "fingerprint": fp,
                        "canary_y": c_y,
                    }
                )
            else:
                rejected_nodes.append({"node_id": node_id, "x": x, "reason": reason})
                node_summaries.append(
                    {
                        "node_id": node_id,
                        "index": x,
                        "status": "TAMPER_REJECTED",
                        "vss_valid": False,
                        "reason": reason,
                        "fingerprint": fp,
                        "canary_y": c_y,
                    }
                )

        return valid_shards, rejected_nodes, node_summaries, observed_canary_points

    def get_public_vault_status(self, active_quorum: Optional[List[str]] = None) -> Dict[str, Any]:
        active_set = set(active_quorum or [])
        valid_shards, rejected_nodes, node_summaries, observed_points = self._inspect_shards_on_disk()

        for n in node_summaries:
            if n["vss_valid"] and n["node_id"] in active_set:
                n["status"] = "QUORUM_ACTIVE"

        curve_points: List[Dict[str, int]] = []
        if len(valid_shards) >= self.threshold:
            canary_quorum = [
                (int(s["x"]), int(s["canary_y"])) for s in valid_shards[: self.threshold]
            ]
            curve_points = self.sss.interpolate_gf256_curve(
                canary_quorum, list(range(0, self.total_shares + 1))
            )

        valid_shards.clear()

        return {
            "threshold_k": self.threshold,
            "total_nodes_n": self.total_shares,
            "key_commitment_prefix": self.key_commitment_hex[:16],
            "feldman_group": "RFC 3526 Group 14 (2048-bit MODP Safe Prime)",
            "quorum_healthy": (self.total_shares - len(rejected_nodes)) >= self.threshold,
            "nodes": node_summaries,
            "rejected_nodes": rejected_nodes,
            "polynomial_curve": {
                "field": "GF(2^8) [x^8 + x^4 + x^3 + x + 1]",
                "interpolated_points": curve_points,
                "observed_shard_points": observed_points,
            },
            "audit_log_count": self.ledger.count_entries(),
        }

    def tamper_shard_for_demo(self, node_index: int) -> Dict[str, Any]:
        if not (1 <= node_index <= self.total_shares):
            raise ValueError(f"Node index must be between 1 and {self.total_shares}.")

        path = self._shard_file(node_index)
        try:
            with open(path, "r", encoding="utf-8") as f:
                shard = json.load(f)
            corrupted_feldman = int(shard["feldman_y_hex"], 16) ^ 0xDEADBEEF1337
            raw_gf = bytearray(bytes.fromhex(shard["gf256_share_hex"]))
            raw_gf[0] ^= 0xFF
            shard["feldman_y_hex"] = hex(corrupted_feldman)
            shard["gf256_share_hex"] = bytes(raw_gf).hex()
            shard["canary_y"] = (int(shard["canary_y"]) ^ 0x55) & 0xFF
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"Shard node_0{node_index} is missing or already unreadable ({type(exc).__name__}); "
                "use restore-nodes first."
            ) from None

        self._write_private_json(path, shard)
        return self.get_public_vault_status()

    def restore_all_shards(self) -> Dict[str, Any]:
        for x in range(1, self.total_shares + 1):
            b_path = self._backup_file(x)
            s_path = self._shard_file(x)
            if os.path.exists(b_path):
                with open(b_path, "rb") as src:
                    raw = src.read()
                fd = os.open(s_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as dst:
                    dst.write(raw)
                os.chmod(s_path, 0o600)
        return self.get_public_vault_status()

    # ------------------------------------------------------------------
    # S4: quorum failover over all k-subsets of the Feldman-valid shards
    # ------------------------------------------------------------------
    def _quorum_candidates(self, valid_shards: List[Dict[str, Any]]):
        """All k-subsets of the valid shards, first k first (C(5,3) = 10 at most)."""
        return itertools.combinations(valid_shards, self.threshold)

    def _seal_with_quorum_failover(
        self,
        valid_shards: List[Dict[str, Any]],
        plaintext_bytes: bytes,
        aad_bytes: bytes,
    ) -> Tuple[Dict[str, str], List[Dict[str, Any]], List[List[str]]]:
        """
        Seal with the first k valid shards. If the C enclave rejects the reconstructed
        key on the key-commitment check (ValueError, rc -10) and more than k valid
        shards exist, retry every other k-combination before giving up.
        Returns (sealed, quorum_used, rejected_combinations).
        """
        rejected_combos: List[List[str]] = []
        last_exc: Optional[Exception] = None
        for combo in self._quorum_candidates(valid_shards):
            quorum = list(combo)
            try:
                sealed = self.sss.enclave_seal_record(
                    quorum_shards=quorum,
                    key_commitment_hex=self.key_commitment_hex,
                    plaintext_bytes=plaintext_bytes,
                    aad_bytes=aad_bytes,
                )
                return sealed, quorum, rejected_combos
            except ValueError as exc:
                last_exc = exc
                rejected_combos.append([str(s.get("node_id", f"x={s.get('x')}")) for s in quorum])
                quorum.clear()
                continue
        raise ValueError(
            f"Key-commitment check failed for all {len(rejected_combos)} k={self.threshold} "
            f"combinations of the {len(valid_shards)} Feldman-valid shards ({last_exc})."
        )

    def _select_verified_quorum(
        self, valid_shards: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[List[str]]]:
        """
        Unseal has no key-commitment check of its own, so a wrong quorum would look like
        a tampered row. Pick a quorum by sealing a throw-away probe (which does check the
        commitment in C) and reuse that quorum for unsealing.
        """
        _, quorum, rejected = self._seal_with_quorum_failover(
            valid_shards, b"vaultmind-quorum-probe", b"quorum-probe"
        )
        return quorum, rejected

    @staticmethod
    def _ledger_aad(seq: int, prev_hash: str, action: str, target: str) -> bytes:
        return json.dumps(
            [int(seq), prev_hash, action, target],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def execute_privileged_intent(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(intent, dict):
            return {
                "success": False,
                "error": (
                    "Enclave Policy Violation: action_intent must be a JSON object, "
                    f"got {type(intent).__name__}."
                ),
            }
        params = intent.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return {
                "success": False,
                "error": (
                    "Enclave Policy Violation: action_intent.params must be a JSON object, "
                    f"got {type(params).__name__}."
                ),
            }
        action_name = str(intent.get("action", "UNKNOWN")).upper()
        target = str(intent.get("target", "[SYSTEM]"))

        if action_name not in ALLOWED_ACTIONS:
            return {
                "success": False,
                "error": f"Enclave Policy Violation: Action '{action_name}' is not in whitelist.",
            }

        valid_shards, rejected_nodes, _, _ = self._inspect_shards_on_disk()
        if len(valid_shards) < self.threshold:
            n_valid = len(valid_shards)
            valid_shards.clear()
            return {
                "success": False,
                "error": (
                    f"Threshold Quorum Failed: Only {n_valid} valid shards available "
                    f"(need k={self.threshold}). Rejected nodes: {[r['node_id'] for r in rejected_nodes]}"
                ),
                "rejected_nodes": rejected_nodes,
            }

        quorum: List[Dict[str, Any]] = []
        max_chain_attempts = 5
        try:
            for attempt in range(max_chain_attempts):
                quorum.clear()
                seq, prev_hash = self.ledger.next_chain_position()
                aad_bytes = self._ledger_aad(seq, prev_hash, action_name, target)
                record_payload = json.dumps(
                    {
                        "seq": seq,
                        "action": action_name,
                        "target": target,
                        "params": params,
                        "sealed_at": time.time(),
                    },
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")

                sealed, quorum, rejected_combos = self._seal_with_quorum_failover(
                    valid_shards, record_payload, aad_bytes
                )
                quorum_ids = [s["node_id"] for s in quorum]
                try:
                    row_id = self.ledger.append_sealed_entry(
                        action=action_name,
                        target_token=target,
                        quorum_nodes=quorum_ids,
                        iv_hex=sealed["iv_hex"],
                        ciphertext_hex=sealed["ciphertext_hex"],
                        hmac_hex=sealed["hmac_hex"],
                        seq=seq,
                        prev_hash=prev_hash,
                    )
                    break
                except LedgerChainConflict:
                    if attempt == max_chain_attempts - 1:
                        raise
                    # Short randomised backoff so concurrent writers stop colliding on the same head.
                    time.sleep(random.uniform(0.002, 0.02) * (attempt + 1))
                    continue

            receipt = {
                "status": "SEALED_IN_SQLITE",
                "ledger_row_id": row_id,
                "ledger_prev_hash": prev_hash,
                "action": action_name,
                "target": target,
                "hmac_sha256_tag": sealed["hmac_hex"][:24] + "...",
                "aes256_ciphertext_preview": sealed["ciphertext_hex"][:24] + "...",
                "quorum_nodes": quorum_ids,
                "rejected_tampered_nodes": [r["node_id"] for r in rejected_nodes],
                "rejected_quorum_combinations": rejected_combos,
                "c_enclave_zeroize": (
                    "Key buffers wiped in C via memset_s after use "
                    "(volatile-loop fallback where memset_s is unavailable); not runtime-verified."
                ),
                "timestamp": time.time(),
            }
            return {"success": True, "receipt": receipt}
        except LedgerChainConflict as exc:
            return {"success": False, "error": f"Ledger Concurrency Conflict: {exc}"}
        except Exception as exc:
            return {"success": False, "error": f"Native C Enclave Error: {exc}"}
        finally:
            valid_shards.clear()
            quorum.clear()

    def verify_ledger_entries(self, limit: int = 15) -> Dict[str, Any]:
        """
        S5: verify the FULL hash chain from row 1 (not only the displayed rows).
        Each row is checked for (a) contiguous sequence id, (b) prev_hash == SHA-256 of
        the previous row, (c) HMAC over AAD = "seq:prev_hash:action:target".
        Returns the newest `limit` rows for display, plus chain-wide findings.
        """
        all_rows = self.ledger.list_all_entries_ascending()
        display_ids = {r["id"] for r in all_rows[-limit:]} if limit and limit > 0 else set()
        valid_shards, rejected_nodes, _, _ = self._inspect_shards_on_disk()
        if len(valid_shards) < self.threshold:
            valid_shards.clear()
            return {
                "verified": False,
                "error": f"Cannot verify ledger: fewer than k={self.threshold} valid shards.",
                "entries": self.ledger.list_entries(limit=limit),
            }

        quorum: List[Dict[str, Any]] = []
        verified_rows: List[Dict[str, Any]] = []
        chain_errors: List[Dict[str, Any]] = []
        all_ok = True

        try:
            try:
                quorum, rejected_combos = self._select_verified_quorum(valid_shards)
            except Exception as exc:
                return {
                    "verified": False,
                    "error": f"Cannot verify ledger: no valid quorum ({exc}).",
                    "entries": self.ledger.list_entries(limit=limit),
                }

            expected_prev = self.ledger.GENESIS_HASH
            expected_seq = 1
            for row in all_rows:
                reasons: List[str] = []
                if row["id"] != expected_seq:
                    if row["id"] > expected_seq:
                        reasons.append(
                            f"Sequence gap: expected row {expected_seq}, found {row['id']} "
                            f"({row['id'] - expected_seq} row(s) deleted)"
                        )
                    else:
                        reasons.append(f"Sequence out of order: expected row {expected_seq}, found {row['id']}")
                if row["prev_hash"] != expected_prev:
                    reasons.append("Hash-chain break: prev_hash does not match SHA-256 of the previous row")
                if row["action"] not in ALLOWED_ACTIONS:
                    reasons.append(f"Policy violation: action '{row['action']}' is not in ALLOWED_ACTIONS")
                chain_ok = not reasons

                aad_bytes = self._ledger_aad(row["id"], row["prev_hash"], row["action"], row["target_token"])
                try:
                    self.sss.enclave_unseal_record(
                        quorum_shards=quorum,
                        iv_hex=row["iv_hex"],
                        ciphertext_hex=row["ciphertext_hex"],
                        hmac_hex=row["hmac_hex"],
                        aad_bytes=aad_bytes,
                    )
                    hmac_ok = True
                except Exception:
                    hmac_ok = False
                    reasons.append(
                        "HMAC-SHA256 failed over AAD (seq, prev_hash, action, target): "
                        "row altered, duplicated or moved"
                    )

                row_ok = chain_ok and hmac_ok
                if not row_ok:
                    all_ok = False
                    chain_errors.append({"id": row["id"], "reasons": reasons})

                if row["id"] in display_ids:
                    verified_rows.append(
                        {
                            **row,
                            "hmac_verified": row_ok,
                            "hmac_tag_valid": hmac_ok,
                            "chain_link_valid": chain_ok,
                            "verification_reason": "; ".join(reasons) if reasons else "OK",
                        }
                    )

                expected_prev = self.ledger.row_hash(row)
                expected_seq = row["id"] + 1

            verified_rows.reverse()  # newest first, like list_entries()
            return {
                "verified": all_ok,
                "quorum_used": [s["node_id"] for s in quorum],
                "rejected_nodes": [r["node_id"] for r in rejected_nodes],
                "rejected_quorum_combinations": rejected_combos,
                "entries": verified_rows,
                "chain_length": len(all_rows),
                "chain_head_hash": expected_prev,
                "chain_errors": chain_errors,
                "chain_note": (
                    "Full chain verified from row 1. Truncation of the newest rows is only "
                    "detectable against an externally recorded chain_head_hash."
                ),
            }
        finally:
            valid_shards.clear()
            quorum.clear()
