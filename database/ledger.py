"""
Database Layer: Encrypted, Hash-Chained SQLite Audit Ledger (vault_ledger.db).
Stores AES-256-CBC ciphertexts and Encrypt-then-MAC HMAC-SHA256 authentication tags
produced inside the native C enclave (`libvaultcrypto.dylib`).

Rows form a hash chain: `prev_hash` of row i is SHA-256 over row i-1
(id, action, target_token, iv_hex, ciphertext_hex, hmac_hex, prev_hash); row 1 links
to GENESIS_HASH. The enclave binds canonical JSON `[id, prev_hash, action, target_token]`
as HMAC AAD, so a deleted, duplicated, reordered, or delimiter-shifted row fails verification.
"""

import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_ROW_COLUMNS = "id, created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex, prev_hash"
LEDGER_SCHEMA_VERSION = 4


class LedgerChainConflict(RuntimeError):
    """The chain head moved between reserving a position and appending a row."""


class EncryptedLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.migration_note: Optional[str] = None
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as f:
            ddl = f.read()
        with self._connect() as conn:
            cols = {
                r["name"]
                for r in conn.execute("PRAGMA table_info(sealed_transactions)").fetchall()
            }
            user_ver = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if cols and ("prev_hash" not in cols or user_ver < LEDGER_SCHEMA_VERSION):
                # Legacy ledger (pre-chain or pre-v4 colon-delimited AAD): keep old rows
                # under a unique archive table name and start a fresh v4 canonical-AAD table.
                base_legacy = f"sealed_transactions_legacy_{time.time_ns()}"
                legacy = base_legacy
                suffix = 1
                while conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (legacy,)
                ).fetchone():
                    legacy = f"{base_legacy}_{suffix}"
                    suffix += 1
                conn.execute(f"ALTER TABLE sealed_transactions RENAME TO {legacy}")
                self.migration_note = (
                    f"Legacy ledger moved to table '{legacy}'; a new v{LEDGER_SCHEMA_VERSION} chained ledger was started."
                )
            conn.executescript(ddl)
            conn.execute(f"PRAGMA user_version = {LEDGER_SCHEMA_VERSION}")
            conn.commit()

    # ------------------------------------------------------------------
    # Hash chain helpers
    # ------------------------------------------------------------------
    @staticmethod
    def row_hash(row: Dict[str, Any]) -> str:
        canonical = json.dumps(
            [
                int(row["id"]),
                row["action"],
                row["target_token"],
                row["iv_hex"],
                row["ciphertext_hex"],
                row["hmac_hex"],
                row["prev_hash"],
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _row_to_dict(r: sqlite3.Row) -> Dict[str, Any]:
        try:
            quorum = json.loads(r["quorum_nodes"])
        except (TypeError, ValueError):
            quorum = r["quorum_nodes"]
        return {
            "id": r["id"],
            "created_at": r["created_at"],
            "action": r["action"],
            "target_token": r["target_token"],
            "quorum_nodes": quorum,
            "iv_hex": r["iv_hex"],
            "ciphertext_hex": r["ciphertext_hex"],
            "hmac_hex": r["hmac_hex"],
            "prev_hash": r["prev_hash"],
        }

    def _head(self, conn: sqlite3.Connection) -> Tuple[int, str]:
        last = conn.execute(
            f"SELECT {_ROW_COLUMNS} FROM sealed_transactions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if last is None:
            return 1, self.GENESIS_HASH
        return int(last["id"]) + 1, self.row_hash(self._row_to_dict(last))

    def next_chain_position(self) -> Tuple[int, str]:
        """Return (seq, prev_hash) the next appended row must carry (and bind in its AAD)."""
        with self._lock, self._connect() as conn:
            return self._head(conn)

    def append_sealed_entry(
        self,
        action: str,
        target_token: str,
        quorum_nodes: List[str],
        iv_hex: str,
        ciphertext_hex: str,
        hmac_hex: str,
        seq: Optional[int] = None,
        prev_hash: Optional[str] = None,
    ) -> int:
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            head_seq, head_prev = self._head(conn)
            if seq is None:
                seq, prev_hash = head_seq, head_prev
            elif seq != head_seq or prev_hash != head_prev:
                conn.rollback()
                raise LedgerChainConflict(
                    "Ledger head moved while sealing; the sealed AAD no longer matches the chain position."
                )
            conn.execute(
                """
                INSERT INTO sealed_transactions
                (id, created_at, action, target_token, quorum_nodes, iv_hex, ciphertext_hex, hmac_hex, prev_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    seq,
                    now,
                    action,
                    target_token,
                    json.dumps(quorum_nodes),
                    iv_hex,
                    ciphertext_hex,
                    hmac_hex,
                    prev_hash,
                ),
            )
            conn.commit()
            return int(seq)

    def list_entries(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {_ROW_COLUMNS}
                FROM sealed_transactions
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def list_all_entries_ascending(self) -> List[Dict[str, Any]]:
        """Every row in physical id order (the order the chain must follow)."""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_ROW_COLUMNS} FROM sealed_transactions ORDER BY id ASC"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_entries(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM sealed_transactions").fetchone()
            return int(row["cnt"]) if row else 0
