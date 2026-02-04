import json
import os
import sqlite3
from typing import Dict, Iterable, Optional, Tuple


class ChainDB:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path)
        self._init_tables()

    def _init_tables(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
        )

        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='blocks'"
        )
        if cur.fetchone():
            cur.execute("PRAGMA table_info(blocks)")
            cols = {row[1] for row in cur.fetchall()}
            if "parent" not in cols or "work" not in cols:
                cur.execute("ALTER TABLE blocks RENAME TO blocks_legacy")
        cur.execute(
            "CREATE TABLE IF NOT EXISTS blocks ("
            "hash TEXT PRIMARY KEY,"
            "height INTEGER,"
            "parent TEXT,"
            "work INTEGER,"
            "data TEXT"
            ")"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_blocks_parent ON blocks(parent)")
        cur.execute(
            "CREATE TABLE IF NOT EXISTS mempool (txid TEXT PRIMARY KEY, data TEXT)"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS contracts ("
            "id TEXT PRIMARY KEY,"
            "creator TEXT,"
            "code TEXT,"
            "storage TEXT"
            ")"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS tx_index ("
            "txid TEXT PRIMARY KEY,"
            "block_hash TEXT,"
            "height INTEGER,"
            "data TEXT"
            ")"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_height ON tx_index(height)")
        cur.execute(
            "CREATE TABLE IF NOT EXISTS address_index ("
            "address TEXT,"
            "txid TEXT,"
            "height INTEGER,"
            "direction TEXT"
            ")"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_addr ON address_index(address)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_addr_height ON address_index(address, height)")
        cur.execute(
            "CREATE TABLE IF NOT EXISTS receipts ("
            "txid TEXT PRIMARY KEY,"
            "block_hash TEXT,"
            "height INTEGER,"
            "gas_used INTEGER,"
            "logs TEXT,"
            "status TEXT"
            ")"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tx_block ON tx_index(block_hash)")
        cur.execute(
            "CREATE TABLE IF NOT EXISTS validators ("
            "address TEXT PRIMARY KEY,"
            "data TEXT"
            ")"
        )
        self.conn.commit()

    def put_block(self, block_hash: str, height: int, parent: str, work: int, data: dict) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO blocks (hash, height, parent, work, data) VALUES (?, ?, ?, ?, ?)",
            (block_hash, height, parent, work, json.dumps(data)),
        )
        self.conn.commit()

    def get_block(self, block_hash: str) -> Optional[dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT data FROM blocks WHERE hash = ?", (block_hash,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row[0])

    def get_block_meta(self, block_hash: str) -> Optional[Tuple[int, str, int]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT height, parent, work FROM blocks WHERE hash = ?", (block_hash,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return (int(row[0]), row[1], int(row[2]))

    def get_block_by_height(self, height: int) -> Iterable[dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT data FROM blocks WHERE height = ?", (height,))
        rows = cur.fetchall()
        for row in rows:
            yield json.loads(row[0])

    def iter_block_metas(self) -> Iterable[Tuple[str, int, str, int]]:
        cur = self.conn.cursor()
        cur.execute("SELECT hash, height, parent, work FROM blocks")
        rows = cur.fetchall()
        for row in rows:
            yield (row[0], int(row[1]), row[2], int(row[3]))

    def put_mempool(self, txid: str, data: dict) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO mempool (txid, data) VALUES (?, ?)",
            (txid, json.dumps(data)),
        )
        self.conn.commit()

    def delete_mempool(self, txid: str) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM mempool WHERE txid = ?", (txid,))
        self.conn.commit()

    def load_mempool(self) -> Dict[str, dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT txid, data FROM mempool")
        rows = cur.fetchall()
        out = {}
        for txid, data in rows:
            out[txid] = json.loads(data)
        return out

    def clear_mempool(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM mempool")
        self.conn.commit()

    def put_contract(self, contract_id: str, creator: str, code: list, storage: dict) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO contracts (id, creator, code, storage) VALUES (?, ?, ?, ?)",
            (contract_id, creator, json.dumps(code), json.dumps(storage)),
        )
        self.conn.commit()

    def clear_contracts(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM contracts")
        self.conn.commit()

    def load_contracts(self) -> Dict[str, dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT id, creator, code, storage FROM contracts")
        rows = cur.fetchall()
        out = {}
        for cid, creator, code, storage in rows:
            out[cid] = {
                "id": cid,
                "creator": creator,
                "code": json.loads(code),
                "storage": json.loads(storage),
            }
        return out

    def put_validator(self, address: str, data: dict) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO validators (address, data) VALUES (?, ?)",
            (address, json.dumps(data)),
        )
        self.conn.commit()

    def clear_validators(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM validators")
        self.conn.commit()

    def load_validators(self) -> Dict[str, dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT address, data FROM validators")
        rows = cur.fetchall()
        return {addr: json.loads(data) for addr, data in rows}

    def clear_tx_index(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM tx_index")
        cur.execute("DELETE FROM address_index")
        cur.execute("DELETE FROM receipts")
        self.conn.commit()

    def put_tx_index(self, txid: str, block_hash: str, height: int, data: dict) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO tx_index (txid, block_hash, height, data) VALUES (?, ?, ?, ?)",
            (txid, block_hash, height, json.dumps(data)),
        )
        self.conn.commit()

    def get_tx(self, txid: str) -> Optional[dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT data FROM tx_index WHERE txid = ?", (txid,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row[0])

    def index_address(self, address: str, txid: str, height: int, direction: str) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO address_index (address, txid, height, direction) VALUES (?, ?, ?, ?)",
            (address, txid, height, direction),
        )
        self.conn.commit()

    def get_address_history(self, address: str, limit: int = 50, offset: int = 0, direction: Optional[str] = None) -> list:
        cur = self.conn.cursor()
        if direction in ("in", "out"):
            cur.execute(
                "SELECT txid, height, direction FROM address_index WHERE address = ? AND direction = ? ORDER BY height DESC LIMIT ? OFFSET ?",
                (address, direction, limit, offset),
            )
        else:
            cur.execute(
                "SELECT txid, height, direction FROM address_index WHERE address = ? ORDER BY height DESC LIMIT ? OFFSET ?",
                (address, limit, offset),
            )
        rows = cur.fetchall()
        return [
            {"txid": r[0], "height": int(r[1]), "direction": r[2]} for r in rows
        ]

    def put_receipt(self, txid: str, block_hash: str, height: int, gas_used: int, logs: list, status: str) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO receipts (txid, block_hash, height, gas_used, logs, status) VALUES (?, ?, ?, ?, ?, ?)",
            (txid, block_hash, height, gas_used, json.dumps(logs), status),
        )
        self.conn.commit()

    def get_receipt(self, txid: str) -> Optional[dict]:
        cur = self.conn.cursor()
        cur.execute("SELECT block_hash, height, gas_used, logs, status FROM receipts WHERE txid = ?", (txid,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "txid": txid,
            "block_hash": row[0],
            "height": int(row[1]),
            "gas_used": int(row[2]),
            "logs": json.loads(row[3]),
            "status": row[4],
        }

    def reset_chain(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM blocks")
        cur.execute("DELETE FROM mempool")
        cur.execute("DELETE FROM contracts")
        cur.execute("DELETE FROM tx_index")
        cur.execute("DELETE FROM address_index")
        cur.execute("DELETE FROM receipts")
        cur.execute("DELETE FROM validators")
        cur.execute("DELETE FROM meta")
        self.conn.commit()

    def prune_blocks(self, min_height: int) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM blocks WHERE height < ?", (min_height,))
        self.conn.commit()

    def set_meta(self, key: str, value: str) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def close(self) -> None:
        self.conn.close()
