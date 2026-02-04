import os
import json
import gzip
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import crypto
from .block import Block
from .contract import Contract, ContractEngine
from .db import ChainDB
from .merkle import merkle_root
from .utils import json_dumps, sha256
from .tx import Transaction, TxInput, TxOutput, create_coinbase

COIN = 100_000_000
BLOCK_REWARD = int(os.getenv("SCRATCHCHAIN_BLOCK_REWARD", str(50 * COIN)))
INITIAL_DIFFICULTY = int(os.getenv("SCRATCHCHAIN_INITIAL_DIFFICULTY", "18"))
BLOCK_TIME = int(os.getenv("SCRATCHCHAIN_BLOCK_TIME", "10"))
DIFFICULTY_ADJUST_INTERVAL = int(os.getenv("SCRATCHCHAIN_DIFF_INTERVAL", "10"))
MAX_BLOCK_SIZE = int(os.getenv("SCRATCHCHAIN_MAX_BLOCK_SIZE", "1000000"))
MAX_BLOCK_GAS = int(os.getenv("SCRATCHCHAIN_MAX_BLOCK_GAS", "100000"))
MAX_TXS_PER_BLOCK = int(os.getenv("SCRATCHCHAIN_MAX_TXS_PER_BLOCK", "2000"))
BASE_GAS_PRICE = int(os.getenv("SCRATCHCHAIN_BASE_GAS_PRICE", "1"))
HALVING_INTERVAL = int(os.getenv("SCRATCHCHAIN_HALVING_INTERVAL", "100"))
MAX_SUPPLY = int(os.getenv("SCRATCHCHAIN_MAX_SUPPLY", str(21_000_000 * COIN)))
MIN_STAKE = int(os.getenv("SCRATCHCHAIN_MIN_STAKE", str(10 * COIN)))
FINALITY_DEPTH = int(os.getenv("SCRATCHCHAIN_FINALITY_DEPTH", "12"))
SLASH_RATE_BPS = int(Decimal(os.getenv("SCRATCHCHAIN_SLASH_RATE_BPS", "500")))
MAX_MEMPOOL_TXS = int(os.getenv("SCRATCHCHAIN_MAX_MEMPOOL_TXS", "5000"))
MAX_MEMPOOL_BYTES = int(os.getenv("SCRATCHCHAIN_MAX_MEMPOOL_BYTES", "5000000"))
MIN_RELAY_FEE_RATE = int(os.getenv("SCRATCHCHAIN_MIN_RELAY_FEE_RATE", "0"))
RBF_MIN_FACTOR = float(os.getenv("SCRATCHCHAIN_RBF_MIN_FACTOR", "1.1"))
RBF_MIN_DELTA = int(os.getenv("SCRATCHCHAIN_RBF_MIN_DELTA", "1000"))
MAX_VALIDATORS = int(os.getenv("SCRATCHCHAIN_MAX_VALIDATORS", "100"))
SNAPSHOT_INTERVAL = int(os.getenv("SCRATCHCHAIN_SNAPSHOT_INTERVAL", "100"))
SNAPSHOT_ENABLED = os.getenv("SCRATCHCHAIN_SNAPSHOTS", "1") == "1"
META_TX_FEE = int(os.getenv("SCRATCHCHAIN_META_TX_FEE", "1000"))
REQUIRE_SIGNED_SNAPSHOT = os.getenv("SCRATCHCHAIN_REQUIRE_SIGNED_SNAPSHOT", "0") == "1"
PRUNE_DEPTH = int(os.getenv("SCRATCHCHAIN_PRUNE_DEPTH", "0"))
GOV_ADDRESS = os.getenv("SCRATCHCHAIN_GOV_ADDRESS", "")
GENESIS_ALLOCATIONS = os.getenv("SCRATCHCHAIN_GENESIS_ALLOCATIONS", "")
GENESIS_PREV = "0" * 64
CONSENSUS = os.getenv("SCRATCHCHAIN_CONSENSUS", "pow").lower()

DEFAULT_PARAMS = {
    "MAX_BLOCK_SIZE": MAX_BLOCK_SIZE,
    "MAX_BLOCK_GAS": MAX_BLOCK_GAS,
    "MAX_TXS_PER_BLOCK": MAX_TXS_PER_BLOCK,
    "BASE_GAS_PRICE": BASE_GAS_PRICE,
    "HALVING_INTERVAL": HALVING_INTERVAL,
    "MAX_SUPPLY": MAX_SUPPLY,
    "MIN_STAKE": MIN_STAKE,
    "FINALITY_DEPTH": FINALITY_DEPTH,
    "SLASH_RATE_BPS": SLASH_RATE_BPS,
    "MAX_MEMPOOL_TXS": MAX_MEMPOOL_TXS,
    "MAX_MEMPOOL_BYTES": MAX_MEMPOOL_BYTES,
    "MIN_RELAY_FEE_RATE": MIN_RELAY_FEE_RATE,
    "RBF_MIN_FACTOR": RBF_MIN_FACTOR,
    "RBF_MIN_DELTA": RBF_MIN_DELTA,
    "MAX_VALIDATORS": MAX_VALIDATORS,
}


@dataclass
class BlockMeta:
    hash: str
    height: int
    parent: str
    work: int


class Chain:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, exist_ok=True)
        self.data_dir = data_dir
        self.db = ChainDB(os.path.join(data_dir, "chain.db"))
        self.index: Dict[str, BlockMeta] = {}
        self.utxo: Dict[str, TxOutput] = {}
        self.stakes: Dict[str, int] = {}
        self.contracts: Dict[str, Contract] = {}
        self.total_issued: int = 0
        self.validators: List[str] = []
        self.validator_registry: Dict[str, dict] = {}
        self.params: Dict[str, object] = dict(DEFAULT_PARAMS)
        self.base_gas_price_next: int = int(self._param("BASE_GAS_PRICE") or BASE_GAS_PRICE)
        self.engine = ContractEngine()
        self.mempool: Dict[str, Transaction] = {}
        self.orphans: Dict[str, Block] = {}
        self.orphan_by_parent: Dict[str, List[str]] = {}
        self.snapshot_enabled = SNAPSHOT_ENABLED
        self.snapshot_interval = SNAPSHOT_INTERVAL
        self.snapshot: Optional[dict] = None

        for h, height, parent, work in self.db.iter_block_metas():
            self.index[h] = BlockMeta(hash=h, height=height, parent=parent, work=work)

        if not self.db.get_meta("difficulty"):
            self.db.set_meta("difficulty", str(INITIAL_DIFFICULTY))

        raw_mempool = self.db.load_mempool()
        for txid, data in raw_mempool.items():
            try:
                self.mempool[txid] = Transaction.from_dict(data)
            except Exception:
                pass

        self.best_tip = self.db.get_meta("best_tip")
        if self.best_tip and self.best_tip not in self.index:
            self.best_tip = None

        if not self.best_tip:
            self.best_tip = self._select_best_tip()
            if self.best_tip:
                self.db.set_meta("best_tip", self.best_tip)

        self.best_work = self.index[self.best_tip].work if self.best_tip else 0
        if self.snapshot_enabled:
            self.snapshot = self._load_latest_snapshot()
        if self.best_tip:
            (
                self.utxo,
                self.stakes,
                self.contracts,
                self.total_issued,
                self.validators,
                self.validator_registry,
                self.params,
            ) = self._rebuild_state(self.best_tip)
            self.base_gas_price_next = self._calc_next_base_gas_price(self.best_tip)
            self._persist_contracts()
            self._persist_validators()
            self._rebuild_indexes(self.best_tip)
            self._revalidate_mempool()

    def _select_best_tip(self) -> Optional[str]:
        if not self.index:
            return None
        best = None
        for meta in self.index.values():
            if not best or meta.work > best.work or (
                meta.work == best.work and meta.height > best.height
            ):
                best = meta
        return best.hash if best else None

    def _param(self, name: str):
        return self.params.get(name, DEFAULT_PARAMS.get(name))

    def has_block(self, block_hash: str) -> bool:
        return block_hash in self.index

    def get_block(self, block_hash: str) -> Optional[Block]:
        data = self.db.get_block(block_hash)
        if not data:
            return None
        return Block.from_dict(data)

    def get_block_by_height(self, height: int) -> Optional[Block]:
        for data in self.db.get_block_by_height(height):
            return Block.from_dict(data)
        return None

    @property
    def height(self) -> int:
        if not self.best_tip:
            return -1
        return self.index[self.best_tip].height

    @property
    def difficulty(self) -> int:
        if not self.best_tip:
            return int(self.db.get_meta("difficulty") or INITIAL_DIFFICULTY)
        block = self.get_block(self.best_tip)
        return block.header.difficulty if block else INITIAL_DIFFICULTY

    def _block_work(self, difficulty: int) -> int:
        if CONSENSUS == "pow":
            return 1 << difficulty
        return 1

    def block_reward(self, height: int) -> int:
        halving = int(self._param("HALVING_INTERVAL") or 0)
        if halving <= 0:
            return BLOCK_REWARD
        halvings = height // halving
        reward = BLOCK_REWARD >> halvings
        return max(reward, 0)

    def _calc_next_base_gas_price(self, parent_hash: str, params: Optional[Dict[str, object]] = None) -> int:
        params = params or self.params
        base_gas_price = int(params.get("BASE_GAS_PRICE", BASE_GAS_PRICE))
        max_block_gas = int(params.get("MAX_BLOCK_GAS", MAX_BLOCK_GAS))
        if parent_hash == GENESIS_PREV:
            return base_gas_price
        parent = self.get_block(parent_hash)
        if not parent:
            return base_gas_price
        base = parent.header.base_gas_price or base_gas_price
        target = max(1, max_block_gas // 2)
        gas_used = parent.header.gas_used
        if gas_used > target:
            delta = max(1, base * (gas_used - target) // target // 8)
            return base + delta
        if gas_used < target:
            delta = max(1, base * (target - gas_used) // target // 8)
            return max(1, base - delta)
        return base

    def _compute_validators(self, stakes: Dict[str, int], registry: Optional[Dict[str, dict]] = None) -> List[str]:
        min_stake = int(self._param("MIN_STAKE") or MIN_STAKE)
        use_registry = bool(registry)
        if use_registry:
            candidates = [addr for addr in registry.keys() if stakes.get(addr, 0) >= min_stake]
        else:
            candidates = [addr for addr, amount in stakes.items() if amount >= min_stake]
        candidates = sorted(candidates, key=lambda a: (-stakes.get(a, 0), a))
        max_validators = int(self._param("MAX_VALIDATORS") or MAX_VALIDATORS)
        if max_validators > 0:
            candidates = candidates[:max_validators]
        return candidates

    def _validate_slash_tx(self, tx: Transaction, stakes: Dict[str, int]) -> Optional[int]:
        payload = tx.payload or {}
        h1 = payload.get("header_a")
        h2 = payload.get("header_b")
        if not isinstance(h1, dict) or not isinstance(h2, dict):
            return None
        try:
            from .block import header_hash_from_dict
            hash1 = header_hash_from_dict(h1)
            hash2 = header_hash_from_dict(h2)
        except Exception:
            return None
        if hash1 == hash2:
            return None
        if h1.get("validator") != h2.get("validator"):
            return None
        if h1.get("height") != h2.get("height"):
            return None
        validator = h1.get("validator")
        if not validator:
            return None
        # verify signatures
        for h in (h1, h2):
            sig = h.get("signature")
            pub = h.get("validator_pubkey")
            algo = h.get("validator_sig_algo")
            if not sig or not pub or not algo:
                return None
            try:
                pubkey = crypto.key_from_hex(pub, algo)
                addr = crypto.address_from_pubkey(pubkey, algo)
                if addr != validator:
                    return None
                if not crypto.verify(header_hash_from_dict(h), sig, pubkey, algo):
                    return None
            except Exception:
                return None
        stake_amt = stakes.get(validator, 0)
        if stake_amt <= 0:
            return None
        rate_bps = int(self._param("SLASH_RATE_BPS") or SLASH_RATE_BPS)
        penalty = max(1, stake_amt * rate_bps // 10000)
        requested = int(payload.get("amount", penalty))
        if requested <= 0 or requested > penalty:
            return None
        return requested

    def _ancestor(self, tip_hash: str, height: int) -> Optional[str]:
        cur = tip_hash
        while cur and cur in self.index:
            meta = self.index[cur]
            if meta.height == height:
                return cur
            cur = meta.parent
        return None

    def _calc_next_difficulty(self, parent_hash: str) -> int:
        if CONSENSUS != "pow":
            return 0
        if parent_hash == GENESIS_PREV:
            return INITIAL_DIFFICULTY
        parent_block = self.get_block(parent_hash)
        if not parent_block:
            return INITIAL_DIFFICULTY
        parent_height = self.index[parent_hash].height
        if parent_height == 0:
            return parent_block.header.difficulty
        if parent_height % DIFFICULTY_ADJUST_INTERVAL != 0:
            return parent_block.header.difficulty

        anchor_height = max(0, parent_height - DIFFICULTY_ADJUST_INTERVAL)
        anchor_hash = self._ancestor(parent_hash, anchor_height)
        if not anchor_hash:
            return parent_block.header.difficulty
        anchor_block = self.get_block(anchor_hash)
        if not anchor_block:
            return parent_block.header.difficulty

        actual = parent_block.header.timestamp - anchor_block.header.timestamp
        expected = DIFFICULTY_ADJUST_INTERVAL * BLOCK_TIME
        diff = parent_block.header.difficulty
        if actual < expected // 4:
            diff += 1
        elif actual > expected * 4:
            diff = max(1, diff - 1)
        return diff

    def _lca_height(self, a: str, b: str) -> int:
        visited = set()
        cur = a
        while cur and cur in self.index:
            visited.add(cur)
            cur = self.index[cur].parent
        cur = b
        while cur and cur in self.index:
            if cur in visited:
                return self.index[cur].height
            cur = self.index[cur].parent
        return -1

    def _chain_hashes(self, tip_hash: str) -> List[str]:
        chain = []
        cur = tip_hash
        while cur and cur in self.index:
            chain.append(cur)
            parent = self.index[cur].parent
            if parent == GENESIS_PREV:
                break
            cur = parent
        chain.reverse()
        return chain

    def _slash_stake(self, utxo: Dict[str, TxOutput], stakes: Dict[str, int], address: str, amount: int) -> int:
        if amount <= 0:
            return 0
        remaining = amount
        # remove stake outputs for address
        for key in list(utxo.keys()):
            out = utxo.get(key)
            if not out or out.address != address or not out.stake:
                continue
            take = min(out.amount, remaining)
            out.amount -= take
            stakes[address] = max(0, stakes.get(address, 0) - take)
            remaining -= take
            if out.amount == 0:
                del utxo[key]
            else:
                utxo[key] = out
            if remaining <= 0:
                break
        return amount - remaining

    def _apply_spend(self, utxo: Dict[str, TxOutput], stakes: Dict[str, int], inp: TxInput) -> None:
        key = f"{inp.prev_txid}:{inp.output_index}"
        prev_out = utxo.get(key)
        if prev_out:
            if prev_out.stake:
                stakes[prev_out.address] = max(0, stakes.get(prev_out.address, 0) - prev_out.amount)
            del utxo[key]

    def _apply_outputs(self, utxo: Dict[str, TxOutput], stakes: Dict[str, int], tx: Transaction) -> None:
        for idx, out in enumerate(tx.outputs):
            utxo[f"{tx.txid}:{idx}"] = out
            if out.stake:
                stakes[out.address] = stakes.get(out.address, 0) + out.amount

    def _tx_sender(self, tx: Transaction) -> str:
        if not tx.inputs:
            return ""
        inp = tx.inputs[0]
        if not inp.pubkey:
            return ""
        pub = crypto.key_from_hex(inp.pubkey, inp.sig_algo)
        return crypto.address_from_pubkey(pub, inp.sig_algo)

    def _parse_amount(self, value) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(Decimal(str(value)) * COIN)
        if isinstance(value, str):
            try:
                return int(Decimal(value) * COIN)
            except (InvalidOperation, ValueError) as exc:
                raise RuntimeError("invalid amount") from exc
        raise RuntimeError("invalid amount type")

    def _parse_commission_bps(self, value) -> int:
        if value is None:
            return -1
        try:
            dec = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise RuntimeError("invalid commission") from exc
        if dec < 0 or dec > 1:
            raise RuntimeError("commission out of range")
        return int(dec * 10000)

    def _apply_validator_tx(
        self,
        registry: Dict[str, dict],
        sender: str,
        payload: dict,
        update: bool,
    ) -> None:
        if not sender:
            raise RuntimeError("missing sender")
        if not isinstance(payload, dict):
            raise RuntimeError("invalid validator payload")
        if update and sender not in registry:
            raise RuntimeError("validator not registered")
        pubkey = payload.get("pubkey")
        if pubkey:
            if not isinstance(pubkey, dict):
                raise RuntimeError("invalid pubkey")
            addr = crypto.address_from_pubkey(crypto.key_from_hex(pubkey, "ecdsa"), "ecdsa")
            if addr != sender:
                raise RuntimeError("pubkey does not match sender")
        elif not update:
            raise RuntimeError("pubkey required for register")
        entry = dict(registry.get(sender, {}))
        if pubkey:
            entry["pubkey"] = pubkey

        if "commission" in payload:
            bps = self._parse_commission_bps(payload.get("commission"))
            entry["commission_bps"] = bps

        name = payload.get("name")
        if name is not None:
            if not isinstance(name, str) or len(name) > 64:
                raise RuntimeError("invalid name")
            entry["name"] = name

        website = payload.get("website")
        if website is not None:
            if not isinstance(website, str) or len(website) > 128:
                raise RuntimeError("invalid website")
            entry["website"] = website

        registry[sender] = entry

    def _apply_gov_update(self, params: Dict[str, object], sender: str, payload: dict) -> None:
        if not GOV_ADDRESS:
            raise RuntimeError("governance disabled")
        if sender != GOV_ADDRESS:
            raise RuntimeError("unauthorized governance update")
        if not isinstance(payload, dict):
            raise RuntimeError("invalid governance payload")
        changes = payload.get("params")
        if not isinstance(changes, dict):
            raise RuntimeError("params required")
        allowed = {
            "MAX_BLOCK_SIZE",
            "MAX_BLOCK_GAS",
            "MAX_TXS_PER_BLOCK",
            "BASE_GAS_PRICE",
            "HALVING_INTERVAL",
            "MAX_SUPPLY",
            "MIN_STAKE",
            "FINALITY_DEPTH",
            "SLASH_RATE_BPS",
            "MAX_MEMPOOL_TXS",
            "MAX_MEMPOOL_BYTES",
            "MIN_RELAY_FEE_RATE",
            "RBF_MIN_FACTOR",
            "RBF_MIN_DELTA",
            "MAX_VALIDATORS",
        }
        for key, raw in changes.items():
            if key not in allowed:
                raise RuntimeError(f"unsupported param {key}")
            if key == "RBF_MIN_FACTOR":
                try:
                    val = float(raw)
                except Exception as exc:
                    raise RuntimeError("invalid RBF_MIN_FACTOR") from exc
                if val < 1.0:
                    raise RuntimeError("RBF_MIN_FACTOR too low")
                params[key] = val
                continue
            try:
                val_int = int(raw)
            except Exception as exc:
                raise RuntimeError(f"invalid value for {key}") from exc
            if key in ("MAX_BLOCK_SIZE", "MAX_BLOCK_GAS", "MAX_TXS_PER_BLOCK", "BASE_GAS_PRICE") and val_int <= 0:
                raise RuntimeError(f"{key} must be > 0")
            if key == "SLASH_RATE_BPS" and (val_int < 0 or val_int > 10000):
                raise RuntimeError("SLASH_RATE_BPS out of range")
            if val_int < 0:
                raise RuntimeError(f"{key} must be >= 0")
            params[key] = val_int

    def _execute_contract_tx(
        self,
        tx: Transaction,
        contracts: Dict[str, Contract],
        sender: str,
    ) -> Tuple[int, List[int]]:
        if tx.tx_type == "contract_create":
            payload = tx.payload or {}
            code = payload.get("code")
            if not isinstance(code, list):
                raise RuntimeError("invalid contract code")
            storage = payload.get("storage", {})
            if not isinstance(storage, dict):
                raise RuntimeError("invalid contract storage")
            cid = tx.txid
            if cid in contracts:
                raise RuntimeError("contract exists")
            contracts[cid] = Contract(contract_id=cid, creator=sender, code=code, storage=storage)
            return len(code) * 2 + len(storage) * 5, []

        if tx.tx_type == "contract_call":
            payload = tx.payload or {}
            cid = payload.get("contract_id")
            if not cid or cid not in contracts:
                raise RuntimeError("unknown contract")
            calldata = payload.get("calldata", [])
            if not isinstance(calldata, list):
                raise RuntimeError("invalid calldata")
            sender_int = int(sender, 16) if sender else 0
            contract = contracts[cid]
            gas_used, logs, _ = self.engine.execute(contract, calldata, sender_int, tx.gas_limit)
            return gas_used, logs

        return 0, []

    def _apply_tx_state(
        self,
        utxo: Dict[str, TxOutput],
        stakes: Dict[str, int],
        contracts: Dict[str, Contract],
        registry: Dict[str, dict],
        params: Dict[str, object],
        tx: Transaction,
        execute_contract: bool = True,
    ) -> Tuple[int, List[int]]:
        gas_used = 0
        logs: List[int] = []
        if execute_contract and tx.tx_type in ("contract_create", "contract_call"):
            sender = self._tx_sender(tx)
            gas_used, logs = self._execute_contract_tx(tx, contracts, sender)
        if tx.tx_type == "validator_register":
            sender = self._tx_sender(tx)
            self._apply_validator_tx(registry, sender, tx.payload or {}, update=False)
        if tx.tx_type == "validator_update":
            sender = self._tx_sender(tx)
            self._apply_validator_tx(registry, sender, tx.payload or {}, update=True)
        if tx.tx_type == "gov_update":
            sender = self._tx_sender(tx)
            self._apply_gov_update(params, sender, tx.payload or {})
        if tx.tx_type == "slash":
            payload = tx.payload or {}
            address = payload.get("validator")
            amount = int(payload.get("amount", 0))
            if address:
                self._slash_stake(utxo, stakes, address, amount)
        for inp in tx.inputs:
            self._apply_spend(utxo, stakes, inp)
        self._apply_outputs(utxo, stakes, tx)
        return gas_used, logs

    def _rebuild_state(
        self, tip_hash: str
    ) -> Tuple[
        Dict[str, TxOutput],
        Dict[str, int],
        Dict[str, Contract],
        int,
        List[str],
        Dict[str, dict],
        Dict[str, object],
    ]:
        utxo: Dict[str, TxOutput] = {}
        stakes: Dict[str, int] = {}
        contracts: Dict[str, Contract] = {}
        registry: Dict[str, dict] = {}
        params: Dict[str, object] = dict(DEFAULT_PARAMS)
        total_issued = 0

        chain_hashes = self._chain_hashes(tip_hash)
        start_index = 0
        if self.snapshot and self.snapshot.get("tip") in chain_hashes:
            try:
                snap = self.snapshot
                utxo = {k: TxOutput.from_dict(v) for k, v in snap.get("utxo", {}).items()}
                stakes = {k: int(v) for k, v in snap.get("stakes", {}).items()}
                contracts = {
                    cid: Contract(cid, c["creator"], list(c["code"]), dict(c["storage"]))
                    for cid, c in snap.get("contracts", {}).items()
                }
                registry = dict(snap.get("validator_registry", {}))
                params = dict(DEFAULT_PARAMS)
                params.update(snap.get("params", {}))
                total_issued = int(snap.get("total_issued", 0))
                start_index = chain_hashes.index(snap["tip"]) + 1
            except Exception:
                utxo, stakes, contracts, registry, params, total_issued = {}, {}, {}, {}, dict(DEFAULT_PARAMS), 0
                start_index = 0

        for h in chain_hashes[start_index:]:
            block = self.get_block(h)
            if not block:
                continue
            for tx in block.txs:
                if tx.is_coinbase:
                    total_issued += sum(o.amount for o in tx.outputs)
                self._apply_tx_state(utxo, stakes, contracts, registry, params, tx, execute_contract=True)
        validators = self._compute_validators(stakes, registry)
        return utxo, stakes, contracts, total_issued, validators, registry, params

    def _persist_contracts(self) -> None:
        self.db.clear_contracts()
        for cid, contract in self.contracts.items():
            self.db.put_contract(cid, contract.creator, contract.code, contract.storage)

    def _persist_validators(self) -> None:
        self.db.clear_validators()
        for addr, data in self.validator_registry.items():
            self.db.put_validator(addr, data)

    def _rebuild_indexes(self, tip_hash: str) -> None:
        self.db.clear_tx_index()
        utxo: Dict[str, TxOutput] = {}
        stakes: Dict[str, int] = {}
        contracts: Dict[str, Contract] = {}
        registry: Dict[str, dict] = {}
        params: Dict[str, object] = dict(DEFAULT_PARAMS)
        for h in self._chain_hashes(tip_hash):
            block = self.get_block(h)
            if not block:
                continue
            height = block.header.height
            for tx in block.txs:
                for inp in tx.inputs:
                    key = f"{inp.prev_txid}:{inp.output_index}"
                    prev_out = utxo.get(key)
                    if prev_out:
                        self.db.index_address(prev_out.address, tx.txid, height, "out")
                gas_used, logs = self._apply_tx_state(
                    utxo, stakes, contracts, registry, params, tx, execute_contract=True
                )
                self.db.put_tx_index(tx.txid, h, height, tx.to_dict(include_sigs=True))
                self.db.put_receipt(tx.txid, h, height, gas_used, logs, "ok")
                for out in tx.outputs:
                    self.db.index_address(out.address, tx.txid, height, "in")

    def _fee_for_tx(self, tx: Transaction, utxo: Dict[str, TxOutput]) -> int:
        if tx.is_coinbase:
            return 0
        total_in = 0
        for inp in tx.inputs:
            key = f"{inp.prev_txid}:{inp.output_index}"
            prev_out = utxo.get(key)
            if prev_out:
                total_in += prev_out.amount
        total_out = sum(o.amount for o in tx.outputs)
        return max(total_in - total_out, 0)

    def _tx_fee_rate(self, tx: Transaction, utxo: Dict[str, TxOutput]) -> float:
        fee = self._fee_for_tx(tx, utxo)
        size = max(tx.estimate_size(), 1)
        return fee / size

    def _select_mempool_txs(self, base_size: int = 0) -> Tuple[List[Transaction], int, int, int]:
        min_gas_price = self._calc_next_base_gas_price(self.best_tip) if self.best_tip else int(self._param("BASE_GAS_PRICE") or BASE_GAS_PRICE)
        max_txs = int(self._param("MAX_TXS_PER_BLOCK") or MAX_TXS_PER_BLOCK)
        max_block_size = int(self._param("MAX_BLOCK_SIZE") or MAX_BLOCK_SIZE)
        max_block_gas = int(self._param("MAX_BLOCK_GAS") or MAX_BLOCK_GAS)
        ordered = sorted(
            self.mempool.values(),
            key=lambda t: (self._tx_fee_rate(t, self.utxo), t.gas_price, t.txid),
            reverse=True,
        )
        temp_utxo = dict(self.utxo)
        temp_stakes = dict(self.stakes)
        temp_contracts = {
            cid: Contract(c.contract_id, c.creator, list(c.code), dict(c.storage))
            for cid, c in self.contracts.items()
        }
        temp_registry = dict(self.validator_registry)
        temp_params = dict(self.params)
        selected: List[Transaction] = []
        fees = 0
        block_size = base_size
        block_gas = 0

        for tx in ordered:
            if len(selected) >= max_txs:
                break
            if tx.tx_type == "slash":
                penalty = self._validate_slash_tx(tx, temp_stakes)
                if penalty is None:
                    continue
                if sum(o.amount for o in tx.outputs) > penalty:
                    continue
            if not tx.validate(temp_utxo):
                continue
            tx_size = tx.estimate_size()
            if block_size + tx_size > max_block_size:
                continue
            try:
                fee = self._fee_for_tx(tx, temp_utxo)
                gas_used = 0
                if tx.tx_type in ("contract_create", "contract_call"):
                    gas_used, _logs = self._apply_tx_state(
                        temp_utxo, temp_stakes, temp_contracts, temp_registry, temp_params, tx, execute_contract=True
                    )
                    if fee < gas_used * tx.gas_price:
                        continue
                    if block_gas + gas_used > max_block_gas:
                        continue
                else:
                    self._apply_tx_state(
                        temp_utxo, temp_stakes, temp_contracts, temp_registry, temp_params, tx, execute_contract=False
                    )
                fees += fee
                block_size += tx_size
                block_gas += gas_used
                selected.append(tx)
            except Exception:
                continue

        return selected, fees, block_gas, block_size

    def _select_validator(
        self,
        prev_hash: str,
        stakes: Dict[str, int],
        validators: Optional[List[str]] = None,
        registry: Optional[Dict[str, dict]] = None,
    ) -> str:
        if validators is None:
            validators = self._compute_validators(stakes, registry or self.validator_registry)
        total = sum(stakes.get(v, 0) for v in validators)
        if total <= 0:
            return ""
        seed = int(prev_hash, 16)
        pick = seed % total
        for addr in sorted(validators):
            pick -= stakes[addr]
            if pick < 0:
                return addr
        return ""

    def init_genesis(self, address: str) -> Block:
        if self.index:
            raise RuntimeError("Chain already initialized")
        outputs: List[TxOutput] = []
        if GENESIS_ALLOCATIONS:
            try:
                alloc = json.loads(GENESIS_ALLOCATIONS)
            except Exception as exc:
                raise RuntimeError("invalid genesis allocations") from exc
            if isinstance(alloc, dict):
                for addr, amt in alloc.items():
                    outputs.append(TxOutput(amount=self._parse_amount(amt), address=str(addr)))
            elif isinstance(alloc, list):
                for entry in alloc:
                    if not isinstance(entry, dict):
                        raise RuntimeError("invalid genesis allocation entry")
                    outputs.append(
                        TxOutput(
                            amount=self._parse_amount(entry.get("amount")),
                            address=str(entry.get("address", "")),
                        )
                    )
            else:
                raise RuntimeError("invalid genesis allocations format")
        else:
            outputs.append(TxOutput(amount=self.block_reward(0), address=address))
        if any(not o.address for o in outputs):
            raise RuntimeError("invalid genesis output address")
        total = sum(o.amount for o in outputs)
        max_supply = int(self._param("MAX_SUPPLY") or MAX_SUPPLY)
        if total > max_supply:
            raise RuntimeError("genesis allocations exceed max supply")
        coinbase = Transaction(inputs=[], outputs=outputs, coinbase_data="genesis", tx_type="coinbase")
        diff = INITIAL_DIFFICULTY if CONSENSUS == "pow" else 0
        block = Block.build(
            GENESIS_PREV,
            0,
            diff,
            [coinbase],
            base_gas_price=int(self._param("BASE_GAS_PRICE") or BASE_GAS_PRICE),
            gas_used=0,
        )
        if CONSENSUS == "pow":
            block.mine()
        self._store_block(block, GENESIS_PREV, 0)
        self.best_tip = block.hash
        self.best_work = self.index[block.hash].work
        self.db.set_meta("best_tip", block.hash)
        self.utxo, self.stakes, self.contracts, self.total_issued, self.validators, self.validator_registry, self.params = self._rebuild_state(block.hash)
        self.base_gas_price_next = self._calc_next_base_gas_price(block.hash)
        self._persist_contracts()
        self._persist_validators()
        self._rebuild_indexes(block.hash)
        return block

    def _store_block(self, block: Block, parent_hash: str, parent_work: int) -> None:
        work = parent_work + self._block_work(block.header.difficulty)
        meta = BlockMeta(hash=block.hash, height=block.header.height, parent=parent_hash, work=work)
        self.index[block.hash] = meta
        self.db.put_block(block.hash, meta.height, parent_hash, work, block.to_dict())

    def _validate_block(self, block: Block, parent_hash: str) -> bool:
        if block.header.prev_hash != parent_hash:
            return False
        if block.header.height == 0 and parent_hash != GENESIS_PREV:
            return False
        if block.header.height > 0 and parent_hash == GENESIS_PREV:
            return False
        if block.header.height > 0 and parent_hash not in self.index:
            return False
        if block.header.height < 0:
            return False
        if block.header.height > 0:
            expected_height = self.index[parent_hash].height + 1
            if block.header.height != expected_height:
                return False

        expected_root = merkle_root([tx.txid for tx in block.txs])
        if block.header.merkle_root != expected_root:
            return False

        parent_params = dict(self.params)
        if block.header.height > 0:
            (
                parent_utxo,
                parent_stakes,
                parent_contracts,
                parent_total_issued,
                parent_validators,
                parent_registry,
                parent_params,
            ) = self._rebuild_state(parent_hash)
        else:
            parent_utxo, parent_stakes, parent_contracts, parent_total_issued = {}, {}, {}, 0
            parent_validators, parent_registry = [], {}

        expected_base_gas = (
            int(parent_params.get("BASE_GAS_PRICE", BASE_GAS_PRICE))
            if block.header.height == 0
            else self._calc_next_base_gas_price(parent_hash, parent_params)
        )
        if block.header.base_gas_price != expected_base_gas:
            return False

        if CONSENSUS == "pow":
            target = 1 << (256 - block.header.difficulty)
            if int(block.hash, 16) >= target:
                return False
            expected_diff = INITIAL_DIFFICULTY if block.header.height == 0 else self._calc_next_difficulty(parent_hash)
            if block.header.difficulty != expected_diff:
                return False
        else:
            if block.header.difficulty != 0:
                return False

        if not block.txs:
            return False
        if not block.txs[0].is_coinbase:
            return False
        if block.txs[0].tx_type != "coinbase":
            return False
        max_txs = int(parent_params.get("MAX_TXS_PER_BLOCK", MAX_TXS_PER_BLOCK))
        if len(block.txs) > max_txs:
            return False

        if CONSENSUS == "pos":
            if block.header.height > 0:
                expected_validator = self._select_validator(parent_hash, parent_stakes, parent_validators)
                if expected_validator:
                    if block.header.validator != expected_validator:
                        return False
                if not block.header.signature:
                    return False
                if not block.header.validator_pubkey or not block.header.validator_sig_algo:
                    return False
                pub = crypto.key_from_hex(block.header.validator_pubkey, block.header.validator_sig_algo)
                addr = crypto.address_from_pubkey(pub, block.header.validator_sig_algo)
                if addr != block.header.validator:
                    return False
                reg = parent_registry.get(addr)
                if reg and reg.get("pubkey") and reg.get("pubkey") != block.header.validator_pubkey:
                    return False
                if not crypto.verify(block.hash, block.header.signature, pub, block.header.validator_sig_algo):
                    return False

        temp_utxo = dict(parent_utxo)
        temp_stakes = dict(parent_stakes)
        temp_contracts = {cid: Contract(c.contract_id, c.creator, list(c.code), dict(c.storage)) for cid, c in parent_contracts.items()}
        temp_registry = dict(parent_registry)
        temp_params = dict(parent_params)
        params_locked = dict(parent_params)

        fees = 0
        block_size = 0
        block_gas = 0
        max_block_size = int(params_locked.get("MAX_BLOCK_SIZE", MAX_BLOCK_SIZE))
        max_block_gas = int(params_locked.get("MAX_BLOCK_GAS", MAX_BLOCK_GAS))
        block_size += block.txs[0].estimate_size()
        for tx in block.txs[1:]:
            if tx.is_coinbase and tx.tx_type != "slash":
                return False
            if tx.tx_type == "slash":
                penalty = self._validate_slash_tx(tx, temp_stakes)
                if penalty is None:
                    return False
                out_sum = sum(o.amount for o in tx.outputs)
                if out_sum > penalty:
                    return False
            if not tx.validate(temp_utxo):
                return False
            if tx.tx_type in ("contract_create", "contract_call"):
                if tx.gas_limit <= 0:
                    return False
                if tx.gas_price < block.header.base_gas_price:
                    return False
            fee = self._fee_for_tx(tx, temp_utxo)
            tx_size = tx.estimate_size()
            if block_size + tx_size > max_block_size:
                return False
            gas_used, _logs = self._apply_tx_state(
                temp_utxo, temp_stakes, temp_contracts, temp_registry, temp_params, tx, execute_contract=True
            )
            if tx.tx_type in ("contract_create", "contract_call"):
                gas_required = gas_used * tx.gas_price
                if fee < gas_required:
                    return False
                if block_gas + gas_used > max_block_gas:
                    return False
            block_size += tx_size
            block_gas += gas_used
            fees += fee

        if block_size > max_block_size:
            return False
        if block_gas != block.header.gas_used:
            return False

        coinbase_out = sum(o.amount for o in block.txs[0].outputs)
        max_supply = int(params_locked.get("MAX_SUPPLY", MAX_SUPPLY))
        if block.header.height == 0:
            if coinbase_out > max_supply:
                return False
        else:
            reward = self.block_reward(block.header.height)
            if coinbase_out > reward + fees:
                return False
            if parent_total_issued + coinbase_out > max_supply:
                return False
        return True


    def add_block(self, block: Block) -> Tuple[str, Optional[str]]:
        if block.hash in self.index:
            return ("known", None)

        parent_hash = block.header.prev_hash
        if block.header.height > 0 and parent_hash not in self.index:
            self.orphans[block.hash] = block
            self.orphan_by_parent.setdefault(parent_hash, []).append(block.hash)
            return ("orphan", parent_hash)

        if not self._validate_block(block, parent_hash):
            return ("invalid", None)

        parent_work = 0
        if block.header.height > 0:
            parent_work = self.index[parent_hash].work
        self._store_block(block, parent_hash, parent_work)

        self._maybe_update_best_tip(block.hash)
        self._try_connect_orphans(block.hash)
        return ("accepted", None)

    def _maybe_update_best_tip(self, new_hash: str) -> None:
        new_meta = self.index[new_hash]
        if not self.best_tip or new_meta.work > self.best_work:
            if self.best_tip:
                lca_height = self._lca_height(new_hash, self.best_tip)
                finality = int(self._param("FINALITY_DEPTH") or FINALITY_DEPTH)
                if lca_height != -1 and self.height - lca_height > finality:
                    return
            self.best_tip = new_hash
            self.best_work = new_meta.work
            self.db.set_meta("best_tip", new_hash)
            self.utxo, self.stakes, self.contracts, self.total_issued, self.validators, self.validator_registry, self.params = self._rebuild_state(new_hash)
            self.base_gas_price_next = self._calc_next_base_gas_price(new_hash)
            self._persist_contracts()
            self._persist_validators()
            self._rebuild_indexes(new_hash)
            self._revalidate_mempool()
            self._maybe_write_snapshot()
            self._prune_blocks()

    def _try_connect_orphans(self, parent_hash: str) -> None:
        children = self.orphan_by_parent.get(parent_hash, [])
        for child_hash in children:
            block = self.orphans.pop(child_hash, None)
            if not block:
                continue
            status, _ = self.add_block(block)
            if status != "accepted":
                self.orphans[child_hash] = block
        self.orphan_by_parent.pop(parent_hash, None)

    def _revalidate_mempool(self) -> None:
        temp_utxo = dict(self.utxo)
        temp_stakes = dict(self.stakes)
        temp_contracts = {cid: Contract(c.contract_id, c.creator, list(c.code), dict(c.storage)) for cid, c in self.contracts.items()}
        temp_registry = dict(self.validator_registry)
        temp_params = dict(self.params)
        min_gas_price = self._calc_next_base_gas_price(self.best_tip) if self.best_tip else int(self._param("BASE_GAS_PRICE") or BASE_GAS_PRICE)
        new_pool: Dict[str, Transaction] = {}
        used = set()
        for txid, tx in self.mempool.items():
            fee_rate = self._tx_fee_rate(tx, temp_utxo)
            if fee_rate < int(self._param("MIN_RELAY_FEE_RATE") or MIN_RELAY_FEE_RATE):
                continue
            if tx.tx_type == "slash":
                penalty = self._validate_slash_tx(tx, temp_stakes)
                if penalty is None:
                    continue
                if sum(o.amount for o in tx.outputs) > penalty:
                    continue
            if not tx.validate(temp_utxo):
                continue
            conflict = False
            for inp in tx.inputs:
                key = f"{inp.prev_txid}:{inp.output_index}"
                if key in used:
                    conflict = True
                    break
            if conflict:
                continue
            if tx.tx_type in ("contract_create", "contract_call"):
                if tx.gas_limit <= 0 or tx.gas_price < min_gas_price:
                    continue
                try:
                    self._apply_tx_state(temp_utxo, temp_stakes, temp_contracts, temp_registry, temp_params, tx, execute_contract=True)
                except Exception:
                    continue
            else:
                self._apply_tx_state(temp_utxo, temp_stakes, temp_contracts, temp_registry, temp_params, tx, execute_contract=False)
            new_pool[txid] = tx
            for inp in tx.inputs:
                used.add(f"{inp.prev_txid}:{inp.output_index}")
        self.mempool = new_pool
        self.db.clear_mempool()
        for txid, tx in self.mempool.items():
            self.db.put_mempool(txid, tx.to_dict(include_sigs=True))
        self._evict_mempool()

    def _mempool_bytes(self) -> int:
        return sum(tx.estimate_size() for tx in self.mempool.values())

    def _evict_mempool(self) -> None:
        max_txs = int(self._param("MAX_MEMPOOL_TXS") or 0)
        max_bytes = int(self._param("MAX_MEMPOOL_BYTES") or 0)
        if max_txs <= 0 and max_bytes <= 0:
            return
        while True:
            over_count = max_txs > 0 and len(self.mempool) > max_txs
            over_bytes = max_bytes > 0 and self._mempool_bytes() > max_bytes
            if not over_count and not over_bytes:
                break
            if not self.mempool:
                break
            worst = min(self.mempool.values(), key=lambda t: self._tx_fee_rate(t, self.utxo))
            self.mempool.pop(worst.txid, None)
            self.db.delete_mempool(worst.txid)

    def add_tx(self, tx: Transaction) -> bool:
        if tx.is_coinbase and tx.tx_type != "slash":
            return False
        if tx.txid in self.mempool:
            return False
        min_relay = int(self._param("MIN_RELAY_FEE_RATE") or MIN_RELAY_FEE_RATE)
        if tx.tx_type == "slash":
            penalty = self._validate_slash_tx(tx, self.stakes)
            if penalty is None:
                return False
            if sum(o.amount for o in tx.outputs) > penalty:
                return False
        if not tx.validate(self.utxo):
            return False
        if tx.tx_type in ("contract_create", "contract_call"):
            min_gas_price = self._calc_next_base_gas_price(self.best_tip) if self.best_tip else int(self._param("BASE_GAS_PRICE") or BASE_GAS_PRICE)
            if tx.gas_limit <= 0 or tx.gas_price < min_gas_price:
                return False
        if tx.tx_type in ("validator_register", "validator_update"):
            sender = self._tx_sender(tx)
            try:
                self._apply_validator_tx(dict(self.validator_registry), sender, tx.payload or {}, update=tx.tx_type.endswith("update"))
            except Exception:
                return False
        if tx.tx_type == "gov_update":
            sender = self._tx_sender(tx)
            try:
                self._apply_gov_update(dict(self.params), sender, tx.payload or {})
            except Exception:
                return False
        fee_rate = self._tx_fee_rate(tx, self.utxo)
        if fee_rate < min_relay:
            return False

        new_inputs = {(i.prev_txid, i.output_index) for i in tx.inputs}
        conflicts = []
        for m in self.mempool.values():
            for inp in m.inputs:
                if (inp.prev_txid, inp.output_index) in new_inputs:
                    conflicts.append(m)
                    break
        if conflicts:
            old_fee = sum(self._fee_for_tx(m, self.utxo) for m in conflicts)
            old_size = sum(max(m.estimate_size(), 1) for m in conflicts)
            old_rate = old_fee / old_size if old_size else 0
            new_fee = self._fee_for_tx(tx, self.utxo)
            new_rate = fee_rate
            min_factor = float(self._param("RBF_MIN_FACTOR") or RBF_MIN_FACTOR)
            min_delta = int(self._param("RBF_MIN_DELTA") or RBF_MIN_DELTA)
            if new_fee < old_fee + min_delta or new_rate < old_rate * min_factor:
                return False
            for m in conflicts:
                self.mempool.pop(m.txid, None)
                self.db.delete_mempool(m.txid)
        self.mempool[tx.txid] = tx
        self.db.put_mempool(tx.txid, tx.to_dict(include_sigs=True))
        self._evict_mempool()
        return True

    def _snapshot_dir(self) -> str:
        return os.path.join(self.data_dir, "snapshots")

    def _snapshot_path(self, height: int, tip: str) -> str:
        return os.path.join(self._snapshot_dir(), f"snapshot_{height}_{tip}.json.gz")

    def _maybe_write_snapshot(self) -> None:
        if not self.snapshot_enabled or not self.best_tip:
            return
        if self.height <= 0 or self.snapshot_interval <= 0:
            return
        if self.height % self.snapshot_interval != 0:
            return
        path = self._snapshot_path(self.height, self.best_tip)
        if os.path.exists(path):
            return
        try:
            os.makedirs(self._snapshot_dir(), exist_ok=True)
            self.save_snapshot(path)
            self.snapshot = self.load_snapshot(path)
        except Exception:
            pass

    def _prune_blocks(self) -> None:
        if PRUNE_DEPTH <= 0 or not self.best_tip:
            return
        finality = int(self._param("FINALITY_DEPTH") or FINALITY_DEPTH)
        keep_depth = max(PRUNE_DEPTH, finality)
        keep_height = max(0, self.height - keep_depth)
        if self.snapshot and isinstance(self.snapshot, dict):
            snap_height = int(self.snapshot.get("height", 0))
            if snap_height > keep_height:
                keep_height = snap_height
        if keep_height <= 0:
            return
        self.db.prune_blocks(keep_height)
        for h, meta in list(self.index.items()):
            if meta.height < keep_height:
                self.index.pop(h, None)
        # drop orphan chains that reference pruned parents
        self.orphans = {h: b for h, b in self.orphans.items() if h in self.index}
        self.orphan_by_parent = {
            p: hs for p, hs in self.orphan_by_parent.items() if p in self.index
        }

    def _load_latest_snapshot(self) -> Optional[dict]:
        if not self.snapshot_enabled:
            return None
        try:
            if not os.path.isdir(self._snapshot_dir()):
                return None
            best = None
            for name in os.listdir(self._snapshot_dir()):
                if not name.startswith("snapshot_") or not name.endswith(".json.gz"):
                    continue
                parts = name.split("_")
                if len(parts) < 3:
                    continue
                try:
                    height = int(parts[1])
                except Exception:
                    continue
                if best is None or height > best[0]:
                    best = (height, os.path.join(self._snapshot_dir(), name))
            if not best:
                return None
            return self.load_snapshot(best[1])
        except Exception:
            return None

    def snapshot_dict(self) -> dict:
        block = self.get_block(self.best_tip) if self.best_tip else None
        if not block:
            raise RuntimeError("no tip to snapshot")
        return {
            "version": 1,
            "height": self.height,
            "tip": self.best_tip,
            "params": dict(self.params),
            "validators": list(self.validators),
            "validator_registry": dict(self.validator_registry),
            "total_issued": self.total_issued,
            "base_gas_price_next": self.base_gas_price_next,
            "utxo": {k: v.to_dict() for k, v in self.utxo.items()},
            "stakes": dict(self.stakes),
            "contracts": {
                cid: {"creator": c.creator, "code": c.code, "storage": c.storage}
                for cid, c in self.contracts.items()
            },
            "block": block.to_dict(),
        }

    def _snapshot_payload(self, snapshot: dict) -> dict:
        return {k: v for k, v in snapshot.items() if k not in ("signature", "signer_pubkey", "signer_id")}

    def sign_snapshot(self, snapshot: dict, priv: dict, pub: dict) -> dict:
        payload = self._snapshot_payload(snapshot)
        msg = sha256(json_dumps(payload).encode())
        sig = crypto.sign(msg, priv, "ecdsa")
        snapshot["signer_pubkey"] = crypto.key_to_hex(pub, "ecdsa")
        snapshot["signer_id"] = crypto.address_from_pubkey(pub, "ecdsa")
        snapshot["signature"] = sig
        return snapshot

    def verify_snapshot(self, snapshot: dict) -> bool:
        sig = snapshot.get("signature")
        pub_hex = snapshot.get("signer_pubkey")
        signer_id = snapshot.get("signer_id")
        if not sig or not isinstance(pub_hex, dict) or not signer_id:
            return False
        try:
            pub = crypto.key_from_hex(pub_hex, "ecdsa")
            calc_id = crypto.address_from_pubkey(pub, "ecdsa")
        except Exception:
            return False
        if calc_id != signer_id:
            return False
        payload = self._snapshot_payload(snapshot)
        msg = sha256(json_dumps(payload).encode())
        return crypto.verify(msg, sig, pub, "ecdsa")

    def _trusted_snapshot_signers(self) -> List[str]:
        trusted: List[str] = []
        raw = os.getenv("SCRATCHCHAIN_SNAPSHOT_TRUST", "").strip()
        if raw:
            trusted.extend([item.strip() for item in raw.split(",") if item.strip()])
        path = os.path.join(self.data_dir, "snapshot_trust.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.loads(f.read())
            if isinstance(obj, dict):
                trusted.extend(obj.get("trusted", []))
            elif isinstance(obj, list):
                trusted.extend(obj)
        except Exception:
            pass
        return list({t for t in trusted if t})

    def save_snapshot(self, path: str, snapshot: Optional[dict] = None) -> None:
        data = snapshot or self.snapshot_dict()
        raw = json.dumps(data).encode()
        with gzip.open(path, "wb") as f:
            f.write(raw)

    def load_snapshot(self, path: str) -> dict:
        with gzip.open(path, "rb") as f:
            raw = f.read()
        return json.loads(raw.decode())

    def get_snapshot_blob(self, height: int) -> Optional[bytes]:
        if not self.snapshot_enabled:
            return None
        if not os.path.isdir(self._snapshot_dir()):
            return None
        best_path = None
        best_height = -1
        for name in os.listdir(self._snapshot_dir()):
            if not name.startswith("snapshot_") or not name.endswith(".json.gz"):
                continue
            parts = name.split("_")
            if len(parts) < 3:
                continue
            try:
                h = int(parts[1])
            except Exception:
                continue
            if height >= 0 and h > height:
                continue
            if h > best_height:
                best_height = h
                best_path = os.path.join(self._snapshot_dir(), name)
        if not best_path:
            return None
        with open(best_path, "rb") as f:
            return f.read()

    def apply_snapshot_blob(self, raw: bytes) -> None:
        data = gzip.decompress(raw)
        snapshot = json.loads(data.decode())
        self.apply_snapshot(snapshot)

    def apply_snapshot(self, snapshot: dict) -> None:
        if not isinstance(snapshot, dict):
            raise RuntimeError("invalid snapshot")
        if snapshot.get("signature"):
            if not self.verify_snapshot(snapshot):
                raise RuntimeError("invalid snapshot signature")
            trusted = self._trusted_snapshot_signers()
            if trusted and snapshot.get("signer_id") not in trusted:
                raise RuntimeError("untrusted snapshot signer")
        elif REQUIRE_SIGNED_SNAPSHOT:
            raise RuntimeError("snapshot signature required")
        block_data = snapshot.get("block")
        if not block_data:
            raise RuntimeError("snapshot missing block")
        block = Block.from_dict(block_data)
        if snapshot.get("tip") and snapshot.get("tip") != block.hash:
            raise RuntimeError("snapshot tip mismatch")

        self.db.reset_chain()
        self.mempool = {}
        self.orphans = {}
        self.orphan_by_parent = {}
        self.index = {}
        self._store_block(block, block.header.prev_hash, 0)
        self.best_tip = block.hash
        self.best_work = self.index[block.hash].work
        self.db.set_meta("best_tip", block.hash)
        self.db.set_meta("difficulty", str(block.header.difficulty))

        self.utxo = {k: TxOutput.from_dict(v) for k, v in snapshot.get("utxo", {}).items()}
        self.stakes = {k: int(v) for k, v in snapshot.get("stakes", {}).items()}
        self.contracts = {
            cid: Contract(cid, c["creator"], list(c["code"]), dict(c["storage"]))
            for cid, c in snapshot.get("contracts", {}).items()
        }
        self.validator_registry = dict(snapshot.get("validator_registry", {}))
        self.params = dict(DEFAULT_PARAMS)
        self.params.update(snapshot.get("params", {}))
        self.total_issued = int(snapshot.get("total_issued", 0))
        self.validators = self._compute_validators(self.stakes, self.validator_registry)
        self.base_gas_price_next = int(snapshot.get("base_gas_price_next", self._param("BASE_GAS_PRICE")))
        self.snapshot = snapshot

        self._persist_contracts()
        self._persist_validators()
        self._rebuild_indexes(self.best_tip)

    def mine_block(
        self,
        miner_address: str,
        miner_priv: Optional[dict] = None,
        miner_algo: str = "ecdsa",
    ) -> Optional[Block]:
        if not self.best_tip:
            return None

        reward = self.block_reward(self.index[self.best_tip].height + 1)
        max_supply = int(self._param("MAX_SUPPLY") or MAX_SUPPLY)
        remaining = max(0, max_supply - self.total_issued)
        reward = min(reward, remaining)
        coinbase = create_coinbase(miner_address, reward, "miner")
        base_size = coinbase.estimate_size()
        selected, fees, block_gas, _block_size = self._select_mempool_txs(base_size)
        coinbase = create_coinbase(miner_address, reward + fees, "miner")
        height = self.index[self.best_tip].height + 1
        difficulty = self._calc_next_difficulty(self.best_tip)

        validator_pubkey = {}
        validator_sig_algo = ""
        if CONSENSUS == "pos":
            expected_validator = self._select_validator(self.best_tip, self.stakes, self.validators)
            if expected_validator and miner_address != expected_validator:
                return None
            if not miner_priv:
                return None
            validator_pubkey = crypto.key_to_hex(crypto.public_key(miner_priv, miner_algo), miner_algo)
            validator_sig_algo = miner_algo

        base_gas_price = self._calc_next_base_gas_price(self.best_tip)
        block = Block.build(
            self.best_tip,
            height,
            difficulty,
            [coinbase] + selected,
            base_gas_price=base_gas_price,
            gas_used=block_gas,
            validator=miner_address if CONSENSUS == "pos" else "",
            validator_pubkey=validator_pubkey,
            validator_sig_algo=validator_sig_algo,
        )

        if CONSENSUS == "pow":
            block.mine()
        else:
            block.header.signature = crypto.sign(block.hash, miner_priv, miner_algo)

        status, _ = self.add_block(block)
        if status != "accepted":
            return None

        for tx in selected:
            self.mempool.pop(tx.txid, None)
            self.db.delete_mempool(tx.txid)
        return block

    def get_tx(self, txid: str) -> Optional[dict]:
        return self.db.get_tx(txid)

    def get_receipt(self, txid: str) -> Optional[dict]:
        return self.db.get_receipt(txid)

    def get_history(self, address: str, limit: int = 50, offset: int = 0, direction: Optional[str] = None) -> list:
        return self.db.get_address_history(address, limit, offset, direction)

    def get_validators(self) -> list:
        out = []
        if self.validator_registry:
            for addr, meta in self.validator_registry.items():
                out.append(
                    {
                        "address": addr,
                        "stake": self.stakes.get(addr, 0),
                        "active": addr in self.validators,
                        "meta": meta,
                    }
                )
        else:
            for addr, amount in self.stakes.items():
                out.append({"address": addr, "stake": amount, "active": addr in self.validators, "meta": {}})
        return sorted(out, key=lambda x: (-x["stake"], x["address"]))

    def get_governance(self) -> dict:
        return {"gov_address": GOV_ADDRESS, "params": dict(self.params)}

    def metrics(self) -> dict:
        heights = self._chain_hashes(self.best_tip) if self.best_tip else []
        window = 20
        times = []
        for h in heights[-window:]:
            block = self.get_block(h)
            if block:
                times.append(block.header.timestamp)
        avg_block_time = 0
        if len(times) >= 2:
            deltas = [b - a for a, b in zip(times, times[1:]) if b >= a]
            if deltas:
                avg_block_time = sum(deltas) / len(deltas)
        return {
            "height": self.height,
            "mempool_bytes": self._mempool_bytes(),
            "utxo_set": len(self.utxo),
            "contracts": len(self.contracts),
            "validators": len(self.validators),
            "avg_block_time": avg_block_time,
            "blocks_known": len(self.index),
            "forks": max(0, len(self.index) - (self.height + 1)) if self.height >= 0 else len(self.index),
        }

    def get_balance(self, address: str) -> int:
        total = 0
        for out in self.utxo.values():
            if out.address == address and not out.stake:
                total += out.amount
        return total

    def get_stake(self, address: str) -> int:
        return self.stakes.get(address, 0)

    def build_transfer_tx(self, wallet, to_addr: str, amount: int, fee: int = 0) -> Optional[Transaction]:
        return self._build_tx(wallet, [TxOutput(amount=amount, address=to_addr)], fee=fee)

    def build_stake_tx(self, wallet, amount: int, fee: int = 0) -> Optional[Transaction]:
        out = TxOutput(amount=amount, address=wallet.address, stake=True)
        return self._build_tx(wallet, [out], tx_type="stake", fee=fee)

    def build_unstake_tx(self, wallet, amount: int, fee: int = 0) -> Optional[Transaction]:
        # spend staked UTXOs
        return self._build_tx(
            wallet,
            [TxOutput(amount=amount, address=wallet.address)],
            tx_type="unstake",
            include_stake_inputs=True,
            fee=fee,
        )

    def build_contract_create_tx(self, wallet, code: List[str], storage: Dict[str, int], gas_limit: int, gas_price: int) -> Optional[Transaction]:
        payload = {"code": code, "storage": storage}
        return self._build_contract_tx(wallet, "contract_create", payload, gas_limit, gas_price)

    def build_slash_tx(self, header_a: dict, header_b: dict, reward_to: Optional[str] = None) -> Optional[Transaction]:
        payload = {"header_a": header_a, "header_b": header_b}
        tx = Transaction(inputs=[], outputs=[], tx_type="slash", payload=payload)
        amount = self._validate_slash_tx(tx, self.stakes)
        if amount is None:
            return None
        if reward_to:
            tx.outputs.append(TxOutput(amount=amount, address=reward_to))
        return tx

    def build_contract_call_tx(self, wallet, contract_id: str, calldata: List[int], gas_limit: int, gas_price: int) -> Optional[Transaction]:
        payload = {"contract_id": contract_id, "calldata": calldata}
        return self._build_contract_tx(wallet, "contract_call", payload, gas_limit, gas_price)

    def build_validator_register_tx(
        self,
        wallet,
        name: str = "",
        website: str = "",
        commission: Optional[object] = None,
        fee: Optional[int] = None,
    ) -> Optional[Transaction]:
        pub_hex = crypto.key_to_hex(crypto.public_key(wallet.priv, wallet.algo), wallet.algo)
        payload = {"pubkey": pub_hex}
        if name:
            payload["name"] = name
        if website:
            payload["website"] = website
        if commission is not None:
            payload["commission"] = commission
        return self._build_tx(wallet, [], tx_type="validator_register", payload=payload, fee=fee or META_TX_FEE)

    def build_validator_update_tx(
        self,
        wallet,
        name: str = "",
        website: str = "",
        commission: Optional[object] = None,
        fee: Optional[int] = None,
    ) -> Optional[Transaction]:
        pub_hex = crypto.key_to_hex(crypto.public_key(wallet.priv, wallet.algo), wallet.algo)
        payload = {"pubkey": pub_hex}
        if name:
            payload["name"] = name
        if website:
            payload["website"] = website
        if commission is not None:
            payload["commission"] = commission
        return self._build_tx(wallet, [], tx_type="validator_update", payload=payload, fee=fee or META_TX_FEE)

    def build_gov_update_tx(self, wallet, params: Dict[str, object], fee: Optional[int] = None) -> Optional[Transaction]:
        if GOV_ADDRESS and wallet.address != GOV_ADDRESS:
            return None
        payload = {"params": params}
        return self._build_tx(wallet, [], tx_type="gov_update", payload=payload, fee=fee or META_TX_FEE)

    def _build_contract_tx(self, wallet, tx_type: str, payload: dict, gas_limit: int, gas_price: int) -> Optional[Transaction]:
        fee_target = gas_limit * gas_price
        if fee_target <= 0:
            return None
        inputs, total = self._select_utxos(wallet.address, fee_target)
        if total < fee_target:
            return None
        outputs: List[TxOutput] = []
        change = total - fee_target
        if change > 0:
            outputs.append(TxOutput(amount=change, address=wallet.address))
        tx = Transaction(inputs=inputs, outputs=outputs, tx_type=tx_type, gas_limit=gas_limit, gas_price=gas_price, payload=payload)
        tx.sign(wallet.priv, wallet.algo)
        return tx

    def _build_tx(
        self,
        wallet,
        outputs: List[TxOutput],
        tx_type: str = "transfer",
        include_stake_inputs: bool = False,
        payload: Optional[dict] = None,
        fee: int = 0,
    ) -> Optional[Transaction]:
        total_out = sum(o.amount for o in outputs) + fee
        if total_out < 0:
            return None
        inputs, total = self._select_utxos(wallet.address, total_out, include_stake_inputs)
        if total < total_out:
            return None
        change = total - total_out
        if change > 0:
            outputs.append(TxOutput(amount=change, address=wallet.address))
        tx = Transaction(inputs=inputs, outputs=outputs, tx_type=tx_type, payload=payload)
        tx.sign(wallet.priv, wallet.algo)
        return tx

    def _select_utxos(self, address: str, amount: int, include_stake: bool = False) -> Tuple[List[TxInput], int]:
        spendable = []
        total = 0
        for key, out in self.utxo.items():
            if out.address != address:
                continue
            if include_stake and not out.stake:
                continue
            if not include_stake and out.stake:
                continue
            txid, idx = key.split(":")
            spendable.append((txid, int(idx), out))
            total += out.amount
            if total >= amount:
                break
        inputs = [TxInput(prev_txid=txid, output_index=idx) for txid, idx, _ in spendable]
        return inputs, total

    def get_headers(self, start_height: int, count: int = 200) -> List[dict]:
        if not self.best_tip:
            return []
        hashes = self._chain_hashes(self.best_tip)
        start = max(0, start_height)
        end = min(start + count, len(hashes))
        headers = []
        for idx in range(start, end):
            block = self.get_block(hashes[idx])
            if block:
                headers.append(block.header.to_dict())
        return headers

    def dump_chain(self) -> List[dict]:
        blocks = []
        if not self.best_tip:
            return blocks
        for h in self._chain_hashes(self.best_tip):
            data = self.db.get_block(h)
            if data:
                blocks.append(data)
        return blocks
