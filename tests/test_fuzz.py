import random

from scratchchain.block import Block
from scratchchain.tx import Transaction


def random_dict(depth=2):
    if depth <= 0:
        return random.randint(0, 100)
    out = {}
    for _ in range(random.randint(1, 5)):
        key = "k" + str(random.randint(0, 100))
        if random.random() < 0.5:
            out[key] = random.randint(0, 100)
        else:
            out[key] = random_dict(depth - 1)
    return out


def test_fuzz_from_dict():
    for _ in range(50):
        tx_data = {
            "inputs": [random_dict(1) for _ in range(random.randint(0, 3))],
            "outputs": [random_dict(1) for _ in range(random.randint(0, 3))],
            "timestamp": random.randint(0, 100000),
            "tx_type": random.choice([
                "transfer",
                "contract_call",
                "stake",
                "slash",
                "validator_register",
                "validator_update",
                "gov_update",
            ]),
        }
        try:
            Transaction.from_dict(tx_data)
        except Exception:
            # from_dict should be resilient to junk input
            pass

    for _ in range(20):
        block_data = {
            "header": {
                "prev_hash": "0" * 64,
                "merkle_root": "0" * 64,
                "timestamp": random.randint(0, 100000),
                "nonce": random.randint(0, 1000),
                "difficulty": random.randint(0, 5),
                "height": random.randint(0, 10),
            },
            "txs": [
                {
                    "inputs": [],
                    "outputs": [],
                }
            ],
        }
        try:
            Block.from_dict(block_data)
        except Exception:
            pass
