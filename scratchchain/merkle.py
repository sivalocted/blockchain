from typing import List, Tuple

from .utils import sha256


def merkle_root(items: List[str]) -> str:
    if not items:
        return sha256(b"")
    level = items[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            combined = (level[i] + level[i + 1]).encode()
            next_level.append(sha256(combined))
        level = next_level
    return level[0]


def merkle_proof(items: List[str], index: int) -> List[Tuple[str, str]]:
    if index < 0 or index >= len(items):
        raise ValueError("index out of range")
    proof: List[Tuple[str, str]] = []
    level = items[:]
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling_index = idx ^ 1
        sibling = level[sibling_index]
        side = "left" if sibling_index < idx else "right"
        proof.append((sibling, side))
        next_level = []
        for i in range(0, len(level), 2):
            combined = (level[i] + level[i + 1]).encode()
            next_level.append(sha256(combined))
        level = next_level
        idx = idx // 2
    return proof


def verify_merkle_proof(leaf: str, proof: List[Tuple[str, str]], root: str) -> bool:
    h = leaf
    for sibling, side in proof:
        if side == "left":
            h = sha256((sibling + h).encode())
        else:
            h = sha256((h + sibling).encode())
    return h == root
