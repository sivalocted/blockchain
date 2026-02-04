from dataclasses import dataclass, field
from typing import Dict, List, Tuple


GAS_COSTS = {
    "PUSH": 1,
    "ADD": 1,
    "SUB": 1,
    "MUL": 2,
    "DIV": 2,
    "MOD": 2,
    "EQ": 1,
    "LT": 1,
    "GT": 1,
    "AND": 1,
    "OR": 1,
    "NOT": 1,
    "DUP": 1,
    "SWAP": 1,
    "POP": 1,
    "LOAD": 2,
    "STORE": 5,
    "CALLDATALOAD": 1,
    "SENDER": 1,
    "LOG": 1,
    "STOP": 0,
    "REVERT": 0,
}


@dataclass
class Contract:
    contract_id: str
    creator: str
    code: List[str]
    storage: Dict[str, int] = field(default_factory=dict)


class ContractEngine:
    def execute(
        self,
        contract: Contract,
        calldata: List[int],
        sender_int: int,
        gas_limit: int,
    ) -> Tuple[int, List[int], int]:
        stack: List[int] = []
        logs: List[int] = []
        gas_used = 0

        pc = 0
        while pc < len(contract.code):
            raw = contract.code[pc]
            parts = raw.strip().split()
            if not parts:
                pc += 1
                continue
            op = parts[0].upper()
            gas_used += GAS_COSTS.get(op, 1)
            if gas_used > gas_limit:
                raise RuntimeError("out of gas")

            if op == "PUSH":
                if len(parts) != 2:
                    raise RuntimeError("PUSH requires value")
                stack.append(int(parts[1]))
            elif op == "ADD":
                b = stack.pop(); a = stack.pop(); stack.append(a + b)
            elif op == "SUB":
                b = stack.pop(); a = stack.pop(); stack.append(a - b)
            elif op == "MUL":
                b = stack.pop(); a = stack.pop(); stack.append(a * b)
            elif op == "DIV":
                b = stack.pop(); a = stack.pop(); stack.append(0 if b == 0 else a // b)
            elif op == "MOD":
                b = stack.pop(); a = stack.pop(); stack.append(0 if b == 0 else a % b)
            elif op == "EQ":
                b = stack.pop(); a = stack.pop(); stack.append(1 if a == b else 0)
            elif op == "LT":
                b = stack.pop(); a = stack.pop(); stack.append(1 if a < b else 0)
            elif op == "GT":
                b = stack.pop(); a = stack.pop(); stack.append(1 if a > b else 0)
            elif op == "AND":
                b = stack.pop(); a = stack.pop(); stack.append(1 if a and b else 0)
            elif op == "OR":
                b = stack.pop(); a = stack.pop(); stack.append(1 if a or b else 0)
            elif op == "NOT":
                a = stack.pop(); stack.append(0 if a else 1)
            elif op == "DUP":
                stack.append(stack[-1])
            elif op == "SWAP":
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op == "POP":
                stack.pop()
            elif op == "LOAD":
                if len(parts) != 2:
                    raise RuntimeError("LOAD requires key")
                key = parts[1]
                stack.append(int(contract.storage.get(key, 0)))
            elif op == "STORE":
                if len(parts) != 2:
                    raise RuntimeError("STORE requires key")
                key = parts[1]
                value = stack.pop()
                contract.storage[key] = int(value)
            elif op == "CALLDATALOAD":
                if len(parts) != 2:
                    raise RuntimeError("CALLDATALOAD requires index")
                idx = int(parts[1])
                stack.append(int(calldata[idx]) if idx < len(calldata) else 0)
            elif op == "SENDER":
                stack.append(sender_int)
            elif op == "LOG":
                logs.append(stack.pop())
            elif op == "STOP":
                break
            elif op == "REVERT":
                raise RuntimeError("revert")
            else:
                raise RuntimeError(f"unknown opcode {op}")
            pc += 1

        ret = stack[-1] if stack else 0
        return gas_used, logs, ret


def compile_source(source: str) -> List[str]:
    code: List[str] = []
    for raw in source.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        code.append(line)
    return code
