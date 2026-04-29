"""
LuauShield VM Opcodes
======================
Defines the custom instruction set for the virtual machine.
Opcode values are randomized per-build (polymorphic).
"""

import random
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class OpcodeInfo:
    """Information about a single VM opcode."""
    name: str           # Human-readable name
    value: int          # Numeric opcode value (randomized per build)
    operand_count: int  # Number of operands following the opcode


# All supported VM instructions
INSTRUCTION_NAMES = [
    # Stack operations
    ('PUSH_CONST', 1),     # Push constant from pool: [idx]
    ('PUSH_LOCAL', 1),     # Push local variable: [slot]
    ('SET_LOCAL', 1),      # Pop -> local variable: [slot]
    ('PUSH_UPVAL', 1),     # Push upvalue: [idx]
    ('SET_UPVAL', 1),      # Pop -> upvalue: [idx]
    ('PUSH_NIL', 0),       # Push nil
    ('PUSH_TRUE', 0),      # Push true
    ('PUSH_FALSE', 0),     # Push false
    ('POP', 0),            # Discard top of stack

    # Arithmetic
    ('ADD', 0),            # Pop 2, push sum
    ('SUB', 0),            # Pop 2, push difference
    ('MUL', 0),            # Pop 2, push product
    ('DIV', 0),            # Pop 2, push quotient
    ('MOD', 0),            # Pop 2, push remainder
    ('POW', 0),            # Pop 2, push power
    ('UNM', 0),            # Negate top of stack
    ('CONCAT', 1),         # Concatenate N strings: [count]

    # Comparison
    ('EQ', 0),             # Pop 2, push ==
    ('LT', 0),             # Pop 2, push <
    ('LE', 0),             # Pop 2, push <=
    ('NOT', 0),            # Logical not
    ('LEN', 0),            # Length operator #

    # Control flow
    ('JMP', 1),            # Unconditional jump: [offset]
    ('JMP_FALSE', 1),      # Jump if falsy: [offset]
    ('JMP_TRUE', 1),       # Jump if truthy: [offset]

    # Functions
    ('CALL', 2),           # Call function: [argc, retc]
    ('RETURN', 1),         # Return values: [count]
    ('CLOSURE', 1),        # Create closure: [proto_idx]
    ('VARARG', 1),         # Push varargs: [count]

    # Globals
    ('GET_GLOBAL', 1),     # Push global: [const_idx for name]
    ('SET_GLOBAL', 1),     # Pop -> global: [const_idx for name]

    # Tables
    ('NEW_TABLE', 2),      # Create table: [array_size, hash_size]
    ('GET_TABLE', 0),      # Pop key, pop table, push table[key]
    ('SET_TABLE', 0),      # Pop value, pop key, pop table, table[key]=value
    ('SET_LIST', 2),       # Set list entries: [start_idx, count]

    # Special
    ('MOVE', 2),           # Copy local: [dest, src]
    ('NOP', 0),            # No operation (junk instruction)
]


class OpcodeMap:
    """
    Manages the mapping between instruction names and their numeric values.
    Values are randomized per-build for polymorphism.
    """

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.opcodes: Dict[str, OpcodeInfo] = {}
        self._by_value: Dict[int, OpcodeInfo] = {}
        self._generate_mapping()

    def _generate_mapping(self):
        """Generate randomized opcode values for this build."""
        # Generate unique random values for each instruction
        values = self.rng.sample(range(1, 256), len(INSTRUCTION_NAMES))

        for (name, operand_count), value in zip(INSTRUCTION_NAMES, values):
            info = OpcodeInfo(name=name, value=value, operand_count=operand_count)
            self.opcodes[name] = info
            self._by_value[value] = info

    def get(self, name: str) -> int:
        """Get the numeric opcode value for an instruction name."""
        return self.opcodes[name].value

    def get_info(self, name: str) -> OpcodeInfo:
        """Get full opcode info by name."""
        return self.opcodes[name]

    def from_value(self, value: int) -> OpcodeInfo:
        """Look up opcode info by numeric value."""
        return self._by_value.get(value)

    def get_all(self) -> Dict[str, OpcodeInfo]:
        """Get all opcode mappings."""
        return dict(self.opcodes)

    def generate_luau_constants(self, name_gen) -> str:
        """Generate Luau local declarations for all opcode constants."""
        lines = []
        # Shuffle the order for additional obfuscation
        items = list(self.opcodes.items())
        self.rng.shuffle(items)

        opcode_names = {}
        for name, info in items:
            var_name = name_gen.gen_name()
            opcode_names[name] = var_name
            lines.append(f"local {var_name}={info.value}")

        return '\n'.join(lines), opcode_names
