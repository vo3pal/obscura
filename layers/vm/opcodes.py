"""
Obscura VM Opcodes
======================
Register-based instruction set with per-build randomized values AND
multiple aliases per semantic opcode (multiple distinct byte values that
map to the same handler). Defeats opcode-frequency analysis.
"""

import random
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .instruction import (
    FORMAT_NONE, FORMAT_A, FORMAT_AB, FORMAT_ABC,
    FORMAT_ABX, FORMAT_ASBX, FORMAT_SBX, instruction_size,
)


# (name, format, default_alias_count)
INSTRUCTION_DEFS: List[Tuple[str, str, int]] = [
    # Movement / loading
    ('MOVE',      FORMAT_AB,   2),
    ('LOADK',     FORMAT_ABX,  3),
    ('LOADBOOL',  FORMAT_ABC,  1),
    ('LOADNIL',   FORMAT_AB,   1),

    # Upvalues / globals
    ('GETUPVAL',  FORMAT_AB,   2),
    ('SETUPVAL',  FORMAT_AB,   2),
    ('GETGLOBAL', FORMAT_ABX,  2),
    ('SETGLOBAL', FORMAT_ABX,  2),

    # Tables
    ('NEWTABLE',  FORMAT_ABC,  1),
    ('GETTABLE',  FORMAT_ABC,  2),
    ('SETTABLE',  FORMAT_ABC,  2),
    ('GETTABLEK', FORMAT_ABC,  2),
    ('SETTABLEK', FORMAT_ABC,  2),
    ('SELF',      FORMAT_ABC,  1),
    ('SETLIST',   FORMAT_ABC,  1),

    # Arithmetic
    ('ADD',       FORMAT_ABC,  3),
    ('SUB',       FORMAT_ABC,  3),
    ('MUL',       FORMAT_ABC,  2),
    ('DIV',       FORMAT_ABC,  2),
    ('MOD',       FORMAT_ABC,  1),
    ('POW',       FORMAT_ABC,  1),
    ('UNM',       FORMAT_AB,   1),
    ('NOT',       FORMAT_AB,   1),
    ('LEN',       FORMAT_AB,   1),
    ('CONCAT',    FORMAT_ABC,  1),

    # Comparison + conditional jump
    ('EQ',        FORMAT_ABC,  2),
    ('LT',        FORMAT_ABC,  2),
    ('LE',        FORMAT_ABC,  1),
    ('TEST',      FORMAT_AB,   2),
    ('TESTSET',   FORMAT_ABC,  1),

    # Control flow
    ('JMP',       FORMAT_SBX,  3),
    ('CALL',      FORMAT_ABC,  3),
    ('TAILCALL',  FORMAT_ABC,  1),
    ('RETURN',    FORMAT_AB,   2),

    # Loop helpers
    ('FORPREP',   FORMAT_ASBX, 1),
    ('FORLOOP',   FORMAT_ASBX, 1),
    ('TFORLOOP',  FORMAT_ABC,  1),

    # Closures / varargs
    ('CLOSURE',   FORMAT_ABX,  2),
    ('VARARG',    FORMAT_AB,   1),

    # Captured-local boxes (proper closure semantics)
    ('MKBOX',     FORMAT_AB,   1),  # R[A] := {R[B]}      box wraps a value
    ('GETBOX',    FORMAT_AB,   2),  # R[A] := R[B][1]     read boxed local
    ('SETBOX',    FORMAT_AB,   2),  # R[A][1] := R[B]     write boxed local

    # No-op
    ('NOP',       FORMAT_NONE, 2),
]


@dataclass
class OpcodeInfo:
    name: str
    fmt: str
    aliases: List[int] = field(default_factory=list)

    @property
    def primary(self) -> int:
        return self.aliases[0]


class OpcodeMap:
    """
    Maps semantic opcode names to one or more byte values (aliases).
    All byte values are unique across the whole map.
    """

    _RESERVED = {0}

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.opcodes: Dict[str, OpcodeInfo] = {}
        self._by_value: Dict[int, OpcodeInfo] = {}
        self._generate()

    def _generate(self):
        total_aliases = sum(count for _, _, count in INSTRUCTION_DEFS)
        available = [v for v in range(1, 256) if v not in self._RESERVED]
        if total_aliases > len(available):
            raise RuntimeError(f"Too many opcode aliases: {total_aliases} > {len(available)}")

        chosen = self.rng.sample(available, total_aliases)
        idx = 0
        for name, fmt, count in INSTRUCTION_DEFS:
            aliases = chosen[idx:idx + count]
            idx += count
            info = OpcodeInfo(name=name, fmt=fmt, aliases=aliases)
            self.opcodes[name] = info
            for v in aliases:
                self._by_value[v] = info

    def get(self, name: str) -> OpcodeInfo:
        return self.opcodes[name]

    def primary(self, name: str) -> int:
        return self.opcodes[name].primary

    def random_alias(self, name: str) -> int:
        return self.rng.choice(self.opcodes[name].aliases)

    def fmt_of(self, name: str) -> str:
        return self.opcodes[name].fmt

    def all_aliases(self) -> List[Tuple[int, OpcodeInfo]]:
        return list(self._by_value.items())

    def fmt_of_byte(self, byte: int) -> str:
        return self._by_value[byte].fmt

    def name_of_byte(self, byte: int) -> str:
        return self._by_value[byte].name
