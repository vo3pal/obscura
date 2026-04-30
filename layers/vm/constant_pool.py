"""
Obscura VM Constant Pool
==============================
Holds and deduplicates literal values (numbers, strings, booleans, nil)
and provides per-build XOR encryption for string content.

The interpreter receives the pool as a Luau table literal where strings
have been XOR-encrypted with a rolling key, and decrypts them lazily on
first use (or eagerly at startup, depending on configuration).
"""

import random
from typing import List, Any, Dict


class ConstantPool:
    """Manages deduplicated literal constants for a VM build."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.constants: List[Any] = []
        self._index: Dict[Any, int] = {}
        # Per-build rolling XOR key (4-16 bytes)
        key_len = self.rng.randint(4, 16)
        self.key: List[int] = [self.rng.randint(1, 255) for _ in range(key_len)]

    # ---- Insertion ----

    def add(self, value: Any) -> int:
        key = self._make_key(value)
        if key in self._index:
            return self._index[key]
        idx = len(self.constants)
        self.constants.append(value)
        self._index[key] = idx
        return idx

    def _make_key(self, value: Any) -> Any:
        if value is None:
            return ('nil',)
        if isinstance(value, bool):
            return ('bool', value)
        if isinstance(value, (int, float)):
            return ('num', float(value))
        if isinstance(value, str):
            return ('str', value)
        return ('other', repr(value))

    # ---- Encryption ----

    def encrypt_string(self, s: str) -> str:
        """Return an escaped Luau string literal body with rolling-XOR encryption."""
        klen = len(self.key)
        out_chars = []
        for i, byte in enumerate(s.encode('utf-8')):
            k = self.key[i % klen]
            out_chars.append(f"\\{byte ^ k}")
        return ''.join(out_chars)

    # ---- Luau emission ----

    def to_luau_table(self) -> str:
        """Generate a Luau table literal containing the (encrypted) constants."""
        entries = []
        for c in self.constants:
            if c is None:
                entries.append("nil")
            elif isinstance(c, bool):
                entries.append("true" if c else "false")
            elif isinstance(c, (int, float)):
                # Preserve integers when possible
                if isinstance(c, int) or (isinstance(c, float) and c.is_integer()):
                    entries.append(str(int(c)))
                else:
                    entries.append(repr(float(c)))
            elif isinstance(c, str):
                entries.append(f'"{self.encrypt_string(c)}"')
            else:
                entries.append("nil")
        return '{' + ','.join(entries) + '}'

    def is_string(self, idx: int) -> bool:
        return isinstance(self.constants[idx], str)

    def size(self) -> int:
        return len(self.constants)
