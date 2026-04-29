"""
LuauShield Name Generator
==========================
Generates obfuscated identifier names using Luau-compatible strategies.
IMPORTANT: Luau only supports ASCII identifiers [a-zA-Z_][a-zA-Z0-9_]*
"""

import random
from typing import Set, Optional


class NameGenerator:
    """Generates unique, obfuscated identifier names with multiple strategies.
    All strategies produce ONLY ASCII-safe Luau identifiers.
    """

    # l/I/1/_ confusion - very effective, all ASCII
    CONFUSABLE_CHARS = ['l', 'I', '1']
    CONFUSABLE_STARTERS = ['l', 'I', '_']

    # Hex-style names
    HEX_CHARS = '0123456789abcdef'

    # Underscore-heavy names (looks like mangled C++)
    UNDERSCORE_CHARS = list('abcdefghijklmnopqrstuvwxyz_')
    UNDERSCORE_STARTERS = ['_', '_', '_']  # bias toward underscore start

    def __init__(self, rng: Optional[random.Random] = None,
                 min_length: int = 8, max_length: int = 14,
                 mix_strategies: bool = True):
        self.rng = rng or random.Random()
        self.min_length = min_length
        self.max_length = max_length
        self._used_names: Set[str] = set()
        self._counter = 0
        self._strategies = ['confusable', 'hex', 'underscore']
        if not mix_strategies:
            self._strategies = [self.rng.choice(self._strategies)]

    def gen_name(self) -> str:
        for _ in range(1000):
            strategy = self.rng.choice(self._strategies)
            if strategy == 'confusable':
                name = self._gen_confusable()
            elif strategy == 'hex':
                name = self._gen_hex()
            else:
                name = self._gen_underscore()

            # Ensure name is valid Luau identifier and unique
            if name not in self._used_names and self._is_valid_luau_id(name):
                self._used_names.add(name)
                return name

        self._counter += 1
        name = f"_v{self._counter:06x}"
        self._used_names.add(name)
        return name

    def _gen_confusable(self) -> str:
        length = self.rng.randint(self.min_length, self.max_length)
        first = self.rng.choice(self.CONFUSABLE_STARTERS)
        rest = ''.join(self.rng.choice(self.CONFUSABLE_CHARS) for _ in range(length - 1))
        return first + rest

    def _gen_hex(self) -> str:
        hex_len = self.rng.randint(4, 8)
        hex_part = ''.join(self.rng.choice(self.HEX_CHARS) for _ in range(hex_len))
        return f"_0x{hex_part}"

    def _gen_underscore(self) -> str:
        """Generate underscore-heavy mangled names like __x_y_z."""
        length = self.rng.randint(self.min_length, self.max_length)
        first = self.rng.choice(self.UNDERSCORE_STARTERS)
        rest = ''.join(self.rng.choice(self.UNDERSCORE_CHARS) for _ in range(length - 1))
        return first + rest

    def _is_valid_luau_id(self, name: str) -> bool:
        """Check name is a valid Luau identifier (ASCII only)."""
        if not name:
            return False
        # Must start with letter or underscore
        if not (name[0].isascii() and (name[0].isalpha() or name[0] == '_')):
            return False
        # Rest must be alphanumeric or underscore, all ASCII
        for c in name[1:]:
            if not (c.isascii() and (c.isalnum() or c == '_')):
                return False
        # Cannot be a Luau keyword
        if name in _LUAU_KEYWORDS:
            return False
        return True

    def gen_state_value(self) -> int:
        return self.rng.randint(0x10, 0xFFFF)

    def gen_xor_key(self) -> int:
        return self.rng.randint(1, 255)

    def gen_large_key(self) -> int:
        return self.rng.randint(0x100, 0xFFFF)

    def reset(self):
        self._used_names.clear()
        self._counter = 0

    def reserve(self, name: str):
        self._used_names.add(name)


_LUAU_KEYWORDS = {
    'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
    'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
    'return', 'then', 'true', 'until', 'while', 'continue',
}
