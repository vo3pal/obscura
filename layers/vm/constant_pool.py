"""
LuauShield VM Constant Pool
==============================
Builds and encrypts the constant pool for the custom VM.
Supports strings, numbers, booleans, and nil constants.
"""

import struct
import random
from typing import List, Any, Dict, Tuple
from utils.crypto import xor_encrypt_rotating, generate_rotating_key


# Type tags for constant pool entries
CONST_NIL = 0
CONST_BOOL = 1
CONST_NUMBER = 2
CONST_STRING = 3


class ConstantPool:
    """
    Manages the constant pool for the VM.
    All constants are collected, deduplicated, indexed, and encrypted.
    """

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.constants: List[Any] = []
        self._index_map: Dict[Any, int] = {}  # value -> index
        self.key = generate_rotating_key(self.rng.randint(8, 16), self.rng)

    def add(self, value: Any) -> int:
        """Add a constant and return its index. Deduplicates."""
        # Create a hashable key
        key = self._make_key(value)
        if key in self._index_map:
            return self._index_map[key]

        idx = len(self.constants)
        self.constants.append(value)
        self._index_map[key] = idx
        return idx

    def _make_key(self, value: Any) -> Any:
        """Create a hashable key for deduplication."""
        if value is None:
            return ('nil',)
        if isinstance(value, bool):
            return ('bool', value)
        if isinstance(value, (int, float)):
            return ('num', value)
        if isinstance(value, str):
            return ('str', value)
        return ('other', str(value))

    def get(self, index: int) -> Any:
        """Get a constant by index."""
        return self.constants[index]

    def size(self) -> int:
        """Get the number of constants."""
        return len(self.constants)

    def serialize(self) -> bytes:
        """Serialize the constant pool to bytes."""
        data = bytearray()

        # Header: constant count (4 bytes, little-endian)
        data.extend(struct.pack('<I', len(self.constants)))

        for const in self.constants:
            if const is None:
                data.append(CONST_NIL)
            elif isinstance(const, bool):
                data.append(CONST_BOOL)
                data.append(1 if const else 0)
            elif isinstance(const, (int, float)):
                data.append(CONST_NUMBER)
                # Encode as double (8 bytes)
                data.extend(struct.pack('<d', float(const)))
            elif isinstance(const, str):
                data.append(CONST_STRING)
                encoded = const.encode('utf-8')
                data.extend(struct.pack('<I', len(encoded)))
                data.extend(encoded)
            else:
                data.append(CONST_NIL)

        return bytes(data)

    def encrypt(self) -> Tuple[bytes, List[int]]:
        """Serialize and encrypt the constant pool."""
        raw = self.serialize()
        encrypted = xor_encrypt_rotating(raw, self.key)
        return encrypted, self.key

    def to_luau_string(self) -> str:
        """Convert the encrypted constant pool to a Luau string literal."""
        encrypted, _ = self.encrypt()
        # Convert to escaped string
        parts = []
        for b in encrypted:
            parts.append(f"\\{b}")
        return '"' + ''.join(parts) + '"'

    def generate_key_table(self, name_gen) -> str:
        """Generate the key table as a Luau table literal."""
        key_name = name_gen.gen_name()
        entries = ','.join(str(k) for k in self.key)
        return key_name, f"local {key_name}={{{entries}}}"

    def generate_decoder(self, pool_var: str, key_var: str, name_gen) -> str:
        """Generate the Luau constant pool decoder function."""
        fn_name = name_gen.gen_name()
        result_var = name_gen.gen_name()
        i_var = name_gen.gen_name()
        klen_var = name_gen.gen_name()

        code = f"""local function {fn_name}({pool_var},{key_var})
local {result_var}={{}}
local {klen_var}=#({key_var})
for {i_var}=1,#({pool_var}) do
local byte=string.byte({pool_var},{i_var})
local k={key_var}[({i_var}-1)%{klen_var}+1]
{result_var}[{i_var}]=string.char(bit32.bxor(byte,k))
end
return table.concat({result_var})
end"""
        return fn_name, code
