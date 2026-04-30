"""
Obscura VM Instruction Format
=================================
Register-based instruction encoding with variable-length operands.

Each instruction starts with a single opcode byte followed by 0-3 operands.
Operands are 16-bit little-endian (lo, hi). Signed operands use bias encoding.

The flat byte stream produced by `encode()` is then encrypted with a rolling
XOR cipher before being embedded in the output.
"""

from dataclasses import dataclass, field
from typing import List, Optional


# Operand encoding: every operand is 2 bytes (16-bit little-endian).
# Signed operands (jump offsets) are biased by 0x8000.
SBX_BIAS = 0x8000


# Instruction format categories. Used by both compiler and interpreter.
# 'A'   = single 16-bit register or count
# 'AB'  = two 16-bit operands (e.g. MOVE dst src)
# 'ABC' = three 16-bit operands (e.g. ADD dst lhs rhs)
# 'ABx' = same as AB but B is a constant pool index (semantic only)
# 'AsBx'= A + signed jump offset
# 'sBx' = signed jump offset only
# ''    = no operands

FORMAT_NONE = ''
FORMAT_A    = 'A'
FORMAT_AB   = 'AB'
FORMAT_ABC  = 'ABC'
FORMAT_ABX  = 'ABx'
FORMAT_ASBX = 'AsBx'
FORMAT_SBX  = 'sBx'


def operand_count(fmt: str) -> int:
    if fmt == FORMAT_NONE:  return 0
    if fmt == FORMAT_A:     return 1
    if fmt == FORMAT_AB:    return 2
    if fmt == FORMAT_ABC:   return 3
    if fmt == FORMAT_ABX:   return 2
    if fmt == FORMAT_ASBX:  return 2
    if fmt == FORMAT_SBX:   return 1
    raise ValueError(f"Unknown format: {fmt}")


def instruction_size(fmt: str) -> int:
    """Total byte size of an instruction with the given format."""
    return 1 + 2 * operand_count(fmt)


@dataclass
class Instruction:
    """A single VM instruction (un-encoded form for the compiler)."""
    op_name: str            # Semantic opcode name (e.g. 'ADD'); resolved to byte by OpcodeMap
    fmt: str                # Format string
    a: int = 0
    b: int = 0
    c: int = 0
    # Backpatch metadata
    pc: int = 0             # Byte offset where this instruction was emitted
    comment: str = ''       # For debugging output


def encode_u16(value: int) -> List[int]:
    """Encode a 16-bit unsigned int as [lo, hi]."""
    value &= 0xFFFF
    return [value & 0xFF, (value >> 8) & 0xFF]


def encode_s16(value: int) -> List[int]:
    """Encode a signed 16-bit int with SBX_BIAS."""
    return encode_u16(value + SBX_BIAS)


def encode_instruction(opcode_byte: int, fmt: str, a: int, b: int, c: int) -> List[int]:
    """Encode a single instruction to a flat byte list."""
    out = [opcode_byte & 0xFF]
    if fmt == FORMAT_NONE:
        pass
    elif fmt == FORMAT_A:
        out += encode_u16(a)
    elif fmt == FORMAT_AB:
        out += encode_u16(a)
        out += encode_u16(b)
    elif fmt == FORMAT_ABC:
        out += encode_u16(a)
        out += encode_u16(b)
        out += encode_u16(c)
    elif fmt == FORMAT_ABX:
        out += encode_u16(a)
        out += encode_u16(b)
    elif fmt == FORMAT_ASBX:
        out += encode_u16(a)
        out += encode_s16(b)
    elif fmt == FORMAT_SBX:
        out += encode_s16(a)
    else:
        raise ValueError(f"Unknown format: {fmt}")
    return out
