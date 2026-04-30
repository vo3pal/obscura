"""
Obscura VM Function Prototypes
==================================
Register-based function prototype with upvalue descriptors and nested protos.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from .instruction import Instruction


@dataclass
class UpvalueDesc:
    """
    Describes an upvalue captured by a closure.

    instack=True  -> The upvalue refers to a local in the immediately enclosing
                     function. `idx` is that local's register index.
    instack=False -> The upvalue refers to an upvalue of the enclosing function.
                     `idx` is that upvalue's index in the parent's upvalue list.
    """
    name: str
    instack: bool
    idx: int


@dataclass
class FunctionPrototype:
    """A compiled function in the VM."""
    name: str = ''
    instructions: List[Instruction] = field(default_factory=list)
    bytecode: List[int] = field(default_factory=list)  # Encoded byte stream
    num_params: int = 0
    is_vararg: bool = False
    max_stacksize: int = 2  # At least 2 registers for safety
    upvalues: List[UpvalueDesc] = field(default_factory=list)
    sub_protos: List['FunctionPrototype'] = field(default_factory=list)
    line_info: List[int] = field(default_factory=list)  # parallel to instructions

    def add_proto(self, proto: 'FunctionPrototype') -> int:
        """Add a nested function prototype, return its index."""
        idx = len(self.sub_protos)
        self.sub_protos.append(proto)
        return idx
