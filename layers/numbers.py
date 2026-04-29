"""
LuauShield Layer 3 — Number Obfuscation
=========================================
Replace numeric literals with equivalent MBA expressions.
Uses arithmetic, bitwise XOR identities, and nested compositions.
"""

from parser.ast_nodes import *
from utils.crypto import generate_mba
from config import ObfuscationConfig
import random


class NumberObfuscator:
    """Replaces numeric literals with obfuscated MBA expressions."""

    # Numbers that are too common/trivial to obfuscate
    SKIP_VALUES = {0, 1, -1}

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.depth = config.mba_depth
        self.skip_trivial = config.skip_trivial_numbers

    def apply(self, block: Block) -> Block:
        """Apply number obfuscation to all numeric literals in the AST."""
        self._visit(block)
        return block

    def _visit(self, node: Node):
        if node is None:
            return

        if isinstance(node, Block):
            for stmt in node.body:
                self._visit(stmt)
            return

        for attr_name in vars(node):
            attr = getattr(node, attr_name)
            if isinstance(attr, NumberLiteral):
                obfuscated = self._obfuscate_number(attr)
                if obfuscated:
                    setattr(node, attr_name, obfuscated)
            elif isinstance(attr, Node):
                self._visit(attr)
            elif isinstance(attr, list):
                for i, item in enumerate(attr):
                    if isinstance(item, NumberLiteral):
                        obfuscated = self._obfuscate_number(item)
                        if obfuscated:
                            attr[i] = obfuscated
                    elif isinstance(item, Node):
                        self._visit(item)

    def _obfuscate_number(self, node: NumberLiteral) -> Node:
        """Generate an obfuscated expression for a number literal."""
        try:
            # Parse the number value
            val_str = node.value.replace('_', '')
            if val_str.startswith('0x') or val_str.startswith('0X'):
                n = int(val_str, 16)
            elif val_str.startswith('0b') or val_str.startswith('0B'):
                n = int(val_str, 2)
            elif '.' in val_str or 'e' in val_str.lower():
                # Float — skip for now (MBA works best with integers)
                return None
            else:
                n = int(val_str)
        except (ValueError, OverflowError):
            return None

        if self.skip_trivial and n in self.SKIP_VALUES:
            return None

        # Don't obfuscate very large numbers (could cause overflow in bit32)
        if abs(n) > 0xFFFFFF:
            return None

        # Generate the MBA expression
        expr_str = self._gen_expression(n)

        # Wrap in a parenthesized identifier node (raw Luau expression)
        return ParenExpr(
            expression=Identifier(name=expr_str),
            line=node.line, col=node.col
        )

    def _gen_expression(self, n: int) -> str:
        """Generate an obfuscated expression that evaluates to n."""
        strategy = self.rng.randint(0, 3)

        if strategy == 0:
            # Simple arithmetic: (n + r) - r
            r = self.rng.randint(10, 500)
            if self.depth >= 2:
                inner = self._gen_inner(n + r)
                return f"{inner}-{r}"
            return f"{n + r}-{r}"

        elif strategy == 1:
            # XOR identity: bxor(bxor(n, k), k) = n
            k = self.rng.randint(1, 0xFF)
            xored = n ^ k
            return f"bit32.bxor({xored},{k})"

        elif strategy == 2:
            # Multiplication: (n * m) / m
            m = self.rng.choice([2, 4, 5, 8, 10])
            return f"math.floor({n * m}/{m})"

        else:
            # Addition decomposition: a + b where a + b = n
            a = self.rng.randint(1, max(2, abs(n) + 100))
            b = n - a
            if self.depth >= 2 and self.rng.random() > 0.5:
                k = self.rng.randint(1, 0xFF)
                return f"bit32.bxor({a ^ k},{(a ^ n) ^ k})"
            return f"({a}+({b}))"

    def _gen_inner(self, n: int) -> str:
        """Generate a nested inner expression."""
        k = self.rng.randint(1, 0xFF)
        if self.rng.random() > 0.5:
            return f"bit32.bxor({n ^ k},{k})"
        r2 = self.rng.randint(1, 100)
        return f"({n + r2}-{r2})"
