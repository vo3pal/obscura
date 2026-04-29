"""
LuauShield Layer 7 — Table Indirection
========================================
Replaces all global/stdlib function references with lookups through
an encrypted indirection table. Defeats simple grep for API names.
"""

from parser.ast_nodes import *
from utils.names import NameGenerator
from utils.globals import LUA_STDLIB, ROBLOX_GLOBALS, ROBLOX_DATATYPES
from config import ObfuscationConfig
from typing import Dict, List, Set, Tuple


class TableIndirection:
    """Replaces global references with indirection table lookups."""

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.name_gen = NameGenerator(rng=self.rng, min_length=8, max_length=12)

        self.table_name = self.name_gen.gen_name()
        self.xor_key = self.rng.randint(1, 0xFF)

        # Collected globals and their indices
        self._globals_found: Dict[str, int] = {}
        self._next_index = 1

    def apply(self, block: Block) -> Block:
        """Apply table indirection to the AST."""
        # First pass: collect all global references
        self._collect_globals(block)

        if not self._globals_found:
            return block

        # Second pass: replace global references with table lookups
        self._replace_globals(block)

        # Build indirection table header
        header = self._build_table()
        block.body = header + block.body

        return block

    def _get_index(self, name: str) -> int:
        """Get or assign an index for a global name."""
        if name not in self._globals_found:
            self._globals_found[name] = self._next_index
            self._next_index += 1
        return self._globals_found[name]

    def _collect_globals(self, node: Node):
        """Walk AST to find all global references."""
        if node is None:
            return

        if isinstance(node, Block):
            for stmt in node.body:
                self._collect_globals(stmt)
            return

        if isinstance(node, Identifier):
            if node.name in self._get_targetable_globals():
                self._get_index(node.name)
            return

        # Recurse into all child nodes
        for attr_name in vars(node):
            attr = getattr(node, attr_name)
            if isinstance(attr, Node):
                self._collect_globals(attr)
            elif isinstance(attr, list):
                for item in attr:
                    if isinstance(item, Node):
                        self._collect_globals(item)

    def _replace_globals(self, node: Node, parent: Node = None, attr_name: str = None):
        """Replace global identifier references with table lookups."""
        if node is None:
            return

        if isinstance(node, Block):
            for stmt in node.body:
                self._replace_globals(stmt)
            return

        if isinstance(node, Identifier):
            if node.name in self._globals_found:
                # Don't replace if this is a member access target
                # (e.g., the 'math' in math.floor — we want to replace the whole thing)
                pass  # Handled in parent nodes
            return

        # Handle MemberExpr: math.floor -> _T[idx]
        if isinstance(node, MemberExpr):
            if isinstance(node.object, Identifier) and node.object.name in self._globals_found:
                # This is a pattern like math.floor — we handle it differently
                full_name = f"{node.object.name}.{node.member}"
                if full_name not in self._globals_found:
                    self._globals_found[full_name] = self._next_index
                    self._next_index += 1
            self._replace_globals(node.object)
            return

        # Handle FunctionCall to check for global function calls
        if isinstance(node, FunctionCall):
            if isinstance(node.func, Identifier) and node.func.name in self._globals_found:
                idx = self._globals_found[node.func.name]
                node.func = self._make_lookup(idx)
            elif isinstance(node.func, MemberExpr):
                if isinstance(node.func.object, Identifier):
                    full_name = f"{node.func.object.name}.{node.func.member}"
                    if full_name in self._globals_found:
                        idx = self._globals_found[full_name]
                        node.func = self._make_lookup(idx)
                    elif node.func.object.name in self._globals_found:
                        idx = self._globals_found[node.func.object.name]
                        node.func = MemberExpr(
                            object=self._make_lookup(idx),
                            member=node.func.member
                        )
                else:
                    self._replace_globals(node.func)
            else:
                self._replace_globals(node.func)
            for arg in node.args:
                self._replace_globals(arg)
            return

        if isinstance(node, MethodCall):
            if isinstance(node.object, Identifier) and node.object.name in self._globals_found:
                idx = self._globals_found[node.object.name]
                node.object = self._make_lookup(idx)
            else:
                self._replace_globals(node.object)
            for arg in node.args:
                self._replace_globals(arg)
            return

        # Generic recursion
        for attr_name in vars(node):
            attr = getattr(node, attr_name)
            if isinstance(attr, Node):
                if isinstance(attr, Identifier) and attr.name in self._globals_found:
                    idx = self._globals_found[attr.name]
                    setattr(node, attr_name, self._make_lookup(idx))
                else:
                    self._replace_globals(attr)
            elif isinstance(attr, list):
                for i, item in enumerate(attr):
                    if isinstance(item, Identifier) and item.name in self._globals_found:
                        idx = self._globals_found[item.name]
                        attr[i] = self._make_lookup(idx)
                    elif isinstance(item, Node):
                        self._replace_globals(item)

    def _make_lookup(self, idx: int) -> IndexExpr:
        """Create a table lookup expression: _T[bit32.bxor(encoded, key)]."""
        encoded = idx ^ self.xor_key
        return IndexExpr(
            object=Identifier(name=self.table_name),
            index=FunctionCall(
                func=MemberExpr(
                    object=Identifier(name='bit32'),
                    member='bxor'
                ),
                args=[
                    NumberLiteral(value=str(encoded)),
                    NumberLiteral(value=str(self.xor_key))
                ]
            )
        )

    def _build_table(self) -> List[Node]:
        """Build the indirection table declaration."""
        # Sort by index to build table
        sorted_globals = sorted(self._globals_found.items(), key=lambda x: x[1])

        fields = []
        for name, idx in sorted_globals:
            # Build the value expression
            if '.' in name:
                parts = name.split('.', 1)
                value = MemberExpr(
                    object=Identifier(name=parts[0]),
                    member=parts[1]
                )
            else:
                value = Identifier(name=name)

            fields.append(TableField(
                key=NumberLiteral(value=str(idx)),
                value=value,
                is_bracket_key=True
            ))

        # Shuffle field order for obfuscation
        self.rng.shuffle(fields)

        table_stmt = LocalStatement(
            names=[self.table_name],
            values=[TableConstructor(fields=fields)]
        )

        return [table_stmt]

    def _get_targetable_globals(self) -> Set[str]:
        """Get the set of globals that should be indirected."""
        targets = set()
        # Core Lua functions we want to hide
        targets.update({
            'print', 'warn', 'error', 'assert', 'pcall', 'xpcall',
            'type', 'typeof', 'tostring', 'tonumber',
            'pairs', 'ipairs', 'next', 'select', 'unpack',
            'setmetatable', 'getmetatable', 'rawget', 'rawset',
            'math', 'string', 'table', 'coroutine', 'bit32', 'os', 'debug',
            'game', 'workspace', 'Instance', 'Vector3', 'Color3', 'Rect', 'UDim', 'UDim2',
            'CFrame', 'BrickColor', 'Enum', 'task', 'tick', 'time', 'delay', 'wait', 'spawn',
            'shared', '_G', 'getfenv', 'setfenv', 'require',
        })
        return targets
