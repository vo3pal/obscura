"""
LuauShield Layer 1 — Identifier Renaming
==========================================
Walk AST, rename all local variables and parameters with obfuscated names.
Scope-aware to prevent collisions. Never renames globals/Roblox APIs.
"""

from parser.ast_nodes import *
from parser.scope import Scope, ScopeAnalyzer
from utils.names import NameGenerator
from utils.globals import is_renameable
from config import ObfuscationConfig
from typing import Dict, Optional


class IdentifierRenamer:
    """Renames all local identifiers in an AST using obfuscated names."""

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.name_gen = NameGenerator(
            rng=config.get_rng(),
            min_length=config.name_min_length,
            max_length=config.name_max_length,
            mix_strategies=config.mix_naming_strategies,
        )

    def apply(self, block: Block) -> Block:
        """Apply identifier renaming to the entire AST."""
        scope = Scope(name="global")
        self._visit_block(block, scope)
        return block

    def _get_or_create_mapping(self, scope: Scope, name: str) -> str:
        """Get existing mapping or create a new one."""
        if name in scope.locals:
            return scope.locals[name]
        obf = self.name_gen.gen_name()
        scope.define(name, obf)
        return obf

    def _resolve(self, scope: Scope, name: str) -> str:
        """Resolve a name through the scope chain."""
        result = scope.resolve(name)
        if result:
            return result
        return name  # Global — don't rename

    def _visit_block(self, block: Block, scope: Scope):
        for stmt in block.body:
            self._visit_node(stmt, scope)

    def _visit_node(self, node: Node, scope: Scope):
        if node is None:
            return

        if isinstance(node, LocalStatement):
            # First visit values (they're evaluated in the outer scope)
            for val in node.values:
                self._visit_node(val, scope)
            # Then define names in current scope
            for i, name in enumerate(node.names):
                if name != "self":
                    obf = self._get_or_create_mapping(scope, name)
                    node.names[i] = obf

        elif isinstance(node, FunctionDecl):
            # If local function, the name is a new local identifier
            if node.is_local and isinstance(node.name, Identifier):
                if node.name.name != "self":
                    obf = self._get_or_create_mapping(scope, node.name.name)
                    node.name.name = obf
            else:
                # Non-local function (e.g. function Table.Method())
                # Visit the name node to resolve any local identifiers used (like Table)
                self._visit_node(node.name, scope)

            # Function body in new scope
            func_scope = Scope(parent=scope, name="func")
            for i, p in enumerate(node.params):
                if p != "self":
                    obf = self._get_or_create_mapping(func_scope, p)
                    node.params[i] = obf
            self._visit_block(node.body, func_scope)

        elif isinstance(node, FunctionExpr):
            func_scope = Scope(parent=scope, name="anon")
            for i, p in enumerate(node.params):
                if p != "self":
                    obf = self._get_or_create_mapping(func_scope, p)
                    node.params[i] = obf
            self._visit_block(node.body, func_scope)

        elif isinstance(node, IfStatement):
            self._visit_node(node.condition, scope)
            if_scope = Scope(parent=scope, name="if")
            self._visit_block(node.body, if_scope)
            for clause in node.elseif_clauses:
                self._visit_node(clause.condition, scope)
                ei_scope = Scope(parent=scope, name="elseif")
                self._visit_block(clause.body, ei_scope)
            if node.else_body:
                else_scope = Scope(parent=scope, name="else")
                self._visit_block(node.else_body, else_scope)

        elif isinstance(node, WhileLoop):
            self._visit_node(node.condition, scope)
            while_scope = Scope(parent=scope, name="while")
            self._visit_block(node.body, while_scope)

        elif isinstance(node, NumericFor):
            self._visit_node(node.start, scope)
            self._visit_node(node.stop, scope)
            if node.step:
                self._visit_node(node.step, scope)
            for_scope = Scope(parent=scope, name="nfor")
            if node.var_name != "self":
                obf = self._get_or_create_mapping(for_scope, node.var_name)
                node.var_name = obf
            self._visit_block(node.body, for_scope)

        elif isinstance(node, GenericFor):
            for_scope = Scope(parent=scope, name="gfor")
            for i, name in enumerate(node.names):
                if name != "self":
                    obf = self._get_or_create_mapping(for_scope, name)
                    node.names[i] = obf
            for it in node.iterators:
                self._visit_node(it, scope)
            self._visit_block(node.body, for_scope)

        elif isinstance(node, RepeatUntil):
            rep_scope = Scope(parent=scope, name="repeat")
            self._visit_block(node.body, rep_scope)
            self._visit_node(node.condition, rep_scope)

        elif isinstance(node, DoBlock):
            do_scope = Scope(parent=scope, name="do")
            self._visit_block(node.body, do_scope)

        elif isinstance(node, ReturnStatement):
            for v in node.values:
                self._visit_node(v, scope)

        elif isinstance(node, AssignStatement):
            for t in node.targets:
                self._visit_node(t, scope)
            for v in node.values:
                self._visit_node(v, scope)

        elif isinstance(node, ExpressionStatement):
            self._visit_node(node.expression, scope)

        elif isinstance(node, Identifier):
            # If this is a local variable, use its obfuscated name
            resolved = scope.resolve(node.name)
            if resolved:
                node.name = resolved
            # If not resolved, it's a global — keep its original name

        elif isinstance(node, BinaryOp):
            self._visit_node(node.left, scope)
            self._visit_node(node.right, scope)

        elif isinstance(node, UnaryOp):
            self._visit_node(node.operand, scope)

        elif isinstance(node, FunctionCall):
            self._visit_node(node.func, scope)
            for a in node.args:
                self._visit_node(a, scope)

        elif isinstance(node, MethodCall):
            self._visit_node(node.object, scope)
            for a in node.args:
                self._visit_node(a, scope)

        elif isinstance(node, MemberExpr):
            self._visit_node(node.object, scope)
            # Don't rename member names — they're property accesses

        elif isinstance(node, IndexExpr):
            self._visit_node(node.object, scope)
            self._visit_node(node.index, scope)

        elif isinstance(node, TableConstructor):
            for f in node.fields:
                if f.key and f.is_bracket_key:
                    self._visit_node(f.key, scope)
                self._visit_node(f.value, scope)

        elif isinstance(node, ParenExpr):
            self._visit_node(node.expression, scope)
