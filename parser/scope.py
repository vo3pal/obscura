"""
LuauShield Scope Tracker
==========================
Scope tree with parent-child chain for tracking variable definitions,
resolving identifiers, and determining what can be renamed.
"""

from typing import Dict, Optional, List, Set
from .ast_nodes import *
from utils.globals import is_renameable


class Scope:
    """A single scope level in the scope tree."""

    def __init__(self, parent: Optional['Scope'] = None, name: str = ""):
        self.parent = parent
        self.name = name
        self.children: List['Scope'] = []
        self.locals: Dict[str, str] = {}    # original_name -> obfuscated_name
        self.references: Set[str] = set()   # All names referenced in this scope

        if parent:
            parent.children.append(self)

    def define(self, name: str, obfuscated: str = ""):
        """Define a local variable in this scope."""
        self.locals[name] = obfuscated

    def resolve(self, name: str) -> Optional[str]:
        """Resolve a name through the scope chain. Returns obfuscated name or None."""
        if name in self.locals:
            return self.locals[name]
        if self.parent:
            return self.parent.resolve(name)
        return None

    def is_local(self, name: str) -> bool:
        """Check if a name is defined as local in this or any parent scope."""
        if name in self.locals:
            return True
        if self.parent:
            return self.parent.is_local(name)
        return False

    def add_reference(self, name: str):
        """Record that a name is referenced in this scope."""
        self.references.add(name)


class ScopeAnalyzer:
    """
    Walks the AST to build a scope tree and collect all local definitions.
    Determines which identifiers can be safely renamed.
    """

    def __init__(self):
        self.root_scope = Scope(name="global")
        self.current_scope = self.root_scope
        self.all_locals: List[tuple] = []  # (scope, name, node)

    def analyze(self, block: Block):
        """Analyze a complete program block."""
        self._visit_block(block)

    def _push_scope(self, name: str = "") -> Scope:
        scope = Scope(parent=self.current_scope, name=name)
        self.current_scope = scope
        return scope

    def _pop_scope(self):
        if self.current_scope.parent:
            self.current_scope = self.current_scope.parent

    def _visit_block(self, block: Block):
        for stmt in block.body:
            self._visit_node(stmt)

    def _visit_node(self, node: Node):
        if node is None:
            return

        if isinstance(node, LocalStatement):
            for name in node.names:
                if is_renameable(name):
                    self.current_scope.define(name)
                    self.all_locals.append((self.current_scope, name, node))
            for val in node.values:
                self._visit_node(val)

        elif isinstance(node, FunctionDecl):
            if node.is_local and isinstance(node.name, Identifier):
                if is_renameable(node.name.name):
                    self.current_scope.define(node.name.name)
                    self.all_locals.append((self.current_scope, node.name.name, node))
            self._push_scope(f"func")
            for p in node.params:
                if is_renameable(p):
                    self.current_scope.define(p)
                    self.all_locals.append((self.current_scope, p, node))
            self._visit_block(node.body)
            self._pop_scope()

        elif isinstance(node, FunctionExpr):
            self._push_scope("anon")
            for p in node.params:
                if is_renameable(p):
                    self.current_scope.define(p)
                    self.all_locals.append((self.current_scope, p, node))
            self._visit_block(node.body)
            self._pop_scope()

        elif isinstance(node, IfStatement):
            self._visit_node(node.condition)
            self._push_scope("if")
            self._visit_block(node.body)
            self._pop_scope()
            for clause in node.elseif_clauses:
                self._visit_node(clause.condition)
                self._push_scope("elseif")
                self._visit_block(clause.body)
                self._pop_scope()
            if node.else_body:
                self._push_scope("else")
                self._visit_block(node.else_body)
                self._pop_scope()

        elif isinstance(node, WhileLoop):
            self._visit_node(node.condition)
            self._push_scope("while")
            self._visit_block(node.body)
            self._pop_scope()

        elif isinstance(node, NumericFor):
            self._visit_node(node.start)
            self._visit_node(node.stop)
            if node.step:
                self._visit_node(node.step)
            self._push_scope("nfor")
            if is_renameable(node.var_name):
                self.current_scope.define(node.var_name)
                self.all_locals.append((self.current_scope, node.var_name, node))
            self._visit_block(node.body)
            self._pop_scope()

        elif isinstance(node, GenericFor):
            self._push_scope("gfor")
            for name in node.names:
                if is_renameable(name):
                    self.current_scope.define(name)
                    self.all_locals.append((self.current_scope, name, node))
            for it in node.iterators:
                self._visit_node(it)
            self._visit_block(node.body)
            self._pop_scope()

        elif isinstance(node, RepeatUntil):
            self._push_scope("repeat")
            self._visit_block(node.body)
            self._visit_node(node.condition)
            self._pop_scope()

        elif isinstance(node, DoBlock):
            self._push_scope("do")
            self._visit_block(node.body)
            self._pop_scope()

        elif isinstance(node, ReturnStatement):
            for v in node.values:
                self._visit_node(v)

        elif isinstance(node, AssignStatement):
            for t in node.targets:
                self._visit_node(t)
            for v in node.values:
                self._visit_node(v)

        elif isinstance(node, ExpressionStatement):
            self._visit_node(node.expression)

        elif isinstance(node, Identifier):
            self.current_scope.add_reference(node.name)

        elif isinstance(node, BinaryOp):
            self._visit_node(node.left)
            self._visit_node(node.right)

        elif isinstance(node, UnaryOp):
            self._visit_node(node.operand)

        elif isinstance(node, FunctionCall):
            self._visit_node(node.func)
            for a in node.args:
                self._visit_node(a)

        elif isinstance(node, MethodCall):
            self._visit_node(node.object)
            for a in node.args:
                self._visit_node(a)

        elif isinstance(node, MemberExpr):
            self._visit_node(node.object)

        elif isinstance(node, IndexExpr):
            self._visit_node(node.object)
            self._visit_node(node.index)

        elif isinstance(node, TableConstructor):
            for f in node.fields:
                if f.key and f.is_bracket_key:
                    self._visit_node(f.key)
                self._visit_node(f.value)

        elif isinstance(node, ParenExpr):
            self._visit_node(node.expression)
