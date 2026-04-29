"""
LuauShield AST Emitter
========================
Converts AST nodes back into valid Luau source code.
Supports minified output with correct operator precedence.
IMPORTANT: Output MUST be valid Roblox Luau syntax.
"""

from .ast_nodes import *
from typing import List


# Operator precedence for correct parenthesization
PRECEDENCE = {
    'or': 1, 'and': 2,
    '<': 3, '>': 3, '<=': 3, '>=': 3, '~=': 3, '==': 3,
    '..': 4,
    '+': 5, '-': 5,
    '*': 6, '/': 6, '%': 6,
    'not': 7, '#': 7, 'unary-': 7,
    '^': 8,
}

RIGHT_ASSOC = {'..', '^'}


class Emitter:
    """Converts AST back to valid Luau source code."""

    def __init__(self, minify: bool = True):
        self.minify = minify
        self._indent = 0

    def emit(self, node: Node) -> str:
        """Emit a node as Luau source code."""
        if node is None:
            return ""
        method = f"_emit_{type(node).__name__}"
        fn = getattr(self, method, None)
        if fn:
            return fn(node)
        return f"--[[UNKNOWN:{type(node).__name__}]]"

    def emit_block(self, block: Block) -> str:
        """Emit a block of statements."""
        parts = []
        for stmt in block.body:
            parts.append(self.emit(stmt))
        sep = " " if self.minify else "\n"
        return sep.join(parts)

    # --- Statements ---

    def _emit_Block(self, node: Block) -> str:
        return self.emit_block(node)

    def _emit_LocalStatement(self, node: LocalStatement) -> str:
        names = ",".join(node.names)
        if node.values:
            vals = ",".join(self.emit(v) for v in node.values)
            return f"local {names}={vals}"
        return f"local {names}"

    def _emit_AssignStatement(self, node: AssignStatement) -> str:
        targets = ",".join(self.emit(t) for t in node.targets)
        vals = ",".join(self.emit(v) for v in node.values)
        return f"{targets}={vals}"

    def _emit_DoBlock(self, node: DoBlock) -> str:
        body = self.emit_block(node.body)
        return f"do {body} end"

    def _emit_WhileLoop(self, node: WhileLoop) -> str:
        cond = self.emit(node.condition)
        body = self.emit_block(node.body)
        return f"while {cond} do {body} end"

    def _emit_RepeatUntil(self, node: RepeatUntil) -> str:
        body = self.emit_block(node.body)
        cond = self.emit(node.condition)
        return f"repeat {body} until {cond}"

    def _emit_IfStatement(self, node: IfStatement) -> str:
        parts = [f"if {self.emit(node.condition)} then {self.emit_block(node.body)}"]
        for clause in node.elseif_clauses:
            parts.append(f" elseif {self.emit(clause.condition)} then {self.emit_block(clause.body)}")
        if node.else_body:
            parts.append(f" else {self.emit_block(node.else_body)}")
        parts.append(" end")
        return "".join(parts)

    def _emit_ElseIfClause(self, node: ElseIfClause) -> str:
        return f"elseif {self.emit(node.condition)} then {self.emit_block(node.body)}"

    def _emit_NumericFor(self, node: NumericFor) -> str:
        parts = [f"for {node.var_name}={self.emit(node.start)},{self.emit(node.stop)}"]
        if node.step:
            parts[0] += f",{self.emit(node.step)}"
        body = self.emit_block(node.body)
        return f"{parts[0]} do {body} end"

    def _emit_GenericFor(self, node: GenericFor) -> str:
        names = ",".join(node.names)
        iters = ",".join(self.emit(it) for it in node.iterators)
        body = self.emit_block(node.body)
        return f"for {names} in {iters} do {body} end"

    def _emit_ReturnStatement(self, node: ReturnStatement) -> str:
        if node.values:
            vals = ",".join(self.emit(v) for v in node.values)
            return f"return {vals}"
        return "return"

    def _emit_BreakStatement(self, node: BreakStatement) -> str:
        return "break"

    def _emit_ContinueStatement(self, node: ContinueStatement) -> str:
        return "continue"

    def _emit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        return self.emit(node.expression)

    def _emit_FunctionDecl(self, node: FunctionDecl) -> str:
        prefix = "local function " if node.is_local else "function "
        name = self.emit(node.name) if node.name else ""

        # Handle method declaration name (MethodCall node used as name)
        if isinstance(node.name, MethodCall):
            name = f"{self.emit(node.name.object)}:{node.name.method}"

        params = ",".join(node.params)
        if node.has_vararg:
            params = f"{params},..." if params else "..."
        body = self.emit_block(node.body)
        return f"{prefix}{name}({params}) {body} end"

    # --- Expressions ---

    def _emit_FunctionExpr(self, node: FunctionExpr) -> str:
        params = ",".join(node.params)
        if node.has_vararg:
            params = f"{params},..." if params else "..."
        body = self.emit_block(node.body)
        return f"function({params}) {body} end"

    def _emit_Identifier(self, node: Identifier) -> str:
        return node.name

    def _emit_NumberLiteral(self, node: NumberLiteral) -> str:
        return node.value

    def _emit_StringLiteral(self, node: StringLiteral) -> str:
        # Escape the value properly for Luau string output
        escaped = (node.value
            .replace('\\', '\\\\')
            .replace('"', '\\"')
            .replace('\n', '\\n')
            .replace('\r', '\\r')
            .replace('\0', '\\0')
            .replace('\t', '\\t')
        )
        # Ensure all characters are ASCII-printable; escape others
        result = []
        for ch in escaped:
            if ord(ch) < 32 or ord(ch) > 126:
                result.append(f'\\{ord(ch)}')
            else:
                result.append(ch)
        return '"' + ''.join(result) + '"'

    def _emit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "true" if node.value else "false"

    def _emit_NilLiteral(self, node: NilLiteral) -> str:
        return "nil"

    def _emit_VarargExpr(self, node: VarargExpr) -> str:
        return "..."

    def _emit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._emit_with_parens(node.left, node.op, is_right=False)
        right = self._emit_with_parens(node.right, node.op, is_right=True)
        # Add spaces around word operators and comparison ops for clarity
        if node.op in ('and', 'or'):
            return f"{left} {node.op} {right}"
        # Add spaces around comparison and arithmetic operators
        if node.op == '-':
            return f"{left} {node.op} {right}"
        return f"{left}{node.op}{right}"

    def _emit_with_parens(self, child: Node, parent_op: str, is_right: bool) -> str:
        """Add parentheses if needed for correct precedence."""
        child_str = self.emit(child)
        if isinstance(child, BinaryOp):
            parent_prec = PRECEDENCE.get(parent_op, 0)
            child_prec = PRECEDENCE.get(child.op, 0)
            if child_prec < parent_prec:
                return f"({child_str})"
            if child_prec == parent_prec and is_right and parent_op not in RIGHT_ASSOC:
                return f"({child_str})"
        return child_str

    def _emit_UnaryOp(self, node: UnaryOp) -> str:
        operand = self.emit(node.operand)
        if node.op == 'not':
            return f"not {operand}"
        if node.op == '-':
            # Avoid --x becoming a comment
            if operand.startswith('-') or operand.startswith('('):
                return f"-({operand})"
            return f"-{operand}"
        return f"{node.op}{operand}"

    def _emit_FunctionCall(self, node: FunctionCall) -> str:
        func = self.emit(node.func)
        args = ",".join(self.emit(a) for a in node.args)
        return f"{func}({args})"

    def _emit_MethodCall(self, node: MethodCall) -> str:
        obj = self.emit(node.object)
        args = ",".join(self.emit(a) for a in node.args)
        return f"{obj}:{node.method}({args})"

    def _emit_MemberExpr(self, node: MemberExpr) -> str:
        obj = self.emit(node.object)
        return f"{obj}.{node.member}"

    def _emit_IndexExpr(self, node: IndexExpr) -> str:
        obj = self.emit(node.object)
        idx = self.emit(node.index)
        return f"{obj}[{idx}]"

    def _emit_TableConstructor(self, node: TableConstructor) -> str:
        if not node.fields:
            return "{}"
        parts = []
        for f in node.fields:
            if f.key is None:
                parts.append(self.emit(f.value))
            elif f.is_bracket_key:
                parts.append(f"[{self.emit(f.key)}]={self.emit(f.value)}")
            else:
                # f.key is a StringLiteral holding the field name
                key_name = f.key.value if isinstance(f.key, StringLiteral) else self.emit(f.key)
                parts.append(f"{key_name}={self.emit(f.value)}")
        return "{" + ",".join(parts) + "}"

    def _emit_ParenExpr(self, node: ParenExpr) -> str:
        return f"({self.emit(node.expression)})"
