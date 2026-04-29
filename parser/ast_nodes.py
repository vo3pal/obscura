"""
LuauShield AST Node Definitions
=================================
All AST node types for representing Luau source code structure.
Each node stores enough information for faithful code emission.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any


# ============================================================================
# BASE NODE
# ============================================================================

@dataclass
class Node:
    """Base class for all AST nodes."""
    line: int = 0
    col: int = 0


# ============================================================================
# PROGRAM / BLOCK
# ============================================================================

@dataclass
class Block(Node):
    """A sequence of statements."""
    body: List[Node] = field(default_factory=list)


# ============================================================================
# STATEMENTS
# ============================================================================

@dataclass
class LocalStatement(Node):
    """local x, y = expr1, expr2"""
    names: List[str] = field(default_factory=list)
    values: List[Node] = field(default_factory=list)


@dataclass
class AssignStatement(Node):
    """x, y = expr1, expr2"""
    targets: List[Node] = field(default_factory=list)
    values: List[Node] = field(default_factory=list)


@dataclass
class DoBlock(Node):
    """do ... end"""
    body: 'Block' = field(default_factory=Block)


@dataclass
class WhileLoop(Node):
    """while condition do ... end"""
    condition: Optional[Node] = None
    body: 'Block' = field(default_factory=Block)


@dataclass
class RepeatUntil(Node):
    """repeat ... until condition"""
    body: 'Block' = field(default_factory=Block)
    condition: Optional[Node] = None


@dataclass
class IfStatement(Node):
    """if cond then ... elseif cond then ... else ... end"""
    condition: Optional[Node] = None
    body: 'Block' = field(default_factory=Block)
    elseif_clauses: List['ElseIfClause'] = field(default_factory=list)
    else_body: Optional['Block'] = None


@dataclass
class ElseIfClause(Node):
    """elseif condition then ..."""
    condition: Optional[Node] = None
    body: 'Block' = field(default_factory=Block)


@dataclass
class NumericFor(Node):
    """for i = start, stop, step do ... end"""
    var_name: str = ""
    start: Optional[Node] = None
    stop: Optional[Node] = None
    step: Optional[Node] = None
    body: 'Block' = field(default_factory=Block)


@dataclass
class GenericFor(Node):
    """for k, v in expr do ... end"""
    names: List[str] = field(default_factory=list)
    iterators: List[Node] = field(default_factory=list)
    body: 'Block' = field(default_factory=Block)


@dataclass
class ReturnStatement(Node):
    """return expr1, expr2, ..."""
    values: List[Node] = field(default_factory=list)


@dataclass
class BreakStatement(Node):
    """break"""
    pass


@dataclass
class ContinueStatement(Node):
    """continue (Luau-specific)"""
    pass


@dataclass
class ExpressionStatement(Node):
    """A statement consisting of a single expression (function call)."""
    expression: Optional[Node] = None


# ============================================================================
# FUNCTION DECLARATIONS
# ============================================================================

@dataclass
class FunctionDecl(Node):
    """function name(...) ... end  OR  local function name(...) ... end"""
    name: Optional[Node] = None  # Can be Identifier, MemberExpr, or MethodExpr
    params: List[str] = field(default_factory=list)
    has_vararg: bool = False
    body: 'Block' = field(default_factory=Block)
    is_local: bool = False


@dataclass
class FunctionExpr(Node):
    """function(...) ... end (anonymous)"""
    params: List[str] = field(default_factory=list)
    has_vararg: bool = False
    body: 'Block' = field(default_factory=Block)


# ============================================================================
# EXPRESSIONS
# ============================================================================

@dataclass
class Identifier(Node):
    """A variable name reference."""
    name: str = ""


@dataclass
class NumberLiteral(Node):
    """A numeric literal."""
    value: str = "0"  # Keep as string to preserve hex/binary form
    raw: str = ""


@dataclass
class StringLiteral(Node):
    """A string literal."""
    value: str = ""
    quote: str = '"'  # Original quote style


@dataclass
class BooleanLiteral(Node):
    """true or false."""
    value: bool = False


@dataclass
class NilLiteral(Node):
    """nil."""
    pass


@dataclass
class VarargExpr(Node):
    """..."""
    pass


@dataclass
class BinaryOp(Node):
    """left op right"""
    op: str = ""
    left: Optional[Node] = None
    right: Optional[Node] = None


@dataclass
class UnaryOp(Node):
    """op operand"""
    op: str = ""     # '-', 'not', '#'
    operand: Optional[Node] = None


@dataclass
class FunctionCall(Node):
    """func(args...)"""
    func: Optional[Node] = None
    args: List[Node] = field(default_factory=list)


@dataclass
class MethodCall(Node):
    """object:method(args...)"""
    object: Optional[Node] = None
    method: str = ""
    args: List[Node] = field(default_factory=list)


@dataclass
class MemberExpr(Node):
    """object.member"""
    object: Optional[Node] = None
    member: str = ""


@dataclass
class IndexExpr(Node):
    """object[index]"""
    object: Optional[Node] = None
    index: Optional[Node] = None


@dataclass
class TableConstructor(Node):
    """{field1, field2, ...}"""
    fields: List['TableField'] = field(default_factory=list)


@dataclass
class TableField(Node):
    """[key] = value  OR  name = value  OR  value"""
    key: Optional[Node] = None      # None for positional
    value: Optional[Node] = None
    is_bracket_key: bool = False     # [expr] = value vs name = value


@dataclass
class ParenExpr(Node):
    """(expression) — parenthesized expression."""
    expression: Optional[Node] = None
