"""
LuauShield Layer 4 — Control Flow Flattening
===============================================
Transforms sequential code blocks into state-machine dispatchers.
Uses while-loop + if/elseif chains with randomized state values.
Supports state encoding (XOR-based next-state computation).
"""

from parser.ast_nodes import *
from utils.names import NameGenerator
from config import ObfuscationConfig
from typing import List


def _append_state_transition(clause_body: Block, stmts: list, i: int, state_var: str, state_values: list, cff_instance):
    """Appends state assignment or break safely, avoiding 'return ... break' syntax errors."""
    if not clause_body.body:
        return

    last_stmt = clause_body.body[-1]

    # If the last statement is Return or Break, we shouldn't append anything
    if isinstance(last_stmt, (ReturnStatement, BreakStatement, ContinueStatement)):
        return

    # Sometimes a Return might be inside a Block or DoBlock
    if isinstance(last_stmt, DoBlock) and last_stmt.body.body:
        if isinstance(last_stmt.body.body[-1], (ReturnStatement, BreakStatement, ContinueStatement)):
            return

    if i + 1 < len(stmts):
        next_state_expr = cff_instance._make_state_assign(state_var, state_values[i + 1])
        clause_body.body.append(next_state_expr)
    else:
        clause_body.body.append(BreakStatement())


class ControlFlowFlattener:
    """Flattens sequential code into state-machine dispatchers."""

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.name_gen = NameGenerator(rng=self.rng, min_length=8, max_length=12)
        self.min_blocks = config.min_blocks_for_cff
        self.encode_transitions = config.encode_state_transitions

    def apply(self, block: Block) -> Block:
        """Apply CFF to all eligible blocks in the AST."""
        self._visit_block(block)
        return block

    def _visit_block(self, block: Block):
        """Visit a block and flatten it if eligible."""
        # First, recurse into child blocks
        for stmt in block.body:
            self._visit_children(stmt)

        # Then flatten this block if it has enough statements
        if len(block.body) >= self.min_blocks:
            flattened = self._flatten_block(block.body)
            block.body = flattened

    def _visit_children(self, node: Node):
        """Recurse into child nodes that contain blocks."""
        if node is None:
            return

        if isinstance(node, FunctionDecl):
            self._visit_block(node.body)
        elif isinstance(node, FunctionExpr):
            self._visit_block(node.body)
        elif isinstance(node, IfStatement):
            self._visit_block(node.body)
            for clause in node.elseif_clauses:
                self._visit_block(clause.body)
            if node.else_body:
                self._visit_block(node.else_body)
        elif isinstance(node, WhileLoop):
            self._visit_block(node.body)
        elif isinstance(node, NumericFor):
            self._visit_block(node.body)
        elif isinstance(node, GenericFor):
            self._visit_block(node.body)
        elif isinstance(node, RepeatUntil):
            self._visit_block(node.body)
        elif isinstance(node, DoBlock):
            self._visit_block(node.body)

    def _flatten_block(self, stmts: List[Node]) -> List[Node]:
        """Convert a list of statements into a state-machine dispatcher."""
        # First, hoist all local declarations so they don't lose scope inside the if-blocks
        hoisted_locals = []
        new_stmts = []

        for stmt in stmts:
            if isinstance(stmt, LocalStatement):
                # Hoist names without values
                hoisted_locals.append(LocalStatement(names=list(stmt.names), values=[], line=stmt.line, col=stmt.col))
                if stmt.values:
                    # Convert original statement to an assignment
                    targets = [Identifier(name=n, line=stmt.line, col=stmt.col) for n in stmt.names]
                    new_stmts.append(AssignStatement(targets=targets, values=list(stmt.values), line=stmt.line, col=stmt.col))
                else:
                    # Empty statement placeholder to keep block count
                    new_stmts.append(DoBlock(body=Block(body=[])))
            elif isinstance(stmt, FunctionDecl):
                # Hoist or convert to assignment
                target = stmt.name
                params = list(stmt.params)
                
                # If it's a method declaration (obj:method), convert to obj.method = function(self, ...)
                if isinstance(target, MethodCall):
                    target = MemberExpr(object=target.object, member=target.method, line=target.line, col=target.col)
                    params.insert(0, 'self')
                
                func_expr = FunctionExpr(
                    params=params, has_vararg=stmt.has_vararg,
                    body=stmt.body, line=stmt.line, col=stmt.col
                )
                
                if stmt.is_local and isinstance(target, Identifier):
                    # local function f() -> hoist 'local f' and assign 'f = function()'
                    hoisted_locals.append(LocalStatement(names=[target.name], values=[], line=stmt.line, col=stmt.col))
                    new_stmts.append(AssignStatement(
                        targets=[Identifier(name=target.name, line=stmt.line, col=stmt.col)],
                        values=[func_expr], line=stmt.line, col=stmt.col
                    ))
                else:
                    # function f() or function a.b() or function a:b() -> convert to assignment
                    new_stmts.append(AssignStatement(
                        targets=[target],
                        values=[func_expr], line=stmt.line, col=stmt.col
                    ))
            else:
                new_stmts.append(stmt)

        stmts = new_stmts

        # Generate unique state values for each block
        state_values = [self.name_gen.gen_state_value() for _ in stmts]

        # Ensure all state values are unique
        used = set()
        for i, sv in enumerate(state_values):
            while sv in used:
                sv = self.name_gen.gen_state_value()
            state_values[i] = sv
            used.add(sv)

        # Terminal state (for break)
        terminal_state = self.name_gen.gen_state_value()
        while terminal_state in used:
            terminal_state = self.name_gen.gen_state_value()

        state_var = self.name_gen.gen_name()

        # Build the if-elseif chain
        # First state
        first_clause_body = Block(body=list(stmts[0:1]))
        _append_state_transition(first_clause_body, stmts, 0, state_var, state_values, self)

        # Build the if statement
        condition = BinaryOp(
            op='==',
            left=Identifier(name=state_var),
            right=NumberLiteral(value=str(state_values[0]))
        )
        if_stmt = IfStatement(
            condition=condition,
            body=first_clause_body,
            elseif_clauses=[],
            else_body=Block(body=[
                ExpressionStatement(expression=FunctionCall(
                    func=Identifier(name='error'),
                    args=[StringLiteral(value='CFF Error: Invalid state')]
                ))
            ])
        )

        # Add elseif clauses for remaining states
        for i in range(1, len(stmts)):
            clause_body = Block(body=[stmts[i]])
            _append_state_transition(clause_body, stmts, i, state_var, state_values, self)

            elseif = ElseIfClause(
                condition=BinaryOp(
                    op='==',
                    left=Identifier(name=state_var),
                    right=NumberLiteral(value=str(state_values[i]))
                ),
                body=clause_body
            )
            if_stmt.elseif_clauses.append(elseif)

        # Shuffle the elseif order (but keep the if as first state)
        self.rng.shuffle(if_stmt.elseif_clauses)

        # Wrap in while true do ... end
        while_loop = WhileLoop(
            condition=BooleanLiteral(value=True),
            body=Block(body=[if_stmt])
        )

        # local state_var = initial_state
        init = LocalStatement(
            names=[state_var],
            values=[NumberLiteral(value=str(state_values[0]))]
        )

        return hoisted_locals + [init, while_loop]

    def _make_state_assign(self, state_var: str, next_state: int) -> AssignStatement:
        """Create a state assignment, optionally with XOR encoding."""
        if self.encode_transitions and self.rng.random() > 0.3:
            # Encoded transition: state = bxor(encoded_value, key)
            key = self.rng.randint(1, 0xFFFF)
            encoded = next_state ^ key
            value = FunctionCall(
                func=MemberExpr(
                    object=Identifier(name="bit32"),
                    member="bxor"
                ),
                args=[
                    NumberLiteral(value=str(encoded)),
                    NumberLiteral(value=str(key))
                ]
            )
        else:
            value = NumberLiteral(value=str(next_state))

        return AssignStatement(
            targets=[Identifier(name=state_var)],
            values=[value]
        )
