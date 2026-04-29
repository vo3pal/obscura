"""
LuauShield Layer 5 — Opaque Predicates
========================================
Generates always-true and always-false conditions using mathematical identities.
Wraps real code in true predicates, injects dead branches in false predicates.
"""

from parser.ast_nodes import *
from utils.names import NameGenerator
from config import ObfuscationConfig
from typing import List


class OpaquePredicateGenerator:
    """Injects opaque predicates to guard real and fake code branches."""

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.name_gen = NameGenerator(rng=self.rng, min_length=6, max_length=10)

    def apply(self, block: Block) -> Block:
        """Apply opaque predicates to blocks in the AST."""
        self._visit_block(block)
        return block

    def _visit_block(self, block: Block):
        new_body = []
        for stmt in block.body:
            self._visit_children(stmt)

            # Randomly wrap simple statements in opaque-true predicates
            if self.rng.random() < 0.25 and isinstance(stmt, (AssignStatement, ExpressionStatement)):
                wrapped = self._wrap_in_true_predicate(stmt)
                new_body.append(wrapped)
            else:
                new_body.append(stmt)

            # Randomly inject dead code after opaque-false predicates
            if self.rng.random() < 0.15:
                dead = self._gen_false_predicate_block()
                new_body.append(dead)

        block.body = new_body

    def _visit_children(self, node: Node):
        if node is None:
            return
        if isinstance(node, FunctionDecl):
            self._visit_block(node.body)
        elif isinstance(node, FunctionExpr):
            self._visit_block(node.body)
        elif isinstance(node, IfStatement):
            self._visit_block(node.body)
            for c in node.elseif_clauses:
                self._visit_block(c.body)
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

    def _wrap_in_true_predicate(self, stmt: Node) -> IfStatement:
        """Wrap a statement in an always-true predicate."""
        cond = self._gen_true_predicate()
        return IfStatement(
            condition=cond,
            body=Block(body=[stmt]),
            elseif_clauses=[],
            else_body=None,
            line=stmt.line, col=stmt.col
        )

    def _gen_true_predicate(self) -> Node:
        """Generate an always-true condition."""
        strategy = self.rng.randint(0, 4)

        if strategy == 0:
            # x * x >= 0 (always true for any integer)
            var = self.name_gen.gen_name()
            val = self.rng.randint(2, 50)
            # (function() local v = N return v*v >= 0 end)()
            return FunctionCall(
                func=ParenExpr(expression=FunctionExpr(
                    params=[],
                    body=Block(body=[
                        LocalStatement(names=[var], values=[NumberLiteral(value=str(val))]),
                        ReturnStatement(values=[BinaryOp(
                            op='>=',
                            left=BinaryOp(op='*',
                                left=Identifier(name=var),
                                right=Identifier(name=var)),
                            right=NumberLiteral(value='0')
                        )])
                    ])
                )),
                args=[]
            )

        elif strategy == 1:
            # bit32.bxor(x, x) == 0 (always true)
            val = self.rng.randint(1, 255)
            return BinaryOp(
                op='==',
                left=FunctionCall(
                    func=MemberExpr(object=Identifier(name='bit32'), member='bxor'),
                    args=[NumberLiteral(value=str(val)), NumberLiteral(value=str(val))]
                ),
                right=NumberLiteral(value='0')
            )

        elif strategy == 2:
            # (a^2 + b^2) == known_constant
            a = self.rng.randint(2, 20)
            b = self.rng.randint(2, 20)
            result = a * a + b * b
            va, vb = self.name_gen.gen_name(), self.name_gen.gen_name()
            return FunctionCall(
                func=ParenExpr(expression=FunctionExpr(
                    params=[],
                    body=Block(body=[
                        LocalStatement(names=[va], values=[NumberLiteral(value=str(a))]),
                        LocalStatement(names=[vb], values=[NumberLiteral(value=str(b))]),
                        ReturnStatement(values=[BinaryOp(
                            op='==',
                            left=BinaryOp(op='+',
                                left=BinaryOp(op='*', left=Identifier(name=va), right=Identifier(name=va)),
                                right=BinaryOp(op='*', left=Identifier(name=vb), right=Identifier(name=vb))),
                            right=NumberLiteral(value=str(result))
                        )])
                    ])
                )),
                args=[]
            )

        elif strategy == 3:
            # (7 * k) % 7 == 0 (always true)
            k = self.rng.randint(1, 100)
            p = self.rng.choice([3, 5, 7, 11, 13])
            return BinaryOp(
                op='==',
                left=BinaryOp(op='%',
                    left=BinaryOp(op='*',
                        left=NumberLiteral(value=str(p)),
                        right=NumberLiteral(value=str(k))),
                    right=NumberLiteral(value=str(p))),
                right=NumberLiteral(value='0')
            )

        else:
            # type(nil) == "nil" (always true)
            return BinaryOp(
                op='==',
                left=FunctionCall(
                    func=Identifier(name='type'),
                    args=[NilLiteral()]
                ),
                right=StringLiteral(value='nil')
            )

    def _gen_false_predicate(self) -> Node:
        """Generate an always-false condition."""
        strategy = self.rng.randint(0, 2)

        if strategy == 0:
            # x * x < 0 (always false)
            val = self.rng.randint(1, 100)
            v = self.name_gen.gen_name()
            return FunctionCall(
                func=ParenExpr(expression=FunctionExpr(
                    params=[],
                    body=Block(body=[
                        LocalStatement(names=[v], values=[NumberLiteral(value=str(val))]),
                        ReturnStatement(values=[BinaryOp(
                            op='<',
                            left=BinaryOp(op='*', left=Identifier(name=v), right=Identifier(name=v)),
                            right=NumberLiteral(value='0')
                        )])
                    ])
                )),
                args=[]
            )

        elif strategy == 1:
            # type(nil) == "number" (always false)
            return BinaryOp(
                op='==',
                left=FunctionCall(func=Identifier(name='type'), args=[NilLiteral()]),
                right=StringLiteral(value='number')
            )

        else:
            # false
            return BooleanLiteral(value=False)

    def _gen_false_predicate_block(self) -> IfStatement:
        """Generate an if block with a false predicate containing junk code."""
        junk_var = self.name_gen.gen_name()
        junk_val = self.rng.randint(1, 1000)

        junk_body = Block(body=[
            LocalStatement(names=[junk_var], values=[NumberLiteral(value=str(junk_val))]),
            ExpressionStatement(expression=FunctionCall(
                func=Identifier(name='error'),
                args=[StringLiteral(value='unreachable')]
            )),
        ])

        return IfStatement(
            condition=self._gen_false_predicate(),
            body=junk_body,
            elseif_clauses=[],
            else_body=None
        )
