"""
LuauShield Layer 6 — Dead Code Injection
==========================================
Injects realistic-looking but unreachable/meaningless code:
- Fake function definitions
- Junk computation blocks
- Shadow variable injection
- Fake API calls in unreachable branches
"""

from parser.ast_nodes import *
from utils.names import NameGenerator
from config import ObfuscationConfig, DeadCodeDensity
from typing import List


class DeadCodeInjector:
    """Injects dead code to increase analysis complexity."""

    # Template junk function bodies
    JUNK_OPERATIONS = [
        'math.floor', 'math.ceil', 'math.abs', 'math.sqrt',
        'math.sin', 'math.cos', 'math.random',
    ]

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.name_gen = NameGenerator(rng=self.rng, min_length=8, max_length=12)
        self.density = config.dead_code_density
        self.fake_func_count = config.fake_function_count

        # Injection probability based on density
        self._prob = {
            DeadCodeDensity.LOW: 0.05,
            DeadCodeDensity.MEDIUM: 0.15,
            DeadCodeDensity.HIGH: 0.30,
        }[self.density]

    def apply(self, block: Block) -> Block:
        """Apply dead code injection to the AST."""
        # Inject junk code throughout the block
        self._inject_junk(block)
        return block

    def _inject_junk(self, block: Block):
        """Inject junk statements throughout a block."""
        new_body = []
        for stmt in block.body:
            # Recurse into child blocks
            self._visit_children(stmt)
            new_body.append(stmt)

            # Do not inject junk after terminal statements, as it causes syntax errors
            # (return, break, and continue MUST be the last statements in a block)
            if isinstance(stmt, (ReturnStatement, BreakStatement, ContinueStatement)):
                continue

            # Randomly inject junk after statements
            if self.rng.random() < self._prob:
                junk = self._gen_junk_statement()
                new_body.append(junk)

        block.body = new_body

    def _visit_children(self, node: Node):
        if node is None:
            return
        if isinstance(node, FunctionDecl):
            self._inject_junk(node.body)
        elif isinstance(node, FunctionExpr):
            self._inject_junk(node.body)
        elif isinstance(node, IfStatement):
            self._inject_junk(node.body)
            for c in node.elseif_clauses:
                self._inject_junk(c.body)
            if node.else_body:
                self._inject_junk(node.else_body)
        elif isinstance(node, WhileLoop):
            self._inject_junk(node.body)
        elif isinstance(node, NumericFor):
            self._inject_junk(node.body)
        elif isinstance(node, GenericFor):
            self._inject_junk(node.body)
        elif isinstance(node, RepeatUntil):
            self._inject_junk(node.body)
        elif isinstance(node, DoBlock):
            self._inject_junk(node.body)

    def _gen_fake_functions(self) -> List[Node]:
        """Generate fake function declarations that are never called."""
        funcs = []
        for _ in range(self.fake_func_count):
            func_name = self.name_gen.gen_name()
            param_count = self.rng.randint(0, 3)
            params = [self.name_gen.gen_name() for _ in range(param_count)]

            body_stmts = []
            # Add some realistic-looking computation
            for _ in range(self.rng.randint(2, 6)):
                body_stmts.append(self._gen_junk_local())

            # Maybe a return
            if self.rng.random() > 0.3:
                ret_var = self.name_gen.gen_name()
                body_stmts.append(LocalStatement(
                    names=[ret_var],
                    values=[NumberLiteral(value=str(self.rng.randint(0, 1000)))]
                ))
                body_stmts.append(ReturnStatement(values=[Identifier(name=ret_var)]))

            func = FunctionDecl(
                name=Identifier(name=func_name),
                params=params,
                body=Block(body=body_stmts),
                is_local=True
            )
            funcs.append(func)
        return funcs

    def _gen_junk_statement(self) -> Node:
        """Generate a single junk statement."""
        # Only use simple locals or shadow variables, avoid complex blocks for memory
        strategy = self.rng.randint(0, 1)

        if strategy == 0:
            return self._gen_junk_local()
        else:
            return self._gen_shadow_variable()

    def _gen_junk_local(self) -> LocalStatement:
        """Generate a junk local variable with a computation."""
        var = self.name_gen.gen_name()
        op = self.rng.choice(self.JUNK_OPERATIONS)
        parts = op.split('.')
        val = self.rng.randint(1, 100)

        func_call = FunctionCall(
            func=MemberExpr(
                object=Identifier(name=parts[0]),
                member=parts[1]
            ),
            args=[NumberLiteral(value=str(val))]
        )
        return LocalStatement(names=[var], values=[func_call])

    def _gen_junk_do_block(self) -> DoBlock:
        """Generate a do block with junk code (creates isolated scope)."""
        var1 = self.name_gen.gen_name()
        var2 = self.name_gen.gen_name()
        return DoBlock(body=Block(body=[
            LocalStatement(
                names=[var1],
                values=[NumberLiteral(value=str(self.rng.randint(1, 500)))]
            ),
            LocalStatement(
                names=[var2],
                values=[BinaryOp(
                    op='*',
                    left=Identifier(name=var1),
                    right=NumberLiteral(value=str(self.rng.randint(2, 10)))
                )]
            ),
        ]))

    def _gen_shadow_variable(self) -> DoBlock:
        """Generate a do block that shadows an outer variable (confuses readers)."""
        var = self.name_gen.gen_name()
        return DoBlock(body=Block(body=[
            LocalStatement(
                names=[var],
                values=[StringLiteral(value='shadow')]
            ),
            LocalStatement(
                names=[self.name_gen.gen_name()],
                values=[Identifier(name=var)]
            ),
        ]))

    def _gen_noop_computation(self) -> Node:
        """Generate a computation that runs but does nothing meaningful."""
        var = self.name_gen.gen_name()
        val = self.rng.randint(1, 100)
        # local x = val; x = x + 1; x = x - 1  (net zero effect)
        return DoBlock(body=Block(body=[
            LocalStatement(
                names=[var],
                values=[NumberLiteral(value=str(val))]
            ),
            AssignStatement(
                targets=[Identifier(name=var)],
                values=[BinaryOp(
                    op='+',
                    left=Identifier(name=var),
                    right=NumberLiteral(value='1')
                )]
            ),
            AssignStatement(
                targets=[Identifier(name=var)],
                values=[BinaryOp(
                    op='-',
                    left=Identifier(name=var),
                    right=NumberLiteral(value='1')
                )]
            ),
        ]))
