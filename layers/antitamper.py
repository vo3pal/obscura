"""
Obscura Layer 8 — Anti-Tamper
==================================
Injects Roblox environment validation, hook detection, timing checks,
integrity verification, and IIFE wrapping for script protection.
"""

from parser.ast_nodes import *
from utils.names import NameGenerator
from config import ObfuscationConfig
from typing import List


class AntiTamperInjector:
    """Injects anti-tamper, anti-debug, and environment hardening code."""

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.name_gen = NameGenerator(rng=self.rng, min_length=8, max_length=12)

    def apply(self, block: Block) -> Block:
        """Apply anti-tamper protections to the AST."""
        guards = []

        if self.config.check_environment:
            guards.extend(self._gen_env_check())

        if self.config.check_hooks:
            guards.extend(self._gen_hook_detection())


        if self.config.check_integrity:
            guards.extend(self._gen_integrity_check())

        # Insert guards at the top
        block.body = guards + block.body

        # Wrap everything in IIFE if configured
        if self.config.wrap_in_iife:
            block = self._wrap_in_iife(block)

        return block

    def _gen_env_check(self) -> List[Node]:
        """Generate Roblox environment validation."""
        # if typeof == nil or game == nil then while true do task.wait(999) end end
        check_var = self.name_gen.gen_name()

        # Check for Roblox environment
        env_check = IfStatement(
            condition=BinaryOp(
                op='or',
                left=BinaryOp(
                    op='==',
                    left=Identifier(name='typeof'),
                    right=NilLiteral()
                ),
                right=BinaryOp(
                    op='==',
                    left=Identifier(name='game'),
                    right=NilLiteral()
                )
            ),
            body=Block(body=[
                # Use a standard error instead of an infinite hang
                ExpressionStatement(expression=FunctionCall(
                    func=Identifier(name='error'),
                    args=[StringLiteral(value='Execution denied')]
                ))
            ]),
            elseif_clauses=[],
            else_body=None
        )

        # Check for RunService
        rs_var = self.name_gen.gen_name()
        rs_check = IfStatement(
            condition=UnaryOp(
                op='not',
                operand=FunctionCall(
                    func=Identifier(name='pcall'),
                    args=[FunctionExpr(
                        params=[],
                        body=Block(body=[
                            ReturnStatement(values=[
                                MethodCall(
                                    object=Identifier(name='game'),
                                    method='GetService',
                                    args=[StringLiteral(value='RunService')]
                                )
                            ])
                        ])
                    )]
                )
            ),
            body=Block(body=[
                ExpressionStatement(expression=FunctionCall(
                    func=Identifier(name='error'),
                    args=[StringLiteral(value='')]
                ))
            ]),
            elseif_clauses=[],
            else_body=None
        )

        return [env_check, rs_check]

    def _gen_hook_detection(self) -> List[Node]:
        """Detect common exploit hooks."""
        type_backup = self.name_gen.gen_name()
        check_fn = self.name_gen.gen_name()

        # local _type = type
        backup = LocalStatement(
            names=[type_backup],
            values=[Identifier(name='type')]
        )

        # Check for injected exploit globals
        exploit_globals = ['getgenv', 'hookfunction', 'fireclickdetector',
                          'getrawmetatable', 'newcclosure', 'checkcaller']

        checks = []
        for g in exploit_globals:
            check = IfStatement(
                condition=BinaryOp(
                    op='~=',
                    left=FunctionCall(
                        func=Identifier(name=type_backup),
                        args=[Identifier(name=g)]
                    ),
                    right=StringLiteral(value='nil')
                ),
                body=Block(body=[
                    ExpressionStatement(expression=FunctionCall(
                        func=Identifier(name='error'),
                        args=[StringLiteral(value='Security violation')]
                    ))
                ]),
                elseif_clauses=[],
                else_body=None
            )
            checks.append(check)

        # Verify core functions haven't been hooked
        core_check = IfStatement(
            condition=BinaryOp(
                op='~=',
                left=FunctionCall(
                    func=Identifier(name=type_backup),
                    args=[Identifier(name='print')]
                ),
                right=StringLiteral(value='function')
            ),
            body=Block(body=[
                ExpressionStatement(expression=FunctionCall(
                    func=Identifier(name='error'),
                    args=[StringLiteral(value='Environment tampered')]
                ))
            ]),
            elseif_clauses=[],
            else_body=None
        )
        checks.append(core_check)

        return [backup] + checks

    def _gen_integrity_check(self) -> List[Node]:
        """Generate function integrity verification."""
        fn_sig = self.name_gen.gen_name()
        target = self.name_gen.gen_name()

        return [DoBlock(body=Block(body=[
            # Store a reference and its string form
            LocalStatement(
                names=[target],
                values=[Identifier(name='print')]
            ),
            LocalStatement(
                names=[fn_sig],
                values=[FunctionCall(
                    func=Identifier(name='tostring'),
                    args=[Identifier(name=target)]
                )]
            ),
            # Later check it hasn't changed
            IfStatement(
                condition=BinaryOp(
                    op='~=',
                    left=FunctionCall(
                        func=Identifier(name='tostring'),
                        args=[Identifier(name=target)]
                    ),
                    right=Identifier(name=fn_sig)
                ),
                body=Block(body=[
                    ExpressionStatement(expression=FunctionCall(
                        func=Identifier(name='error'),
                        args=[StringLiteral(value='Integrity check failed')]
                    ))
                ]),
                elseif_clauses=[],
                else_body=None
            )
        ]))]

    def _wrap_in_iife(self, block: Block) -> Block:
        """Wrap entire code in do local _ = (function() ... end)() end to prevent syntax errors."""
        iife = LocalStatement(
            names=['_'],
            values=[FunctionCall(
                func=ParenExpr(expression=FunctionExpr(
                    params=[],
                    body=block
                )),
                args=[]
            )]
        )
        # Wrap the IIFE inside a `do ... end` block to prevent ambiguous parsing
        return Block(body=[DoBlock(body=Block(body=[iife]))])
