"""
Obscura Layer 8 — Anti-Tamper
==================================
Injects Roblox environment validation, hook detection, repeated integrity
verification, and IIFE wrapping for script protection.
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
        self.guard_name = self.name_gen.gen_name()

    def _char_expr(self, value: str) -> Identifier:
        return Identifier(name='string.char(' + ','.join(str(ord(ch)) for ch in value) + ')')

    def apply(self, block: Block) -> Block:
        """Apply anti-tamper protections to the AST."""
        guards = []

        # Add calls before inserting the guard implementation itself, so its
        # internal helper closure is not instrumented recursively.
        if self.config.check_integrity:
            self._inject_function_guards(block)

        if self.config.check_environment:
            guards.extend(self._gen_env_check())

        if self.config.check_hooks:
            guards.extend(self._gen_hook_detection())


        if self.config.check_integrity:
            guards.extend(self._gen_integrity_check())

        # Run once during startup and once again immediately before the last
        # top-level operation. Function bodies receive their own entry checks.
        original = block.body
        if self.config.check_integrity and original:
            tail_index = max(0, len(original) - 1)
            original = original[:tail_index] + [self._guard_call()] + original[tail_index:]
        block.body = guards + original

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
                    args=[StringLiteral(value='')]
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
                                    args=[self._char_expr('RunService')]
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
                    right=FunctionCall(
                        func=Identifier(name=type_backup),
                        args=[NilLiteral()]
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
            checks.append(check)

        # Verify core functions haven't been hooked
        core_check = IfStatement(
            condition=BinaryOp(
                op='~=',
                left=FunctionCall(
                    func=Identifier(name=type_backup),
                    args=[Identifier(name='print')]
                ),
                right=FunctionCall(
                    func=Identifier(name=type_backup),
                    args=[FunctionExpr(params=[], body=Block(body=[]))]
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
        checks.append(core_check)

        return [backup] + checks

    def _gen_integrity_check(self) -> List[Node]:
        """Build a polymorphic guard tied to build-specific integrity data."""
        names = {key: self.name_gen.gen_name() for key in (
            'type', 'typeof', 'tostring', 'pcall', 'string', 'table', 'math',
            'bit', 'error', 'game', 'data', 'counter', 'fail', 'hash', 'i',
            'ok', 'result', 'challenge', 'states', 'token', 'state', 'start',
            'index', 'expected',
        )}
        values = [self.rng.randint(0, 255) for _ in range(self.rng.randint(11, 19))]
        seed = self.rng.randrange(4294967296)
        multiplier = self.rng.randrange(257, 65536, 2)
        digests = []
        for start in range(len(values)):
            digest = seed
            for offset in range(len(values)):
                digest = (digest * multiplier + values[(start + offset) % len(values)]) % 4294967296
            digests.append(digest)
        challenge_mask = self.rng.randrange(1, 0x1000000)
        state_multiplier = self.rng.randrange(257, 65536, 2)
        token_multiplier = self.rng.randrange(257, 65536, 2)
        counter_multiplier = self.rng.randrange(257, 65536, 2)
        state_add = self.rng.randrange(4294967296)
        data = '{' + ','.join(str(value) for value in values) + '}'
        expected = '{' + ','.join(str(value) for value in digests) + '}'
        n = names
        code = f'''local {self.guard_name}=(function()
local {n['type']},{n['typeof']},{n['tostring']},{n['pcall']}=type,typeof,tostring,pcall
local {n['string']},{n['table']},{n['math']},{n['bit']}=string,table,math,bit32
local {n['error']},{n['game']}=error,game
local {n['data']}={data}
local {n['expected']}={expected}
local {n['counter']}=0
local {n['states']}={{}}
local function {n['fail']}() return {n['error']}("") end
return function({n['token']})
{n['counter']}={n['counter']}+1
if type~={n['type']} or typeof~={n['typeof']} or tostring~={n['tostring']} or pcall~={n['pcall']}
or string~={n['string']} or table~={n['table']} or math~={n['math']} or bit32~={n['bit']}
or error~={n['error']} or game~={n['game']} then return {n['fail']}() end
local {n['state']}={n['states']}[{n['token']}] or {n['bit']}.bxor({seed},{n['token']})
{n['state']}=({n['state']}*{state_multiplier}+{n['token']}*{token_multiplier}+{n['counter']}*{counter_multiplier}+{state_add})%4294967296
{n['states']}[{n['token']}]={n['state']}
local {n['start']}={n['state']}%#{n['data']}+1
local {n['hash']}={seed}
for {n['i']}=0,#{n['data']}-1 do
local {n['index']}=({n['start']}+{n['i']}-1)%#{n['data']}+1
{n['hash']}=({n['hash']}*{multiplier}+{n['data']}[{n['index']}])%4294967296
end
if {n['hash']}~={n['expected']}[{n['start']}] then return {n['fail']}() end
local {n['challenge']}={n['bit']}.bxor(({n['state']}+{n['counter']}*{challenge_mask})%4294967296,{challenge_mask})
if {n['bit']}.bxor({n['challenge']},{challenge_mask})~=({n['state']}+{n['counter']}*{challenge_mask})%4294967296 then return {n['fail']}() end
local {n['ok']},{n['result']}={n['pcall']}(function()
return {n['type']}({n['type']})=="function"
and {n['type']}({n['typeof']})=="function"
and {n['type']}({n['string']})=="table"
and {n['type']}({n['table']})=="table"
and {n['type']}({n['math']})=="table"
and {n['type']}({n['bit']})=="table"
and {n['string']}.byte({n['string']}.char(83,69,78,84),1)==83
and {n['string']}.sub({n['string']}.char(83,69,78,84),2,4)=="ENT"
and {n['table']}.concat({{"S","E","N"}})=="SEN"
and {n['math']}.floor(511/2)==255
and {n['bit']}.bxor(165,90)==255
and {n['bit']}.band(255,90)==90
and {n['tostring']}(65535)=="65535"
end)
if not {n['ok']} or not {n['result']} then return {n['fail']}() end
if getgenv~=nil or hookfunction~=nil or getrawmetatable~=nil or newcclosure~=nil or checkcaller~=nil then return {n['fail']}() end
return true
end
end)()'''
        return [
            ExpressionStatement(expression=Identifier(name=code)),
            self._guard_call(),
        ]

    def _guard_call(self) -> ExpressionStatement:
        return ExpressionStatement(expression=FunctionCall(
            func=Identifier(name=self.guard_name),
            args=[NumberLiteral(value=str(self.rng.randrange(1, 0x1000000)))]
        ))

    def _inject_function_guards(self, node: Node):
        """Invoke the integrity guard at each protected function entry."""
        if node is None or isinstance(node, Identifier):
            return
        for value in vars(node).values():
            if isinstance(value, (FunctionDecl, FunctionExpr)):
                self._inject_function_guards(value.body)
                value.body.body.insert(0, self._guard_call())
            elif isinstance(value, Node):
                self._inject_function_guards(value)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, (FunctionDecl, FunctionExpr)):
                        self._inject_function_guards(child.body)
                        child.body.body.insert(0, self._guard_call())
                    elif isinstance(child, Node):
                        self._inject_function_guards(child)

    def _wrap_in_iife(self, block: Block) -> Block:
        """Isolate locals while forwarding chunk arguments and return values."""
        iife = ReturnStatement(
            values=[FunctionCall(
                func=ParenExpr(expression=FunctionExpr(
                    params=[],
                    has_vararg=True,
                    body=block
                )),
                args=[VarargExpr()]
            )]
        )
        # Wrap the IIFE inside a `do ... end` block to prevent ambiguous parsing
        return Block(body=[DoBlock(body=Block(body=[iife]))])
