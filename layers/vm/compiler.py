"""
LuauShield VM Compiler
========================
Walks the AST and emits custom bytecode for the stack-based VM.
Handles constants, locals, globals, arithmetic, control flow, and function calls.
"""

from parser.ast_nodes import *
from .opcodes import OpcodeMap
from .constant_pool import ConstantPool
from config import ObfuscationConfig
from utils.names import NameGenerator
from typing import List, Dict, Optional
import random


class VMCompilationError(Exception):
    pass


class FunctionPrototype:
    """Represents a compiled function in the VM."""

    def __init__(self):
        self.bytecode: List[int] = []
        self.num_params: int = 0
        self.has_vararg: bool = False
        self.max_locals: int = 0
        self.sub_protos: List['FunctionPrototype'] = []


class VMCompiler:
    """
    Compiles an AST into custom VM bytecode.
    Manages instruction emission, local slots, jump resolution, and constant pooling.
    """

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.opcodes = OpcodeMap(self.rng)
        self.pool = ConstantPool(self.rng)
        self.name_gen = NameGenerator(rng=self.rng, min_length=8, max_length=12)

        # Compilation state
        self._locals: Dict[str, int] = {}  # name -> slot
        self._next_slot: int = 0
        self._bytecode: List[int] = []
        self._protos: List[FunctionPrototype] = []
        self._break_targets: List[List[int]] = []  # Stack of break patch lists
        self._continue_targets: List[int] = []      # Stack of continue targets

    def compile(self, block: Block) -> FunctionPrototype:
        """Compile a complete program to a function prototype."""
        proto = FunctionPrototype()
        self._bytecode = proto.bytecode
        self._locals = {}
        self._next_slot = 0

        self._compile_block(block)

        # Implicit return at end
        self._emit(self.opcodes.get('PUSH_NIL'))
        self._emit(self.opcodes.get('RETURN'), 1)

        proto.max_locals = self._next_slot
        proto.sub_protos = self._protos
        return proto

    def _emit(self, *values):
        """Emit one or more bytecode values."""
        for v in values:
            self._bytecode.append(v & 0xFF)

    def _emit_at(self, pos: int, value: int):
        """Patch a bytecode value at a specific position."""
        self._bytecode[pos] = value & 0xFF

    def _current_pos(self) -> int:
        """Get current bytecode position."""
        return len(self._bytecode)

    def _alloc_local(self, name: str) -> int:
        """Allocate a local variable slot."""
        slot = self._next_slot
        self._locals[name] = slot
        self._next_slot += 1
        return slot

    def _get_local(self, name: str) -> Optional[int]:
        """Get the slot for a local variable."""
        return self._locals.get(name)

    # --- Compilation methods ---

    def _compile_block(self, block: Block):
        """Compile a block of statements."""
        for stmt in block.body:
            self._compile_node(stmt)

    def _compile_node(self, node: Node):
        """Compile a single AST node."""
        if isinstance(node, LocalStatement):
            self._compile_local(node)
        elif isinstance(node, AssignStatement):
            self._compile_assign(node)
        elif isinstance(node, ExpressionStatement):
            self._compile_expr(node.expression)
            self._emit(self.opcodes.get('POP'))
        elif isinstance(node, IfStatement):
            self._compile_if(node)
        elif isinstance(node, WhileLoop):
            self._compile_while(node)
        elif isinstance(node, NumericFor):
            self._compile_numeric_for(node)
        elif isinstance(node, GenericFor):
            self._compile_generic_for(node)
        elif isinstance(node, RepeatUntil):
            self._compile_repeat(node)
        elif isinstance(node, ReturnStatement):
            self._compile_return(node)
        elif isinstance(node, BreakStatement):
            self._compile_break()
        elif isinstance(node, ContinueStatement):
            self._compile_continue()
        elif isinstance(node, DoBlock):
            self._compile_block(node.body)
        elif isinstance(node, FunctionDecl):
            self._compile_func_decl(node)

    def _compile_local(self, node: LocalStatement):
        """Compile a local statement."""
        for i, name in enumerate(node.names):
            slot = self._alloc_local(name)
            if i < len(node.values):
                self._compile_expr(node.values[i])
            else:
                self._emit(self.opcodes.get('PUSH_NIL'))
            self._emit(self.opcodes.get('SET_LOCAL'), slot)

    def _compile_assign(self, node: AssignStatement):
        """Compile an assignment statement."""
        # Evaluate all values first
        for val in node.values:
            self._compile_expr(val)

        # Assign to targets (in reverse for stack order)
        for i in range(len(node.targets) - 1, -1, -1):
            target = node.targets[i]
            if isinstance(target, Identifier):
                slot = self._get_local(target.name)
                if slot is not None:
                    self._emit(self.opcodes.get('SET_LOCAL'), slot)
                else:
                    idx = self.pool.add(target.name)
                    self._emit(self.opcodes.get('SET_GLOBAL'), idx)
            elif isinstance(target, IndexExpr):
                self._compile_expr(target.object)
                self._compile_expr(target.index)
                # value is already on stack from above
                self._emit(self.opcodes.get('SET_TABLE'))
            elif isinstance(target, MemberExpr):
                self._compile_expr(target.object)
                idx = self.pool.add(target.member)
                self._emit(self.opcodes.get('PUSH_CONST'), idx)
                self._emit(self.opcodes.get('SET_TABLE'))

    def _compile_expr(self, node: Node):
        """Compile an expression (pushes result onto stack)."""
        if node is None:
            self._emit(self.opcodes.get('PUSH_NIL'))
            return

        if isinstance(node, NumberLiteral):
            val_str = node.value.replace('_', '')
            try:
                if val_str.startswith('0x') or val_str.startswith('0X'):
                    val = int(val_str, 16)
                elif val_str.startswith('0b') or val_str.startswith('0B'):
                    val = int(val_str, 2)
                elif '.' in val_str or 'e' in val_str.lower():
                    val = float(val_str)
                else:
                    val = int(val_str)
            except ValueError:
                val = 0
            idx = self.pool.add(val)
            self._emit(self.opcodes.get('PUSH_CONST'), idx)

        elif isinstance(node, StringLiteral):
            idx = self.pool.add(node.value)
            self._emit(self.opcodes.get('PUSH_CONST'), idx)

        elif isinstance(node, BooleanLiteral):
            if node.value:
                self._emit(self.opcodes.get('PUSH_TRUE'))
            else:
                self._emit(self.opcodes.get('PUSH_FALSE'))

        elif isinstance(node, NilLiteral):
            self._emit(self.opcodes.get('PUSH_NIL'))

        elif isinstance(node, Identifier):
            slot = self._get_local(node.name)
            if slot is not None:
                self._emit(self.opcodes.get('PUSH_LOCAL'), slot)
            else:
                idx = self.pool.add(node.name)
                self._emit(self.opcodes.get('GET_GLOBAL'), idx)

        elif isinstance(node, BinaryOp):
            self._compile_expr(node.left)
            self._compile_expr(node.right)
            op_map = {
                '+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV',
                '%': 'MOD', '^': 'POW', '==': 'EQ', '<': 'LT', '<=': 'LE',
                '..': 'CONCAT',
            }
            if node.op in op_map:
                self._emit(self.opcodes.get(op_map[node.op]))
                if node.op == '..':
                    pass  # CONCAT with count=2
            elif node.op == '~=':
                self._emit(self.opcodes.get('EQ'))
                self._emit(self.opcodes.get('NOT'))
            elif node.op == '>':
                # a > b => b < a (swap operands already on stack)
                self._emit(self.opcodes.get('LT'))
            elif node.op == '>=':
                self._emit(self.opcodes.get('LE'))
            elif node.op == 'and':
                # Short-circuit: if first is falsy, skip second
                self._compile_expr(node.left)
                jump_pos = self._current_pos()
                self._emit(self.opcodes.get('JMP_FALSE'), 0)  # Placeholder
                self._emit(self.opcodes.get('POP'))
                self._compile_expr(node.right)
                self._emit_at(jump_pos + 1, self._current_pos() - jump_pos - 2)
                return  # Already handled
            elif node.op == 'or':
                self._compile_expr(node.left)
                jump_pos = self._current_pos()
                self._emit(self.opcodes.get('JMP_TRUE'), 0)
                self._emit(self.opcodes.get('POP'))
                self._compile_expr(node.right)
                self._emit_at(jump_pos + 1, self._current_pos() - jump_pos - 2)
                return

        elif isinstance(node, UnaryOp):
            self._compile_expr(node.operand)
            if node.op == '-':
                self._emit(self.opcodes.get('UNM'))
            elif node.op == 'not':
                self._emit(self.opcodes.get('NOT'))
            elif node.op == '#':
                self._emit(self.opcodes.get('LEN'))

        elif isinstance(node, FunctionCall):
            self._compile_expr(node.func)
            for arg in node.args:
                self._compile_expr(arg)
            self._emit(self.opcodes.get('CALL'), len(node.args), 1)

        elif isinstance(node, MethodCall):
            self._compile_expr(node.object)
            # Duplicate object for self parameter
            idx = self.pool.add(node.method)
            self._emit(self.opcodes.get('PUSH_CONST'), idx)
            self._emit(self.opcodes.get('GET_TABLE'))
            # Push self + args
            self._compile_expr(node.object)
            for arg in node.args:
                self._compile_expr(arg)
            self._emit(self.opcodes.get('CALL'), len(node.args) + 1, 1)

        elif isinstance(node, MemberExpr):
            self._compile_expr(node.object)
            idx = self.pool.add(node.member)
            self._emit(self.opcodes.get('PUSH_CONST'), idx)
            self._emit(self.opcodes.get('GET_TABLE'))

        elif isinstance(node, IndexExpr):
            self._compile_expr(node.object)
            self._compile_expr(node.index)
            self._emit(self.opcodes.get('GET_TABLE'))

        elif isinstance(node, TableConstructor):
            self._emit(self.opcodes.get('NEW_TABLE'), len(node.fields), 0)
            for i, field in enumerate(node.fields):
                if field.key is None:
                    # Array part
                    idx = self.pool.add(i + 1)
                    self._emit(self.opcodes.get('PUSH_CONST'), idx)
                elif field.is_bracket_key:
                    self._compile_expr(field.key)
                else:
                    # Named field
                    key_name = field.key.value if isinstance(field.key, StringLiteral) else str(field.key)
                    idx = self.pool.add(key_name)
                    self._emit(self.opcodes.get('PUSH_CONST'), idx)
                self._compile_expr(field.value)
                self._emit(self.opcodes.get('SET_TABLE'))

        elif isinstance(node, FunctionExpr):
            # Compile as sub-prototype
            saved_bytecode = self._bytecode
            saved_locals = self._locals.copy()
            saved_slot = self._next_slot

            proto = FunctionPrototype()
            proto.num_params = len(node.params)
            proto.has_vararg = node.has_vararg
            self._bytecode = proto.bytecode
            self._locals = {}
            self._next_slot = 0

            for p in node.params:
                self._alloc_local(p)

            self._compile_block(node.body)
            self._emit(self.opcodes.get('PUSH_NIL'))
            self._emit(self.opcodes.get('RETURN'), 1)

            proto.max_locals = self._next_slot
            proto_idx = len(self._protos)
            self._protos.append(proto)

            # Restore state
            self._bytecode = saved_bytecode
            self._locals = saved_locals
            self._next_slot = saved_slot

            self._emit(self.opcodes.get('CLOSURE'), proto_idx)

        elif isinstance(node, ParenExpr):
            self._compile_expr(node.expression)

        elif isinstance(node, VarargExpr):
            self._emit(self.opcodes.get('VARARG'), 1)

    def _compile_if(self, node: IfStatement):
        """Compile an if statement."""
        self._compile_expr(node.condition)
        false_jump = self._current_pos()
        self._emit(self.opcodes.get('JMP_FALSE'), 0)

        self._compile_block(node.body)
        end_jumps = []
        end_jumps.append(self._current_pos())
        self._emit(self.opcodes.get('JMP'), 0)

        # Patch false jump
        self._emit_at(false_jump + 1, self._current_pos() - false_jump - 2)

        for clause in node.elseif_clauses:
            self._compile_expr(clause.condition)
            false_jump = self._current_pos()
            self._emit(self.opcodes.get('JMP_FALSE'), 0)

            self._compile_block(clause.body)
            end_jumps.append(self._current_pos())
            self._emit(self.opcodes.get('JMP'), 0)

            self._emit_at(false_jump + 1, self._current_pos() - false_jump - 2)

        if node.else_body:
            self._compile_block(node.else_body)

        # Patch all end jumps
        end_pos = self._current_pos()
        for jp in end_jumps:
            self._emit_at(jp + 1, end_pos - jp - 2)

    def _compile_while(self, node: WhileLoop):
        """Compile a while loop."""
        loop_start = self._current_pos()
        self._break_targets.append([])

        self._compile_expr(node.condition)
        exit_jump = self._current_pos()
        self._emit(self.opcodes.get('JMP_FALSE'), 0)

        self._compile_block(node.body)

        # Jump back to start
        back_offset = loop_start - self._current_pos() - 2
        self._emit(self.opcodes.get('JMP'), back_offset & 0xFF)

        # Patch exit jump
        self._emit_at(exit_jump + 1, self._current_pos() - exit_jump - 2)

        # Patch break targets
        for bp in self._break_targets.pop():
            self._emit_at(bp + 1, self._current_pos() - bp - 2)

    def _compile_numeric_for(self, node: NumericFor):
        """Compile a numeric for loop."""
        slot = self._alloc_local(node.var_name)

        self._compile_expr(node.start)
        self._emit(self.opcodes.get('SET_LOCAL'), slot)

        # Evaluate stop
        stop_slot = self._next_slot
        self._next_slot += 1
        self._compile_expr(node.stop)
        self._emit(self.opcodes.get('SET_LOCAL'), stop_slot)

        loop_start = self._current_pos()
        self._break_targets.append([])

        # Check: i <= stop
        self._emit(self.opcodes.get('PUSH_LOCAL'), slot)
        self._emit(self.opcodes.get('PUSH_LOCAL'), stop_slot)
        self._emit(self.opcodes.get('LE'))
        exit_jump = self._current_pos()
        self._emit(self.opcodes.get('JMP_FALSE'), 0)

        self._compile_block(node.body)

        # Increment
        self._emit(self.opcodes.get('PUSH_LOCAL'), slot)
        if node.step:
            self._compile_expr(node.step)
        else:
            idx = self.pool.add(1)
            self._emit(self.opcodes.get('PUSH_CONST'), idx)
        self._emit(self.opcodes.get('ADD'))
        self._emit(self.opcodes.get('SET_LOCAL'), slot)

        # Loop back
        back_offset = loop_start - self._current_pos() - 2
        self._emit(self.opcodes.get('JMP'), back_offset & 0xFF)

        self._emit_at(exit_jump + 1, self._current_pos() - exit_jump - 2)

        for bp in self._break_targets.pop():
            self._emit_at(bp + 1, self._current_pos() - bp - 2)

    def _compile_generic_for(self, node: GenericFor):
        """Compile a generic for loop (simplified)."""
        # Evaluate iterators
        for it in node.iterators:
            self._compile_expr(it)

        # Allocate locals for loop variables
        slots = []
        for name in node.names:
            slots.append(self._alloc_local(name))

        self._break_targets.append([])
        loop_start = self._current_pos()

        # Call iterator, assign results
        self._emit(self.opcodes.get('CALL'), 0, len(node.names))
        for s in slots:
            self._emit(self.opcodes.get('SET_LOCAL'), s)

        # Check first var is not nil
        self._emit(self.opcodes.get('PUSH_LOCAL'), slots[0])
        self._emit(self.opcodes.get('PUSH_NIL'))
        self._emit(self.opcodes.get('EQ'))
        exit_jump = self._current_pos()
        self._emit(self.opcodes.get('JMP_TRUE'), 0)

        self._compile_block(node.body)

        back_offset = loop_start - self._current_pos() - 2
        self._emit(self.opcodes.get('JMP'), back_offset & 0xFF)

        self._emit_at(exit_jump + 1, self._current_pos() - exit_jump - 2)

        for bp in self._break_targets.pop():
            self._emit_at(bp + 1, self._current_pos() - bp - 2)

    def _compile_repeat(self, node: RepeatUntil):
        """Compile a repeat...until loop."""
        loop_start = self._current_pos()
        self._break_targets.append([])

        self._compile_block(node.body)
        self._compile_expr(node.condition)

        # Jump back if condition is false
        back_offset = loop_start - self._current_pos() - 2
        self._emit(self.opcodes.get('JMP_FALSE'), back_offset & 0xFF)

        for bp in self._break_targets.pop():
            self._emit_at(bp + 1, self._current_pos() - bp - 2)

    def _compile_return(self, node: ReturnStatement):
        """Compile a return statement."""
        count = len(node.values)
        for val in node.values:
            self._compile_expr(val)
        if count == 0:
            self._emit(self.opcodes.get('PUSH_NIL'))
            count = 1
        self._emit(self.opcodes.get('RETURN'), count)

    def _compile_break(self):
        """Compile a break statement."""
        if self._break_targets:
            self._break_targets[-1].append(self._current_pos())
            self._emit(self.opcodes.get('JMP'), 0)  # Patched later

    def _compile_continue(self):
        """Compile a continue statement."""
        if self._continue_targets:
            target = self._continue_targets[-1]
            offset = target - self._current_pos() - 2
            self._emit(self.opcodes.get('JMP'), offset & 0xFF)

    def _compile_func_decl(self, node: FunctionDecl):
        """Compile a function declaration."""
        # Compile as function expression
        func_expr = FunctionExpr(
            params=node.params,
            has_vararg=node.has_vararg,
            body=node.body
        )
        self._compile_expr(func_expr)

        # Assign to name
        if isinstance(node.name, Identifier):
            if node.is_local:
                slot = self._alloc_local(node.name.name)
                self._emit(self.opcodes.get('SET_LOCAL'), slot)
            else:
                idx = self.pool.add(node.name.name)
                self._emit(self.opcodes.get('SET_GLOBAL'), idx)
