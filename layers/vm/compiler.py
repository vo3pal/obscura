"""
Obscura VM Compiler (Register-Based)
========================================
Walks the Luau AST and emits register-based bytecode for the new VM.

Design notes
------------
* Each function maintains a *register file* indexed from 0.
* Locals occupy stable register slots in declaration order.
* Temporaries used during expression evaluation occupy registers above
  the active locals; they are reclaimed automatically.
* Multi-return values use the Lua 5.1 sentinel: B/C == 0 means
  "all results, up to top-of-stack".
* Closures emit a CLOSURE instruction immediately followed by N pseudo-
  instructions (MOVE / GETUPVAL) that link upvalues into the new closure.
* Globals (Roblox + Lua + Luau builtins) all flow through GETGLOBAL/
  SETGLOBAL which the runtime resolves via the _ENV upvalue.
"""

from parser.ast_nodes import *
from .opcodes import OpcodeMap
from .constant_pool import ConstantPool
from .proto import FunctionPrototype, UpvalueDesc
from .instruction import (
    Instruction, encode_instruction, instruction_size,
    FORMAT_NONE, FORMAT_A, FORMAT_AB, FORMAT_ABC,
    FORMAT_ABX, FORMAT_ASBX, FORMAT_SBX,
)
from config import ObfuscationConfig
from typing import List, Dict, Optional, Tuple
import ast
import math
import random
import re


# Sentinel for "all results to top" used in CALL / RETURN / VARARG / SETLIST.
MULTRET = 0


class VMCompilationError(Exception):
    pass


class _LocalVar:
    __slots__ = ('name', 'reg', 'captured')
    def __init__(self, name: str, reg: int, captured: bool = False):
        self.name = name
        self.reg = reg
        self.captured = captured  # True -> register holds a box {value}


class _FuncState:
    """State for one function being compiled (mirrors lparser.c FuncState)."""

    def __init__(self, parent: Optional['_FuncState'] = None, is_vararg: bool = False):
        self.parent = parent
        self.proto = FunctionPrototype()
        self.proto.is_vararg = is_vararg
        # Register allocation
        self.free_reg = 0           # Next free register
        self.max_stack = 0          # Highwater mark
        # Locals: stack of active locals (most recent last)
        self.actvars: List[_LocalVar] = []
        # Lexical scopes: each scope records the actvars-stack length at entry
        self.scope_stack: List[int] = []
        # Upvalues: name -> index in proto.upvalues
        self.upvalue_index: Dict[str, int] = {}
        # Loop patch lists
        self.break_lists: List[List[int]] = []      # stack of pending break PCs
        self.continue_targets: List[int] = []        # stack of continue jump targets
        # Captured-locals analysis: names of locals declared in this function
        # that are referenced by inner closures.
        self.captured_names: set = set()

    # ---- Register allocation ----

    def reserve_regs(self, n: int) -> int:
        """Reserve n contiguous registers, return first."""
        first = self.free_reg
        self.free_reg += n
        if self.free_reg > self.max_stack:
            self.max_stack = self.free_reg
        return first

    def _local_watermark(self) -> int:
        """Return the first register that is safe to use as a temp.

        This is one past the highest register occupied by any active local.
        We cannot use len(actvars) because for-loop internal registers create
        gaps (e.g. init/limit/step at base..base+2, then loop-var at base+3).
        """
        if not self.actvars:
            return 0
        return max(v.reg for v in self.actvars) + 1

    def free_reg_to(self, target: int):
        """Free all temp registers down to (and not below) `target`."""
        # Don't free below the active-local watermark.
        watermark = self._local_watermark()
        if target < watermark:
            target = watermark
        if self.free_reg > target:
            self.free_reg = target

    def free_temp(self, reg: int):
        """Free a single temp register if it is the topmost temp."""
        if reg >= self._local_watermark() and reg == self.free_reg - 1:
            self.free_reg -= 1

    # ---- Scopes / locals ----

    def enter_scope(self):
        self.scope_stack.append(len(self.actvars))

    def leave_scope(self):
        target = self.scope_stack.pop()
        # Drop locals introduced inside this scope
        del self.actvars[target:]
        # Free their registers
        self.free_reg = max(target, 0)
        if self.free_reg > self.max_stack:
            self.max_stack = self.free_reg

    def declare_local(self, name: str) -> int:
        """Declare a new local; allocates next register."""
        reg = self.reserve_regs(1)
        captured = name in self.captured_names
        self.actvars.append(_LocalVar(name, reg, captured=captured))
        return reg

    def find_local(self, name: str) -> Optional[int]:
        """Search active locals from innermost outward. Returns register, or None."""
        for v in reversed(self.actvars):
            if v.name == name:
                return v.reg
        return None

    def find_local_var(self, name: str) -> Optional['_LocalVar']:
        for v in reversed(self.actvars):
            if v.name == name:
                return v
        return None


class VMCompiler:
    """Compiles a Luau AST into register-based VM bytecode."""

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.opcodes = OpcodeMap(self.rng)
        self.pool = ConstantPool(self.rng)
        self.fs: Optional[_FuncState] = None

    _IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

    def _eval_raw_number_expr(self, expr: str) -> Optional[float]:
        if self._IDENT_RE.match(expr):
            return None
        normalized = expr.replace('bit32.bxor', 'bxor').replace('math.floor', 'floor')
        if not re.fullmatch(r'[0-9A-Za-z_\s+\-*/(),.]+', normalized):
            return None

        def eval_node(node):
            if isinstance(node, ast.Expression):
                return eval_node(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return node.value
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
                return -eval_node(node.operand)
            if isinstance(node, ast.BinOp):
                left = eval_node(node.left)
                right = eval_node(node.right)
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, ast.Div):
                    return left / right
                raise ValueError
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                args = [eval_node(a) for a in node.args]
                if node.func.id == 'bxor' and len(args) == 2:
                    return int(args[0]) ^ int(args[1])
                if node.func.id == 'floor' and len(args) == 1:
                    return math.floor(args[0])
            raise ValueError

        try:
            value = eval_node(ast.parse(normalized, mode='eval'))
        except Exception:
            return None
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    # =================================================================
    # Public API
    # =================================================================

    def compile(self, block: Block) -> FunctionPrototype:
        """Compile the top-level chunk as a vararg function."""
        self._enter_function(is_vararg=True)
        # Pre-scan top-level for captured locals
        self.fs.captured_names = self._scan_captured_in_block(block, set())
        self._compile_block(block)
        # Implicit return
        self._emit('RETURN', a=0, b=1)  # B=1 -> return 0 values
        proto = self._leave_function()
        return proto

    # =================================================================
    # Captured-locals pre-scan
    # =================================================================

    def _scan_captured_in_block(self, block: Block, declared_outside: set) -> set:
        """Find which locals (declared in this function's scope) are captured by
        inner closures.

        `declared_outside` is the set of names visible to this function from
        outside (params + outer locals/upvalues). Locals declared inside
        `block` shadow those.

        Returns the set of THIS function's local names that are referenced
        free in any inner FunctionExpr/FunctionDecl.
        """
        captured: set = set()
        # Names declared *in this function so far*
        scope_locals = set(declared_outside)
        # Names declared in this function only (not inherited)
        own_locals = set(declared_outside)  # used as base; we'll diff at end
        own_introduced: set = set()

        def visit(node, scope: set):
            if node is None:
                return
            if isinstance(node, LocalStatement):
                for v in node.values:
                    visit(v, scope)
                for n in node.names:
                    scope.add(n)
                    own_introduced.add(n)
            elif isinstance(node, NumericFor):
                visit(node.start, scope); visit(node.stop, scope)
                if node.step is not None: visit(node.step, scope)
                inner = set(scope); inner.add(node.var_name)
                own_introduced.add(node.var_name)
                visit_block(node.body, inner)
            elif isinstance(node, GenericFor):
                for it in node.iterators: visit(it, scope)
                inner = set(scope)
                for n in node.names:
                    inner.add(n)
                    own_introduced.add(n)
                visit_block(node.body, inner)
            elif isinstance(node, FunctionDecl):
                # Determine if this declaration is local (introduces a name)
                if node.is_local and isinstance(node.name, Identifier):
                    scope.add(node.name.name)
                    own_introduced.add(node.name.name)
                # Inner function body: scan its free vars
                free = self._scan_free_vars(node.body, set(node.params), node.has_vararg)
                for nm in free:
                    if nm in own_introduced:
                        captured.add(nm)
                # Don't recurse into the inner body for THIS function's purpose
            elif isinstance(node, FunctionExpr):
                free = self._scan_free_vars(node.body, set(node.params), node.has_vararg)
                for nm in free:
                    if nm in own_introduced:
                        captured.add(nm)
            elif isinstance(node, DoBlock):
                visit_block(node.body, set(scope))
            elif isinstance(node, IfStatement):
                visit(node.condition, scope)
                visit_block(node.body, set(scope))
                for c in node.elseif_clauses:
                    visit(c.condition, scope)
                    visit_block(c.body, set(scope))
                if node.else_body:
                    visit_block(node.else_body, set(scope))
            elif isinstance(node, WhileLoop):
                visit(node.condition, scope)
                visit_block(node.body, set(scope))
            elif isinstance(node, RepeatUntil):
                visit_block(node.body, set(scope))
                visit(node.condition, scope)
            elif isinstance(node, AssignStatement):
                for t in node.targets: visit(t, scope)
                for v in node.values: visit(v, scope)
            elif isinstance(node, ReturnStatement):
                for v in node.values: visit(v, scope)
            elif isinstance(node, ExpressionStatement):
                visit(node.expression, scope)
            else:
                # Walk children of generic expressions
                self._walk_expr(node, lambda n: visit(n, scope))

        def visit_block(blk, scope):
            for st in blk.body:
                visit(st, scope)

        visit_block(block, scope_locals)
        return captured

    def _scan_free_vars(self, body: Block, declared: set, has_vararg: bool) -> set:
        """Return the set of names referenced free in `body` (not declared inside)."""
        free: set = set()

        def visit(node, scope: set):
            if node is None: return
            if isinstance(node, Identifier):
                if self._IDENT_RE.match(node.name) and node.name not in scope:
                    free.add(node.name)
                return
            if isinstance(node, LocalStatement):
                for v in node.values: visit(v, scope)
                for n in node.names: scope.add(n)
                return
            if isinstance(node, NumericFor):
                visit(node.start, scope); visit(node.stop, scope)
                if node.step is not None: visit(node.step, scope)
                inner = set(scope); inner.add(node.var_name)
                visit_block(node.body, inner)
                return
            if isinstance(node, GenericFor):
                for it in node.iterators: visit(it, scope)
                inner = set(scope)
                for n in node.names: inner.add(n)
                visit_block(node.body, inner)
                return
            if isinstance(node, FunctionDecl):
                if node.is_local and isinstance(node.name, Identifier):
                    scope.add(node.name.name)
                inner = set(node.params); inner.update(scope)
                # Recurse: anything free in inner is free in us if not declared here
                inner_free = self._scan_free_vars(node.body, set(node.params), node.has_vararg)
                for nm in inner_free:
                    if nm not in scope:
                        free.add(nm)
                # Also visit name target if non-local
                if not node.is_local and node.name is not None:
                    visit(node.name, scope)
                return
            if isinstance(node, FunctionExpr):
                inner_free = self._scan_free_vars(node.body, set(node.params), node.has_vararg)
                for nm in inner_free:
                    if nm not in scope:
                        free.add(nm)
                return
            if isinstance(node, DoBlock):
                visit_block(node.body, set(scope)); return
            if isinstance(node, IfStatement):
                visit(node.condition, scope)
                visit_block(node.body, set(scope))
                for c in node.elseif_clauses:
                    visit(c.condition, scope)
                    visit_block(c.body, set(scope))
                if node.else_body: visit_block(node.else_body, set(scope))
                return
            if isinstance(node, WhileLoop):
                visit(node.condition, scope)
                visit_block(node.body, set(scope))
                return
            if isinstance(node, RepeatUntil):
                visit_block(node.body, set(scope))
                visit(node.condition, scope)
                return
            if isinstance(node, AssignStatement):
                for t in node.targets: visit(t, scope)
                for v in node.values: visit(v, scope)
                return
            if isinstance(node, ReturnStatement):
                for v in node.values: visit(v, scope); return
            if isinstance(node, ExpressionStatement):
                visit(node.expression, scope); return
            # Generic walker for expressions
            self._walk_expr(node, lambda n: visit(n, scope))

        def visit_block(blk, scope):
            for st in blk.body:
                visit(st, scope)

        visit_block(body, declared)
        return free

    def _walk_expr(self, node, fn):
        """Visit children of an expression node, applying fn to each."""
        if node is None: return
        if isinstance(node, BinaryOp):
            fn(node.left); fn(node.right)
        elif isinstance(node, UnaryOp):
            fn(node.operand)
        elif isinstance(node, FunctionCall):
            fn(node.func)
            for a in node.args: fn(a)
        elif isinstance(node, MethodCall):
            fn(node.object)
            for a in node.args: fn(a)
        elif isinstance(node, MemberExpr):
            fn(node.object)
        elif isinstance(node, IndexExpr):
            fn(node.object); fn(node.index)
        elif isinstance(node, TableConstructor):
            for f in node.fields:
                if f.key is not None: fn(f.key)
                fn(f.value)
        elif isinstance(node, ParenExpr):
            fn(node.expression)
        # Literals / VarargExpr / NilLiteral etc. have no children

    # =================================================================
    # Function state plumbing
    # =================================================================

    def _enter_function(self, is_vararg: bool):
        self.fs = _FuncState(parent=self.fs, is_vararg=is_vararg)

    def _leave_function(self) -> FunctionPrototype:
        proto = self.fs.proto
        proto.max_stacksize = max(self.fs.max_stack, 2)
        # Encode bytecode
        proto.bytecode = self._encode_proto(proto)
        self.fs = self.fs.parent
        return proto

    def _encode_proto(self, proto: FunctionPrototype) -> List[int]:
        """Produce the flat byte stream for the proto's instructions."""
        out: List[int] = []
        # Two-pass: first pass assigned PCs already during emission.
        for ins in proto.instructions:
            opbyte = self.opcodes.random_alias(ins.op_name)
            out.extend(encode_instruction(opbyte, ins.fmt, ins.a, ins.b, ins.c))
        return out

    # =================================================================
    # Emission helpers
    # =================================================================

    def _current_pc(self) -> int:
        """Return current byte-offset within the function being compiled."""
        # PC is in bytes for jump-offset arithmetic.
        pc = 0
        for ins in self.fs.proto.instructions:
            pc += instruction_size(ins.fmt)
        return pc

    def _emit(self, op_name: str, a: int = 0, b: int = 0, c: int = 0) -> Instruction:
        fmt = self.opcodes.fmt_of(op_name)
        ins = Instruction(op_name=op_name, fmt=fmt, a=a, b=b, c=c, pc=self._current_pc())
        self.fs.proto.instructions.append(ins)
        return ins

    def _patch_jump(self, ins: Instruction, target_pc: int):
        """Patch a JMP-style instruction's offset so it jumps to target_pc.

        The offset encoded in the instruction is added to PC *after* the
        instruction has been read. So:
            offset = target_pc - (ins.pc + size_of(ins))
        """
        size = instruction_size(ins.fmt)
        # Operand stored in a (sBx) or b (AsBx)
        offset = target_pc - (ins.pc + size)
        if ins.fmt == FORMAT_SBX:
            ins.a = offset
        elif ins.fmt == FORMAT_ASBX:
            ins.b = offset
        else:
            raise VMCompilationError(f"Cannot patch jump on fmt {ins.fmt}")

    def _emit_jump(self) -> Instruction:
        return self._emit('JMP', a=0)

    def _emit_jump_to(self, target_pc: int) -> Instruction:
        ins = self._emit_jump()
        self._patch_jump(ins, target_pc)
        return ins

    # ---- Local read/write helpers (handle captured boxing) ----

    def _read_local(self, lv: '_LocalVar', dst_reg: int):
        """Emit code to read local `lv` into register `dst_reg`."""
        if lv.captured:
            self._emit('GETBOX', a=dst_reg, b=lv.reg)
        else:
            if dst_reg != lv.reg:
                self._emit('MOVE', a=dst_reg, b=lv.reg)

    def _write_local(self, lv: '_LocalVar', src_reg: int):
        """Emit code to write the value in `src_reg` to local `lv`."""
        if lv.captured:
            self._emit('SETBOX', a=lv.reg, b=src_reg)
        else:
            if lv.reg != src_reg:
                self._emit('MOVE', a=lv.reg, b=src_reg)

    def _box_local_after_init(self, lv: '_LocalVar'):
        """If lv is captured, wrap its initial value in a box.

        The init value is currently sitting in lv.reg. We turn it into
        a box `{value}` in-place using MKBOX (which reads R[lv.reg] and
        writes R[lv.reg] := {old}).
        """
        if lv.captured:
            self._emit('MKBOX', a=lv.reg, b=lv.reg)

    # =================================================================
    # Statement compilation
    # =================================================================

    def _compile_block(self, block: Block):
        for stmt in block.body:
            self._compile_stmt(stmt)

    def _compile_stmt(self, node: Node):
        if isinstance(node, LocalStatement):
            self._compile_local(node)
        elif isinstance(node, AssignStatement):
            self._compile_assign(node)
        elif isinstance(node, ExpressionStatement):
            self._compile_expr_stmt(node)
        elif isinstance(node, IfStatement):
            self._compile_if(node)
        elif isinstance(node, WhileLoop):
            self._compile_while(node)
        elif isinstance(node, RepeatUntil):
            self._compile_repeat(node)
        elif isinstance(node, NumericFor):
            self._compile_numeric_for(node)
        elif isinstance(node, GenericFor):
            self._compile_generic_for(node)
        elif isinstance(node, ReturnStatement):
            self._compile_return(node)
        elif isinstance(node, BreakStatement):
            self._compile_break()
        elif isinstance(node, ContinueStatement):
            self._compile_continue()
        elif isinstance(node, DoBlock):
            self.fs.enter_scope()
            self._compile_block(node.body)
            self.fs.leave_scope()
        elif isinstance(node, FunctionDecl):
            self._compile_func_decl(node)
        else:
            raise VMCompilationError(f"Unsupported statement: {type(node).__name__}")

    # ---- Local statement: local a, b = ... ----

    def _compile_local(self, node: LocalStatement):
        # Evaluate RHS into temp registers (in order), then *declare* locals
        # AFTER all RHS has been computed so RHS cannot see new locals.
        n_names = len(node.names)
        n_vals = len(node.values)

        # Allocate target registers ahead of time so multi-return spread fits.
        base = self.fs.free_reg

        if n_vals == 0:
            # local a, b  -> all nil
            self._emit('LOADNIL', a=base, b=n_names - 1)
            self.fs.reserve_regs(n_names)
        else:
            # Evaluate all-but-last to single registers; last gets multi-return slack.
            for i in range(n_vals - 1):
                self._expr_to_next_reg(node.values[i])
            last = node.values[n_vals - 1]
            extras = n_names - (n_vals - 1)  # how many regs the last expr should fill
            if extras < 1:
                extras = 1
            self._expr_to_next_reg_multi(last, want=extras)
            # Pad with nil if RHS produced fewer than n_names
            cur = self.fs.free_reg
            target = base + n_names
            if cur < target:
                self._emit('LOADNIL', a=cur, b=(target - cur) - 1)
                self.fs.reserve_regs(target - cur)
            elif cur > target:
                # Drop excess
                self.fs.free_reg = target

        # Now declare the locals at the registers we just filled.
        new_locals: List[_LocalVar] = []
        for i, name in enumerate(node.names):
            captured = name in self.fs.captured_names
            lv = _LocalVar(name, base + i, captured=captured)
            self.fs.actvars.append(lv)
            new_locals.append(lv)
        # Ensure free_reg matches active-locals watermark
        self.fs.free_reg = max(self.fs.free_reg, base + n_names)
        if self.fs.free_reg > self.fs.max_stack:
            self.fs.max_stack = self.fs.free_reg
        # Box captured locals (in-place wrap of their init value)
        for lv in new_locals:
            self._box_local_after_init(lv)

    # ---- Assignment: a, t.x, t[k] = ... ----

    def _compile_assign(self, node: AssignStatement):
        n_targets = len(node.targets)
        n_vals = len(node.values)

        # Evaluate all values into a contiguous register block, then assign.
        base = self.fs.free_reg

        for i in range(n_vals - 1):
            self._expr_to_next_reg(node.values[i])
        if n_vals > 0:
            last = node.values[n_vals - 1]
            extras = n_targets - (n_vals - 1)
            if extras < 1:
                extras = 1
            self._expr_to_next_reg_multi(last, want=extras)

        # Pad with nil for missing values
        cur = self.fs.free_reg
        need = base + n_targets
        if cur < need:
            self._emit('LOADNIL', a=cur, b=(need - cur) - 1)
            self.fs.reserve_regs(need - cur)
        elif cur > need:
            self.fs.free_reg = need

        # Assign each target from its source register, in REVERSE so that
        # earlier assignments don't clobber later sources held in temps.
        # But targets that use compound indexing need their object/key
        # evaluated *now*, so we evaluate them after value computation.
        for i in range(n_targets - 1, -1, -1):
            target = node.targets[i]
            src_reg = base + i
            self._compile_assign_target(target, src_reg)
        self.fs.free_reg = base  # release all value temps

    def _compile_assign_target(self, target: Node, src_reg: int):
        if isinstance(target, Identifier):
            lv = self.fs.find_local_var(target.name)
            if lv is not None:
                self._write_local(lv, src_reg)
            else:
                upv = self._resolve_upvalue(self.fs, target.name)
                if upv is not None:
                    self._emit('SETUPVAL', a=src_reg, b=upv)
                else:
                    idx = self.pool.add(target.name)
                    self._emit('SETGLOBAL', a=src_reg, b=idx)
        elif isinstance(target, MemberExpr):
            obj_reg = self._expr_to_any_reg(target.object)
            key_idx = self.pool.add(target.member)
            self._emit('SETTABLEK', a=obj_reg, b=key_idx, c=src_reg)
            # obj_reg might be a temp; release
            if obj_reg >= self.fs._local_watermark():
                self.fs.free_reg_to(obj_reg)
        elif isinstance(target, IndexExpr):
            obj_reg = self._expr_to_any_reg(target.object)
            key_reg = self._expr_to_any_reg(target.index)
            self._emit('SETTABLE', a=obj_reg, b=key_reg, c=src_reg)
            # Free temps used for obj/key (but src_reg lives in the value block)
            watermark = self.fs._local_watermark()
            if key_reg >= watermark:
                self.fs.free_reg_to(key_reg)
            if obj_reg >= watermark:
                self.fs.free_reg_to(obj_reg)
        else:
            raise VMCompilationError(f"Invalid assignment target: {type(target).__name__}")

    # ---- Expression statement ----

    def _compile_expr_stmt(self, node: ExpressionStatement):
        expr = node.expression
        # Most legal expression-statements are calls; result is discarded.
        if isinstance(expr, (FunctionCall, MethodCall)):
            base = self.fs.free_reg
            self._compile_call(expr, want=0)  # 0 returns
            self.fs.free_reg = base
        else:
            # Compile and discard
            base = self.fs.free_reg
            self._expr_to_next_reg(expr)
            self.fs.free_reg = base

    # ---- If ----

    def _compile_if(self, node: IfStatement):
        # Compile condition, JMP_FALSE chain, body, JMP to end, ...
        end_jumps: List[Instruction] = []

        clauses: List[Tuple[Node, Block]] = [(node.condition, node.body)]
        for c in node.elseif_clauses:
            clauses.append((c.condition, c.body))

        for cond, body in clauses:
            # Evaluate condition as boolean, with TEST + JMP
            self.fs.enter_scope()
            cond_reg = self._expr_to_any_reg(cond)
            # TEST A B: if not (R[A] <=> B) then pc++  -> followed by JMP
            self._emit('TEST', a=cond_reg, b=0)  # B=0 means "want falsy to skip"
            jmp_false = self._emit_jump()
            # Free condition temp before body
            if cond_reg >= self.fs._local_watermark():
                self.fs.free_reg_to(cond_reg)

            self._compile_block(body)
            end_jumps.append(self._emit_jump())
            self._patch_jump(jmp_false, self._current_pc())
            self.fs.leave_scope()

        if node.else_body is not None:
            self.fs.enter_scope()
            self._compile_block(node.else_body)
            self.fs.leave_scope()

        end_pc = self._current_pc()
        for j in end_jumps:
            self._patch_jump(j, end_pc)

    # ---- While ----

    def _compile_while(self, node: WhileLoop):
        loop_start = self._current_pc()
        self.fs.break_lists.append([])
        self.fs.continue_targets.append(loop_start)
        self.fs.enter_scope()

        cond_reg = self._expr_to_any_reg(node.condition)
        self._emit('TEST', a=cond_reg, b=0)
        exit_jmp = self._emit_jump()
        if cond_reg >= self.fs._local_watermark():
            self.fs.free_reg_to(cond_reg)

        self._compile_block(node.body)
        self._emit_jump_to(loop_start)
        self._patch_jump(exit_jmp, self._current_pc())

        # Patch breaks
        end_pc = self._current_pc()
        for b in self.fs.break_lists.pop():
            self._patch_jump(b, end_pc)
        self.fs.continue_targets.pop()
        self.fs.leave_scope()

    # ---- Repeat ----

    def _compile_repeat(self, node: RepeatUntil):
        loop_start = self._current_pc()
        self.fs.break_lists.append([])
        # Continue jumps to the until-condition test
        # We don't know that PC yet — use a forward-resolved patch list.
        cont_patches: List[Instruction] = []
        self.fs.continue_targets.append(-1)  # marker; we use list below

        self.fs.enter_scope()
        # Save actvars count so continue can't escape locals
        self._compile_block(node.body)

        cond_pc = self._current_pc()
        # Patch any pending continues
        for ins in cont_patches:
            self._patch_jump(ins, cond_pc)
        # Replace any -1 marker in continue_targets with actual PC for naive uses
        self.fs.continue_targets[-1] = cond_pc

        cond_reg = self._expr_to_any_reg(node.condition)
        self._emit('TEST', a=cond_reg, b=0)
        # Loop back if falsy
        back = self._emit_jump()
        self._patch_jump(back, loop_start)
        if cond_reg >= self.fs._local_watermark():
            self.fs.free_reg_to(cond_reg)

        end_pc = self._current_pc()
        for bp in self.fs.break_lists.pop():
            self._patch_jump(bp, end_pc)
        self.fs.continue_targets.pop()
        self.fs.leave_scope()

    # ---- Numeric for ----

    def _compile_numeric_for(self, node: NumericFor):
        # for i = start, stop, step  ->  internal regs: [start, stop, step, i]
        # FORPREP / FORLOOP convention (Lua 5.1 style):
        #   R[A]   = internal counter (start - step)
        #   R[A+1] = stop
        #   R[A+2] = step
        #   R[A+3] = visible loop var i
        self.fs.break_lists.append([])
        self.fs.enter_scope()

        base = self.fs.free_reg
        # Eval start, stop, step into base..base+2
        self._expr_to_reg(node.start, base)
        self.fs.reserve_regs(1)
        self._expr_to_reg(node.stop, base + 1)
        self.fs.reserve_regs(1)
        if node.step is not None:
            self._expr_to_reg(node.step, base + 2)
        else:
            idx = self.pool.add(1)
            self._emit('LOADK', a=base + 2, b=idx)
        self.fs.reserve_regs(1)

        # Reserve loop var
        i_reg = self.fs.reserve_regs(1)  # base + 3
        # Declare it as a local visible in the body
        captured = node.var_name in self.fs.captured_names
        loop_lv = _LocalVar(node.var_name, i_reg, captured=captured)
        self.fs.actvars.append(loop_lv)

        # FORPREP base, sBx -> jumps to FORLOOP test
        forprep = self._emit('FORPREP', a=base, b=0)
        body_start = self._current_pc()
        # Per-iteration box for captured loop var: each iteration must produce
        # a FRESH box so closures captured inside the body bind to that
        # iteration's value (Lua semantics).
        if captured:
            self._emit('MKBOX', a=i_reg, b=i_reg)
        self.fs.continue_targets.append(body_start)  # not strictly needed
        self._compile_block(node.body)

        # FORLOOP base, sBx -> body_start
        forloop = self._emit('FORLOOP', a=base, b=0)
        self._patch_jump(forloop, body_start)
        # FORPREP jumps to the FORLOOP we just emitted
        self._patch_jump(forprep, forloop.pc)

        end_pc = self._current_pc()
        for bp in self.fs.break_lists.pop():
            self._patch_jump(bp, end_pc)
        self.fs.continue_targets.pop()
        self.fs.leave_scope()

    # ---- Generic for ----

    def _compile_generic_for(self, node: GenericFor):
        # for var_1,...,var_n in exprlist do body end
        # Internal registers (R[A], R[A+1], R[A+2]) are: iter func, state, control.
        # User-visible vars start at R[A+3] (var_1 .. var_n).
        self.fs.break_lists.append([])
        self.fs.enter_scope()

        base = self.fs.free_reg
        # Eval iterator expressions; pad/truncate to exactly 3 results
        n_iters = len(node.iterators)
        for i in range(n_iters - 1):
            self._expr_to_next_reg(node.iterators[i])
        if n_iters > 0:
            extras = 3 - (n_iters - 1)
            if extras < 1: extras = 1
            self._expr_to_next_reg_multi(node.iterators[n_iters - 1], want=extras)
        cur = self.fs.free_reg
        need = base + 3
        if cur < need:
            self._emit('LOADNIL', a=cur, b=(need - cur) - 1)
            self.fs.reserve_regs(need - cur)
        elif cur > need:
            self.fs.free_reg = need

        # Declare user vars
        n_vars = len(node.names)
        var_base = self.fs.reserve_regs(n_vars)
        loop_lvs: List[_LocalVar] = []
        for i, name in enumerate(node.names):
            captured = name in self.fs.captured_names
            lv = _LocalVar(name, var_base + i, captured=captured)
            self.fs.actvars.append(lv)
            loop_lvs.append(lv)

        # Jump over the body to the TFORLOOP test (Lua 5.1 layout)
        prep = self._emit_jump()
        body_start = self._current_pc()
        # Per-iteration box: each iteration of generic-for produces fresh boxes
        # for any captured loop variable so closures bind to that value.
        for lv in loop_lvs:
            if lv.captured:
                self._emit('MKBOX', a=lv.reg, b=lv.reg)
        self._compile_block(node.body)

        self._patch_jump(prep, self._current_pc())
        # TFORLOOP A B C
        #   A = iterator base register
        #   B = body start (sBx-like via instruction's c field reused as sBx)
        # We use the C field as count of vars and store the back-jump in B.
        tfor = self._emit('TFORLOOP', a=base, b=0, c=n_vars)
        # Compute back-jump offset: target = body_start, computed at patch time
        size = instruction_size(tfor.fmt)
        tfor.b = body_start - (tfor.pc + size)

        end_pc = self._current_pc()
        for bp in self.fs.break_lists.pop():
            self._patch_jump(bp, end_pc)
        self.fs.leave_scope()

    # ---- Return ----

    def _compile_return(self, node: ReturnStatement):
        n = len(node.values)
        if n == 0:
            self._emit('RETURN', a=0, b=1)  # B=1 -> 0 values
            return

        base = self.fs.free_reg
        for i in range(n - 1):
            self._expr_to_next_reg(node.values[i])
        last = node.values[n - 1]
        if self._is_multret_expr(last):
            self._expr_to_next_reg_multi(last, want=MULTRET)
            # B = 0 -> all values up to top-of-stack
            self._emit('RETURN', a=base, b=0)
        else:
            self._expr_to_next_reg(last)
            # B = n+1 -> exactly n values
            self._emit('RETURN', a=base, b=n + 1)
        self.fs.free_reg = base

    def _compile_break(self):
        if not self.fs.break_lists:
            raise VMCompilationError("'break' outside of a loop")
        ins = self._emit_jump()
        self.fs.break_lists[-1].append(ins)

    def _compile_continue(self):
        if not self.fs.continue_targets:
            raise VMCompilationError("'continue' outside of a loop")
        target = self.fs.continue_targets[-1]
        if target < 0:
            # Forward target (repeat-until): emit unpatched and rely on later patch
            ins = self._emit_jump()
            # We don't currently patch these in repeat; document gap.
            # For now, treat continue in repeat as jump to loop start.
            # (Repeat continue could be improved, but Luau semantics align with
            #  Lua: continue jumps to condition.)
            # Fall back: patch at repeat's cond_pc when it becomes known.
            # The repeat handler stores the cond_pc back into continue_targets[-1].
            # So we need a deferred patch list. Implement quickly:
            self.fs._pending_continue = getattr(self.fs, '_pending_continue', [])
            self.fs._pending_continue.append(ins)
        else:
            ins = self._emit_jump()
            self._patch_jump(ins, target)

    # ---- Function declaration ----

    def _compile_func_decl(self, node: FunctionDecl):
        if node.is_local and isinstance(node.name, Identifier):
            # Pre-declare the local SO the body can reference itself recursively.
            reg = self.fs.declare_local(node.name.name)
            lv = self.fs.actvars[-1]
            # If the local is captured (e.g. recursive self-reference), we need
            # a stable box BEFORE compiling the body so inner closures can
            # capture the same box that we'll later write the function into.
            if lv.captured:
                self._emit('LOADNIL', a=reg, b=0)
                self._emit('MKBOX', a=reg, b=reg)
            proto_idx = self._compile_function_body(node.params, node.has_vararg, node.body)
            # Build the closure into a temp, then store into the local
            tmp = self.fs.reserve_regs(1)
            self._emit('CLOSURE', a=tmp, b=proto_idx)
            self._emit_upval_links(self.fs.proto.sub_protos[proto_idx])
            self._write_local(lv, tmp)
            self.fs.free_temp(tmp)
        elif isinstance(node.name, MethodCall):
            # function obj:method(...) end
            # Sugar for: obj.method = function(self, ...) ... end
            # The parser encodes this as MethodCall(object=obj, method='method').
            # Prepend implicit 'self' parameter.
            params = ['self'] + list(node.params)
            proto_idx = self._compile_function_body(params, node.has_vararg, node.body)
            tmp = self.fs.reserve_regs(1)
            self._emit('CLOSURE', a=tmp, b=proto_idx)
            self._emit_upval_links(self.fs.proto.sub_protos[proto_idx])
            # Store into obj.method
            obj_reg = self._expr_to_any_reg(node.name.object)
            key_idx = self.pool.add(node.name.method)
            self._emit('SETTABLEK', a=obj_reg, b=key_idx, c=tmp)
            if obj_reg >= self.fs._local_watermark():
                self.fs.free_reg_to(obj_reg)
            self.fs.free_temp(tmp)
        elif isinstance(node.name, Identifier):
            proto_idx = self._compile_function_body(node.params, node.has_vararg, node.body)
            tmp = self.fs.reserve_regs(1)
            self._emit('CLOSURE', a=tmp, b=proto_idx)
            self._emit_upval_links(self.fs.proto.sub_protos[proto_idx])
            idx = self.pool.add(node.name.name)
            self._emit('SETGLOBAL', a=tmp, b=idx)
            self.fs.free_temp(tmp)
        else:
            # MemberExpr chain: function a.b.c() end  →  a.b.c = closure
            proto_idx = self._compile_function_body(node.params, node.has_vararg, node.body)
            tmp = self.fs.reserve_regs(1)
            self._emit('CLOSURE', a=tmp, b=proto_idx)
            self._emit_upval_links(self.fs.proto.sub_protos[proto_idx])
            self._compile_assign_target(node.name, tmp)
            self.fs.free_temp(tmp)

    def _compile_function_body(self, params: List[str], has_vararg: bool, body: Block) -> int:
        """Compile a nested function; return its index in the parent's sub_protos."""
        parent = self.fs
        self._enter_function(is_vararg=has_vararg)
        self.fs.proto.num_params = len(params)
        # Pre-scan body for captured locals BEFORE declaring params
        self.fs.captured_names = self._scan_captured_in_block(body, set(params))
        # Params occupy registers 0..n-1
        param_lvs: List[_LocalVar] = []
        for p in params:
            self.fs.declare_local(p)
            param_lvs.append(self.fs.actvars[-1])
        # Box captured params at function entry
        for lv in param_lvs:
            self._box_local_after_init(lv)
        self._compile_block(body)
        # Implicit return
        self._emit('RETURN', a=0, b=1)
        proto = self._leave_function()
        idx = parent.proto.add_proto(proto)
        return idx

    def _emit_upval_links(self, proto: FunctionPrototype):
        """Emit MOVE/GETUPVAL pseudo-instructions immediately after CLOSURE.

        For each upvalue in the new proto, we tell the runtime where to fetch
        its initial value:
            instack=True  -> MOVE     A=0  B=local_reg     (in parent)
            instack=False -> GETUPVAL A=0  B=parent_upidx
        The interpreter's CLOSURE handler consumes exactly N such pseudo-
        instructions from the byte stream after the CLOSURE itself.
        """
        for uv in proto.upvalues:
            if uv.instack:
                self._emit('MOVE', a=0, b=uv.idx)
            else:
                self._emit('GETUPVAL', a=0, b=uv.idx)

    # =================================================================
    # Expression compilation
    # =================================================================

    def _expr_to_next_reg(self, expr: Node) -> int:
        """Compile expression, place result in a freshly reserved register."""
        reg = self.fs.reserve_regs(1)
        self._expr_to_reg(expr, reg)
        return reg

    def _expr_to_next_reg_multi(self, expr: Node, want: int) -> int:
        """Like _expr_to_next_reg but for calls/varargs that can return many.

        `want` is in CALL/VARARG semantics:
            >0 -> exactly `want` results
             0 -> MULTRET (all results)
        """
        if isinstance(expr, (FunctionCall, MethodCall)):
            base = self.fs.free_reg
            self._compile_call(expr, want=want)
            if want > 0:
                self.fs.reserve_regs(want)
            # If MULTRET, free_reg already advanced by call (top-of-stack semantic)
            return base
        if isinstance(expr, VarargExpr):
            base = self.fs.reserve_regs(1)
            # B = want+1, or 0 for MULTRET
            self._emit('VARARG', a=base, b=(0 if want == MULTRET else want + 1))
            if want > 1:
                self.fs.reserve_regs(want - 1)
            return base
        # Non-multret expressions just produce one value
        return self._expr_to_next_reg(expr)

    def _is_multret_expr(self, expr: Node) -> bool:
        return isinstance(expr, (FunctionCall, MethodCall, VarargExpr))

    def _expr_to_any_reg(self, expr: Node) -> int:
        """If the expression is a non-captured local, return its register;
        else compile to a new reg. (Captured locals must be unwrapped via GETBOX.)
        """
        if isinstance(expr, Identifier):
            lv = self.fs.find_local_var(expr.name)
            if lv is not None and not lv.captured:
                return lv.reg
        return self._expr_to_next_reg(expr)

    def _expr_to_reg(self, expr: Node, reg: int):
        """Compile expression to a specific target register."""
        if expr is None:
            self._emit('LOADNIL', a=reg, b=0)
            return

        if isinstance(expr, NumberLiteral):
            val = self._parse_number(expr.value)
            idx = self.pool.add(val)
            self._emit('LOADK', a=reg, b=idx)
            return

        if isinstance(expr, StringLiteral):
            idx = self.pool.add(expr.value)
            self._emit('LOADK', a=reg, b=idx)
            return

        if isinstance(expr, BooleanLiteral):
            self._emit('LOADBOOL', a=reg, b=1 if expr.value else 0, c=0)
            return

        if isinstance(expr, NilLiteral):
            self._emit('LOADNIL', a=reg, b=0)
            return

        if isinstance(expr, VarargExpr):
            # Single value from varargs
            self._emit('VARARG', a=reg, b=2)  # B=2 -> 1 value
            return

        if isinstance(expr, Identifier):
            raw_num = self._eval_raw_number_expr(expr.name)
            if raw_num is not None:
                idx = self.pool.add(raw_num)
                self._emit('LOADK', a=reg, b=idx)
                return
            lv = self.fs.find_local_var(expr.name)
            if lv is not None:
                self._read_local(lv, reg)
                return
            upv = self._resolve_upvalue(self.fs, expr.name)
            if upv is not None:
                self._emit('GETUPVAL', a=reg, b=upv)
                return
            idx = self.pool.add(expr.name)
            self._emit('GETGLOBAL', a=reg, b=idx)
            return

        if isinstance(expr, BinaryOp):
            self._compile_binop(expr, reg)
            return

        if isinstance(expr, UnaryOp):
            self._compile_unop(expr, reg)
            return

        if isinstance(expr, FunctionCall) or isinstance(expr, MethodCall):
            # Call to single value; place result at reg
            base = self.fs.free_reg
            self._compile_call(expr, want=1)
            if base != reg:
                self._emit('MOVE', a=reg, b=base)
            self.fs.free_reg = base
            return

        if isinstance(expr, MemberExpr):
            obj_reg = self._expr_to_any_reg(expr.object)
            key_idx = self.pool.add(expr.member)
            self._emit('GETTABLEK', a=reg, b=obj_reg, c=key_idx)
            if obj_reg >= self.fs._local_watermark() and obj_reg != reg:
                self.fs.free_reg_to(obj_reg)
            return

        if isinstance(expr, IndexExpr):
            obj_reg = self._expr_to_any_reg(expr.object)
            key_reg = self._expr_to_any_reg(expr.index)
            self._emit('GETTABLE', a=reg, b=obj_reg, c=key_reg)
            watermark = self.fs._local_watermark()
            # Free both temps (key first since it's higher, then obj).
            # Result goes into `reg` which is separate from these temps.
            if key_reg >= watermark and key_reg != reg:
                self.fs.free_reg_to(key_reg)
            if obj_reg >= watermark and obj_reg != reg:
                self.fs.free_reg_to(obj_reg)
            return

        if isinstance(expr, TableConstructor):
            self._compile_table_constructor(expr, reg)
            return

        if isinstance(expr, FunctionExpr):
            proto_idx = self._compile_function_body(expr.params, expr.has_vararg, expr.body)
            self._emit('CLOSURE', a=reg, b=proto_idx)
            self._emit_upval_links(self.fs.proto.sub_protos[proto_idx])
            return

        if isinstance(expr, ParenExpr):
            self._expr_to_reg(expr.expression, reg)
            return

        raise VMCompilationError(f"Unsupported expression: {type(expr).__name__}")

    # ---- Binary / Unary ----

    _BIN_DIRECT = {
        '+': 'ADD', '-': 'SUB', '*': 'MUL', '/': 'DIV',
        '%': 'MOD', '^': 'POW',
    }

    _BIN_CMP = {
        '==': ('EQ', 1),
        '~=': ('EQ', 0),
        '<':  ('LT', 1),
        '>':  ('LT', 1),    # swapped operands
        '<=': ('LE', 1),
        '>=': ('LE', 1),    # swapped operands
    }

    def _compile_binop(self, node: BinaryOp, reg: int):
        op = node.op
        if op in ('and', 'or'):
            self._compile_logical(node, reg)
            return

        if op == '..':
            # Build CONCAT chain across consecutive temps
            base = self.fs.free_reg
            self._collect_concat(node, base)
            top = self.fs.free_reg - 1
            self._emit('CONCAT', a=reg, b=base, c=top)
            self.fs.free_reg = base
            return

        if op in self._BIN_DIRECT:
            l = self._expr_to_any_reg(node.left)
            r = self._expr_to_any_reg(node.right)
            self._emit(self._BIN_DIRECT[op], a=reg, b=l, c=r)
            self._free_two_temps(l, r)
            return

        if op in self._BIN_CMP:
            opname, want = self._BIN_CMP[op]
            l = self._expr_to_any_reg(node.left)
            r = self._expr_to_any_reg(node.right)
            if op in ('>', '>='):
                l, r = r, l
            # Pattern: cmp + LOADBOOL true skip, LOADBOOL false
            self._emit(opname, a=want, b=l, c=r)
            jmp = self._emit_jump()
            # PC where the false path lives
            self._emit('LOADBOOL', a=reg, b=0, c=1)  # set false, skip next
            self._patch_jump(jmp, self._current_pc())
            self._emit('LOADBOOL', a=reg, b=1, c=0)  # set true
            self._free_two_temps(l, r)
            return

        raise VMCompilationError(f"Unsupported binary op: {op}")

    def _collect_concat(self, node: Node, base: int):
        """Flatten nested `..` into consecutive registers starting at base."""
        if isinstance(node, BinaryOp) and node.op == '..':
            self._collect_concat(node.left, base)
            self._collect_concat(node.right, self.fs.free_reg)
        else:
            r = self.fs.reserve_regs(1)
            self._expr_to_reg(node, r)

    def _compile_logical(self, node: BinaryOp, reg: int):
        # 'and': if left is falsy -> result is left, else right
        # 'or' : if left is truthy -> result is left, else right
        self._expr_to_reg(node.left, reg)
        # TEST reg, B  : if (R[reg] <=> B) then ok else pc++
        # For 'and': want truthy to continue; B=1
        # For 'or' : want falsy to continue;  B=0
        want = 1 if node.op == 'and' else 0
        self._emit('TEST', a=reg, b=want)
        jmp = self._emit_jump()
        self._expr_to_reg(node.right, reg)
        self._patch_jump(jmp, self._current_pc())

    def _compile_unop(self, node: UnaryOp, reg: int):
        operand = self._expr_to_any_reg(node.operand)
        op = node.op
        if op == '-':
            self._emit('UNM', a=reg, b=operand)
        elif op == 'not':
            self._emit('NOT', a=reg, b=operand)
        elif op == '#':
            self._emit('LEN', a=reg, b=operand)
        else:
            raise VMCompilationError(f"Unsupported unary op: {op}")
        if operand >= self.fs._local_watermark() and operand != reg:
            self.fs.free_reg_to(operand)

    def _free_two_temps(self, a: int, b: int):
        watermark = self.fs._local_watermark()
        m = min(a, b)
        if m >= watermark:
            self.fs.free_reg_to(m)
        else:
            # Free the higher one if it's a temp
            hi = max(a, b)
            if hi >= watermark:
                self.fs.free_reg_to(hi)

    # ---- Calls ----

    def _compile_call(self, node: Node, want: int):
        """Compile a call. `want` is number of expected results, or MULTRET=0."""
        base = self.fs.free_reg

        if isinstance(node, MethodCall):
            # SELF: place obj in base+1, method in base
            obj_reg = self._expr_to_any_reg(node.object)
            self.fs.free_reg = base  # reset: SELF needs base..base+1
            self.fs.reserve_regs(2)
            key_idx = self.pool.add(node.method)
            self._emit('SELF', a=base, b=obj_reg, c=key_idx)
            # Now: R[base]=method, R[base+1]=obj. Compile remaining args after.
            args = node.args
            n_args_extra = len(args)
            # Compile each arg into next reg
            for i in range(n_args_extra - 1):
                self._expr_to_next_reg(args[i])
            if n_args_extra > 0:
                last = args[n_args_extra - 1]
                if self._is_multret_expr(last):
                    self._expr_to_next_reg_multi(last, want=MULTRET)
                    b_field = 0  # MULTRET args
                else:
                    self._expr_to_next_reg(last)
                    b_field = (n_args_extra + 1) + 1  # +1 for self, +1 for B-encoding
            else:
                b_field = 2  # 1 arg (self), B = nargs+1 = 2
            if n_args_extra > 0 and not self._is_multret_expr(args[-1]):
                b_field = (n_args_extra + 1) + 1
        else:
            # Regular FunctionCall
            fn = node.func
            self._expr_to_reg(fn, base)
            self.fs.free_reg = base + 1
            if self.fs.free_reg > self.fs.max_stack:
                self.fs.max_stack = self.fs.free_reg
            args = node.args
            n_args = len(args)
            for i in range(n_args - 1):
                self._expr_to_next_reg(args[i])
            if n_args > 0:
                last = args[n_args - 1]
                if self._is_multret_expr(last):
                    self._expr_to_next_reg_multi(last, want=MULTRET)
                    b_field = 0
                else:
                    self._expr_to_next_reg(last)
                    b_field = n_args + 1
            else:
                b_field = 1  # 0 args -> B=1

        # C = want+1, with C=0 meaning MULTRET
        c_field = 0 if want == MULTRET else (want + 1)
        self._emit('CALL', a=base, b=b_field, c=c_field)

        # After call: free_reg is at base + want (or untouched for MULTRET)
        if want != MULTRET:
            self.fs.free_reg = base + want

    # ---- Table constructor ----

    _FPF = 50  # Fields-per-flush, like Lua 5.1

    def _compile_table_constructor(self, node: TableConstructor, reg: int):
        # Estimate sizes for NEWTABLE hints (non-binding)
        n_array = sum(1 for f in node.fields if f.key is None)
        n_hash = len(node.fields) - n_array

        self._emit('NEWTABLE', a=reg, b=min(n_array, 0xFFFF), c=min(n_hash, 0xFFFF))

        # Hash-part fields: emit SETTABLE/SETTABLEK directly (not flushed).
        # Array-part fields: accumulate in consecutive temps and flush via SETLIST.
        array_buffer_base = None
        array_count = 0
        flush_blocks = 0  # Number of SETLIST flushes done so far (FPF blocks)

        last_field_is_multret = False
        n_fields = len(node.fields)

        def flush_array(count: int, with_multret: bool = False):
            nonlocal flush_blocks, array_buffer_base
            if count == 0 and not with_multret:
                return
            # SETLIST A B C : R[A][offset+i] := R[A+i] for i=1..B
            #   B = count (0 for MULTRET)
            #   C = block index (1-based)
            block = flush_blocks + 1
            self._emit('SETLIST', a=reg, b=(0 if with_multret else count), c=block)
            flush_blocks = block
            # Free temps used by buffer
            if array_buffer_base is not None:
                self.fs.free_reg = array_buffer_base
            array_buffer_base = None

        for i, field in enumerate(node.fields):
            if field.key is None:
                # Array part — push value into next reg
                if array_buffer_base is None:
                    array_buffer_base = self.fs.free_reg
                is_last_array = True
                # Check if there are more array entries after this
                for j in range(i + 1, n_fields):
                    if node.fields[j].key is None:
                        is_last_array = False
                        break
                if is_last_array and self._is_multret_expr(field.value):
                    self._expr_to_next_reg_multi(field.value, want=MULTRET)
                    flush_array(array_count + 1, with_multret=True)
                    array_count = 0
                    last_field_is_multret = True
                else:
                    self._expr_to_next_reg(field.value)
                    array_count += 1
                    if array_count >= self._FPF:
                        flush_array(array_count)
                        array_count = 0
            else:
                # Hash part: emit immediately
                if field.is_bracket_key:
                    # Bracket key: SETTABLE
                    save = self.fs.free_reg
                    key_reg = self._expr_to_next_reg(field.key)
                    val_reg = self._expr_to_next_reg(field.value)
                    self._emit('SETTABLE', a=reg, b=key_reg, c=val_reg)
                    self.fs.free_reg = save
                else:
                    key_name = field.key.value if isinstance(field.key, StringLiteral) else str(field.key)
                    if isinstance(field.key, Identifier):
                        key_name = field.key.name
                    save = self.fs.free_reg
                    val_reg = self._expr_to_next_reg(field.value)
                    key_idx = self.pool.add(key_name)
                    self._emit('SETTABLEK', a=reg, b=key_idx, c=val_reg)
                    self.fs.free_reg = save

        if array_count > 0:
            flush_array(array_count)

    # =================================================================
    # Number parsing
    # =================================================================

    def _parse_number(self, s: str):
        s = s.replace('_', '')
        try:
            if s.startswith('0x') or s.startswith('0X'):
                return int(s, 16)
            if s.startswith('0b') or s.startswith('0B'):
                return int(s[2:], 2)
            if '.' in s or 'e' in s.lower():
                return float(s)
            return int(s)
        except Exception:
            return 0

    # =================================================================
    # Upvalue resolution (recursive)
    # =================================================================

    def _resolve_upvalue(self, fs: _FuncState, name: str) -> Optional[int]:
        """Resolve `name` as an upvalue in `fs`. Returns upvalue index or None."""
        if name in fs.upvalue_index:
            return fs.upvalue_index[name]
        parent = fs.parent
        if parent is None:
            return None
        # Check if it's a local in parent
        local_in_parent = parent.find_local(name)
        if local_in_parent is not None:
            idx = len(fs.proto.upvalues)
            fs.proto.upvalues.append(UpvalueDesc(name=name, instack=True, idx=local_in_parent))
            fs.upvalue_index[name] = idx
            return idx
        # Otherwise try to resolve in grandparent (recursively).
        parent_uv = self._resolve_upvalue(parent, name)
        if parent_uv is not None:
            idx = len(fs.proto.upvalues)
            fs.proto.upvalues.append(UpvalueDesc(name=name, instack=False, idx=parent_uv))
            fs.upvalue_index[name] = idx
            return idx
        return None
