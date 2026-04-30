"""
Obscura VM Interpreter Generator (Register-Based, Encrypted Bytecode)
=========================================================================
Emits the Luau/Lua runtime that executes register-based VM bytecode.

Compatibility
-------------
The generated runtime works in:
  * Roblox Studio (Luau)
  * Lua 5.1 / 5.2 / 5.3 / 5.4 (where bit32 or bit lib exists, otherwise a
    pure-Lua XOR helper is emitted)
  * LuaJIT

It avoids using:
  * Lua 5.3+ bitwise operators (`~`, `&`, `|`)
  * `goto` (not supported by Luau)
  * `string.unpack` (Lua 5.3+ only)

It uses:
  * `bit32.bxor` if present (Roblox + Luau + Lua 5.2)
  * `bit.bxor` if present (LuaJIT)
  * pure-Lua byte XOR fallback otherwise
  * `unpack` if present, else `table.unpack` (Lua 5.2+)
  * `getfenv()` if present, else `_G` (for the global environment)

Per-build polymorphism
----------------------
  * Opcode byte values are randomized
  * Multiple aliases (distinct bytes) map to the same handler
  * Bytecode is encrypted with a per-build rolling XOR cipher
  * Constant pool strings are encrypted with a separate rolling XOR cipher
  * All variable names in the runtime are obfuscated
  * Handler order in the if/elseif chain is randomized
"""

import random
from typing import Dict, List

from .opcodes import OpcodeMap
from .constant_pool import ConstantPool
from .proto import FunctionPrototype
from .instruction import (
    FORMAT_NONE, FORMAT_A, FORMAT_AB, FORMAT_ABC,
    FORMAT_ABX, FORMAT_ASBX, FORMAT_SBX, instruction_size,
)
from utils.names import NameGenerator
from config import ObfuscationConfig


# ---------------------------------------------------------------------------
# Roblox / Luau / Lua globals whitelist — these must always resolve via
# the global environment (getfenv()/_G). The compiler already handles this
# automatically by emitting GETGLOBAL for any name that isn't a local or
# upvalue. We document the list here for reference.
# ---------------------------------------------------------------------------
ROBLOX_GLOBALS = {
    # Roblox runtime
    'game', 'workspace', 'script', 'shared', 'plugin', 'DebuggerManager',
    'Instance', 'Vector3', 'Vector2', 'CFrame', 'Color3', 'BrickColor',
    'UDim', 'UDim2', 'Ray', 'Region3', 'Enum', 'Random', 'TweenInfo',
    'NumberRange', 'NumberSequence', 'NumberSequenceKeypoint',
    'ColorSequence', 'ColorSequenceKeypoint', 'Rect', 'Faces',
    'Axes', 'PathWaypoint', 'PhysicalProperties',
    # Roblox task lib
    'task', 'wait', 'spawn', 'delay', 'tick', 'time', 'elapsedTime',
    # Standard libs
    'string', 'table', 'math', 'os', 'io', 'coroutine', 'debug',
    'bit32', 'bit', 'utf8',
    # Globals
    'pairs', 'ipairs', 'next', 'select', 'unpack', 'tonumber', 'tostring',
    'type', 'typeof', 'assert', 'error', 'pcall', 'xpcall',
    'rawget', 'rawset', 'rawequal', 'rawlen',
    'setmetatable', 'getmetatable', 'newproxy',
    'print', 'warn', 'require', 'collectgarbage', 'loadstring',
    'getfenv', 'setfenv', 'gcinfo',
    '_G', '_ENV', '_VERSION',
}


class InterpreterGenerator:
    """Generates the Luau runtime that executes our register-based bytecode."""

    def __init__(self, config: ObfuscationConfig, opcodes: OpcodeMap,
                 pool: ConstantPool, name_gen: NameGenerator):
        self.config = config
        self.rng = config.get_rng()
        self.opcodes = opcodes
        self.pool = pool
        self.name_gen = name_gen
        # Per-build rolling key for bytecode stream encryption
        klen = self.rng.randint(4, 16)
        self.bc_key: List[int] = [self.rng.randint(1, 255) for _ in range(klen)]

    # =================================================================
    # Public entry
    # =================================================================

    def generate(self, main_proto: FunctionPrototype) -> str:
        names = self._gen_names()
        parts: List[str] = []

        # 1. Compatibility shims
        parts.append(self._gen_compat_shims(names))

        # 2. Constant pool key + decode
        parts.append(self._gen_constant_pool(names))

        # 3. Bytecode key
        parts.append(self._gen_bytecode_key(names))

        # 4. Encrypt all proto bytecodes and emit them as data tables
        all_protos = self._flatten_protos(main_proto)
        parts.append(self._gen_protos(names, all_protos))

        # 5. Lookup tables used by the exec function (must come BEFORE exec).
        parts.append(self._gen_lookup_tables(names))

        # 6. The exec function
        parts.append(self._gen_exec_function(names))

        # 7. Entry point
        parts.append(self._gen_entry(names))

        return '\n'.join(parts)

    # =================================================================
    # Names
    # =================================================================

    def _gen_names(self) -> Dict[str, str]:
        keys = [
            # Globals
            'bxor', 'unpack', 'env',
            # Tables
            'consts', 'ck', 'ckn',
            'bk', 'bkn',
            'protos',
            # Exec function and locals
            'exec', 'proto', 'upvals', 'varargs',
            'R', 'pc', 'bc', 'sp', 'top', 'op',
            # Operand temps
            'a', 'b', 'c', 'tmp', 'tmp2', 'tmp3',
            # Helpers
            'rd16', 'rds16',
            # Loop locals
            'i', 'j', 'k', 'n',
            # CLOSURE temps
            'newuv', 'newproto', 'pop', 'pa', 'pb',
            # CALL temps
            'fn', 'args', 'nargs', 'nret', 'rets',
            # Misc
            'box',
            # Lookup tables (declared before exec so it can capture them)
            'opsize', 'ismove',
        ]
        out = {}
        for k in keys:
            out[k] = self.name_gen.gen_name()
        return out

    # =================================================================
    # Compatibility shims (bit ops, unpack, env)
    # =================================================================

    def _gen_compat_shims(self, n: Dict[str, str]) -> str:
        return f"""local {n['bxor']}=(bit32 and bit32.bxor) or (bit and bit.bxor) or (function()
local function _x(a,b)
local r,p=0,1
for _=1,8 do
local ab,bb=a%2,b%2
if ab~=bb then r=r+p end
a=(a-ab)/2;b=(b-bb)/2;p=p*2
end
return r
end
return _x
end)()
local {n['unpack']}=unpack or table.unpack
local {n['env']}=(getfenv and getfenv()) or _G"""

    # =================================================================
    # Constant pool emission + runtime string decryption
    # =================================================================

    def _gen_constant_pool(self, n: Dict[str, str]) -> str:
        key_entries = ','.join(str(k) for k in self.pool.key)
        consts_table = self.pool.to_luau_table()
        # Decrypt strings on startup (eager)
        return f"""local {n['ck']}={{{key_entries}}}
local {n['ckn']}=#{n['ck']}
local {n['consts']}={consts_table}
for {n['i']},{n['tmp']} in ipairs({n['consts']}) do
if type({n['tmp']})=="string" then
local {n['tmp2']}={{}}
for {n['j']}=1,#{n['tmp']} do
{n['tmp2']}[{n['j']}]=string.char({n['bxor']}(string.byte({n['tmp']},{n['j']}),{n['ck']}[({n['j']}-1)%{n['ckn']}+1]))
end
{n['consts']}[{n['i']}]=table.concat({n['tmp2']})
end
end"""

    # =================================================================
    # Bytecode key
    # =================================================================

    def _gen_bytecode_key(self, n: Dict[str, str]) -> str:
        return f"""local {n['bk']}={{{','.join(str(k) for k in self.bc_key)}}}
local {n['bkn']}=#{n['bk']}"""

    # =================================================================
    # Proto serialization
    # =================================================================

    def _flatten_protos(self, root: FunctionPrototype) -> List[FunctionPrototype]:
        """Flatten nested protos into a flat list with rewritten sub-proto refs.

        Returns a list where index 0 is the root. Each proto's `sub_protos`
        list (which may contain duplicate entries) is converted into indices
        into this flat list and stored in a parallel list `sp_indices`.
        """
        flat: List[FunctionPrototype] = []
        sp_indices: Dict[int, List[int]] = {}  # id(proto) -> list of flat indices

        def walk(p: FunctionPrototype) -> int:
            idx = len(flat)
            flat.append(p)
            child_indices: List[int] = []
            for child in p.sub_protos:
                child_idx = walk(child)
                child_indices.append(child_idx)
            sp_indices[id(p)] = child_indices
            return idx

        walk(root)
        # Stash sp_indices as an attribute on each proto for emission
        for p in flat:
            p._sp_indices = sp_indices[id(p)]
        return flat

    def _encrypt_bytecode(self, bc: List[int]) -> List[int]:
        """Apply rolling XOR with bc_key to the byte stream.

        The runtime decrypts using key index `(pc-1) % klen + 1` (Lua 1-based).
        """
        klen = len(self.bc_key)
        return [b ^ self.bc_key[i % klen] for i, b in enumerate(bc)]

    def _gen_protos(self, n: Dict[str, str], protos: List[FunctionPrototype]) -> str:
        """Emit the table of all proto data."""
        lines = [f"local {n['protos']}={{}}"]
        for i, p in enumerate(protos):
            enc_bc = self._encrypt_bytecode(p.bytecode)
            bc_str = ','.join(str(b) for b in enc_bc)
            sp_str = ','.join(str(idx + 1) for idx in p._sp_indices)  # Lua 1-based
            lines.append(
                f"{n['protos']}[{i + 1}]="
                f"{{bc={{{bc_str}}},"
                f"np={p.num_params},"
                f"va={'true' if p.is_vararg else 'false'},"
                f"nuv={len(p.upvalues)},"
                f"ms={p.max_stacksize},"
                f"sp={{{sp_str}}}}}"
            )
        return '\n'.join(lines)

    # =================================================================
    # Exec function (the heart of the VM)
    # =================================================================

    def _gen_exec_function(self, n: Dict[str, str]) -> str:
        """Generate the main `exec` interpreter function."""
        # Build all opcode handler bodies
        handlers = self._build_handlers(n)
        # Shuffle for polymorphism
        self.rng.shuffle(handlers)

        # Build the if/elseif chain
        chain_lines: List[str] = []
        for i, h in enumerate(handlers):
            kw = 'if' if i == 0 else 'elseif'
            body = h['body']
            if body.startswith(';'):
                body = body[1:]
            chain_lines.append(f"{kw} {n['op']}=={h['byte']} then {body}")
        chain_lines.append("else error(\"VM: bad opcode \"..tostring(" + n['op'] + "))")
        chain_lines.append("end")
        chain = '\n'.join(chain_lines)

        # The exec function
        # Reads operand bytes; pc is byte-offset (1-based for Lua array indexing).
        # All u16 operands are little-endian (lo, hi).
        # Signed sBx is biased by 0x8000 (32768) at encode time.
        return f"""local {n['exec']}
{n['exec']}=function({n['proto']},{n['upvals']},...)
local {n['varargs']}={{...}}
local {n['nargs']}=select("#",...)
local {n['R']}={{}}
for {n['i']}=1,{n['proto']}.np do {n['R']}[{n['i']}-1]={n['varargs']}[{n['i']}] end
local {n['bc']}={n['proto']}.bc
local {n['sp']}={n['proto']}.sp
local {n['pc']}=1
local {n['top']}={n['proto']}.np
local {n['box']}
while true do
local {n['op']}={n['bxor']}({n['bc']}[{n['pc']}],{n['bk']}[({n['pc']}-1)%{n['bkn']}+1]); {n['pc']}={n['pc']}+1
{chain}
end
end"""

    # =================================================================
    # Handler construction
    # =================================================================

    def _build_handlers(self, n: Dict[str, str]) -> List[dict]:
        """Build one handler dict per opcode alias byte."""
        handlers: List[dict] = []

        # Read each alias and its semantic name
        for byte, info in self.opcodes.all_aliases():
            body = self._gen_handler_body(info.name, info.fmt, n)
            handlers.append({'byte': byte, 'body': body, 'name': info.name})

        return handlers

    # ---- Operand-reading code generator ----

    def _read_u16_inline(self, n: Dict[str, str], dest: str) -> str:
        """Generate inline code to read a u16 from BC at PC, advancing PC."""
        bx, bc, bk, bkn, pc = n['bxor'], n['bc'], n['bk'], n['bkn'], n['pc']
        return (
            f"local {dest}={bx}({bc}[{pc}],{bk}[({pc}-1)%{bkn}+1])"
            f"+{bx}({bc}[{pc}+1],{bk}[{pc}%{bkn}+1])*256;"
            f"{pc}={pc}+2"
        )

    def _read_s16_inline(self, n: Dict[str, str], dest: str) -> str:
        """Generate inline code to read an s16 (biased by 0x8000)."""
        bx, bc, bk, bkn, pc = n['bxor'], n['bc'], n['bk'], n['bkn'], n['pc']
        return (
            f"local {dest}={bx}({bc}[{pc}],{bk}[({pc}-1)%{bkn}+1])"
            f"+{bx}({bc}[{pc}+1],{bk}[{pc}%{bkn}+1])*256-32768;"
            f"{pc}={pc}+2"
        )

    def _read_operands(self, fmt: str, n: Dict[str, str]) -> str:
        """Generate operand-reading code based on the instruction format.
        Sets locals named `a`, `b`, `c` based on what the format provides.
        """
        a_name, b_name, c_name = n['a'], n['b'], n['c']
        if fmt == FORMAT_NONE:
            return ""
        if fmt == FORMAT_A:
            return self._read_u16_inline(n, a_name)
        if fmt == FORMAT_SBX:
            return self._read_s16_inline(n, a_name)
        if fmt == FORMAT_AB:
            return self._read_u16_inline(n, a_name) + ";" + self._read_u16_inline(n, b_name)
        if fmt == FORMAT_ABC:
            return (self._read_u16_inline(n, a_name) + ";" +
                    self._read_u16_inline(n, b_name) + ";" +
                    self._read_u16_inline(n, c_name))
        if fmt == FORMAT_ABX:
            return self._read_u16_inline(n, a_name) + ";" + self._read_u16_inline(n, b_name)
        if fmt == FORMAT_ASBX:
            return self._read_u16_inline(n, a_name) + ";" + self._read_s16_inline(n, b_name)
        raise ValueError(f"Unknown format: {fmt}")

    # ---- Per-opcode handler bodies ----

    def _gen_handler_body(self, op_name: str, fmt: str, n: Dict[str, str]) -> str:
        ops = self._read_operands(fmt, n)
        a, b, c = n['a'], n['b'], n['c']
        R = n['R']
        CONSTS = n['consts']
        UPVALS = n['upvals']
        ENV = n['env']
        EXEC = n['exec']
        SP = n['sp']
        PROTOS = n['protos']
        UNPACK = n['unpack']
        BC = n['bc']
        BK = n['bk']
        BKN = n['bkn']
        BXOR = n['bxor']
        PC = n['pc']
        VA = n['varargs']
        NARGS = n['nargs']
        TOP = n['top']
        OPSIZE = n['opsize']
        ISMOVE = n['ismove']

        if op_name == 'MOVE':
            return ops + f";{R}[{a}]={R}[{b}]"
        if op_name == 'LOADK':
            return ops + f";{R}[{a}]={CONSTS}[{b}+1]"
        if op_name == 'LOADBOOL':
            # If C != 0, skip the next instruction (size depends on its fmt)
            return (ops + f";{R}[{a}]=({b}~=0);"
                    f"if {c}~=0 then "
                    # Skip next instruction: read its opcode, look up size, advance.
                    f"local _no={BXOR}({BC}[{PC}],{BK}[({PC}-1)%{BKN}+1]);"
                    f"{PC}={PC}+1+{OPSIZE}[_no] "
                    f"end")
        if op_name == 'LOADNIL':
            # R[A..A+B] := nil
            return ops + f";for _i={a},{a}+{b} do {R}[_i]=nil end"

        if op_name == 'GETUPVAL':
            # Unwrap box
            return ops + f";{R}[{a}]={UPVALS}[{b}+1][1]"
        if op_name == 'SETUPVAL':
            return ops + f";{UPVALS}[{b}+1][1]={R}[{a}]"

        if op_name == 'GETGLOBAL':
            return ops + f";{R}[{a}]={ENV}[{CONSTS}[{b}+1]]"
        if op_name == 'SETGLOBAL':
            return ops + f";{ENV}[{CONSTS}[{b}+1]]={R}[{a}]"

        if op_name == 'NEWTABLE':
            return ops + f";{R}[{a}]={{}}"
        if op_name == 'GETTABLE':
            return ops + f";{R}[{a}]={R}[{b}][{R}[{c}]]"
        if op_name == 'SETTABLE':
            return ops + f";{R}[{a}][{R}[{b}]]={R}[{c}]"
        if op_name == 'GETTABLEK':
            return ops + f";{R}[{a}]={R}[{b}][{CONSTS}[{c}+1]]"
        if op_name == 'SETTABLEK':
            return ops + f";{R}[{a}][{CONSTS}[{b}+1]]={R}[{c}]"
        if op_name == 'SELF':
            return ops + (f";{R}[{a}+1]={R}[{b}];"
                          f"{R}[{a}]={R}[{b}][{CONSTS}[{c}+1]]")
        if op_name == 'SETLIST':
            # B = count (0 = MULTRET via top), C = block index (1-based)
            FPF = 50
            return ops + (
                f";local _t={R}[{a}];"
                f"local _off=({c}-1)*{FPF};"
                f"local _cnt=({b}==0) and ({TOP}-{a}-1) or {b};"
                f"for _i=1,_cnt do _t[_off+_i]={R}[{a}+_i] end"
            )

        if op_name == 'ADD':
            return ops + f";{R}[{a}]={R}[{b}]+{R}[{c}]"
        if op_name == 'SUB':
            return ops + f";{R}[{a}]={R}[{b}]-{R}[{c}]"
        if op_name == 'MUL':
            return ops + f";{R}[{a}]={R}[{b}]*{R}[{c}]"
        if op_name == 'DIV':
            return ops + f";{R}[{a}]={R}[{b}]/{R}[{c}]"
        if op_name == 'MOD':
            return ops + f";{R}[{a}]={R}[{b}]%{R}[{c}]"
        if op_name == 'POW':
            return ops + f";{R}[{a}]={R}[{b}]^{R}[{c}]"
        if op_name == 'UNM':
            return ops + f";{R}[{a}]=-{R}[{b}]"
        if op_name == 'NOT':
            return ops + f";{R}[{a}]=not {R}[{b}]"
        if op_name == 'LEN':
            return ops + f";{R}[{a}]=#({R}[{b}])"
        if op_name == 'CONCAT':
            return ops + (
                f";local _s={R}[{b}];"
                f"for _i={b}+1,{c} do _s=_s..{R}[_i] end;"
                f"{R}[{a}]=_s"
            )

        if op_name == 'EQ':
            # Compiler emits cmp + JMP true-skip pattern. Semantics:
            #   if (R[B]==R[C]) ~= A then pc++ (skip the JMP)
            return ops + (
                f";if ({R}[{b}]=={R}[{c}])~=({a}~=0) then "
                f"local _no={BXOR}({BC}[{PC}],{BK}[({PC}-1)%{BKN}+1]);"
                f"{PC}={PC}+1+{OPSIZE}[_no] "
                f"end"
            )
        if op_name == 'LT':
            return ops + (
                f";if ({R}[{b}]<{R}[{c}])~=({a}~=0) then "
                f"local _no={BXOR}({BC}[{PC}],{BK}[({PC}-1)%{BKN}+1]);"
                f"{PC}={PC}+1+{OPSIZE}[_no] "
                f"end"
            )
        if op_name == 'LE':
            return ops + (
                f";if ({R}[{b}]<={R}[{c}])~=({a}~=0) then "
                f"local _no={BXOR}({BC}[{PC}],{BK}[({PC}-1)%{BKN}+1]);"
                f"{PC}={PC}+1+{OPSIZE}[_no] "
                f"end"
            )
        if op_name == 'TEST':
            # if not (R[A] <=> B) then pc++ (skip next, usually a JMP)
            # B==1 -> want truthy; B==0 -> want falsy
            return ops + (
                f";local _v={R}[{a}];"
                f"local _t=(_v~=nil and _v~=false);"
                f"if _t~=({b}~=0) then "
                f"local _no={BXOR}({BC}[{PC}],{BK}[({PC}-1)%{BKN}+1]);"
                f"{PC}={PC}+1+{OPSIZE}[_no] "
                f"end"
            )
        if op_name == 'TESTSET':
            return ops + (
                f";local _v={R}[{b}];"
                f"local _t=(_v~=nil and _v~=false);"
                f"if _t==({c}~=0) then {R}[{a}]=_v else "
                f"local _no={BXOR}({BC}[{PC}],{BK}[({PC}-1)%{BKN}+1]);"
                f"{PC}={PC}+1+{OPSIZE}[_no] "
                f"end"
            )

        if op_name == 'JMP':
            # sBx in `a`
            return ops + f";{PC}={PC}+{a}"

        if op_name == 'CALL':
            # CALL A B C: A=func reg, B=nargs+1 (0=MULTRET), C=nresults+1 (0=MULTRET)
            return ops + (
                f";local _f={R}[{a}];"
                f"local _nargs;"
                f"if {b}==0 then _nargs={TOP}-{a}-1 else _nargs={b}-1 end;"
                f"local _ar={{}};"
                f"for _i=1,_nargs do _ar[_i]={R}[{a}+_i] end;"
                f"local _rt={{_f({UNPACK}(_ar,1,_nargs))}};"
                f"local _rn=#_rt;"
                f"if {c}==0 then "
                f"for _i=1,_rn do {R}[{a}+_i-1]=_rt[_i] end;"
                f"{TOP}={a}+_rn "
                f"else "
                f"local _want={c}-1;"
                f"for _i=1,_want do {R}[{a}+_i-1]=_rt[_i] end "
                f"end"
            )
        if op_name == 'TAILCALL':
            # Same as CALL with MULTRET; not optimized in our VM
            return ops + (
                f";local _f={R}[{a}];"
                f"local _nargs;"
                f"if {b}==0 then _nargs={TOP}-{a}-1 else _nargs={b}-1 end;"
                f"local _ar={{}};"
                f"for _i=1,_nargs do _ar[_i]={R}[{a}+_i] end;"
                f"return _f({UNPACK}(_ar,1,_nargs))"
            )
        if op_name == 'RETURN':
            # B == 0 -> return all from A to TOP
            # B == 1 -> return 0 values
            # else  -> return B-1 values from A
            return ops + (
                f";if {b}==0 then "
                f"local _rt={{}};for _i={a},{TOP}-1 do _rt[_i-{a}+1]={R}[_i] end;"
                f"return {UNPACK}(_rt,1,{TOP}-{a}) "
                f"elseif {b}==1 then return "
                f"else "
                f"local _rt={{}};for _i=1,{b}-1 do _rt[_i]={R}[{a}+_i-1] end;"
                f"return {UNPACK}(_rt,1,{b}-1) "
                f"end"
            )

        if op_name == 'FORPREP':
            # R[A] -= R[A+2] ; pc += sBx
            return ops + (
                f";{R}[{a}]={R}[{a}]-{R}[{a}+2];"
                f"{PC}={PC}+{b}"
            )
        if op_name == 'FORLOOP':
            # R[A] += R[A+2]; if (step>0 and i<=stop) or (step<0 and i>=stop) then
            #   R[A+3] = R[A]; pc += sBx
            return ops + (
                f";{R}[{a}]={R}[{a}]+{R}[{a}+2];"
                f"local _stp={R}[{a}+2];"
                f"local _i={R}[{a}];"
                f"local _stop={R}[{a}+1];"
                f"if (_stp>=0 and _i<=_stop) or (_stp<0 and _i>=_stop) then "
                f"{R}[{a}+3]=_i;{PC}={PC}+{b} "
                f"end"
            )
        if op_name == 'TFORLOOP':
            # B = sBx back-jump offset to body start, C = number of vars
            return ops + (
                f";local _f={R}[{a}];local _s={R}[{a}+1];local _v={R}[{a}+2];"
                f"local _rt={{_f(_s,_v)}};"
                f"if _rt[1]~=nil then "
                f"{R}[{a}+2]=_rt[1];"
                f"for _i=1,{c} do {R}[{a}+2+_i]=_rt[_i] end;"
                f"{PC}={PC}+{b} "
                f"end"
            )

        if op_name == 'CLOSURE':
            # Read N pseudo-instructions for upvalue links
            return ops + (
                f";local _np={SP}[{b}+1];"
                f"local _newp={PROTOS}[_np];"
                f"local _nuv=_newp.nuv;"
                f"local _newuv={{}};"
                f"for _i=1,_nuv do "
                f"local _po={BXOR}({BC}[{PC}],{BK}[({PC}-1)%{BKN}+1]); {PC}={PC}+1;"
                f"{self._read_u16_inline(n, '_pa')};"
                f"{self._read_u16_inline(n, '_pb')};"
                # Either MOVE or GETUPVAL (any alias).
                # If it's any MOVE alias, capture local register (a box).
                # If it's any GETUPVAL alias, share parent's upvalue.
                f"if {ISMOVE}[_po] then _newuv[_i]={R}[_pb] "
                f"else _newuv[_i]={UPVALS}[_pb+1] end "
                f"end;"
                f"local _np2=_newp;"
                f"{R}[{a}]=function(...) return {EXEC}(_np2,_newuv,...) end"
            )
        if op_name == 'VARARG':
            # B == 0 -> all-to-top; else B-1 values
            return ops + (
                f";if {b}==0 then "
                f"local _van={NARGS}-{n['proto']}.np;"
                f"if _van<0 then _van=0 end;"
                f"for _i=1,_van do {R}[{a}+_i-1]={VA}[{n['proto']}.np+_i] end;"
                f"{TOP}={a}+_van "
                f"else "
                f"local _want={b}-1;"
                f"for _i=1,_want do {R}[{a}+_i-1]={VA}[{n['proto']}.np+_i] end "
                f"end"
            )

        if op_name == 'MKBOX':
            return ops + f";{R}[{a}]={{{R}[{b}]}}"
        if op_name == 'GETBOX':
            return ops + f";{R}[{a}]={R}[{b}][1]"
        if op_name == 'SETBOX':
            return ops + f";{R}[{a}][1]={R}[{b}]"

        if op_name == 'NOP':
            return ops + ";--[[nop]]"

        raise NotImplementedError(f"Handler for {op_name} not implemented")

    # =================================================================
    # Entry point and helpers
    # =================================================================

    def _gen_lookup_tables(self, n: Dict[str, str]) -> str:
        """Lookup tables used by exec for skipping instructions and CLOSURE links."""
        # opsize: opcode-byte -> operand-block size (excludes opcode byte)
        size_entries = [
            f"[{byte}]={instruction_size(info.fmt) - 1}"
            for byte, info in self.opcodes.all_aliases()
        ]
        # ismove: opcode-byte -> true iff it's any MOVE alias
        move_aliases = self.opcodes.opcodes['MOVE'].aliases
        ismove_entries = ','.join(f"[{v}]=true" for v in move_aliases)
        return (
            f"local {n['opsize']}={{{','.join(size_entries)}}}\n"
            f"local {n['ismove']}={{{ismove_entries}}}"
        )

    def _gen_entry(self, n: Dict[str, str]) -> str:
        return f"return {n['exec']}({n['protos']}[1],{{}},...)"
