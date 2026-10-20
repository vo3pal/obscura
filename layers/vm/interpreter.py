"""
Obscura VM Interpreter Generator (Register-Based, Encrypted Bytecode)
=========================================================================
Emits the Luau runtime that executes register-based VM bytecode.

Compatibility
-------------
The validation target is Roblox Luau. Compatibility shims exist for some Lua
environments, but cross-version Lua compatibility is not certified. In
particular, generalized __iter setup relies on Luau's table.foreach boundary.

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
  * Bytecode uses repeating multi-byte XOR with per-build keys
  * Hardened builds use shuffled function constant pools and independent keys
  * Operand order and byte order vary by operation in hardened builds
  * Eligible straight-line sequences can use fused instructions
  * All variable names in the runtime are obfuscated
  * Hardened output mixes operation sequences and uses a numeric dispatch tree
"""

import random
from typing import Dict, List

from .opcodes import OpcodeMap
from .constant_pool import ConstantPool
from .payload import PayloadHash, key_record
from .proto import FunctionPrototype
from .instruction import (
    FORMAT_NONE, FORMAT_A, FORMAT_AB, FORMAT_ABC, FORMAT_ABCD,
    FORMAT_ABX, FORMAT_ASBX, FORMAT_SBX, instruction_size, operand_count,
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
        # Per-build repeating key for bytecode stream encoding
        klen = self.rng.randint(4, 16)
        self.bc_key: List[int] = [self.rng.randint(1, 255) for _ in range(klen)]
        self.hash_seed = self.rng.randrange(4294967296)
        # Products stay below 2^48, exactly representable in Luau doubles.
        self.hash_multiplier = self.rng.randrange(257, 65536, 2)
        self.runtime_check_interval = self.rng.randint(3, 9)
        self.lookup_mul = self.rng.randrange(1, 256, 2)
        self.lookup_add = self.rng.randrange(256)
        self.lookup_mask_mul = self.rng.randrange(1, 256, 2)
        self.lookup_mask_add = self.rng.randrange(256)
        self._key_records = {}

    def _lookup_slot(self, byte: int) -> int:
        return (byte * self.lookup_mul + self.lookup_add) % 256

    def _lookup_mask(self, slot: int) -> int:
        return (slot * self.lookup_mask_mul + self.lookup_mask_add) % 256

    def _lookup_slot_expr(self, expression: str) -> str:
        return f"(({expression})*{self.lookup_mul}+{self.lookup_add})%256"

    def _lookup_mask_expr(self, expression: str) -> str:
        return f"(({expression})*{self.lookup_mask_mul}+{self.lookup_mask_add})%256"

    # =================================================================
    # Public entry
    # =================================================================

    def generate(self, main_proto: FunctionPrototype) -> str:
        names = self._gen_names()
        parts: List[str] = []
        all_protos = self._flatten_protos(main_proto)
        for proto in all_protos:
            if self.config.vm_per_proto_keys:
                proto.bytecode_key = [self.rng.randint(1,255) for _ in range(self.rng.randint(8,16))]
            if self.config.vm_position_keys:
                proto.bytecode_mul = self.rng.randrange(1, 256, 2)
                proto.bytecode_add = self.rng.randrange(256)
            else:
                proto.bytecode_mul = 0
                proto.bytecode_add = 0
            if self.config.vm_per_proto_opcodes:
                proto.opcode_mul = self.rng.randrange(1, 256, 2)
                proto.opcode_add = self.rng.randrange(256)
                proto.opcode_inverse = pow(proto.opcode_mul, -1, 256)
            else:
                proto.opcode_mul = 1
                proto.opcode_add = 0
                proto.opcode_inverse = 1
            if self.config.vm_stateful_fetch:
                proto.fetch_seed = self.rng.randrange(65536)
                proto.fetch_share = self.rng.randrange(65536)
                proto.fetch_mul = self.rng.randrange(1, 65536, 2)
                proto.fetch_add = self.rng.randrange(65536)
                proto.fetch_step = self.rng.randrange(1, 65536, 2)
                proto.fetch_byte = self.rng.randrange(1, 256, 2)
                proto.fetch_bias = self.rng.randrange(256)
                proto.fetch_tag_seed = self.rng.randrange(4294967296)
                proto.fetch_tag_mul = self.rng.randrange(257, 65536, 2)
                proto.fetch_family = self.rng.randrange(3)
            if self.config.vm_shuffle_prototypes:
                proto.proto_link_mul = self.rng.randrange(1, 65536, 2)
                proto.proto_link_add = self.rng.randrange(65536)
            if self.config.vm_operand_layouts:
                proto.operand_mul = self.rng.randrange(1, 65536, 2)
                proto.operand_add = self.rng.randrange(65536)
                proto.operand_opcode_mul = self.rng.randrange(1, 65536, 2)
                proto.operand_salt = self.rng.randrange(65536)
                proto.operand_family = self.rng.randrange(3)
            proto.interpreter_index = (self.rng.randint(1, 2)
                                       if self.config.vm_multi_interpreters else 1)
        root_wire_bytecode = self._encode_proto_opcodes(main_proto)
        root_wire_bytecode = self._encode_proto_operands(main_proto, root_wire_bytecode)
        self._root_salt = self._hash_bytes(self._encrypt_bytecode(
            self._stateful_encode(main_proto, root_wire_bytecode),
            main_proto.bytecode_key if self.config.vm_per_proto_keys else None,
            main_proto.bytecode_mul, main_proto.bytecode_add))

        # 1. Compatibility shims
        parts.append(self._gen_compat_shims(names))
        if (self.config.vm_dynamic_keys or self.config.vm_integrity_check
                or self.config.vm_runtime_integrity):
            parts.append(self._gen_payload_helpers(names))

        # 2. Constant pool key + decode
        parts.append(self._gen_constant_pool(names))

        # 3. Bytecode key
        parts.append(self._gen_bytecode_key(names))

        # 4. Encrypt all proto bytecodes and emit them as data tables
        # Emit only aliases present in this build, with one body per semantic op.
        self._used_aliases = {}
        for proto_index,proto in enumerate(all_protos):
            # Static loop nesting estimates repeated work. Weight function
            # bodies above one-time chunk setup; do not let closure link data
            # influence dispatch order. This changes generation, not runtime.
            weights = {ins.pc: (8 if proto_index else 1) for ins in proto.instructions}
            links = set()
            for index,ins in enumerate(proto.instructions):
                if ins.op_name == 'CLOSURE':
                    count = len(proto.sub_protos[ins.b].upvalues)
                    links.update(r.pc for r in proto.instructions[index+1:index+1+count])
                if ins.op_name in ('JMP','FORLOOP','TFORLOOP'):
                    offset = ins.a if ins.op_name=='JMP' else ins.b
                    target = ins.pc+instruction_size(ins.fmt)+offset
                    if target < ins.pc:
                        for candidate in proto.instructions:
                            if target <= candidate.pc <= ins.pc:
                                weights[candidate.pc] = min(weights[candidate.pc]*8,4096)
            pc = 0
            while pc < len(proto.bytecode):
                byte = proto.bytecode[pc]
                frequency = 0 if pc in links else weights[pc]
                self._used_aliases[byte] = self._used_aliases.get(byte, 0) + frequency
                pc += instruction_size(self.opcodes.fmt_of_byte(byte))
        parts.append(self._gen_protos(names, all_protos))

        if self.config.vm_integrity_check:
            parts.append(self._gen_integrity_check(names))
        if self.config.vm_dynamic_keys:
            parts.append(self._gen_key_setup(names))
        if not self.config.vm_lazy_constants:
            if self.config.vm_partition_constants:
                parts.append(f"for _,_p in ipairs({names['protos']}) do {names['cget']}(_p) end")
            else:
                parts.append(f"for _i=1,{self.pool.size()} do {names['cget']}(_i) end")

        if self.config.vm_predecode_bytecode:
            parts.append(self._gen_bytecode_decode(names))

        parts.append(self._gen_call_helper(names))

        # 5. Lookup tables used by the exec function (must come BEFORE exec).
        parts.append(self._gen_lookup_tables(names))

        # 6. One or more structurally independent interpreter bodies. Nested
        # closures call the router, so prototypes can switch engines freely.
        if self.config.vm_multi_interpreters:
            parts.append(f"local {names['exec']},{names['exec1']},{names['exec2']}")
            parts.append(self._gen_exec_function(names, names['exec1']))
            parts.append(self._gen_exec_function(names, names['exec2']))
            parts.append(f'''{names['exec']}=function(_p,_u,...)
if _p.ix==1 then return {names['exec1']}(_p,_u,...)
else return {names['exec2']}(_p,_u,...) end
end''')
        else:
            parts.append(f"local {names['exec']}")
            parts.append(self._gen_exec_function(names, names['exec']))

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
            'consts', 'ck', 'ckn', 'cget', 'pending', 'invoke', 'pack',
            'bk', 'bkn',
            'protos',
            # Exec function and locals
            'exec', 'exec1', 'exec2', 'proto', 'upvals', 'varargs',
            'R', 'pc', 'bc', 'sp', 'top', 'op',
            # Operand temps
            'a', 'b', 'c', 'd', 'tmp', 'tmp2', 'tmp3',
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
            'hashstep', 'hashuint', 'hashblob', 'hashkey', 'hashvalue',
            'hashpool', 'hashproto', 'salt', 'unkey', 'number',
            'decode',
            'readbyte', 'resetfetch',
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
local {n['env']}=(getfenv and getfenv()) or _G
local {n['pack']}=table.pack or function(...) return {{n=select("#",...),...}} end"""

    # =================================================================
    # Constant pool emission + runtime string decryption
    # =================================================================

    def _gen_constant_pool(self, n: Dict[str, str]) -> str:
        numeric = self.config.vm_encode_numbers
        number_helper = ''
        if numeric:
            number_helper = f'''local function {n['number']}(_v)
if _v=="inf" then return math.huge elseif _v=="-inf" then return -math.huge
elseif _v=="nan" then return 0/0 end
local _r=tonumber(_v);if _r==nil then error("VM: invalid numeric constant") end;return _r
end\n'''
        convert = f"if _kind==2 then _v={n['number']}(_v) end;" if numeric else ''
        if self.config.vm_partition_constants:
            return number_helper + f"""local function {n['cget']}(_p)
{f"_p.ck={n['unkey']}(_p.ck,_p.ks)" if self.config.vm_dynamic_keys and self.config.vm_lazy_constants else ''}
for _i,_kind in pairs(_p.pending) do
local _v=_p.k[_i]
local _s={{}}
for _j=1,#_v do
_s[_j]=string.char({n['bxor']}(string.byte(_v,_j),_p.ck[(_j-1)%#_p.ck+1]))
end
_v=table.concat(_s);{convert}_p.k[_i]=_v
end
_p.pending=nil;_p.ck=nil;_p.ready=true
{'_p.ks=nil' if not self.config.vm_predecode_bytecode or not self.config.vm_per_proto_keys else ''}
end"""
        key_entries = self._gen_key_table(self.pool.key, n, self._root_salt)
        consts_table = self.pool.to_luau_table(numeric)
        _, kinds = self.pool.encoded_values(numeric)
        pending = ','.join(f'[{i+1}]={kind}' for i,kind in enumerate(kinds) if kind)
        return number_helper + f"""local {n['ck']}={key_entries}
local {n['ckn']}=#{n['ck']}
local {n['consts']}={consts_table}
local {n['pending']}={{{pending}}}
local {n['cget']}
{n['cget']}=function({n['i']})
local {n['tmp']}={n['consts']}[{n['i']}]
local _kind={n['pending']}[{n['i']}]
if _kind then
local {n['tmp2']}={{}}
for {n['j']}=1,#{n['tmp']} do
{n['tmp2']}[{n['j']}]=string.char({n['bxor']}(string.byte({n['tmp']},{n['j']}),{n['ck']}[({n['j']}-1)%{n['ckn']}+1]))
end
{n['tmp']}=table.concat({n['tmp2']})
{f"if _kind==2 then {n['tmp']}={n['number']}({n['tmp']}) end" if numeric else ''}
{n['consts']}[{n['i']}]={n['tmp']}
{n['pending']}[{n['i']}]=nil
end
return {n['tmp']}
end"""

    # =================================================================
    # Bytecode key
    # =================================================================

    def _key_record(self, key, salt):
        record = self._key_records.get(id(key))
        if record is None:
            record = key_record(key, salt, self.rng, self.config.vm_dynamic_keys)
            self._key_records[id(key)] = record
        return record

    def _gen_key_table(self, key: List[int], n: Dict[str, str], salt=0) -> str:
        record = self._key_record(key, salt)
        if isinstance(record, list):
            return '{' + ','.join(map(str,record)) + '}'
        return ('{q={' + ','.join(map(str,record['q'])) + '},'
                + ','.join(f'{field}={record[field]}' for field in ('s','a','d')) + '}')

    def _gen_bytecode_key(self, n: Dict[str, str]) -> str:
        if self.config.vm_per_proto_keys:
            return ''
        return f"""local {n['bk']}={self._gen_key_table(self.bc_key, n, self._root_salt)}
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
        if self.config.vm_shuffle_prototypes and len(flat) > 2:
            order = list(range(1, len(flat)))
            self.rng.shuffle(order)
            order.insert(0, 0)
            remap = {old: new for new, old in enumerate(order)}
            flat = [flat[old] for old in order]
            for p in flat:
                p._sp_indices = [remap[index] for index in sp_indices[id(p)]]
        else:
            for p in flat:
                p._sp_indices = sp_indices[id(p)]
        return flat

    def _encrypt_bytecode(self, bc: List[int], key=None, multiplier=0, offset=0) -> List[int]:
        """Apply keyed, position-dependent XOR to the byte stream.

        The extra affine byte mask prevents a repeating-key pattern while
        retaining constant-time random access for branches.
        """
        key = self.bc_key if key is None else key
        return [b ^ key[i % len(key)] ^ (((i + 1) * multiplier + offset) % 256)
                for i, b in enumerate(bc)]

    def _stateful_encode(self, proto: FunctionPrototype, bytecode: List[int]) -> List[int]:
        """Encode each instruction with a state chained through its clear bytes."""
        if not self.config.vm_stateful_fetch or self.config.vm_predecode_bytecode:
            return bytecode
        out = list(bytecode)
        proto.fetch_positions = []
        proto.fetch_lengths = []
        proto.fetch_tags = []
        for instruction in proto.instructions:
            start = instruction.pc
            state = (proto.fetch_seed + (start + 1) * proto.fetch_mul
                     + proto.fetch_add) % 65536
            size = instruction_size(instruction.fmt)
            tag = (proto.fetch_tag_seed + (start + 1) * proto.fetch_tag_mul) % 4294967296
            for relative in range(size):
                position = start + relative
                clear = bytecode[position]
                high, low = state // 256, state % 256
                if proto.fetch_family == 1:
                    mask = ((high + proto.fetch_byte) % 256) ^ low
                    state = (state * proto.fetch_step + clear * proto.fetch_byte
                             + relative + 1 + proto.fetch_bias) % 65536
                elif proto.fetch_family == 2:
                    mask = high ^ ((low + proto.fetch_bias) % 256)
                    state = (state * proto.fetch_step + clear + proto.fetch_bias
                             + (relative + 1) * proto.fetch_byte) % 65536
                else:
                    mask = high ^ low
                    state = (state * proto.fetch_step + clear
                             + (relative + 1) * proto.fetch_byte
                             + proto.fetch_bias) % 65536
                out[position] = clear ^ mask
                tag = (tag * proto.fetch_tag_mul + clear
                       + (relative + 1) * proto.fetch_byte
                       + proto.fetch_bias) % 4294967296
            proto.fetch_positions.append(start + 1)
            proto.fetch_lengths.append(size)
            proto.fetch_tags.append(tag)
        return out

    def _encode_proto_opcodes(self, proto: FunctionPrototype) -> List[int]:
        """Apply a prototype-specific bijection to instruction opcode bytes."""
        bytecode = list(proto.bytecode)
        for instruction in proto.instructions:
            bytecode[instruction.pc] = (
                bytecode[instruction.pc] * proto.opcode_mul + proto.opcode_add
            ) % 256
        return bytecode

    def _encode_proto_operands(self, proto: FunctionPrototype,
                               bytecode: List[int]) -> List[int]:
        """Apply a position- and opcode-dependent mask to every operand pair."""
        if not self.config.vm_operand_layouts:
            return bytecode
        out = list(bytecode)
        for instruction in proto.instructions:
            info = self.opcodes.get(instruction.op_name)
            opcode = proto.bytecode[instruction.pc]
            count = operand_count(instruction.fmt)
            for slot in range(count):
                position = instruction.pc + 1 + slot * 2
                first, second = out[position], out[position + 1]
                if info.byte_order == 'little':
                    value = first + second * 256
                else:
                    value = second + first * 256
                mask = self._operand_mask_value(proto, position + 1, opcode)
                value ^= mask
                low, high = value % 256, value // 256
                if info.byte_order == 'little':
                    out[position], out[position + 1] = low, high
                else:
                    out[position], out[position + 1] = high, low
        return out

    @staticmethod
    def _operand_mask_value(proto: FunctionPrototype, position: int,
                            opcode: int) -> int:
        """Mirror the generated Luau operand-mask families exactly."""
        base = (position * proto.operand_mul + proto.operand_add) % 65536
        keyed_opcode = (opcode * proto.operand_opcode_mul
                        + proto.operand_salt) % 65536
        if proto.operand_family == 1:
            return base ^ keyed_opcode
        if proto.operand_family == 2:
            return (((position + opcode + 1) * proto.operand_mul
                     + proto.operand_add
                     + ((position * opcode) % 65536) * proto.operand_opcode_mul
                     + proto.operand_salt) % 65536)
        return (base + keyed_opcode) % 65536

    def _hash_bytes(self, data: List[int]) -> int:
        h = self.hash_seed
        for byte in data:
            h = ((h * self.hash_multiplier) + byte) % 4294967296
        return h

    def _gen_protos(self, n: Dict[str, str], protos: List[FunctionPrototype]) -> str:
        """Emit the table of all proto data."""
        lines = [f"local {n['protos']}={{}}"]
        for i, p in enumerate(protos):
            wire_bc = self._encode_proto_opcodes(p)
            wire_bc = self._encode_proto_operands(p, wire_bc)
            plain_hash = self._hash_bytes(wire_bc)
            protected_bc = self._stateful_encode(p, wire_bc)
            enc_bc = self._encrypt_bytecode(
                protected_bc, p.bytecode_key if self.config.vm_per_proto_keys else None,
                p.bytecode_mul, p.bytecode_add)
            bc_str = ','.join(str(b) for b in enc_bc)
            wire_sp = [(idx + 1) ^ (((j + 1) * p.proto_link_mul + p.proto_link_add) % 65536)
                       for j, idx in enumerate(p._sp_indices)]
            sp_str = ','.join(map(str, wire_sp))
            salt = self._hash_bytes(enc_bc)
            runtime_hash = plain_hash if self.config.vm_predecode_bytecode else salt
            pool_field = ''
            if self.config.vm_partition_constants:
                pool = p.constant_pool
                _, kinds = pool.encoded_values(self.config.vm_encode_numbers)
                pending = ','.join(f'[{j+1}]={kind}' for j,kind in enumerate(kinds) if kind)
                pool_field = (f",k={pool.to_luau_table(self.config.vm_encode_numbers)},ck={self._gen_key_table(pool.key,n,salt)},"
                              f"kc={pool.size()},pending={{{pending}}}")
            key_field = f",bk={self._gen_key_table(p.bytecode_key,n,salt)}" if self.config.vm_per_proto_keys else ''
            digest = PayloadHash(self.hash_seed,self.hash_multiplier)
            digest.blob(enc_bc)
            for value in (p.num_params,int(p.is_vararg),len(p.upvalues),p.max_stacksize,
                          p.bytecode_mul,p.bytecode_add,p.opcode_mul,p.opcode_add,
                          p.opcode_inverse,p.interpreter_index,p.fetch_share,
                          p.fetch_seed ^ p.fetch_share,p.fetch_mul,p.fetch_add,
                          p.fetch_step,p.fetch_byte,p.fetch_bias,p.fetch_tag_seed,
                          p.fetch_tag_mul,p.fetch_family,p.proto_link_mul,
                          p.proto_link_add,p.operand_mul,p.operand_add,
                          p.operand_opcode_mul,p.operand_salt,p.operand_family,
                          len(wire_sp)):
                digest.uint(value)
            for index in wire_sp:
                digest.uint(index)
            digest.blob(p.fetch_positions)
            digest.blob(p.fetch_lengths)
            digest.blob(p.fetch_tags)
            if self.config.vm_integrity_check:
                digest.uint(plain_hash)
                if self.config.vm_runtime_integrity:
                    digest.uint(runtime_hash)
            if self.config.vm_per_proto_keys:
                digest.key(self._key_record(p.bytecode_key,salt))
            if self.config.vm_partition_constants:
                values,kinds = pool.encoded_values(self.config.vm_encode_numbers)
                digest.pool(values,kinds,self._key_record(pool.key,salt))
            hash_field = (f",ih={digest.value},ph={plain_hash}"
                          if self.config.vm_integrity_check else '')
            runtime_field = (f",rh={runtime_hash}"
                             if self.config.vm_runtime_integrity else '')
            positions = ','.join(map(str, p.fetch_positions))
            lengths = ','.join(map(str, p.fetch_lengths))
            tags = ','.join(map(str, p.fetch_tags))
            lookup = ','.join(f'[{pc}]={j + 1}' for j, pc in enumerate(p.fetch_positions))
            fetch_field = (f",f1={p.fetch_share},f2={p.fetch_seed ^ p.fetch_share},"
                           f"fm={p.fetch_mul},fa={p.fetch_add},fq={p.fetch_step},"
                           f"fw={p.fetch_byte},fb={p.fetch_bias},fts={p.fetch_tag_seed},"
                           f"ftm={p.fetch_tag_mul},ff={p.fetch_family},"
                           f"lm={p.proto_link_mul},la={p.proto_link_add},"
                           f"xm={p.operand_mul},xa={p.operand_add},"
                           f"xo={p.operand_opcode_mul},xs={p.operand_salt},"
                           f"xf={p.operand_family},"
                           f"fp={{{positions}}},fl={{{lengths}}},"
                           f"ft={{{tags}}},fx={{{lookup}}}")
            lines.append(
                f"{n['protos']}[{i + 1}]="
                f"{{bc={{{bc_str}}},"
                f"np={p.num_params},"
                f"va={'true' if p.is_vararg else 'false'},"
                f"nuv={len(p.upvalues)},"
                f"ms={p.max_stacksize},"
                f"bm={p.bytecode_mul},"
                f"ba={p.bytecode_add},"
                f"om={p.opcode_mul},"
                f"oa={p.opcode_add},"
                f"oi={p.opcode_inverse},"
                f"ix={p.interpreter_index},"
                f"sp={{{sp_str}}}{hash_field}{runtime_field}{pool_field}{key_field}{fetch_field}}}"
            )
        return '\n'.join(lines)

    def _gen_payload_helpers(self, n):
        """Loader-only helpers; no hash, key schedule or number parser in dispatch."""
        step,u,blob,key,value,pool,proto = (n[k] for k in
            ('hashstep','hashuint','hashblob','hashkey','hashvalue','hashpool','hashproto'))
        parts = [f'''local function {step}(_h,_b) return (_h*{self.hash_multiplier}+_b)%4294967296 end
local function {n['salt']}(_v)
local _h={self.hash_seed};for _i=1,#_v do _h={step}(_h,_v[_i]) end;return _h
end''']
        if self.config.vm_dynamic_keys:
            parts.append(f'''local function {n['unkey']}(_v,_salt)
local _state=(_v.s+_salt)%65536;local _previous=0;local _out={{}}
for _i=1,#_v.q do
_state=(_state*_v.a+_v.d+_previous*257+_i)%65536
local _mask={n['bxor']}(math.floor(_state/256),_state%256)
_previous={n['bxor']}(_v.q[_i],_mask);_out[_i]=_previous
end
return _out
end''')
        if self.config.vm_integrity_check:
            parts.append(f'''local function {u}(_h,_v)
if type(_v)~="number" or _v<0 or _v>=4294967296 or _v~=math.floor(_v) then error("VM: integrity check failed") end
for _i=1,4 do _h={step}(_h,_v%256);_v=math.floor(_v/256) end;return _h
end
local function {blob}(_h,_v)
_h={u}(_h,#_v)
if type(_v)=="string" then
for _i=1,#_v do _h={step}(_h,string.byte(_v,_i)) end
else for _i=1,#_v do _h={step}(_h,_v[_i]) end end
return _h
end
local function {key}(_h,_v)
if _v.q then
_h={step}(_h,1);_h={u}(_h,_v.s);_h={u}(_h,_v.a);_h={u}(_h,_v.d)
return {blob}(_h,_v.q)
end
return {blob}({step}(_h,0),_v)
end
local function {value}(_h,_v)
local _t=type(_v)
if _t=="nil" then return {step}(_h,0)
elseif _t=="boolean" then return {step}({step}(_h,1),_v and 1 or 0)
elseif _t=="number" then
_h={step}(_h,2)
if _v~=_v then return {step}(_h,3)
elseif _v==math.huge then return {step}(_h,1)
elseif _v==-math.huge then return {step}(_h,2) end
_h={step}(_h,0);_h={step}(_h,(_v<0 or (_v==0 and 1/_v<0)) and 1 or 0)
local _m,_e=math.frexp(math.abs(_v));_h={u}(_h,_e+2048);_m=_m*9007199254740992
for _i=1,7 do _h={step}(_h,_m%256);_m=math.floor(_m/256) end
return _h
end
return {blob}({step}(_h,3),_v)
end
local function {pool}(_h,_k,_pending,_count,_key)
_h={u}(_h,_count);_h={key}(_h,_key)
for _i=1,_count do _h={step}(_h,_pending[_i] or 0);_h={value}(_h,_k[_i]) end
return _h
end
local function {proto}(_p)
local _h={blob}({self.hash_seed},_p.bc)
_h={u}(_h,_p.np);_h={u}(_h,_p.va and 1 or 0);_h={u}(_h,_p.nuv);_h={u}(_h,_p.ms)
_h={u}(_h,_p.bm);_h={u}(_h,_p.ba)
_h={u}(_h,_p.om);_h={u}(_h,_p.oa);_h={u}(_h,_p.oi)
_h={u}(_h,_p.ix)
_h={u}(_h,_p.f1);_h={u}(_h,_p.f2);_h={u}(_h,_p.fm);_h={u}(_h,_p.fa)
_h={u}(_h,_p.fq);_h={u}(_h,_p.fw);_h={u}(_h,_p.fb);_h={u}(_h,_p.fts);_h={u}(_h,_p.ftm);_h={u}(_h,_p.ff)
_h={u}(_h,_p.lm);_h={u}(_h,_p.la);_h={u}(_h,_p.xm);_h={u}(_h,_p.xa)
_h={u}(_h,_p.xo);_h={u}(_h,_p.xs);_h={u}(_h,_p.xf)
_h={u}(_h,#_p.sp);for _i=1,#_p.sp do _h={u}(_h,_p.sp[_i]) end
_h={blob}(_h,_p.fp);_h={blob}(_h,_p.fl);_h={blob}(_h,_p.ft)
for _i=1,#_p.fp do if _p.fx[_p.fp[_i]]~=_i then return -1 end end
_h={u}(_h,_p.ph)
{f"_h={u}(_h,_p.rh)" if self.config.vm_runtime_integrity else ''}
{f"_h={key}(_h,_p.bk)" if self.config.vm_per_proto_keys else ''}
{f"_h={pool}(_h,_p.k,_p.pending,_p.kc,_p.ck)" if self.config.vm_partition_constants else ''}
return _h
end''')
        return '\n'.join(parts)

    def _gen_key_setup(self, n):
        lines = []
        if not self.config.vm_partition_constants or not self.config.vm_per_proto_keys:
            lines.append(f"local _salt={n['salt']}({n['protos']}[1].bc)")
            if not self.config.vm_partition_constants:
                lines.append(f"{n['ck']}={n['unkey']}({n['ck']},_salt);{n['ckn']}=#{n['ck']}")
            if not self.config.vm_per_proto_keys:
                lines.append(f"{n['bk']}={n['unkey']}({n['bk']},_salt);{n['bkn']}=#{n['bk']}")
        if self.config.vm_partition_constants or self.config.vm_per_proto_keys:
            lines.append(f"for _,_p in ipairs({n['protos']}) do local _salt={n['salt']}(_p.bc)")
            lines.append('_p.ks=_salt')
            for field,enabled in [('bk',self.config.vm_per_proto_keys),('ck',self.config.vm_partition_constants)]:
                deferred = (field=='bk' and self.config.vm_predecode_bytecode) or (field=='ck' and self.config.vm_lazy_constants)
                if enabled and not deferred:
                    lines.append(f"_p.{field}={n['unkey']}(_p.{field},_salt)")
            lines.append('end')
        return '\n'.join(lines)

    def _gen_integrity_check(self, n: Dict[str, str]) -> str:
        shared = PayloadHash(self.hash_seed,self.hash_multiplier)
        if not self.config.vm_per_proto_keys:
            shared.key(self._key_record(self.bc_key,self._root_salt))
        if not self.config.vm_partition_constants:
            values,kinds = self.pool.encoded_values(self.config.vm_encode_numbers)
            shared.pool(values,kinds,self._key_record(self.pool.key,self._root_salt))
        shared_runtime = f"local _h={self.hash_seed};"
        if not self.config.vm_per_proto_keys:
            shared_runtime += f"_h={n['hashkey']}(_h,{n['bk']});"
        if not self.config.vm_partition_constants:
            shared_runtime += f"_h={n['hashpool']}(_h,{n['consts']},{n['pending']},{self.pool.size()},{n['ck']});"
        shared_runtime += f'if _h~={shared.value} then error("VM: integrity check failed") end\n'
        return shared_runtime + f"""for {n['i']}=1,#{n['protos']} do
local {n['proto']}={n['protos']}[{n['i']}]
local {n['tmp']}={n['hashproto']}({n['proto']})
if {n['tmp']}~={n['proto']}.ih then error("VM: integrity check failed") end
{n['proto']}.ih=nil
end"""

    def _gen_bytecode_decode(self, n: Dict[str, str]) -> str:
        verify_proto = (f'''if {n['salt']}(_p.bc)~=_p.ph then error("VM: integrity check failed") end
_p.ph=nil''' if self.config.vm_integrity_check else '')
        verify_shared = (f'''if {n['salt']}({n['bc']})~={n['protos']}[{n['i']}].ph then error("VM: integrity check failed") end
{n['protos']}[{n['i']}].ph=nil''' if self.config.vm_integrity_check else '')
        if self.config.vm_per_proto_keys:
            return f'''local function {n['decode']}(_p)
local _key=_p.bk
{f"_key={n['unkey']}(_key,_p.ks)" if self.config.vm_dynamic_keys else ''}
for _j=1,#_p.bc do _p.bc[_j]={n['bxor']}(_p.bc[_j],_key[(_j-1)%#_key+1]) end
for _j=1,#_p.bc do _p.bc[_j]={n['bxor']}(_p.bc[_j],(_j*_p.bm+_p.ba)%256) end
{verify_proto}
_p.bk=nil;_p.bm=nil;_p.ba=nil;_p.decoded=true
_p.ks=nil
end'''
        key = f"{n['protos']}[{n['i']}].bk" if self.config.vm_per_proto_keys else n['bk']
        size = f"#{key}" if self.config.vm_per_proto_keys else n['bkn']
        return f"""for {n['i']}=1,#{n['protos']} do
local {n['bc']}={n['protos']}[{n['i']}].bc
for {n['j']}=1,#{n['bc']} do
{n['bc']}[{n['j']}]={n['bxor']}({n['bc']}[{n['j']}],{key}[({n['j']}-1)%{size}+1])
{n['bc']}[{n['j']}]={n['bxor']}({n['bc']}[{n['j']}],({n['j']}*{n['protos']}[{n['i']}].bm+{n['protos']}[{n['i']}].ba)%256)
end
{verify_shared}
{n['protos']}[{n['i']}].bm=nil;{n['protos']}[{n['i']}].ba=nil
end
{n['bk']}=nil;{n['bkn']}=nil"""

    def _gen_call_helper(self, n: Dict[str, str]) -> str:
        # Common call arities avoid allocating an argument table entirely.
        return f"""local function {n['invoke']}(_f,_r,_a,_count)
if _count==0 then return _f() end
if _count==1 then return _f(_r[_a+1]) end
if _count==2 then return _f(_r[_a+1],_r[_a+2]) end
if _count==3 then return _f(_r[_a+1],_r[_a+2],_r[_a+3]) end
local _args={{}}
for _i=1,_count do _args[_i]=_r[_a+_i] end
return _f({n['unpack']}(_args,1,_count))
end"""

    # =================================================================
    # Exec function (the heart of the VM)
    # =================================================================

    def _gen_exec_function(self, n: Dict[str, str], target: str) -> str:
        """Generate the main `exec` interpreter function."""
        # Build all opcode handler bodies
        handlers = self._build_handlers(n)
        # Put frequently emitted operations first; randomize ties per build.
        self.rng.shuffle(handlers)
        handlers.sort(key=lambda h: -h['frequency'])

        # Build the if/elseif chain
        chain_lines: List[str] = []
        for i, h in enumerate(handlers):
            kw = 'if' if i == 0 else 'elseif'
            body = h['body']
            if body.startswith(';'):
                body = body[1:]
            condition = ' or '.join(self._opcode_condition(n, byte) for byte in h['bytes'])
            chain_lines.append(f"{kw} {condition} then {body}")
        chain_lines.append("else error(\"VM: bad opcode \"..tostring(" + n['op'] + "))")
        chain_lines.append("end")
        chain = '\n'.join(chain_lines)
        if self.config.vm_superinstructions and len(handlers)>4:
            # Keep the hottest bodies near the root, then partition remaining
            # aliases through a numeric decision tree. No dispatch function
            # calls or per-instruction bucket tables are needed. Build-specific
            # blocks and aliases produce different leaf bodies and thresholds.
            count = self.rng.randint(2,4)
            hot,rest = handlers[:count],handlers[count:]
            nodes = []
            for index,handler in enumerate(hot):
                condition = ' or '.join(self._opcode_condition(n, byte) for byte in handler['bytes'])
                nodes.append(f"{'if' if index==0 else 'elseif'} {condition} then {handler['body'].lstrip(';')}")
            nodes.append('else '+self._dispatch_tree(rest,n))
            nodes.append('end')
            chain='\n'.join(nodes)
        function_data = ''
        if self.config.vm_partition_constants:
            if self.config.vm_lazy_constants:
                decode = f";{n['decode']}({n['proto']})" if self.config.vm_per_proto_keys and self.config.vm_predecode_bytecode else ''
                function_data = f"if not {n['proto']}.ready then {n['cget']}({n['proto']}){decode} end;"
            function_data += f"local {n['consts']}={n['proto']}.k"
        if self.config.vm_per_proto_keys and self.config.vm_predecode_bytecode and not (self.config.vm_partition_constants and self.config.vm_lazy_constants):
            function_data = f"if not {n['proto']}.decoded then {n['decode']}({n['proto']}) end;" + function_data
        if self.config.vm_per_proto_keys and not self.config.vm_predecode_bytecode:
            function_data += (';' if function_data else '') + f"local {n['bk']}={n['proto']}.bk;local {n['bkn']}=#{n['bk']}"
        fetch_setup = ''
        if self.config.vm_stateful_fetch and not self.config.vm_predecode_bytecode:
            fetch_setup = f'''local _fs,_fn,_fi,_fh,_fx,_fc=0,0,0,0,0,{{}}
local function {n['resetfetch']}(_p)
_fx={n['proto']}.fx[_p];if not _fx then error("VM: invalid control edge") end
_fs=({n['bxor']}({n['proto']}.f1,{n['proto']}.f2)+_p*{n['proto']}.fm+{n['proto']}.fa)%65536
_fh=({n['proto']}.fts+_p*{n['proto']}.ftm)%4294967296;_fn=_p;_fi=0;_fc={{}}
end
local function {n['readbyte']}(_p)
local _v=_fc[_p];if _v~=nil then _fc[_p]=nil;return _v end
while _fn<=_p do
local _x={n['bxor']}({n['bc']}[_fn],{n['bk']}[(_fn-1)%{n['bkn']}+1])
_x={n['bxor']}(_x,(_fn*{n['proto']}.bm+{n['proto']}.ba)%256)
local _hi,_lo=math.floor(_fs/256),_fs%256
local _mask
if {n['proto']}.ff==1 then _mask={n['bxor']}((_hi+{n['proto']}.fw)%256,_lo)
elseif {n['proto']}.ff==2 then _mask={n['bxor']}(_hi,(_lo+{n['proto']}.fb)%256)
else _mask={n['bxor']}(_hi,_lo) end
_x={n['bxor']}(_x,_mask)
_fi=_fi+1;_fc[_fn]=_x
if {n['proto']}.ff==1 then
_fs=(_fs*{n['proto']}.fq+_x*{n['proto']}.fw+_fi+{n['proto']}.fb)%65536
else _fs=(_fs*{n['proto']}.fq+_x+_fi*{n['proto']}.fw+{n['proto']}.fb)%65536 end
_fh=(_fh*{n['proto']}.ftm+_x+_fi*{n['proto']}.fw+{n['proto']}.fb)%4294967296
_fn=_fn+1
if _fi=={n['proto']}.fl[_fx] and _fh~={n['proto']}.ft[_fx] then error("VM: instruction authentication failed") end
end
_v=_fc[_p];_fc[_p]=nil;return _v
end'''
        runtime_guard = ''
        if self.config.vm_runtime_integrity:
            runtime_guard = f'''{n['proto']}.rc=({n['proto']}.rc or 1)-1
if {n['proto']}.rc<=0 then
if {n['salt']}({n['proto']}.bc)~={n['proto']}.rh then error("VM: integrity check failed") end
{n['proto']}.rc={self.runtime_check_interval}
end'''

        # The exec function
        # Reads operand bytes; pc is byte-offset (1-based for Lua array indexing).
        # Each handler uses its generated operand layout and byte order.
        # Signed sBx is biased by 0x8000 (32768) at encode time.
        return f"""{target}=function({n['proto']},{n['upvals']},...)
{function_data}
{runtime_guard}
local {n['varargs']}
if {n['proto']}.va then {n['varargs']}={n['pack']}(...) end
local {n['nargs']}=select("#",...)
local {n['R']}=table.create and table.create({n['proto']}.ms) or {{}}
for {n['i']}=1,{n['proto']}.np do {n['R']}[{n['i']}-1]=select({n['i']},...) end
local {n['bc']}={n['proto']}.bc
{fetch_setup}
local {n['sp']}={n['proto']}.sp
local {n['pc']}=1
local {n['top']}={n['proto']}.np
local {n['box']}
while true do
if {n['pc']}>#{n['bc']} then return end
{f"{n['resetfetch']}({n['pc']})" if self.config.vm_stateful_fetch and not self.config.vm_predecode_bytecode else ''}
local {n['op']}={self._byte_expr(n,n['pc'])}; {n['pc']}={n['pc']}+1
{n['op']}=((({n['op']}-{n['proto']}.oa)%256)*{n['proto']}.oi)%256
{chain}
end
end"""

    def _opcode_condition(self, n: Dict[str, str], byte: int) -> str:
        """Emit equivalent, build-specific opcode predicates."""
        shape = self.rng.randrange(4) if self.config.vm_handler_variants else 0
        if shape == 1:
            return f"({n['op']}-{byte})==0"
        if shape == 2:
            return f"({byte}-{n['op']})==0"
        if shape == 3:
            return f"not ({n['op']}~={byte})"
        return f"{n['op']}=={byte}"

    # =================================================================
    # Handler construction
    # =================================================================

    def _build_handlers(self, n: Dict[str, str]) -> List[dict]:
        """Build one handler per used semantic opcode, sharing alias bodies."""
        handlers: List[dict] = []

        for name, info in self.opcodes.opcodes.items():
            aliases = [byte for byte in info.aliases if byte in self._used_aliases]
            if not aliases:
                continue
            # Short-circuit the most frequent alias first without adding any
            # runtime work or changing the semantic handler's weight.
            aliases.sort(key=lambda byte: -self._used_aliases[byte])
            body = self._gen_block_body(info,n) if info.components else self._gen_handler_body(info.name, info.fmt, n)
            handlers.append({'bytes': aliases, 'body': body, 'name': name,
                             'frequency': sum(self._used_aliases[byte] for byte in aliases)})

        return handlers

    def _dispatch_tree(self, handlers, n):
        entries=sorted((byte,handler) for handler in handlers for byte in handler['bytes'])
        def emit(values):
            if len(values)<=3:
                lines=[]
                for index,(byte,handler) in enumerate(values):
                    lines.append(f"{'if' if index==0 else 'elseif'} {self._opcode_condition(n,byte)} then {handler['body'].lstrip(';')}")
                lines.append(f'else error("VM: bad opcode "..tostring({n["op"]})) end')
                return '\n'.join(lines)
            split=len(values)//2
            pivot=values[split-1][0]
            return f"if {n['op']}<={pivot} then {emit(values[:split])} else {emit(values[split:])} end"
        return emit(entries)

    # ---- Operand-reading code generator ----

    def _gen_block_body(self, info, n):
        # Read the block's shuffled operand inventory once. The body has no
        # nested VM dispatch or component opcode bytes. Each operation keeps
        # its own lexical scope so a yield or error preserves normal ordering.
        operands = [self.name_gen.gen_name() for _ in range(operand_count(info.fmt))]
        reads = []
        for slot,index in enumerate(info.layout):
            position = n['pc'] if slot==0 else f"{n['pc']}+{slot*2}"
            low,high = (position,position+'+1') if info.byte_order=='little' else (position+'+1',position)
            expression = f"{self._byte_expr(n,low)}+256*{self._byte_expr(n,high)}"
            if self.config.vm_operand_layouts:
                expression = f"{n['bxor']}({expression},{self._operand_mask_expr(n, position, n['op'])})"
            reads.append(f'local {operands[index]}={expression}')
        reads.append(f"{n['pc']}={n['pc']}+{len(operands)*2}")
        bodies = []
        offset = 0
        for name in info.components:
            fmt = self.opcodes.fmt_of(name)
            count = operand_count(fmt)
            names = dict(n)
            for field,value in zip(('a','b','c','d'),operands[offset:offset+count]):
                names[field] = value
            body = self._gen_handler_body(name,fmt,names,read=False)
            bodies.append('do '+body.lstrip(';')+' end')
            offset += count
        return ';'.join(reads+bodies)

    def _byte_expr(self, n: Dict[str,str], pos: str) -> str:
        if self.config.vm_predecode_bytecode:
            return f"{n['bc']}[{pos}]"
        if self.config.vm_stateful_fetch:
            return f"{n['readbyte']}({pos})"
        keyed = f"{n['bxor']}({n['bc']}[{pos}],{n['bk']}[({pos}-1)%{n['bkn']}+1])"
        return f"{n['bxor']}({keyed},(({pos})*{n['proto']}.bm+{n['proto']}.ba)%256)"

    def _operand_mask_expr(self, n: Dict[str, str], position: str,
                           opcode: str) -> str:
        """Emit the selected per-prototype operand mask without a shared helper."""
        proto, bxor = n['proto'], n['bxor']
        base = f"(({position})*{proto}.xm+{proto}.xa)%65536"
        keyed = f"(({opcode})*{proto}.xo+{proto}.xs)%65536"
        family1 = f"{bxor}({base},{keyed})"
        family2 = (f"((({position})+({opcode})+1)*{proto}.xm+{proto}.xa+"
                   f"((({position})*({opcode}))%65536)*{proto}.xo+{proto}.xs)%65536")
        family0 = f"({base}+{keyed})%65536"
        return (f"({proto}.xf==1 and {family1} or "
                f"({proto}.xf==2 and {family2} or {family0}))")

    def _read_u16_inline(self, n: Dict[str, str], dest: str,
                         byte_order='little', opcode=None) -> str:
        """Generate inline code to read a u16 from BC at PC, advancing PC."""
        bx, bc, bk, bkn, pc = n['bxor'], n['bc'], n['bk'], n['bkn'], n['pc']
        lo,hi = (pc,pc+'+1') if byte_order=='little' else (pc+'+1',pc)
        low,high = self._byte_expr(n,lo),self._byte_expr(n,hi)
        expression = f'{low}+{high}*256'
        if self.config.vm_handler_variants and self.rng.randrange(2):
            expression = f'256*{high}+{low}'
        if self.config.vm_operand_layouts:
            expression = f"{bx}({expression},{self._operand_mask_expr(n, pc, opcode or n['op'])})"
        return (
            f"local {dest}={expression};"
            f"{pc}={pc}+2"
        )

    def _read_s16_inline(self, n: Dict[str, str], dest: str,
                         byte_order='little', opcode=None) -> str:
        """Generate inline code to read an s16 (biased by 0x8000)."""
        bx, bc, bk, bkn, pc = n['bxor'], n['bc'], n['bk'], n['bkn'], n['pc']
        lo,hi = (pc,pc+'+1') if byte_order=='little' else (pc+'+1',pc)
        low,high = self._byte_expr(n,lo),self._byte_expr(n,hi)
        expression = f'{low}+{high}*256'
        if self.config.vm_handler_variants and self.rng.randrange(2):
            expression = f'{high}*256+{low}'
        if self.config.vm_operand_layouts:
            expression = f"{bx}({expression},{self._operand_mask_expr(n, pc, opcode or n['op'])})"
        expression = f'{expression}-32768'
        return (
            f"local {dest}={expression};"
            f"{pc}={pc}+2"
        )

    def _skip_next_inline(self, n: Dict[str, str]) -> str:
        bx, bc, bk, bkn, pc, opsize = n['bxor'], n['bc'], n['bk'], n['bkn'], n['pc'], n['opsize']
        return (
            f"if {pc}>#{bc} then return end;"
            + (f"{n['resetfetch']}({pc});" if self.config.vm_stateful_fetch and not self.config.vm_predecode_bytecode else '') +
            f"local _no={self._byte_expr(n,pc)};"
            f"_no=(((_no-{n['proto']}.oa)%256)*{n['proto']}.oi)%256;"
            f"local _nk={self._lookup_slot_expr('_no')};"
            f"{pc}={pc}+1+{n['bxor']}({opsize}[_nk],{self._lookup_mask_expr('_nk')})"
        )

    def _read_operands(self, fmt: str, n: Dict[str, str], info) -> str:
        """Generate operand-reading code based on the instruction format.
        Sets locals named `a`, `b`, `c` based on what the format provides.
        """
        names = [n['a'],n['b'],n['c'],n['d']]
        reads = []
        for index in info.layout:
            signed = (fmt==FORMAT_SBX and index==0) or (fmt==FORMAT_ASBX and index==1)
            reader = self._read_s16_inline if signed else self._read_u16_inline
            reads.append(reader(n,names[index],info.byte_order))
        return ';'.join(reads)

    # ---- Per-opcode handler bodies ----

    def _gen_handler_body(self, op_name: str, fmt: str, n: Dict[str, str], *, read=True) -> str:
        ops = self._read_operands(fmt, n, self.opcodes.get(op_name)) if read else ''
        a, b, c = n['a'], n['b'], n['c']
        R = n['R']
        CONSTS = n['consts']
        CGET = n['cget']
        per_lookup_decode = self.config.vm_lazy_constants and not self.config.vm_partition_constants
        K = lambda idx: f"{CGET}({idx})" if per_lookup_decode else f"{CONSTS}[{idx}]"
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
        # All forms evaluate the same expression exactly once and retain the
        # operand order, metamethod dispatch and yielding behavior. No MBA
        # identities on user numbers (floats, NaNs and infinities are valid).
        shape = self.rng.randrange(3) if self.config.vm_handler_variants else 0
        def store(expression, target=None):
            target = target or f'{R}[{a}]'
            if shape == 1:
                return f';local _value={expression};{target}=_value'
            if shape == 2:
                return f';do local _result={expression};{target}=_result end'
            return f';{target}={expression}'

        if op_name.startswith('F') and op_name[1:-1] in ('ADD','SUB','MUL','DIV','MOD','POW'):
            symbol = {'ADD':'+','SUB':'-','MUL':'*','DIV':'/','MOD':'%','POW':'^'}[op_name[1:-1]]
            left,right = (b,c) if op_name.endswith('R') else (c,b)
            return (ops + f";{R}[{c}]={K(f'{n['d']}+1')}"
                    + store(f"{R}[{left}]{symbol}{R}[{right}]"))

        if op_name == 'MOVE':
            return ops + store(f"{R}[{b}]")
        if op_name == 'LOADK':
            return ops + store(K(f'{b}+1'))
        if op_name == 'LOADBOOL':
            # If C != 0, skip the next instruction (size depends on its fmt)
            return (ops + f";{R}[{a}]=({b}~=0);"
                    f"if {c}~=0 then "
                    # Skip next instruction: read its opcode, look up size, advance.
                    f"{self._skip_next_inline(n)} "
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
            return ops + store(f"{ENV}[{K(f'{b}+1')}]")
        if op_name == 'SETGLOBAL':
            return ops + f";{ENV}[{K(f'{b}+1')}]={R}[{a}]"

        if op_name == 'NEWTABLE':
            return ops + f";{R}[{a}]={{}}"
        if op_name == 'GETTABLE':
            return ops + store(f"{R}[{b}][{R}[{c}]]")
        if op_name == 'SETTABLE':
            return ops + f";{R}[{a}][{R}[{b}]]={R}[{c}]"
        if op_name == 'GETTABLEK':
            return ops + store(f"{R}[{b}][{K(f'{c}+1')}]")
        if op_name == 'SETTABLEK':
            return ops + f";{R}[{a}][{K(f'{b}+1')}]={R}[{c}]"
        if op_name == 'SELF':
            return ops + (f";{R}[{a}+1]={R}[{b}];"
                          f"{R}[{a}]={R}[{b}][{K(f'{c}+1')}]")
        if op_name == 'SETLIST':
            # B = count (0 = MULTRET via top), C = absolute array offset.
            return ops + (
                f";local _t={R}[{a}];"
                f"local _off={c};"
                f"local _cnt=({b}==0) and ({TOP}-{a}-1) or {b};"
                f"for _i=1,_cnt do _t[_off+_i]={R}[{a}+_i] end"
            )

        arithmetic = {'ADD':'+','SUB':'-','MUL':'*','DIV':'/','MOD':'%','POW':'^'}
        if op_name in arithmetic:
            return ops + store(f"{R}[{b}]{arithmetic[op_name]}{R}[{c}]")
        if op_name == 'UNM':
            return ops + store(f"-{R}[{b}]")
        if op_name == 'NOT':
            return ops + store(f"not {R}[{b}]")
        if op_name == 'LEN':
            return ops + store(f"#({R}[{b}])")
        if op_name == 'CONCAT':
            return ops + (
                f";local _s={R}[{b}];"
                f"for _i={b}+1,{c} do _s=_s..{R}[_i] end;"
                f"{R}[{a}]=_s"
            )

        if op_name in ('EQ','LT','LE'):
            # Compiler emits cmp + JMP true-skip pattern. Semantics:
            #   if (R[B]==R[C]) ~= A then pc++ (skip the JMP)
            symbol={'EQ':'==','LT':'<','LE':'<='}[op_name]
            condition = f'({R}[{b}]{symbol}{R}[{c}])~=({a}~=0)'
            if shape:
                condition = f'({R}[{b}]{symbol}{R}[{c}])==({a}==0)'
            return ops + (
                f";if {condition} then "
                f"{self._skip_next_inline(n)} "
                f"end"
            )
        if op_name == 'TEST':
            # if not (R[A] <=> B) then pc++ (skip next, usually a JMP)
            # B==1 -> want truthy; B==0 -> want falsy
            return ops + (
                f";local _v={R}[{a}];"
                f"local _t=(_v~=nil and _v~=false);"
                f"if _t~=({b}~=0) then "
                f"{self._skip_next_inline(n)} "
                f"end"
            )
        if op_name == 'TESTSET':
            return ops + (
                f";local _v={R}[{b}];"
                f"local _t=(_v~=nil and _v~=false);"
                f"if _t==({c}~=0) then {R}[{a}]=_v else "
                f"{self._skip_next_inline(n)} "
                f"end"
            )

        if op_name == 'JMP':
            # sBx in `a`
            return ops + store(f"{PC}+{a}", PC)

        if op_name == 'CALL':
            # CALL A B C: A=func reg, B=nargs+1 (0=MULTRET), C=nresults+1 (0=MULTRET)
            return ops + (
                f";local _f={R}[{a}];"
                f"local _nargs;"
                f"if {b}==0 then _nargs={TOP}-{a}-1 else _nargs={b}-1 end;"
                f"if {c}==1 then {n['invoke']}(_f,{R},{a},_nargs) "
                f"elseif {c}==2 then {R}[{a}]={n['invoke']}(_f,{R},{a},_nargs) "
                f"elseif {c}==3 then local _v1,_v2={n['invoke']}(_f,{R},{a},_nargs);"
                f"{R}[{a}]=_v1;{R}[{a}+1]=_v2 "
                f"elseif {c}==4 then local _v1,_v2,_v3={n['invoke']}(_f,{R},{a},_nargs);"
                f"{R}[{a}]=_v1;{R}[{a}+1]=_v2;{R}[{a}+2]=_v3 "
                f"else local _rt={n['pack']}({n['invoke']}(_f,{R},{a},_nargs));"
                f"local _rn=_rt.n;"
                f"if {c}==0 then "
                f"for _i=1,_rn do {R}[{a}+_i-1]=_rt[_i] end;"
                f"{TOP}={a}+_rn "
                f"else "
                f"local _want={c}-1;"
                f"for _i=1,_want do {R}[{a}+_i-1]=_rt[_i] end "
                f"end end"
            )
        if op_name == 'TAILCALL':
            # Same as CALL with MULTRET; not optimized in our VM
            return ops + (
                f";local _f={R}[{a}];"
                f"local _nargs;"
                f"if {b}==0 then _nargs={TOP}-{a}-1 else _nargs={b}-1 end;"
                f"return {n['invoke']}(_f,{R},{a},_nargs)"
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
                f"elseif {b}==2 then return {R}[{a}] "
                f"elseif {b}==3 then return {R}[{a}],{R}[{a}+1] "
                f"elseif {b}==4 then return {R}[{a}],{R}[{a}+1],{R}[{a}+2] "
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
        if op_name == 'TFORPREP':
            # Match Luau's generalized iteration setup without adding work to
            # every iteration. __iter takes priority over callable tables.
            return ops + (
                f";local _f={R}[{a}];"
                f"if type(_f)~='function' then "
                f"local _mt=getmetatable(_f);"
                f"if _mt~=nil and type(_mt)~='table' then "
                f"error('VM: protected iterator metatable is unsupported') end;"
                f"local _iter=_mt and rawget(_mt,'__iter');"
                f"if _iter~=nil then "
                # Luau invokes __iter across a non-yieldable C boundary. A
                # direct Lua call would incorrectly allow __iter to yield.
                f"table.foreach({{_f}},function(_, _object) "
                f"{R}[{a}],{R}[{a}+1],{R}[{a}+2]=_iter(_object) end) "
                f"elseif type(_f)=='table' and not (_mt and rawget(_mt,'__call')~=nil) then "
                f"{R}[{a}]=next;{R}[{a}+1]=_f;{R}[{a}+2]=nil "
                f"end end"
            )
        if op_name == 'TFORLOOP':
            # B = sBx back-jump offset to body start, C = number of vars
            # Most game loops consume one to three results. Capture these
            # directly, discarding unused results as native iteration does,
            # instead of allocating a packed table on every step. Invoke the
            # iterator once in either path; only nil terminates iteration.
            return ops + (
                f";if {b}>=32768 then {b}={b}-65536 end"
                f";local _f={R}[{a}];local _s={R}[{a}+1];local _v={R}[{a}+2];"
                f"if {c}<=3 then "
                f"local _v1,_v2,_v3=_f(_s,_v);"
                f"if _v1~=nil then "
                f"{R}[{a}+2]=_v1;{R}[{a}+3]=_v1;"
                f"if {c}>=2 then {R}[{a}+4]=_v2 end;"
                f"if {c}==3 then {R}[{a}+5]=_v3 end;"
                f"{PC}={PC}+{b} end "
                f"else local _rt={n['pack']}(_f(_s,_v));"
                f"if _rt[1]~=nil then "
                f"{R}[{a}+2]=_rt[1];"
                f"for _i=1,{c} do {R}[{a}+2+_i]=_rt[_i] end;"
                f"{PC}={PC}+{b} "
                f"end end"
            )

        if op_name == 'CLOSURE':
            # Read N pseudo-instructions for upvalue links
            link_reset = (f"{n['resetfetch']}({PC});"
                          if self.config.vm_stateful_fetch and not self.config.vm_predecode_bytecode else '')
            return ops + (
                f";local _np={BXOR}({SP}[{b}+1],(({b}+1)*{n['proto']}.lm+{n['proto']}.la)%65536);"
                f"local _newp={PROTOS}[_np];"
                f"if not _newp then error('VM: invalid prototype relation') end;"
                f"local _nuv=_newp.nuv;"
                f"local _newuv={{}};"
                f"for _i=1,_nuv do {link_reset}"
                f"local _po={self._byte_expr(n,PC)}; {PC}={PC}+1;"
                f"_po=(((_po-{n['proto']}.oa)%256)*{n['proto']}.oi)%256;"
                f"{self._read_u16_inline(n, '_pa', opcode='_po')};"
                f"{self._read_u16_inline(n, '_pb', opcode='_po')};"
                # Either MOVE or GETUPVAL (any alias).
                # If it's any MOVE alias, capture local register (a box).
                # If it's any GETUPVAL alias, share parent's upvalue.
                f"local _pk={self._lookup_slot_expr('_po')};"
                f"local _pm={self._lookup_mask_expr('_pk')};"
                f"if {BXOR}({ISMOVE}[_pk] or _pm,_pm)==1 then _newuv[_i]={R}[_pb] "
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
            f"[{self._lookup_slot(byte)}]={instruction_size(info.fmt) - 1 ^ self._lookup_mask(self._lookup_slot(byte))}"
            for byte, info in self.opcodes.all_aliases() if byte in self._used_aliases
        ]
        # ismove: opcode-byte -> true iff it's any MOVE alias
        move_aliases = self.opcodes.opcodes['MOVE'].aliases
        ismove_entries = ','.join(
            f"[{self._lookup_slot(v)}]={1 ^ self._lookup_mask(self._lookup_slot(v))}"
            for v in move_aliases
        )
        return (
            f"local {n['opsize']}={{{','.join(size_entries)}}}\n"
            f"local {n['ismove']}={{{ismove_entries}}}"
        )

    def _gen_entry(self, n: Dict[str, str]) -> str:
        return f"return {n['exec']}({n['protos']}[1],{{}},...)"
