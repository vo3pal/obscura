"""
Obscura VM Interpreter Generator
=====================================
Generates the polymorphic Luau interpreter stub that gets embedded in the output.
This is the runtime VM that executes custom bytecode in Roblox.
IMPORTANT: All output must be valid Roblox Luau syntax.
"""

import random
from .opcodes import OpcodeMap
from .constant_pool import ConstantPool
from .compiler import VMCompiler, FunctionPrototype
from utils.names import NameGenerator
from config import ObfuscationConfig
from typing import Dict, List


class InterpreterGenerator:
    """Generates a polymorphic Luau VM interpreter stub."""

    def __init__(self, config: ObfuscationConfig, opcodes: OpcodeMap,
                 pool: ConstantPool, name_gen: NameGenerator):
        self.config = config
        self.rng = config.get_rng()
        self.opcodes = opcodes
        self.pool = pool
        self.name_gen = name_gen

    def generate(self, main_proto: FunctionPrototype) -> str:
        """Generate the complete VM stub: decoder + interpreter + bytecode + entry point."""
        v = self._gen_var_names()
        parts = []

        # 1. Generate per-string XOR keys and encrypted const table
        str_xor_key = self.rng.randint(1, 255)
        consts_var = self.name_gen.gen_name()
        const_entries = self._generate_const_table(str_xor_key)
        key_var = self.name_gen.gen_name()
        parts.append(f"local {key_var}={str_xor_key}")
        parts.append(f"local {consts_var}={const_entries}")
        # Decrypt string entries at runtime
        dec_i = self.name_gen.gen_name()
        dec_s = self.name_gen.gen_name()
        dec_r = self.name_gen.gen_name()
        dec_b = self.name_gen.gen_name()
        parts.append(
            f"for {dec_i},_v in ipairs({consts_var}) do "
            f"if type(_v)==\"string\" then "
            f"local {dec_r}={{}} "
            f"for {dec_s}=1,#_v do "
            f"local {dec_b}=string.byte(_v,{dec_s}) "
            f"{dec_r}[{dec_s}]=string.char(bit32.bxor({dec_b},{key_var})) "
            f"end "
            f"{consts_var}[{dec_i}]=table.concat({dec_r}) "
            f"end end"
        )

        # 3. Bytecode as table
        bc_var = self.name_gen.gen_name()
        bc_entries = ','.join(str(b) for b in main_proto.bytecode)
        parts.append(f"local {bc_var}={{{bc_entries}}}")

        # 4. Sub-prototypes bytecode
        proto_vars = []
        for i, proto in enumerate(main_proto.sub_protos):
            pv = self.name_gen.gen_name()
            proto_vars.append(pv)
            pe = ','.join(str(b) for b in proto.bytecode)
            parts.append(f"local {pv}={{{pe}}}")

        proto_tbl = self.name_gen.gen_name()
        if proto_vars:
            parts.append(f"local {proto_tbl}={{{','.join(proto_vars)}}}")
        else:
            parts.append(f"local {proto_tbl}={{}}")

        # 5. The VM interpreter function
        vm_code = self._generate_vm_function(v, consts_var, proto_tbl)
        parts.append(vm_code)

        # 6. Entry point
        parts.append(f"return {v['vm_func']}({bc_var},{consts_var},{v['empty_env']},{proto_tbl})")

        return '\n'.join(parts)

    def _generate_const_table(self, xor_key: int) -> str:
        """Generate the constant pool as a Luau table literal with strings XOR-encrypted."""
        entries = []
        for const in self.pool.constants:
            if const is None:
                entries.append("nil")
            elif isinstance(const, bool):
                entries.append("true" if const else "false")
            elif isinstance(const, (int, float)):
                entries.append(str(const))
            elif isinstance(const, str):
                encrypted = ''.join(f'\\{b ^ xor_key}' for b in const.encode('utf-8'))
                entries.append(f'"{encrypted}"')
            else:
                entries.append("nil")
        return '{' + ','.join(entries) + '}'

    def _gen_var_names(self) -> Dict[str, str]:
        """Generate all variable names used in the interpreter."""
        keys = [
            'vm_func', 'bytecode', 'constants', 'env',
            'stack', 'locals_tbl', 'ip', 'sp', 'op',
            'push_fn', 'pop_fn', 'a', 'b', 'result',
            'func', 'args', 'argc', 'retc', 'ret_vals',
            'i', 'key', 'val', 'tbl', 'offset',
            'empty_env', 'proto_tbl', 'passed_args'
        ]
        return {k: self.name_gen.gen_name() for k in keys}

    def _generate_vm_function(self, v: Dict[str, str], consts_var: str, proto_tbl: str) -> str:
        """Generate the VM interpreter function in Luau."""
        ops = self.opcodes

        # Build handler cases
        handlers = self._build_handlers(v, ops)

        # Shuffle handler order for polymorphism
        self.rng.shuffle(handlers)

        # Build proper if/elseif/end chain
        handler_chain = self._build_if_chain(handlers, v['op'])

        vm_code = f"""local {v['empty_env']}={{}}
local function {v['vm_func']}({v['bytecode']},{v['constants']},{v['env']},{v['proto_tbl']},{v['passed_args']})
local {v['stack']}={{}}
local {v['locals_tbl']}={v['passed_args']} or {{}}
local {v['ip']}=1
local {v['sp']}=0
local function {v['push_fn']}({v['val']})
{v['sp']}={v['sp']}+1
{v['stack']}[{v['sp']}]={v['val']}
end
local function {v['pop_fn']}()
local {v['val']}={v['stack']}[{v['sp']}]
{v['sp']}={v['sp']}-1
return {v['val']}
end
while {v['ip']}<=#({v['bytecode']}) do
local {v['op']}={v['bytecode']}[{v['ip']}]
{v['ip']}={v['ip']}+1
{handler_chain}
end
end"""
        return vm_code

    def _build_if_chain(self, handlers: List[dict], op_var: str) -> str:
        """Build a proper if/elseif/end chain from handler dicts."""
        if not handlers:
            return ""

        lines = []
        for i, h in enumerate(handlers):
            keyword = "if" if i == 0 else "elseif"
            lines.append(f"{keyword} {op_var}=={h['value']} then")
            lines.append(h['body'])
        lines.append("end")
        return '\n'.join(lines)

    def _build_handlers(self, v: Dict[str, str], ops: OpcodeMap) -> List[dict]:
        """Build all opcode handler dicts with value and body."""
        handlers = []
        p = v['push_fn']
        pp = v['pop_fn']
        ip = v['ip']
        bc = v['bytecode']
        sp = v['sp']
        stk = v['stack']
        loc = v['locals_tbl']
        cst = v['constants']

        def h(op_name, body):
            val = ops.get(op_name)
            handlers.append({'value': val, 'body': body})

        # Stack operations
        h('PUSH_CONST', f"local _idx={bc}[{ip}];{ip}={ip}+1;{p}({cst}[_idx+1])")
        h('PUSH_LOCAL', f"local _sl={bc}[{ip}];{ip}={ip}+1;{p}({loc}[_sl])")
        h('SET_LOCAL', f"local _sl={bc}[{ip}];{ip}={ip}+1;{loc}[_sl]={pp}()")
        h('PUSH_NIL', f"{p}(nil)")
        h('PUSH_TRUE', f"{p}(true)")
        h('PUSH_FALSE', f"{p}(false)")
        h('POP', f"{sp}={sp}-1")

        # Arithmetic
        h('ADD', f"local _b={pp}();local _a={pp}();{p}(_a+_b)")
        h('SUB', f"local _b={pp}();local _a={pp}();{p}(_a-_b)")
        h('MUL', f"local _b={pp}();local _a={pp}();{p}(_a*_b)")
        h('DIV', f"local _b={pp}();local _a={pp}();{p}(_a/_b)")
        h('MOD', f"local _b={pp}();local _a={pp}();{p}(_a%_b)")
        h('POW', f"local _b={pp}();local _a={pp}();{p}(_a^_b)")
        h('UNM', f"{stk}[{sp}]=-{stk}[{sp}]")
        h('CONCAT', f"local _n={bc}[{ip}];{ip}={ip}+1;local _parts={{}};for _ci=1,_n do _parts[_n-_ci+1]={pp}() end;{p}(table.concat(_parts))")

        # Comparison
        h('EQ', f"local _b={pp}();local _a={pp}();{p}(_a==_b)")
        h('LT', f"local _b={pp}();local _a={pp}();{p}(_a<_b)")
        h('LE', f"local _b={pp}();local _a={pp}();{p}(_a<=_b)")
        h('NOT', f"{stk}[{sp}]=not {stk}[{sp}]")
        h('LEN', f"{stk}[{sp}]=#({stk}[{sp}])")

        # Control flow
        h('JMP', f"local _off={bc}[{ip}]+{bc}[{ip}+1]*256;{ip}={ip}+2;if _off>32767 then _off=_off-65536 end;{ip}={ip}+_off")
        h('JMP_FALSE', f"local _off={bc}[{ip}]+{bc}[{ip}+1]*256;{ip}={ip}+2;if not {stk}[{sp}] then {sp}={sp}-1;if _off>32767 then _off=_off-65536 end;{ip}={ip}+_off else {sp}={sp}-1 end")
        h('JMP_TRUE', f"local _off={bc}[{ip}]+{bc}[{ip}+1]*256;{ip}={ip}+2;if {stk}[{sp}] then {sp}={sp}-1;if _off>32767 then _off=_off-65536 end;{ip}={ip}+_off else {sp}={sp}-1 end")

        # Functions — use unpack (Luau) not table.unpack
        h('CALL', f"local _ac={bc}[{ip}];{ip}={ip}+1;local _rc={bc}[{ip}];{ip}={ip}+1;local _ar={{}};for _ci=_ac,1,-1 do _ar[_ci]={pp}() end;local _fn={pp}();local _rt={{_fn(unpack(_ar))}};for _ci=1,math.min(_rc,#_rt) do {p}(_rt[_ci]) end")
        h('RETURN', f"local _cnt={bc}[{ip}];{ip}={ip}+1;local _rt={{}};for _ci=_cnt,1,-1 do _rt[_ci]={pp}() end;return unpack(_rt)")

        # Globals and Environment
        h('GET_GLOBAL', f"local _idx={bc}[{ip}];{ip}={ip}+1;local _nm={cst}[_idx+1];{p}(({v['env']})[_nm] or getfenv()[_nm])")
        h('SET_GLOBAL', f"local _idx={bc}[{ip}];{ip}={ip}+1;local _nm={cst}[_idx+1];local _val={pp}();({v['env']})[_nm]=_val;if ({v['env']})[_nm]==nil then getfenv()[_nm]=_val end")

        # Tables
        h('NEW_TABLE', f"local _arr={bc}[{ip}];{ip}={ip}+1;local _hash={bc}[{ip}];{ip}={ip}+1;{p}({{}})")
        h('GET_TABLE', f"local _key={pp}();local _tbl={pp}();{p}(_tbl[_key])")
        h('SET_TABLE', f"local _key={pp}();local _tbl={pp}();local _val={pp}();_tbl[_key]=_val")
        h('SET_LIST', f"local _start={bc}[{ip}];{ip}={ip}+1;local _cnt={bc}[{ip}];{ip}={ip}+1;local _tbl={stk}[{sp}];for _ci=1,_cnt do _tbl[_start+_ci-1]={pp}() end")

        # Closure
        h('CLOSURE', f"local _idx={bc}[{ip}];{ip}={ip}+1;local _proto={v['proto_tbl']}[_idx+1];{p}(function(...) return {v['vm_func']}(_proto,{v['constants']},{v['env']},{v['proto_tbl']},{{...}}) end)")

        # Vararg
        h('VARARG', f"local _cnt={bc}[{ip}];{ip}={ip}+1;{p}(nil)")

        # Special
        h('MOVE', f"local _dest={bc}[{ip}];{ip}={ip}+1;local _src={bc}[{ip}];{ip}={ip}+1;{loc}[_dest]={loc}[_src]")
        h('DUP', f"{p}({stk}[{sp}])")
        h('SWAP', f"local _a={pp}();local _b={pp}();{p}(_a);{p}(_b)")

        # NOP
        h('NOP', "--[[ nop ]]")

        return handlers
