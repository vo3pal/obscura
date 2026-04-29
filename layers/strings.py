"""
Obscura Layer 2 — String Encryption
========================================
Collects all string literals, encrypts them with per-string XOR keys + Base64,
builds a centralized string table, and injects a polymorphic decoder.
"""

from parser.ast_nodes import *
from utils.crypto import encrypt_string
from utils.names import NameGenerator
from config import ObfuscationConfig
from typing import List, Tuple


# The decoder function template for Luau
# This implements Base64 decode + XOR in pure Luau using bit32
DECODER_TEMPLATE = '''local {decoder_name}=(function()
local {b_var}='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local {lookup_var}={{}}
for {i_var}=1,#({b_var}) do {lookup_var}[string.sub({b_var},{i_var},{i_var})]={i_var}-1 end
return function({s_var},{k_var})
local {result_var}={{}}
local {ri_var}=1
local {buf_var}=0
local {bits_var}=0
for {ci_var}=1,#({s_var}) do
local {ch_var}=string.sub({s_var},{ci_var},{ci_var})
local {val_var}={lookup_var}[{ch_var}]
if {val_var} then
{buf_var}={buf_var}*64+{val_var}
{bits_var}={bits_var}+6
if {bits_var}>=8 then
{bits_var}={bits_var}-8
local {byte_var}=math.floor({buf_var}/2^{bits_var})
{buf_var}={buf_var}-{byte_var}*2^{bits_var}
{result_var}[{ri_var}]=string.char(bit32.bxor({byte_var},{k_var}))
{ri_var}={ri_var}+1
end
end
end
return table.concat({result_var})
end
end)()'''


class StringEncryptor:
    """Encrypts all string literals in the AST."""

    def __init__(self, config: ObfuscationConfig):
        self.config = config
        self.rng = config.get_rng()
        self.name_gen = NameGenerator(rng=self.rng, min_length=8, max_length=12)
        self.strings: List[Tuple[str, str, int]] = []  # (original, encrypted, key)
        self.decoder_name = self.name_gen.gen_name()
        self.table_name = self.name_gen.gen_name()

    def apply(self, block: Block) -> Block:
        """Apply string encryption to the AST."""
        # Collect and encrypt all strings
        self._collect_strings(block)

        if not self.strings:
            return block

        # Build the string table and decoder header
        header_stmts = self._build_header()

        # Inject header at the top
        block.body = header_stmts + block.body
        return block

    def _collect_strings(self, node: Node):
        """Walk AST and replace string literals with decoder calls."""
        if node is None:
            return

        if isinstance(node, Block):
            for stmt in node.body:
                self._collect_strings(stmt)
            return

        # Process child nodes and replace strings in-place
        for attr_name in vars(node):
            attr = getattr(node, attr_name)
            if isinstance(attr, StringLiteral) and attr_name != 'key':
                self._replace_string(node, attr_name, attr)
            elif isinstance(attr, Node):
                self._collect_strings(attr)
            elif isinstance(attr, list):
                for i, item in enumerate(attr):
                    if isinstance(item, StringLiteral):
                        self._replace_string_in_list(attr, i, item)
                    elif isinstance(item, Node):
                        self._collect_strings(item)

    def _replace_string(self, parent: Node, attr_name: str, string_node: StringLiteral):
        """Replace a string literal with a decoder call."""
        encrypted, key = encrypt_string(string_node.value, self.rng)
        idx = len(self.strings)
        self.strings.append((string_node.value, encrypted, key))

        # Create: decoder(table[idx+1], key)
        call = FunctionCall(
            func=Identifier(name=self.decoder_name),
            args=[
                IndexExpr(
                    object=Identifier(name=self.table_name),
                    index=NumberLiteral(value=str(idx + 1))
                ),
                NumberLiteral(value=str(key))
            ],
            line=string_node.line, col=string_node.col
        )
        setattr(parent, attr_name, call)

    def _replace_string_in_list(self, lst: list, idx: int, string_node: StringLiteral):
        """Replace a string literal in a list with a decoder call."""
        encrypted, key = encrypt_string(string_node.value, self.rng)
        str_idx = len(self.strings)
        self.strings.append((string_node.value, encrypted, key))

        call = FunctionCall(
            func=Identifier(name=self.decoder_name),
            args=[
                IndexExpr(
                    object=Identifier(name=self.table_name),
                    index=NumberLiteral(value=str(str_idx + 1))
                ),
                NumberLiteral(value=str(key))
            ],
            line=string_node.line, col=string_node.col
        )
        lst[idx] = call

    def _build_header(self) -> List[Node]:
        """Build the decoder function and string table as AST nodes."""
        stmts = []

        # Build string table: local TABLE = {"enc1", "enc2", ...}
        fields = []
        for _, encrypted, _ in self.strings:
            fields.append(TableField(
                key=None,
                value=StringLiteral(value=encrypted),
            ))

        table_stmt = LocalStatement(
            names=[self.table_name],
            values=[TableConstructor(fields=fields)]
        )
        stmts.append(table_stmt)

        # The decoder is injected as raw Luau via a special marker node
        # We use the template with all variable names obfuscated
        decoder_code = self._generate_decoder()
        stmts.insert(0, ExpressionStatement(
            expression=Identifier(name=decoder_code)
        ))

        return stmts

    def _generate_decoder(self) -> str:
        """Generate the decoder function code with obfuscated variable names."""
        names = {
            'decoder_name': self.decoder_name,
            'b_var': self.name_gen.gen_name(),
            'lookup_var': self.name_gen.gen_name(),
            'i_var': self.name_gen.gen_name(),
            's_var': self.name_gen.gen_name(),
            'k_var': self.name_gen.gen_name(),
            'result_var': self.name_gen.gen_name(),
            'ri_var': self.name_gen.gen_name(),
            'buf_var': self.name_gen.gen_name(),
            'bits_var': self.name_gen.gen_name(),
            'ci_var': self.name_gen.gen_name(),
            'ch_var': self.name_gen.gen_name(),
            'val_var': self.name_gen.gen_name(),
            'byte_var': self.name_gen.gen_name(),
        }
        return DECODER_TEMPLATE.format(**names)

