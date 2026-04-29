"""
LuauShield Obfuscator — Pipeline Orchestrator
================================================
Chains all obfuscation layers in the correct order, manages the full
transformation pipeline from source code to protected output.
"""

import re
from config import ObfuscationConfig
from parser.lexer import Lexer
from parser.parser import Parser
from parser.emitter import Emitter
from parser.ast_nodes import Block
from layers.identifier import IdentifierRenamer
from layers.strings import StringEncryptor
from layers.numbers import NumberObfuscator
from layers.cff import ControlFlowFlattener
from layers.predicates import OpaquePredicateGenerator
from layers.deadcode import DeadCodeInjector
from layers.indirection import TableIndirection
from layers.antitamper import AntiTamperInjector
from layers.vm.compiler import VMCompiler
from layers.vm.interpreter import InterpreterGenerator
from layers.vm.opcodes import OpcodeMap
from layers.vm.constant_pool import ConstantPool
from utils.names import NameGenerator
from typing import Optional


class ObfuscationError(Exception):
    """Raised when obfuscation fails."""
    pass


class Obfuscator:
    """
    Main obfuscation pipeline orchestrator.
    Applies layers in order based on configuration.
    """

    def __init__(self, config: Optional[ObfuscationConfig] = None):
        self.config = config or ObfuscationConfig()

    def obfuscate(self, source: str) -> str:
        """
        Obfuscate a Luau source string.
        Returns the obfuscated Luau source.
        """
        try:
            # Pre-processing: strip Luau type annotations
            if self.config.strip_types:
                source = self._strip_types(source)

            # Strip comments
            if self.config.strip_comments:
                source = self._strip_comments(source)

            # Check if VM mode — uses a completely different pipeline
            if self.config.virtualize:
                return self._obfuscate_vm(source)

            # Standard pipeline: parse → transform → emit
            return self._obfuscate_standard(source)

        except Exception as e:
            raise ObfuscationError(f"Obfuscation failed: {e}") from e

    def _obfuscate_standard(self, source: str) -> str:
        """
        Standard obfuscation pipeline: AST transformation → Emission.
        
        Applies layers 1-8 based on configuration.
        """
        # Parse source to AST
        parser = Parser.from_source(source)
        ast = parser.parse()

        # Layer 4: Control Flow Flattening (must come before identifier renaming)
        if self.config.control_flow_flatten:
            cff = ControlFlowFlattener(self.config)
            ast = cff.apply(ast)

        # Layer 5: Opaque Predicates
        if self.config.opaque_predicates:
            predicates = OpaquePredicateGenerator(self.config)
            ast = predicates.apply(ast)

        # Layer 6: Dead Code Injection
        if self.config.inject_dead_code:
            deadcode = DeadCodeInjector(self.config)
            ast = deadcode.apply(ast)

        # Layer 3: Number Obfuscation
        if self.config.obfuscate_numbers:
            numbers = NumberObfuscator(self.config)
            ast = numbers.apply(ast)

        # Layer 2: String Encryption
        if self.config.encrypt_strings:
            string_encryptor = StringEncryptor(self.config)
            ast = string_encryptor.apply(ast)

        # Layer 1: Identifier Renaming
        if self.config.rename_identifiers:
            renamer = IdentifierRenamer(self.config)
            ast = renamer.apply(ast)

        # Layer 7: Table Indirection
        if self.config.table_indirection:
            indirection = TableIndirection(self.config)
            ast = indirection.apply(ast)

        # Layer 8: Anti-Tamper (wraps everything)
        if self.config.anti_tamper:
            antitamper = AntiTamperInjector(self.config)
            ast = antitamper.apply(ast)

        # Emit final Luau code
        emitter = Emitter(minify=self.config.minify)
        output = emitter.emit(ast)

        # Ensure everything after the header is on a single line
        output = output.replace('\n', ' ').replace('\r', ' ')

        # Add build signature comment (exactly 3 lines)
        header = f"--!nocheck\n--!nolint\n-- LuauShield [{self.config._build_id}]\n"
        return header + output

    def _obfuscate_vm(self, source: str) -> str:
        """
        VM-based obfuscation pipeline: AST → Bytecode → Interpreter.
        
        Translates Luau AST into a custom instruction set executed by a
        generated virtual machine stub.
        """
        # Parse source to AST
        parser = Parser.from_source(source)
        ast = parser.parse()

        rng = self.config.get_rng()
        name_gen = NameGenerator(rng=rng, min_length=8, max_length=12)

        # Compile AST to custom bytecode
        vm_compiler = VMCompiler(self.config)
        main_proto = vm_compiler.compile(ast)

        # Generate the interpreter stub
        interpreter_gen = InterpreterGenerator(
            self.config,
            vm_compiler.opcodes,
            vm_compiler.pool,
            name_gen
        )
        vm_output = interpreter_gen.generate(main_proto)

        # Construct the final code
        code_parts = [
            "print('LuauShield VM Protected Script Loading...')",
            "print('LuauShield VM Payload Initializing...')",
            vm_output
        ]
        
        final_code = " ".join(code_parts)
        
        # Wrap in IIFE if configured
        if self.config.wrap_in_iife:
            final_code = f"(function() {final_code} end)()"

        # Ensure everything after the header is on a single line
        final_code = final_code.replace('\n', ' ').replace('\r', ' ')

        # Add build signature and suppress Studio analysis (exactly 3 lines of comments)
        header = f"--!nocheck\n--!nolint\n-- LuauShield VM [{self.config._build_id}]\n"
        return header + final_code

    def _strip_types(self, source: str) -> str:
        """
        Remove Luau type declarations (type/export type) from source code.
        Inline annotations are handled by the parser's lexer.
        """
        source = re.sub(r'^\s*type\s+\w+\s*=\s*[^\n]+', '', source, flags=re.MULTILINE)
        source = re.sub(r'^\s*export\s+type\s+\w+\s*=\s*[^\n]+', '', source, flags=re.MULTILINE)
        return source

    def _strip_comments(self, source: str) -> str:
        """Remove all Luau comments (single-line and block)."""
        # Remove long comments first: --[[ ... ]]
        source = re.sub(r'--\[=*\[.*?\]=*\]', '', source, flags=re.DOTALL)
        # Remove single-line comments: -- ...
        source = re.sub(r'--[^\n]*', '', source)
        return source


def obfuscate(source: str, config: Optional[ObfuscationConfig] = None) -> str:
    """Convenience function to obfuscate a Luau source string."""
    obfuscator = Obfuscator(config)
    return obfuscator.obfuscate(source)
