"""Regression tests for native hardening features."""
import base64
import re
import unittest

from config import ObfuscationConfig, ProtectionLevel
from layers.strings import StringEncryptor
from layers.vm.constant_pool import ConstantPool
from layers.vm.interpreter import InterpreterGenerator
from layers.vm.instruction import Instruction, FORMAT_AB
from layers.vm.opcodes import OpcodeMap
from layers.vm.proto import FunctionPrototype
from obfuscator import Obfuscator
from utils.names import NameGenerator


class HardeningTests(unittest.TestCase):
    def test_maximum_enables_double_encryption(self):
        self.assertFalse(ObfuscationConfig(level=ProtectionLevel.STANDARD,
                                           seed=1).double_encrypt)
        self.assertTrue(ObfuscationConfig(level=ProtectionLevel.MAXIMUM,
                                          seed=1).double_encrypt)
        self.assertTrue(ObfuscationConfig(level=ProtectionLevel.PARANOID,
                                          seed=1).double_encrypt)

    def test_double_encryption_round_trip(self):
        config = ObfuscationConfig(seed=12345, double_encrypt=True)
        encryptor = StringEncryptor(config)
        value = "Obscura \u2603\x00payload"
        encoded, token, token2 = encryptor._encrypt_string(value, 1)
        payload = base64.b64decode(encoded)
        checksum = 0
        for byte in payload:
            checksum = (checksum * encryptor.payload_hash_multiplier + byte) % 4294967296
        self.assertEqual(checksum, encryptor._checksums[1])
        if encryptor._reverse[1]:
            payload = payload[::-1]

        packed = token ^ (encryptor.token_mask + 131)
        seed, step = packed // 256, packed % 256
        packed2 = token2 ^ (encryptor.token_mask + 197)
        seed2, step2 = packed2 // 256, packed2 % 256
        clear = []
        for pos, byte in enumerate(payload, start=1):
            key1 = encryptor.master_key[(pos + seed + 1) % len(encryptor.master_key)]
            dynamic1 = (seed + pos * step + key1 + 17) % 256
            key2 = encryptor.second_master_key[(pos + seed2 + 1) % len(encryptor.second_master_key)]
            dynamic2 = (seed2 + pos * step2 + key2 + 29) % 256
            clear.append(((byte - dynamic2) % 256) ^ dynamic1)
        self.assertEqual(bytes(clear).decode("utf-8"), value)

    def test_hardened_output_has_no_plaintext(self):
        output = Obfuscator(ObfuscationConfig(
            level=ProtectionLevel.MAXIMUM, seed=12345,
        )).obfuscate('return "obscura-private-value"')
        self.assertNotIn("obscura-private-value", output)
        self.assertIn("%256", output)
        self.assertIn("%4294967296", output)
        self.assertIn("-- Obscura [", output)

    def test_builds_use_polymorphic_string_layouts(self):
        source = 'return "one","two","three","four","five","six"'
        first = Obfuscator(ObfuscationConfig(
            level=ProtectionLevel.MAXIMUM, seed=11,
        )).obfuscate(source)
        second = Obfuscator(ObfuscationConfig(
            level=ProtectionLevel.MAXIMUM, seed=12,
        )).obfuscate(source)
        self.assertNotEqual(first, second)
        self.assertNotIn('"three"', first)
        self.assertNotIn('"three"', second)

    def test_antitamper_is_build_specific_and_repeated(self):
        source = '''local function protected(value)
return value + 1
end
return protected(4)'''
        first = Obfuscator(ObfuscationConfig(
            level=ProtectionLevel.MAXIMUM, seed=101,
        )).obfuscate(source)
        second = Obfuscator(ObfuscationConfig(
            level=ProtectionLevel.MAXIMUM, seed=102,
        )).obfuscate(source)
        self.assertNotEqual(first, second)
        self.assertIn("getgenv~=nil", first)
        self.assertIn("hookfunction~=nil", first)
        self.assertIn("%4294967296", first)
        self.assertIn("%#", first)
        self.assertIn(".bxor(", first)
        # Startup, tail and protected-function entry checks all call the
        # generated guard, while its implementation also contains closures.
        self.assertGreater(first.count("()"), 3)

    def test_vm_position_dependent_bytecode_mask(self):
        config = ObfuscationConfig(virtualize=True, vm_hardening="max", seed=404)
        rng = config.get_rng()
        opcodes = OpcodeMap(rng, diversify=True, fusion=True, extended=True,
                            handler_variants=True)
        generator = InterpreterGenerator(
            config, opcodes, ConstantPool(rng), NameGenerator(rng=rng),
        )
        bytecode = [17, 17, 17, 17, 17, 17, 17, 17]
        key = [91, 91]
        multiplier, offset = 73, 19
        encrypted = generator._encrypt_bytecode(bytecode, key, multiplier, offset)
        decrypted = [
            value ^ key[index % len(key)] ^ (((index + 1) * multiplier + offset) % 256)
            for index, value in enumerate(encrypted)
        ]
        self.assertEqual(decrypted, bytecode)
        self.assertGreater(len(set(encrypted)), 2)

    def test_hardened_vm_emits_authenticated_position_keys(self):
        output = Obfuscator(ObfuscationConfig(
            virtualize=True, vm_hardening="max", seed=505,
        )).obfuscate('local function f(x) return x+1 end;return f(4)')
        self.assertIn("bm=", output)
        self.assertIn("ba=", output)
        self.assertIn("om=", output)
        self.assertIn("oa=", output)
        self.assertIn("oi=", output)
        self.assertIn("integrity check failed", output)

    def test_max_vm_uses_stateful_instruction_fetch(self):
        output = Obfuscator(ObfuscationConfig(
            virtualize=True, vm_hardening="max", seed=506,
        )).obfuscate('local x=2; if x>1 then x=x+3 end; return x')
        self.assertIn("f1=", output)
        self.assertIn("f2=", output)
        self.assertIn("fm=", output)
        self.assertIn("fa=", output)
        self.assertIn("fq=", output)
        self.assertIn("fw=", output)
        self.assertIn("ff=", output)
        self.assertIn("lm=", output)
        self.assertIn("la=", output)
        self.assertIn("instruction authentication failed", output)

    def test_stateful_fetch_round_trip_and_instruction_tag(self):
        config = ObfuscationConfig(virtualize=True, vm_hardening="max", seed=507)
        rng = config.get_rng()
        opcodes = OpcodeMap(rng, diversify=True, fusion=True, extended=True,
                            handler_variants=True)
        generator = InterpreterGenerator(
            config, opcodes, ConstantPool(rng), NameGenerator(rng=rng),
        )
        proto = FunctionPrototype(
            instructions=[Instruction('MOVE', FORMAT_AB, pc=0)],
            bytecode=[31, 4, 0, 9, 0], fetch_seed=1234, fetch_mul=71,
            fetch_add=29, fetch_step=313, fetch_byte=19, fetch_bias=7,
            fetch_tag_seed=9981, fetch_tag_mul=769,
        )
        for family in range(3):
            proto.fetch_family = family
            encoded = generator._stateful_encode(proto, proto.bytecode)
            state = (proto.fetch_seed + proto.fetch_mul + proto.fetch_add) % 65536
            tag = (proto.fetch_tag_seed + proto.fetch_tag_mul) % 4294967296
            decoded = []
            for index, value in enumerate(encoded, start=1):
                high, low = state // 256, state % 256
                if family == 1:
                    mask = ((high + proto.fetch_byte) % 256) ^ low
                elif family == 2:
                    mask = high ^ ((low + proto.fetch_bias) % 256)
                else:
                    mask = high ^ low
                clear = value ^ mask
                decoded.append(clear)
                if family == 1:
                    state = (state * proto.fetch_step + clear * proto.fetch_byte
                             + index + proto.fetch_bias) % 65536
                else:
                    state = (state * proto.fetch_step + clear + index * proto.fetch_byte
                             + proto.fetch_bias) % 65536
                tag = (tag * proto.fetch_tag_mul + clear + index * proto.fetch_byte
                       + proto.fetch_bias) % 4294967296
            self.assertEqual(decoded, proto.bytecode)
            self.assertEqual(tag, proto.fetch_tags[0])

    def test_vm_lookup_metadata_uses_a_build_bijection(self):
        config = ObfuscationConfig(virtualize=True, vm_hardening="max", seed=508)
        rng = config.get_rng()
        generator = InterpreterGenerator(
            config,
            OpcodeMap(rng, diversify=True, fusion=True, extended=True,
                      handler_variants=True),
            ConstantPool(rng), NameGenerator(rng=rng),
        )
        slots = [generator._lookup_slot(value) for value in range(256)]
        self.assertEqual(len(set(slots)), 256)
        for size in range(17):
            slot = slots[size]
            encoded = size ^ generator._lookup_mask(slot)
            self.assertEqual(encoded ^ generator._lookup_mask(slot), size)

    def test_vm_uses_distinct_per_prototype_opcode_encodings(self):
        source = '''local function a() return 1 end
local function b() return 2 end
local function c() return 3 end
local function d() return 4 end
return a()+b()+c()+d()'''
        output = Obfuscator(ObfuscationConfig(
            virtualize=True, vm_hardening="max", seed=606,
        )).obfuscate(source)
        mappings = [tuple(map(int, match)) for match in
                    re.findall(r'om=(\d+),oa=(\d+),oi=(\d+)', output)]
        engines = [int(value) for value in re.findall(r'ix=(\d+)', output)]
        self.assertGreaterEqual(len(mappings), 5)
        self.assertGreater(len(set(mappings)), 1)
        self.assertEqual(len(engines), len(mappings))
        self.assertGreater(len(set(engines)), 1)
        self.assertIn(".rc=", output)
        self.assertIn(".rh", output)
        self.assertRegex(output, r"_po=.*\.oa.*\.oi")
        for multiplier, offset, inverse in mappings:
            self.assertEqual((multiplier * inverse) % 256, 1)
            for opcode in (1, 17, 127, 255):
                wire = (opcode * multiplier + offset) % 256
                self.assertEqual(((wire - offset) % 256 * inverse) % 256, opcode)


if __name__ == "__main__":
    unittest.main()
