"""
Obscura Configuration
=====================
ObfuscationConfig dataclass with per-layer toggles and protection level presets.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import random
import secrets


class ProtectionLevel(Enum):
    """Predefined protection level presets."""
    MINIMAL = 1    # Layers 1-3: identifiers, strings, numbers
    STANDARD = 2   # Layers 1-6: + CFF, predicates, dead code
    MAXIMUM = 3    # Layers 1-8: + indirection, anti-tamper
    PARANOID = 4   # Separate VM pipeline with maximum hardening


class DeadCodeDensity(Enum):
    """How much dead code to inject."""
    LOW = "low"        # ~5% size increase
    MEDIUM = "medium"  # ~15% size increase
    HIGH = "high"      # ~30% size increase


@dataclass
class ObfuscationConfig:
    """Master configuration for the obfuscation pipeline."""

    # --- Protection Level (overrides individual toggles if set) ---
    level: Optional[ProtectionLevel] = None

    # --- Individual Layer Toggles ---
    rename_identifiers: bool = True       # Layer 1
    encrypt_strings: bool = True          # Layer 2
    obfuscate_numbers: bool = True        # Layer 3
    control_flow_flatten: bool = True     # Layer 4
    opaque_predicates: bool = True        # Layer 5
    inject_dead_code: bool = True         # Layer 6
    table_indirection: bool = True        # Layer 7
    anti_tamper: bool = True              # Layer 8
    virtualize: bool = False              # Layer 9 (VM) — opt-in

    # --- Layer-Specific Settings ---
    # Identifier renaming
    name_min_length: int = 8
    name_max_length: int = 14
    mix_naming_strategies: bool = True    # Use multiple naming styles per build

    # String encryption
    use_string_table: bool = True         # Centralized string table vs inline
    double_encrypt: bool = False          # Double-layer encryption
    string_decode_mode: str = "lazy"      # lazy cache | eager pool (no hot-path calls)

    # Number obfuscation
    mba_depth: int = 2                    # Expression nesting depth (1-3)
    skip_trivial_numbers: bool = True     # Skip 0, 1, -1

    # Control flow flattening
    use_dispatch_table: bool = True       # Function dispatch vs if-chain
    encode_state_transitions: bool = True # XOR-encode next-state values
    min_blocks_for_cff: int = 3           # Minimum statements to apply CFF

    # Dead code
    dead_code_density: DeadCodeDensity = DeadCodeDensity.MEDIUM
    fake_function_count: int = 5

    # Anti-tamper
    check_environment: bool = True
    check_hooks: bool = True
    check_integrity: bool = True
    wrap_in_iife: bool = True

    # VM
    vm_hardening: Optional[str] = None    # basic | client-max | max; resolved below
    vm_lazy_constants: Optional[bool] = None
    vm_dynamic_keys: Optional[bool] = None
    vm_integrity_check: Optional[bool] = None
    vm_operand_layouts: Optional[bool] = None
    vm_partition_constants: Optional[bool] = None
    vm_per_proto_keys: Optional[bool] = None
    vm_fuse_instructions: Optional[bool] = None
    vm_extended_fusion: Optional[bool] = None
    vm_encode_numbers: Optional[bool] = None
    vm_handler_variants: Optional[bool] = None
    vm_superinstructions: Optional[bool] = None
    vm_position_keys: Optional[bool] = None
    vm_shuffle_prototypes: Optional[bool] = None
    vm_per_proto_opcodes: Optional[bool] = None
    vm_multi_interpreters: Optional[bool] = None
    vm_runtime_integrity: Optional[bool] = None
    vm_stateful_fetch: Optional[bool] = None # Rolling instruction-local recovery
    vm_predecode_bytecode: bool = False   # Rolling reads by default; True caches decoded bytecode

    # --- Global Settings ---
    seed: Optional[int] = None            # None = private 256-bit OS-random seed
    minify: bool = True                   # Minify output
    strip_comments: bool = True           # Remove all comments
    strip_types: bool = True              # Remove Luau type annotations

    # --- Internal State (set at runtime) ---
    _rng: random.Random = field(default_factory=random.Random, repr=False)
    _build_id: str = field(default="", repr=False)

    def __post_init__(self):
        """Apply protection level presets and initialize RNG."""
        if self.level is not None:
            self._apply_level(self.level)
        self._resolve_vm_profile()
        self._init_rng()

    def _apply_level(self, level: ProtectionLevel):
        """Apply a protection level preset, setting layer toggles."""
        lv = level.value
        self.rename_identifiers = lv >= ProtectionLevel.MINIMAL.value
        self.encrypt_strings = lv >= ProtectionLevel.MINIMAL.value
        self.obfuscate_numbers = lv >= ProtectionLevel.MINIMAL.value
        self.control_flow_flatten = lv >= ProtectionLevel.STANDARD.value
        self.opaque_predicates = lv >= ProtectionLevel.STANDARD.value
        self.inject_dead_code = lv >= ProtectionLevel.STANDARD.value
        self.table_indirection = lv >= ProtectionLevel.MAXIMUM.value
        self.anti_tamper = lv >= ProtectionLevel.MAXIMUM.value
        self.double_encrypt = lv >= ProtectionLevel.MAXIMUM.value
        self.virtualize = lv >= ProtectionLevel.PARANOID.value
        if lv >= ProtectionLevel.PARANOID.value:
            self.vm_hardening = self.vm_hardening or "max"

    def _resolve_vm_profile(self):
        """One resolver for CLI/API, preserving explicit per-feature overrides."""
        self.vm_hardening = self.vm_hardening or "basic"
        if self.vm_hardening not in ('basic', 'client-max', 'max'):
            raise ValueError(f'Unknown VM hardening profile: {self.vm_hardening}')
        hardened = self.vm_hardening != 'basic'
        defaults = {
            'vm_lazy_constants': hardened,
            'vm_dynamic_keys': hardened,
            'vm_integrity_check': hardened,
            'vm_operand_layouts': hardened,
            'vm_partition_constants': hardened,
            'vm_per_proto_keys': hardened,
            'vm_fuse_instructions': hardened,
            'vm_extended_fusion': self.vm_hardening == 'max',
            'vm_encode_numbers': hardened,
            'vm_handler_variants': hardened,
            'vm_superinstructions': hardened,
            'vm_position_keys': hardened,
            'vm_shuffle_prototypes': hardened,
            'vm_per_proto_opcodes': hardened,
            'vm_multi_interpreters': self.vm_hardening == 'max',
            'vm_runtime_integrity': hardened,
            'vm_stateful_fetch': self.vm_hardening == 'max',
        }
        for name,value in defaults.items():
            if getattr(self,name) is None:
                setattr(self,name,value)

    def _init_rng(self):
        """Initialize the random number generator."""
        if self.seed is None:
            self.seed = secrets.randbits(256)
            # Independent randomness; hashing a small seed would expose a
            # searchable identifier. Neither seed nor RNG state is published.
            self._build_id = secrets.token_hex(8)
        else:
            # Explicit development seeds retain byte-for-byte reproducibility
            # without putting their value into released Lua or normal logs.
            self._build_id = 'development'
        self._rng = random.Random(self.seed)

    def get_rng(self) -> random.Random:
        """Get the seeded RNG instance for deterministic output."""
        return self._rng


# --- Preset Constructors ---

def minimal_config(**kwargs) -> ObfuscationConfig:
    """Quick config: identifier renaming + string encryption + number obfuscation."""
    return ObfuscationConfig(level=ProtectionLevel.MINIMAL, **kwargs)


def lightweight_config(**kwargs) -> ObfuscationConfig:
    """Native Luau control flow with identifiers and startup-only string decoding."""
    config = ObfuscationConfig(level=ProtectionLevel.MINIMAL, **kwargs)
    config.obfuscate_numbers = False
    config.string_decode_mode = "eager"
    return config

def standard_config(**kwargs) -> ObfuscationConfig:
    """Quick config: layers 1-6 (no table indirection, no anti-tamper, no VM)."""
    return ObfuscationConfig(level=ProtectionLevel.STANDARD, **kwargs)

def maximum_config(**kwargs) -> ObfuscationConfig:
    """Quick config: layers 1-8 (everything except VM)."""
    return ObfuscationConfig(level=ProtectionLevel.MAXIMUM, **kwargs)

def paranoid_config(**kwargs) -> ObfuscationConfig:
    """Quick config: separate VM pipeline with maximum hardening."""
    return ObfuscationConfig(level=ProtectionLevel.PARANOID, **kwargs)
