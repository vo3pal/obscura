"""
LuauShield Configuration
========================
ObfuscationConfig dataclass with per-layer toggles and protection level presets.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import random
import time


class ProtectionLevel(Enum):
    """Predefined protection level presets."""
    MINIMAL = 1    # Layers 1-3: identifiers, strings, numbers
    STANDARD = 2   # Layers 1-6: + CFF, predicates, dead code
    MAXIMUM = 3    # Layers 1-8: + indirection, anti-tamper
    PARANOID = 4   # All 9 layers including custom VM


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
    check_timing: bool = True
    check_integrity: bool = True
    wrap_in_iife: bool = True

    # VM
    vm_opcode_count: int = 30             # Number of VM instructions
    vm_obfuscate_interpreter: bool = True # Apply layers 1-6 to the VM stub

    # --- Global Settings ---
    seed: Optional[int] = None            # None = unique per run
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
        self._init_rng()

    def _apply_level(self, level: ProtectionLevel):
        """Apply a protection level preset, setting layer toggles."""
        # Reset all
        self.rename_identifiers = False
        self.encrypt_strings = False
        self.obfuscate_numbers = False
        self.control_flow_flatten = False
        self.opaque_predicates = False
        self.inject_dead_code = False
        self.table_indirection = False
        self.anti_tamper = False
        self.virtualize = False

        if level.value >= ProtectionLevel.MINIMAL.value:
            self.rename_identifiers = True
            self.encrypt_strings = True
            self.obfuscate_numbers = True

        if level.value >= ProtectionLevel.STANDARD.value:
            self.control_flow_flatten = True
            self.opaque_predicates = True
            self.inject_dead_code = True

        if level.value >= ProtectionLevel.MAXIMUM.value:
            self.table_indirection = True
            self.anti_tamper = True

        if level.value >= ProtectionLevel.PARANOID.value:
            self.virtualize = True

    def _init_rng(self):
        """Initialize the random number generator."""
        if self.seed is None:
            self.seed = int(time.time() * 1000) & 0xFFFFFFFF
        self._rng = random.Random(self.seed)
        self._build_id = f"{self.seed:08x}"

    def get_rng(self) -> random.Random:
        """Get the seeded RNG instance for deterministic output."""
        return self._rng


# --- Preset Constructors ---

def minimal_config(**kwargs) -> ObfuscationConfig:
    """Quick config: identifier renaming + string encryption + number obfuscation."""
    return ObfuscationConfig(level=ProtectionLevel.MINIMAL, **kwargs)

def standard_config(**kwargs) -> ObfuscationConfig:
    """Quick config: layers 1-6 (no table indirection, no anti-tamper, no VM)."""
    return ObfuscationConfig(level=ProtectionLevel.STANDARD, **kwargs)

def maximum_config(**kwargs) -> ObfuscationConfig:
    """Quick config: layers 1-8 (everything except VM)."""
    return ObfuscationConfig(level=ProtectionLevel.MAXIMUM, **kwargs)

def paranoid_config(**kwargs) -> ObfuscationConfig:
    """Quick config: all 9 layers including custom VM."""
    return ObfuscationConfig(level=ProtectionLevel.PARANOID, **kwargs)
