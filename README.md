# 🌑 Obscura

<div align="center">

**A high-performance, 9-layer Luau obfuscation engine for the Roblox environment.**

*Transforms readable source into encrypted, virtualized, and control-flow-hardened output — resistant to both static and dynamic analysis.*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Target-Roblox%20%2F%20Luau-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Layers](https://img.shields.io/badge/Protection%20Layers-9-purple?style=flat-square)

</div>

---

> [!IMPORTANT]
> Obscura is a research and portfolio project exploring Luau bytecode virtualization, control-flow protection, and source transformation techniques for educational purposes. Use responsibly and only on code you own or have permission to protect.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Protection Layers](#%EF%B8%8F-protection-layers)
- [Getting Started](#-getting-started)
- [CLI Reference](#-cli-reference)
- [Protection Levels](#-protection-levels)
- [Technical Deep-Dive: The VM](#-technical-deep-dive-the-obscura-vm)
- [Architecture](#-architecture)
- [How Each Layer Works](#-how-each-layer-works)
- [FAQ](#-faq)
- [License](#-license)

---

## 🌐 Overview

Obscura is a multi-stage source-to-source transformer that takes standard Luau code and produces output that is:

- **Unreadable** — all identifiers are replaced with randomized, visually-confusing names
- **Encrypted** — all string constants and VM constants are XOR-encrypted and decoded at runtime
- **Structurally destroyed** — control flow is flattened into a state-machine dispatcher, removing all natural code structure
- **Virtualized** — optionally compiled into a custom 30+ opcode instruction set executed by a generated stack-based interpreter

Each build is **unique and non-reproducible by default** (seeded by timestamp). Every output uses different opcode mappings, different identifier names, different XOR keys, and a different build ID — meaning a deobfuscator built for one output will not work on the next.

---

## 🛡️ Protection Layers

Obscura applies up to **9 independent layers** in a defined pipeline. Each layer adds a new dimension of protection. Even if an attacker defeats one layer, the remaining layers continue to protect the underlying logic.

| # | Layer | What It Does |
|---|-------|-------------|
| 1 | **Identifier Renaming** | Replaces all local variables, functions, and parameters with randomized names |
| 2 | **String Encryption** | Encrypts all string literals with per-string XOR keys + Base64; decoded at runtime |
| 3 | **Number Obfuscation (MBA)** | Replaces numeric literals with mathematically-equivalent boolean-arithmetic expressions |
| 4 | **Control Flow Flattening** | Shatters sequential code into a `while true` state-machine dispatcher |
| 5 | **Opaque Predicates** | Injects always-true/false branches that are statically irresolvable |
| 6 | **Dead Code Injection** | Inserts realistic-looking but unreachable junk computations |
| 7 | **Table Indirection** | Wraps all global/API accesses through an XOR-keyed indirection table |
| 8 | **Anti-Tamper** | Runtime checks for exploit globals, environment hooks, and integrity violations |
| 9 | **VM Virtualization** | Compiles Luau AST into custom encrypted bytecode executed by a generated interpreter |

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **pip** (standard with Python)
- A **Roblox Studio** environment for testing output scripts

### Installation

```bash
git clone https://github.com/vo3pal-ux/obscura.git
cd obscura
pip install -r requirements.txt
```

### Quick Start

```bash
# Standard obfuscation (layers 1-8, no VM)
python main.py --input script.lua --output protected.lua

# Full 9-layer protection with VM
python main.py --input script.lua --output protected.lua --vm

# Paranoid level preset (all layers, including VM)
python main.py --input script.lua --output protected.lua --level 4

# Lightweight mode (identifiers + strings only, minimal overhead)
python main.py --input script.lua --output protected.lua --lightweight

# Reproducible build with fixed seed
python main.py --input script.lua --output protected.lua --seed 12345

# Process an entire directory recursively
python main.py --input ./src/ --output ./dist/ --recursive
```

---

## 🖥️ CLI Reference

```
python main.py [OPTIONS]
```

<details>
<summary><strong>View all options</strong></summary>

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--input` | `-i` | `PATH` | *(required)* | Input `.lua`/`.luau` file or directory |
| `--output` | `-o` | `PATH` | *(required)* | Output file or directory |
| `--level` | `-l` | `1-4` | `None` | Protection level preset (overrides individual flags) |
| `--vm` | | flag | `false` | Enable VM virtualization (Layer 9) |
| `--antitamper` | | flag | `false` | Enable anti-tamper (Layer 8) |
| `--strings/--no-strings` | | bool | `true` | Toggle string encryption |
| `--cff/--no-cff` | | bool | `true` | Toggle control flow flattening |
| `--deadcode/--no-deadcode` | | bool | `true` | Toggle dead code injection |
| `--density` | | `low/medium/high` | `medium` | Dead code injection density |
| `--seed` | | `INT` | random | RNG seed for reproducible builds |
| `--recursive` | `-r` | flag | `false` | Process directory recursively |
| `--lightweight` | | flag | `false` | Minimal mode: identifiers + strings only |
| `--quiet` | `-q` | flag | `false` | Suppress banner and verbose output |

</details>

---

## 🎚️ Protection Levels

Use `--level` to apply a preset instead of toggling individual layers.

<details>
<summary><strong>Level 1 — Minimal</strong></summary>

**Layers active:** 1, 2, 3

Applies identifier renaming, string encryption, and number obfuscation. Extremely fast with minimal size overhead. Good for production scripts where performance matters.

```bash
python main.py --input script.lua --output out.lua --level 1
```

</details>

<details>
<summary><strong>Level 2 — Standard</strong></summary>

**Layers active:** 1, 2, 3, 4, 5, 6

Adds control flow flattening, opaque predicates, and dead code injection on top of Level 1. Recommended for most use cases. Output is structurally unrecognizable.

```bash
python main.py --input script.lua --output out.lua --level 2
```

</details>

<details>
<summary><strong>Level 3 — Maximum</strong></summary>

**Layers active:** 1, 2, 3, 4, 5, 6, 7, 8

Adds global table indirection and anti-tamper runtime checks. All API calls are hidden behind an XOR-indexed lookup table. Roblox exploit environment detection is active.

```bash
python main.py --input script.lua --output out.lua --level 3
```

</details>

<details>
<summary><strong>Level 4 — Paranoid</strong></summary>

**Layers active:** All 9

Enables the full VM virtualization pipeline on top of Level 3. Your script is compiled to a custom instruction set and executed by a generated stack-based interpreter. The constant pool is XOR-encrypted. No readable strings, no recognizable opcodes, no native structure.

```bash
python main.py --input script.lua --output out.lua --level 4
```

</details>

---

## 🔬 Technical Deep-Dive: The Obscura VM

> The VM is the most powerful protection layer. When enabled, your Luau source is never emitted directly — it is compiled into a custom bytecode format and executed by a runtime interpreter that is itself obfuscated and embedded in the output.

<details>
<summary><strong>Instruction Set (30+ opcodes)</strong></summary>

The VM implements a complete stack-based instruction set covering:

| Category | Instructions |
|----------|-------------|
| Stack | `PUSH_CONST`, `PUSH_LOCAL`, `SET_LOCAL`, `PUSH_NIL`, `PUSH_TRUE`, `PUSH_FALSE`, `POP`, `DUP`, `SWAP` |
| Arithmetic | `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `UNM`, `CONCAT` |
| Comparison | `EQ`, `LT`, `LE`, `NOT`, `LEN` |
| Control Flow | `JMP`, `JMP_FALSE`, `JMP_TRUE` |
| Functions | `CALL`, `RETURN`, `CLOSURE`, `VARARG` |
| Globals | `GET_GLOBAL`, `SET_GLOBAL` |
| Tables | `NEW_TABLE`, `GET_TABLE`, `SET_TABLE`, `SET_LIST` |
| Misc | `MOVE`, `NOP`, `PUSH_UPVAL`, `SET_UPVAL` |

</details>

<details>
<summary><strong>Polymorphic Opcode Mapping</strong></summary>

Every build generates a **fresh, random numeric mapping** for all opcodes. The same instruction (`ADD`, `CALL`, etc.) maps to a different byte value each run. This means:

- A deobfuscator that hardcodes `0x05 = ADD` for one build is wrong for every other build
- There is no universal opcode table to extract
- The interpreter itself uses these randomized values, so the mapping is only meaningful per-output

The opcode table is shuffled and assigned from `random.sample(range(1, 256), N)` using the seeded RNG.

</details>

<details>
<summary><strong>Encrypted Constant Pool</strong></summary>

All string constants used by the VM (including API names like `"Instance"`, `"workspace"`, `"GetService"`, etc.) are stored **XOR-encrypted** in the constant pool table.

- Each build generates a random single-byte XOR key
- All string bytes are XOR'd before being embedded as `\NNN` numeric escapes
- A compact runtime decryption loop decodes each string entry before the VM executes
- **No plaintext string names appear anywhere in the output**

Numbers, booleans, and nil are stored as-is since they carry no structural information.

</details>

<details>
<summary><strong>16-bit Jump Addressing</strong></summary>

Jump offsets are encoded as **little-endian 16-bit signed integers** (`offset_lo + offset_hi * 256`), supporting signed offsets in the range `-32768` to `+32767`. This allows scripts with thousands of instructions to be virtualized without truncation.

</details>

<details>
<summary><strong>Sub-Prototype Support (Closures)</strong></summary>

Anonymous functions and closures are compiled as **sub-prototypes** — separate bytecode streams stored alongside the main bytecode. The `CLOSURE` instruction creates a Luau function that wraps a recursive call to the VM with the sub-prototype's bytecode, allowing full nested function support.

</details>

---

## 🏗️ Architecture

```
obscura/
├── main.py               # CLI entry point (click-based)
├── obfuscator.py         # Pipeline orchestrator
├── config.py             # ObfuscationConfig dataclass + presets
│
├── parser/
│   ├── lexer.py          # Full Luau tokenizer
│   ├── parser.py         # Recursive-descent parser → AST
│   ├── ast_nodes.py      # All AST node dataclasses
│   ├── emitter.py        # AST → Luau source emitter (minified)
│   └── scope.py          # Scope tree + variable tracking
│
├── layers/
│   ├── identifier.py     # Layer 1: Identifier renaming
│   ├── strings.py        # Layer 2: String encryption
│   ├── numbers.py        # Layer 3: MBA number obfuscation
│   ├── cff.py            # Layer 4: Control flow flattening
│   ├── predicates.py     # Layer 5: Opaque predicates
│   ├── deadcode.py       # Layer 6: Dead code injection
│   ├── indirection.py    # Layer 7: Table indirection
│   ├── antitamper.py     # Layer 8: Anti-tamper injection
│   └── vm/
│       ├── opcodes.py        # Opcode definitions + randomized mapping
│       ├── constant_pool.py  # Constant pool management + encryption
│       ├── compiler.py       # AST → custom bytecode compiler
│       └── interpreter.py    # Polymorphic Luau VM stub generator
│
└── utils/
    ├── names.py          # Obfuscated identifier name generator
    ├── crypto.py         # XOR encryption, Base64, MBA utilities
    └── globals.py        # Roblox/Luau globals whitelist (never rename)
```

<details>
<summary><strong>Pipeline execution order</strong></summary>

**Standard mode (layers 1–8):**

```
Source
  → strip_types()          # Remove Luau type annotations
  → strip_comments()       # Remove all comments
  → Parser → AST
  → Layer 4: CFF           # Must run before identifier renaming (hoists locals)
  → Layer 5: Predicates
  → Layer 6: Dead Code
  → Layer 3: Numbers       # MBA runs after structure is established
  → Layer 2: Strings       # Injects decoder header at top
  → Layer 1: Identifiers   # Renames everything including injected names
  → Layer 7: Indirection   # Wraps globals after renaming
  → Layer 8: Anti-Tamper   # Wraps entire block in IIFE
  → Emitter → minified output
```

**VM mode (layer 9):**

```
Source
  → strip_types() + strip_comments()
  → Parser → AST
  → VMCompiler → FunctionPrototype (bytecode + constant pool)
  → InterpreterGenerator → Luau VM stub with encrypted constants
  → IIFE wrap → minified output
```

</details>

---

## 🔍 How Each Layer Works

<details>
<summary><strong>Layer 1 — Identifier Renaming</strong></summary>

Walks the entire AST with a scope-aware visitor. Every local variable, function parameter, and local function name is replaced with a randomly-generated obfuscated name.

Three name strategies are mixed per-build:
- **Confusable**: Uses only `l`, `I`, `1` characters — visually indistinguishable
- **Hex-style**: Generates names like `_0x3fa2c1`
- **Underscore-mangled**: Generates names like `__x_yz_w`

A whitelist (`utils/globals.py`) of all Lua stdlib, Roblox globals, datatypes, and services ensures that protected names are never renamed, preventing broken output.

</details>

<details>
<summary><strong>Layer 2 — String Encryption</strong></summary>

Collects all string literals in the AST, encrypts each with an independent random XOR key, Base64-encodes the result, and stores everything in a centralized string table.

A polymorphic Base64+XOR decoder function is injected at the top of the script with all its internal variable names obfuscated. Each string reference in the code is replaced with a call to this decoder.

**Example transformation:**
```lua
-- Before
local name = "workspace"

-- After (conceptual)
local _T = {"d29ya3NwYWNl"}  -- base64(xor("workspace", 42))
local _D = (function() ... end)()  -- decoder
local name = _D(_T[1], 42)
```

</details>

<details>
<summary><strong>Layer 3 — Number Obfuscation (MBA)</strong></summary>

Replaces integer literals with Mixed Boolean-Arithmetic expressions that evaluate to the same value at runtime.

Four strategies (randomly chosen per number):
- **Arithmetic**: `(N + R) - R` with nested XOR inner expressions
- **XOR identity**: `bit32.bxor(N ^ K, K)`
- **Multiplication**: `math.floor((N * M) / M)`
- **Decomposition**: `bit32.bxor(A ^ K, (A ^ N) ^ K)`

Trivial values (0, 1, -1) and floats are skipped. Numbers larger than `0xFFFFFF` are skipped to avoid `bit32` overflow.

</details>

<details>
<summary><strong>Layer 4 — Control Flow Flattening</strong></summary>

The most structurally disruptive layer. Transforms every block of sequential statements into a `while true do` state-machine:

1. Each original statement is assigned a unique random state value
2. Local variable declarations are **hoisted** above the loop to preserve scope
3. The loop body is a single `if/elseif` chain dispatching on the current state
4. Elseif clauses are **shuffled** randomly, destroying execution order hints
5. State transitions can optionally be **XOR-encoded**: `state = bit32.bxor(encoded, key)`

**Example transformation:**
```lua
-- Before
local x = 1
local y = x + 2
print(y)

-- After (conceptual)
local x
local y
local _s = 47291   -- random initial state
while true do
  if _s == 47291 then x = 1; _s = bit32.bxor(19874, 6621)
  elseif _s == 13253 then print(y); break
  elseif _s == 29882 then y = x + 2; _s = 13253
  else error("CFF Error: Invalid state") end
end
```

</details>

<details>
<summary><strong>Layer 5 — Opaque Predicates</strong></summary>

Injects two types of mathematically-grounded conditions that analysis tools cannot resolve:

- **Always-true predicates** wrap real code: `if bit32.bxor(N,N)==0 then ... end`
- **Always-false predicates** guard dead branches: `if (function() local v=N return v*v<0 end)() then error("unreachable") end`

True predicate strategies: `x*x >= 0`, `bxor(x,x)==0`, `a²+b²==known`, `(p*k)%p==0`, `type(nil)=="nil"`.

</details>

<details>
<summary><strong>Layer 6 — Dead Code Injection</strong></summary>

Sprinkles inert code throughout the script at configurable density (low/medium/high).

Injection types:
- **Junk locals**: `local _x = math.floor(47)` — real computation, result unused
- **Shadow variables**: `do local _x = "shadow"; local _y = _x end` — isolated scope, confuses readers

Dead code is never injected after terminal statements (`return`, `break`, `continue`) to avoid syntax errors.

</details>

<details>
<summary><strong>Layer 7 — Table Indirection</strong></summary>

Collects all references to Lua stdlib and Roblox globals, assigns each a random index, and replaces all accesses with XOR-indexed table lookups.

```lua
-- Before
local part = Instance.new("Part")
math.random(1, 10)

-- After (conceptual)
local _T = {[1]=Instance, [3]=math.random, ...}  -- shuffled
local part = _T[bit32.bxor(encoded_1, key)].new("Part")
_T[bit32.bxor(encoded_3, key)](1, 10)
```

The table field order is shuffled, and the index values are XOR-encoded, making static lookup analysis non-trivial.

</details>

<details>
<summary><strong>Layer 8 — Anti-Tamper</strong></summary>

Injects three categories of runtime protection at the top of the script:

**Environment checks:**
- Verifies `typeof` and `game` are not nil (not running outside Roblox)
- Verifies `game:GetService("RunService")` succeeds

**Hook detection:**
- Backs up the native `type` function
- Checks that known exploit globals (`getgenv`, `hookfunction`, `fireclickdetector`, `getrawmetatable`, `newcclosure`, `checkcaller`) are nil
- Verifies `print` is still a function (not hooked)

**Integrity check:**
- Stores `tostring(print)` at startup and verifies it hasn't changed

Any violation calls `error()` immediately. The entire script is wrapped in a `do local _ = (function() ... end)() end` IIFE to prevent global scope leakage.

</details>

---

## ❓ FAQ

<details>
<summary><strong>Does Obscura guarantee my script can never be deobfuscated?</strong></summary>

No obfuscator can offer a mathematical guarantee. However, Obscura stacks 9 independent protection layers, uses per-build randomization, and encrypts all constants. A deobfuscator would need to: reverse the VM opcodes (randomized per build), decrypt the constant pool (random XOR key), un-flatten the CFF (shuffled state machine), and defeat string decryption — all simultaneously. The cost of analysis far exceeds the value of most scripts.

</details>

<details>
<summary><strong>Will the output run correctly in Roblox Studio?</strong></summary>

Yes. The output includes `--!nocheck` and `--!nolint` directives to suppress Studio type checker warnings. The emitter targets Roblox Luau syntax specifically, and all generated runtime code (`bit32`, `unpack`, `string.byte`, etc.) uses Roblox-available APIs.

</details>

<details>
<summary><strong>Why does VM mode produce larger output?</strong></summary>

The VM embeds a complete stack-based interpreter in the output alongside the compiled bytecode and encrypted constant pool. This overhead is fixed per-script (roughly 3-5KB for the interpreter stub) and does not scale with script size. For very small scripts, the overhead ratio is high; for larger scripts it becomes negligible.

</details>

<details>
<summary><strong>Can I use --seed for reproducible builds?</strong></summary>

Yes. Passing `--seed <integer>` fixes the RNG for the entire pipeline, producing identical output for the same input. Useful for diffing, CI/CD pipelines, or comparing builds. Without `--seed`, the seed is derived from the current timestamp in milliseconds.

</details>

<details>
<summary><strong>What Luau features are supported?</strong></summary>

The parser and compiler support: local variables, functions (named, anonymous, local, method syntax), all control flow (`if/elseif/else`, `while`, `repeat/until`, numeric `for`, generic `for`, `break`, `continue`), tables, string/number/boolean/nil literals, all arithmetic and comparison operators, method calls (`:` syntax), varargs (`...`), `do...end` blocks, and Luau type annotations (stripped before processing).

</details>

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full text.

---

## ⚠️ Disclaimer

Obscura is intended for **educational purposes** and for protecting intellectual property within the Roblox ecosystem. The authors are not responsible for misuse. Do not use this tool on code you do not own or do not have explicit permission to obfuscate.
