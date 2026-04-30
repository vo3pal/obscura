# Obscura

<div align="center">

**Luau Obfuscation Engine for Roblox Studio**

*9 independent protection layers. Custom register-based VM. Per-build randomized opcode mapping. Zero plaintext output.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Target-Roblox%20%2F%20Luau-E2231A?style=for-the-badge)](https://luau-lang.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Layers](https://img.shields.io/badge/Protection%20Layers-9-a855f7?style=for-the-badge)](#%EF%B8%8F-protection-layers)
[![VM](https://img.shields.io/badge/Custom%20VM-30%2B%20Opcodes-f59e0b?style=for-the-badge)](#-technical-deep-dive-the-obscura-vm)

</div>

---

> [!IMPORTANT]
> Obscura is a **research and portfolio project** exploring Luau bytecode virtualization, register-based VM design, control-flow protection, and source transformation techniques — built for educational purposes. Use responsibly and only on code you own or have explicit permission to protect.

---

## 📑 Table of Contents

- [Before & After](#-before--after)
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

## 👁️ Before & After

> Same script. Same functionality. Unrecognizable output.

### The original script

```lua
while true do
    local part = Instance.new("Part")
    local size = math.random(2, 10)
    part.Size = Vector3.new(size, size, size)
    part.Position = Vector3.new(
        math.random(-50, 50),
        math.random(50, 100),
        math.random(-50, 50)
    )
    part.Anchored = false
    part.Material = Enum.Material.SmoothPlastic
    part.Color = Color3.fromRGB(
        math.random(0, 255),
        math.random(0, 255),
        math.random(0, 255)
    )
    part.Parent = workspace
    game:GetService("Debris"):AddItem(part, 10)
    wait(0.3)
end
```

---

### After Layer 1 — Identifier Renaming

All local names replaced with randomized confusable identifiers. Globals (`Instance`, `math`, `workspace`) are preserved exactly.

```lua
while true do
    local lIlIllIIlIl = Instance.new("Part")
    local _0x4fa2 = math.random(2, 10)
    lIlIllIIlIl.Size = Vector3.new(_0x4fa2, _0x4fa2, _0x4fa2)
    lIlIllIIlIl.Position = Vector3.new(
        math.random(-50, 50), math.random(50, 100), math.random(-50, 50)
    )
    lIlIllIIlIl.Anchored = false
    lIlIllIIlIl.Material = Enum.Material.SmoothPlastic
    lIlIllIIlIl.Color = Color3.fromRGB(
        math.random(0, 255), math.random(0, 255), math.random(0, 255)
    )
    lIlIllIIlIl.Parent = workspace
    game:GetService("Debris"):AddItem(lIlIllIIlIl, 10)
    wait(0.3)
end
```

---

### After Layer 2 — String Encryption

Every string literal is Base64+XOR encrypted and replaced with a runtime decoder call. No string appears in plaintext.

```lua
local lIlIIlIlIl = {"UGFydA==", "RGVicmlz", "U21vb3RoUGxhc3RpYw==", ...}
local llIIlIIllI = (function()
    -- polymorphic Base64+XOR decoder, all internals obfuscated
    ...
end)()
-- "Part"   → llIIlIIllI(lIlIIlIlIl[1], 187)
-- "Debris" → llIIlIIllI(lIlIIlIlIl[2], 54)
Instance.new(llIIlIIllI(lIlIIlIlIl[1], 187))
game:GetService(llIIlIIllI(lIlIIlIlIl[2], 54))
```

---

### After Layer 3 — Number Obfuscation (MBA)

Every numeric literal is replaced with a mathematically-equivalent Mixed Boolean-Arithmetic expression.

```lua
-- 10  →  bit32.bxor(bit32.bxor(10, 0xA3F1) + 0xA3F1, 0)
-- 255 →  math.floor((255 * 7919) / 7919)
-- 50  →  bit32.bxor(0x6D ^ 0x43, (0x6D ^ 50) ^ 0x43)
-- 0.3 →  0.3   (floats are not obfuscated)
math.random(bit32.bxor(bit32.bxor(2,0xF4A)+0xF4A,0), math.floor((10*6247)/6247))
```

---

### After Layer 4 — Control Flow Flattening

The loop body is shattered into a shuffled `while true` state machine. Execution order is completely non-linear and unrecoverable statically.

```lua
local lIlIllIIlIl, _0x4fa2
local __s = 81742
while true do
    if __s == 29371 then
        lIlIllIIlIl.Parent = workspace; __s = bit32.bxor(54219, 11083)
    elseif __s == 81742 then
        lIlIllIIlIl = Instance.new("Part"); __s = bit32.bxor(77401, 29187)
    elseif __s == 48214 then
        lIlIllIIlIl.Anchored = false; __s = 91023
    elseif __s == 45132 then
        wait(0.3); break
    -- ... 6 more shuffled states
    else error("CFF Error: invalid state") end
end
```

---

### After Layer 9 — Full VM Virtualization

The entire script is compiled into a custom register-based bytecode format. No Luau source is emitted. A generated interpreter stub executes it — with polymorphic opcodes, encrypted constants, and no readable identifiers anywhere.

```
--!nocheck
--!nolint
-- Obscura VM [dfb89be2]
(function(...) local lIIllIlIIl={...};local llIlIIllIl=table.unpack or unpack
local IlIIlIlIlI={[1]={bc="\163\049\217\091\044\182\201...",...,nuv=2,np=0},
...}
local IllIlIllIl={{"\163\049","\217\091",...}}  -- XOR-encrypted constant pool
local function IlIlIlIIIl(proto,upvals,...)
-- ... 200+ line polymorphic interpreter with randomized opcode dispatch ...
end
return IlIlIlIIIl(IlIIlIlIlI[1],{},...) end)(...)
```

**Stats for the script above:**

| Metric | Value |
|--------|-------|
| Original size | `560 B` |
| Level 2 output | `~5.2 KB` (9.3×) |
| Level 4 VM output | `~49 KB` (87×) |
| Plaintext strings in output | `0` |
| Recognizable variable names | `0` |
| Opcode mapping lifespan | single build only |

---

## 🌐 Overview

Obscura is a multi-stage source-to-source transformer that takes readable Luau code and produces output that is:

- **Unreadable** — all identifiers replaced with randomized, visually-confusing names using three name strategies mixed per-build
- **Encrypted** — all string constants and VM constants XOR-encrypted; no plaintext in output
- **Structurally destroyed** — control flow flattened into a shuffled state-machine dispatcher; original code structure is irrecoverable
- **Mathematically obscured** — every integer replaced with a Mixed Boolean-Arithmetic expression evaluating to the same value
- **Virtualized** — optionally compiled into a custom 30+ opcode register-based instruction set executed by a generated interpreter
- **Anti-analyzed** — runtime checks for exploit globals, environment hooks, and function integrity

Each build is **unique and non-reproducible by default** (seeded by timestamp milliseconds). Every output uses different opcode byte values, different identifier names, different XOR keys, and a different build ID. A deobfuscator built for build `dfb89be2` will not work on build `dfb89be3`.

---

## 🛡️ Protection Layers

Obscura applies up to **9 independent layers** in a defined pipeline. Each layer adds a new attack surface an adversary must defeat.

| # | Layer | What It Does | Size Impact |
|---|-------|-------------|-------------|
| 1 | **Identifier Renaming** | Randomized confusable/hex/mangled variable names | ~−15% (minification) |
| 2 | **String Encryption** | Per-string XOR+Base64 encryption with polymorphic decoder | ~+50% |
| 3 | **Number Obfuscation (MBA)** | Mixed Boolean-Arithmetic expression substitution | ~+10% |
| 4 | **Control Flow Flattening** | Shuffled `while true` state-machine dispatcher | ~+3× |
| 5 | **Opaque Predicates** | Irresolvable always-true/false branch injection | ~+20% |
| 6 | **Dead Code Injection** | Realistic unreachable junk computations | ~+15% |
| 7 | **Table Indirection** | XOR-keyed lookup table for all global/API accesses | ~+5% |
| 8 | **Anti-Tamper** | Runtime exploit detection + integrity verification | ~+3 KB |
| 9 | **VM Virtualization** | Custom encrypted bytecode + generated interpreter | ~+40 KB |

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **pip** (standard with Python)
- A **Roblox Studio** environment for testing VM output

### Installation

```bash
git clone https://github.com/vo3pal-ux/obscura.git
cd obscura
pip install -r requirements.txt
```

### Quick Start

```bash
# Standard obfuscation (layers 1-8)
python main.py --input script.lua --output protected.lua

# Full 9-layer protection with VM
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

Identifier renaming, string encryption, number obfuscation. Minimal size overhead. Good for production scripts where performance matters.

```bash
python main.py --input script.lua --output out.lua --level 1
```

</details>

<details>
<summary><strong>Level 2 — Standard</strong></summary>

**Layers active:** 1, 2, 3, 4, 5, 6

Adds control flow flattening, opaque predicates, and dead code injection. Output is structurally unrecognizable. Recommended for most use cases.

```bash
python main.py --input script.lua --output out.lua --level 2
```

</details>

<details>
<summary><strong>Level 3 — Maximum</strong></summary>

**Layers active:** 1, 2, 3, 4, 5, 6, 7, 8

Adds global table indirection and anti-tamper runtime checks. All API calls are hidden behind an XOR-indexed lookup table. Exploit environment detection active.

```bash
python main.py --input script.lua --output out.lua --level 3
```

</details>

<details>
<summary><strong>Level 4 — Paranoid</strong></summary>

**Layers active:** All 9

Full VM virtualization. Your script is compiled to a custom register-based instruction set and executed by a generated interpreter embedded in the output. The constant pool is XOR-encrypted. No readable strings, no recognizable opcodes, no native Luau structure visible.

```bash
python main.py --input script.lua --output out.lua --level 4
```

</details>

---

## 🔬 Technical Deep-Dive: The Obscura VM

> The VM is the highest-complexity protection layer. When enabled, your Luau source is **never emitted** — it is compiled into a custom register-based bytecode format and executed by a runtime interpreter that is itself obfuscated and embedded in the output.

<details>
<summary><strong>Register-Based Architecture</strong></summary>

Unlike stack-based VMs, Obscura uses a **register-based design** (similar to Lua 5.1's own bytecode):

- Each function prototype has a fixed-size register file (`R[0]..R[N]`)
- Locals occupy stable register slots in declaration order
- Temporaries use registers above the active local high-water mark and are reclaimed after each expression
- Multi-return calls use sentinel `B=0`/`C=0` to indicate "all results to top of stack"
- `CALL A B C` — function in `R[A]`, args in `R[A+1]..R[A+B-1]`, results written back to `R[A]`

</details>

<details>
<summary><strong>Instruction Set (30+ opcodes)</strong></summary>

| Category | Instructions |
|----------|-------------|
| **Loads** | `LOADK`, `LOADNIL`, `LOADBOOL` |
| **Moves** | `MOVE`, `GETUPVAL`, `SETUPVAL` |
| **Globals** | `GETGLOBAL`, `SETGLOBAL` |
| **Tables** | `GETTABLE`, `SETTABLE`, `GETTABLEK`, `SETTABLEK`, `NEWTABLE`, `SETLIST`, `SELF` |
| **Arithmetic** | `ADD`, `SUB`, `MUL`, `DIV`, `MOD`, `POW`, `UNM`, `CONCAT`, `LEN` |
| **Comparison** | `EQ`, `LT`, `LE`, `TEST`, `TESTSET` |
| **Jumps** | `JMP`, `FORPREP`, `FORLOOP`, `TFORLOOP` |
| **Functions** | `CALL`, `TAILCALL`, `RETURN`, `CLOSURE`, `VARARG` |
| **Closures** | `MKBOX`, `GETBOX`, `SETBOX` — captured upvalue boxing |
| **Misc** | `NOP` |

</details>

<details>
<summary><strong>Polymorphic Opcode Mapping</strong></summary>

Every build generates a **fresh, random numeric mapping** for all opcodes using `random.sample(range(1, 256), N)` seeded by the build timestamp. The same logical instruction (`ADD`, `CALL`, etc.) maps to a different byte value each run:

```
Build A:  ADD=0x3F  CALL=0xA7  JMP=0x12
Build B:  ADD=0xC2  CALL=0x55  JMP=0xE9
```

- A deobfuscator that hardcodes any opcode byte is wrong for every other build
- The interpreter dispatch table itself uses these randomized values
- There is no static universal opcode table to extract

</details>

<details>
<summary><strong>Encrypted Constant Pool</strong></summary>

All string constants — including API names like `"Instance"`, `"workspace"`, `"GetService"`, property names like `"Size"`, `"Color"` — are **XOR-encrypted** before embedding:

- Random single-byte XOR key per build
- All string bytes XOR'd and embedded as `\NNN` numeric escapes
- A compact runtime decryption loop decodes each entry before the VM starts
- **Zero plaintext string names in the output**

Numbers, booleans, and nil are stored as-is (no structural information).

</details>

<details>
<summary><strong>16-bit Jump Addressing</strong></summary>

Jump offsets are encoded as **little-endian 16-bit signed integers** (`lo + hi * 256`), supporting offsets in the range `−32768` to `+32767`. Scripts with thousands of instructions can be virtualized without truncation.

</details>

<details>
<summary><strong>Closure and Sub-Prototype Support</strong></summary>

Nested functions and closures compile as **sub-prototypes** — separate bytecode streams stored alongside the main prototype. The `CLOSURE` instruction:

1. Reads `N` pseudo-instructions (`MOVE`/`GETUPVAL`) that link upvalue slots
2. Creates a Luau `function` wrapper that calls the VM interpreter recursively with the sub-prototype's bytecode and the captured upvalue list

Captured locals are **boxed** via `MKBOX`/`GETBOX`/`SETBOX` instructions so mutations in a closure propagate back to the enclosing scope correctly.

</details>

---

## 🔍 How Each Layer Works

<details>
<summary><strong>Layer 1 — Identifier Renaming</strong></summary>

Walks the entire AST with a scope-aware visitor. Every local variable, function parameter, and local function name is replaced with a randomly-generated name. Three strategies are mixed per-build:

- **Confusable** — uses only `l`, `I`, `1` characters: `lIlIIllIlI` — visually indistinguishable at a glance
- **Hex-style** — generates names like `_0x3fa2c1`
- **Underscore-mangled** — generates names like `__x_yz_w`

A whitelist (`utils/globals.py`) covering all Lua stdlib, Roblox globals, datatypes, services, and enum paths ensures protected names are never renamed.

</details>

<details>
<summary><strong>Layer 2 — String Encryption</strong></summary>

Collects all string literals in the AST, encrypts each with an independent random XOR key, Base64-encodes the ciphertext, stores everything in a centralized string table, and injects a polymorphic decoder at the top of the script.

```lua
-- Before
local material = "SmoothPlastic"

-- After
local _T = {"U21vb3RoUGxhc3RpYw==", ...}
local _D = (function() --[[ Base64+XOR decoder, fully obfuscated ]] end)()
local material = _D(_T[1], 187)
```

</details>

<details>
<summary><strong>Layer 3 — Number Obfuscation (MBA)</strong></summary>

Replaces integer literals with Mixed Boolean-Arithmetic expressions. Four strategies chosen randomly per number:

```lua
-- 255 → math.floor((255 * 7919) / 7919)
-- 10  → bit32.bxor(bit32.bxor(10, 0xA3F1) + 0xA3F1, 0)
-- 50  → bit32.bxor(0x6D ~ 0x43, (0x6D ~ 50) ~ 0x43)
-- 2   → (bit32.bxor(2, R) + R) - R   where R is a random constant
```

Trivial values (`0`, `1`, `-1`), floats, and numbers above `0xFFFFFF` are skipped.

</details>

<details>
<summary><strong>Layer 4 — Control Flow Flattening</strong></summary>

The most structurally disruptive layer. Every block of sequential statements becomes a shuffled `while true` state machine:

1. Each statement assigned a unique random state integer
2. Local declarations **hoisted** above the loop to preserve scope
3. `if/elseif` chain dispatches on current state — order **shuffled**
4. State transitions optionally **XOR-encoded**: `_s = bit32.bxor(encoded, key)`

```lua
-- Before: 3 sequential statements
local x = 1; local y = x + 2; print(y)

-- After: shuffled state machine
local x, y
local _s = 81742
while true do
    if _s == 29371 then print(y); break
    elseif _s == 81742 then x = 1; _s = bit32.bxor(44109, 13227)
    elseif _s == 56882 then y = x + 2; _s = 29371
    else error("CFF Error: invalid state") end
end
```

</details>

<details>
<summary><strong>Layer 5 — Opaque Predicates</strong></summary>

Injects mathematically-grounded conditions that static analysis cannot resolve:

- **Always-true** wraps real code: `if bit32.bxor(N, N) == 0 then ... end`
- **Always-false** guards unreachable branches: `if (function() local v=N return v*v<0 end)() then error() end`

Predicate strategies: `x*x >= 0`, `bxor(x,x)==0`, `a²+b²==known`, `(p*k)%p==0`, `type(nil)=="nil"`.

</details>

<details>
<summary><strong>Layer 6 — Dead Code Injection</strong></summary>

Sprinkles inert code at configurable density (`low`/`medium`/`high`):

- **Junk locals** — `local _x = math.floor(47)` — real computation, result discarded
- **Shadow scopes** — `do local _x = "shadow"; local _y = _x end` — isolated, confuses readers

Never injected after terminal statements (`return`, `break`, `continue`).

</details>

<details>
<summary><strong>Layer 7 — Table Indirection</strong></summary>

Hides every global and API reference behind an XOR-indexed lookup table:

```lua
-- Before
local part = Instance.new("Part")
math.random(1, 10)

-- After
local _T = {[bit32.bxor(3,0x5A)]=Instance, [bit32.bxor(7,0x5A)]=math.random}
local part = _T[bit32.bxor(3, 0x5A)].new("Part")
_T[bit32.bxor(7, 0x5A)](1, 10)
```

Table field order is shuffled per-build. Index values are XOR-encoded, making static lookup reconstruction non-trivial.

</details>

<details>
<summary><strong>Layer 8 — Anti-Tamper</strong></summary>

Injects three categories of runtime protection:

**Environment validation:**
- Verifies `typeof` and `game` are not `nil` (rejects non-Roblox environments)
- Verifies `game:GetService("RunService")` succeeds

**Hook detection:**
- Backs up native `type` function
- Checks that known exploit globals (`getgenv`, `hookfunction`, `fireclickdetector`, `getrawmetatable`, `newcclosure`, `checkcaller`) are absent
- Verifies `print` is still a function (not replaced by a hook)

**Integrity check:**
- Captures `tostring(print)` at script start and re-validates it hasn't changed

Any violation calls `error()` immediately. The full block is wrapped in a `do local _ = (function() ... end)() end` IIFE to prevent global scope leakage.

</details>

---

## ❓ FAQ

<details>
<summary><strong>Does Obscura guarantee my script can never be deobfuscated?</strong></summary>

No obfuscator can offer a mathematical guarantee — a sufficiently motivated and resourced attacker can always reverse anything given enough time. However, Obscura stacks 9 independent layers, uses per-build randomization, and encrypts all constants. A complete reversal requires: recovering the randomized opcode table, decrypting the XOR constant pool, un-flattening the CFF state machine (shuffled per-build), defeating string decryption, and reconstructing the original identifier mapping — all without any shared state between builds. The practical cost of analysis far exceeds the value of most scripts.

</details>

<details>
<summary><strong>Will the output run correctly in Roblox Studio?</strong></summary>

Yes. All output includes `--!nocheck` and `--!nolint` directives to suppress Studio type-checker warnings. The emitter and VM stub target Roblox Luau syntax specifically, and all runtime code (`bit32`, `table.unpack`, `string.byte`, etc.) uses only Roblox-available APIs.

</details>

<details>
<summary><strong>Why does VM mode produce much larger output?</strong></summary>

The VM embeds a complete register-based interpreter (~40 KB) alongside the compiled bytecode and encrypted constant pool. This is fixed overhead per output — it does not scale with script size. For small scripts the size ratio is high; for larger scripts it becomes negligible.

</details>

<details>
<summary><strong>Can I use --seed for reproducible builds?</strong></summary>

Yes. `--seed <integer>` fixes the RNG for the entire pipeline, producing identical output for the same input. Useful for diffing, CI/CD, or comparing builds. Without `--seed`, the seed is derived from the current timestamp in milliseconds — every run produces a different build.

</details>

<details>
<summary><strong>What Luau features are supported?</strong></summary>

The parser and compiler support: local variables, all function forms (named, anonymous, local, method `:` syntax), all control flow (`if/elseif/else`, `while`, `repeat/until`, numeric `for`, generic `for`, `break`, `continue`), tables (array and record constructors), string/number/boolean/nil literals, all arithmetic and comparison operators, method calls, varargs (`...`), `do...end` blocks, and Luau type annotations (stripped at the start of the pipeline).

</details>

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full text.

---

## ⚠️ Disclaimer

Obscura is a **research and portfolio project** built for educational exploration of compiler design, bytecode virtualization, and program transformation. It is not affiliated with or endorsed by Roblox Corporation. I wont be held responsible for any misuse.
