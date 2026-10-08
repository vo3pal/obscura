# Obscura

A Luau obfuscator for Roblox. Version 1.1.0. Requires Python 3.10 or newer.

**[TRY HERE — obscura.vo3pal.dev](https://obscura.vo3pal.dev/)**

## Setup

```sh
git clone https://github.com/vo3pal/obscura.git
cd obscura
python -m pip install -r requirements.txt
```

## Usage

Run from the project folder. Start with the included example:

```sh
python main.py examples/score.luau
```

This writes `examples/score.obf.luau`. Paste the entire generated file into a
Script in `ServerScriptService` and press Play; it should print `15`.
For a LocalScript, use a client location such as `StarterPlayerScripts`.
Obscura transforms code locally; it does not upload it to Roblox.

For your own script:

```sh
python main.py script.luau
python main.py script.luau --mode vm -o dist/script.luau
python main.py "C:/My Project/Pasted text.txt" --mode vm
```

Without `-o`, a file becomes `NAME.obf.luau` (or `NAME.obf.lua` for `.lua` input).
Pasted `.txt` files containing Luau also work. Keep the original for editing;
Obscura rejects an output path that would overwrite the input.

## Modes

The CLI defaults to `lightweight`. Choose a mode with `--mode`:

| Mode | Behavior |
| --- | --- |
| `lightweight` | Renames locals, minifies, and decodes strings at startup. |
| `rename` | Renames locals and minifies; leaves literals readable. |
| `native` | Adds integer expressions, eligible control-flow changes, dead code, global indirection and checks. |
| `vm` | Uses the max VM profile with rolling bytecode reads, encoded constants, randomized instruction layouts, fusion and payload checks. |

```sh
python main.py examples/score.luau --mode rename
python main.py examples/score.luau --mode native
python main.py examples/score.luau --mode vm
```

**Rolling decode is on by default whenever VM execution is enabled**, including
`--mode vm`, `--vm`, `--level 4` and Python configurations. It leaves the stored
bytecode encoded and decodes each instruction/operand read. It adds runtime work
and does not prevent recovery of the script's behavior.

To decode each function's bytecode once and cache it instead:

```sh
python main.py script.luau --mode vm --vm-cached
```

`--vm-rolling` explicitly selects the default. `--mode vm` selects the `max`
profile; the older `--vm` flag selects `basic` unless a profile is provided.
For example, to select the smaller fusion budget of `client-max`:

```sh
python main.py script.luau --mode vm --vm-hardening client-max
```

Use `--help` for common options or `--help-all` for individual settings and older
flags. Explicit `--input`, `--output`, `--level`, `--vm`, `--lightweight` and
`--rename-only` commands still work. Omit `--seed` unless you need repeatable
development output. Builds without it use a fresh random seed.

## Folders

```sh
python main.py scripts
python main.py scripts --mode vm -o dist
```

Folders recurse through `.lua` and `.luau` files and preserve their relative
paths. The first command writes to `scripts-obfuscated`; the second writes to
`dist`. Generated `.obf` files are skipped. Keep output outside the input folder.
If one file fails, the other files are still processed and the command exits
with an error. Use `--quiet` to suppress successful-file messages.

## Example

[examples/score.luau](examples/score.luau) prints `15`:

```lua
local function addBonus(score)
    return score + 10
end

print(addBonus(5))
```

```sh
python main.py examples/score.luau --mode rename --seed 12345 -o dist/score-renamed.luau
```

Complete generated output:

```lua
--!nocheck
--!nolint
-- Obscura [development]
local function _0x9b68(_ldniruftrf) return _ldniruftrf+10 end print(_0x9b68(5))
```

This is actual output from the command above. It demonstrates renaming; the `10`
remains readable. Original local names and comments are discarded. Table fields,
Roblox property names and API names retain their meaning so the code still works.
For VM output, run the same command with `--mode vm` and omit the development seed.

## ModuleScripts

```sh
python main.py examples/module.luau --mode vm -o dist/module.luau
```

Paste the entire output into a ModuleScript named `Score` in `ReplicatedStorage`.
Use it from a separate Script:

```lua
local score = require(game:GetService("ReplicatedStorage"):WaitForChild("Score"))
assert(score.Payload == "Round score")
assert(score:Add(5) == 5)
assert(score:Add(10) == 15)
print(score.Total) -- 15
```

The included module returns a table with methods and persistent state. Paste
the output into a ModuleScript, keeping the `return`; do not add another wrapper.

## Python

Use the lightweight preset to match the CLI default:

```python
from config import lightweight_config
from obfuscator import Obfuscator

output = Obfuscator(lightweight_config()).obfuscate('print("Hello, Roblox")')
```

For the max VM profile with default rolling reads:

```python
from config import ObfuscationConfig
from obfuscator import Obfuscator

config = ObfuscationConfig(virtualize=True, vm_hardening="max")
output = Obfuscator(config).obfuscate('return {Total = 5050}')
```

Set `vm_predecode_bytecode=True` for cached bytecode. A plain
`ObfuscationConfig()` selects native layer settings, not the CLI's lightweight
preset; `virtualize=True` alone selects the basic VM profile.

## Limits

The parser supports a subset of Luau. Backtick interpolation, floor division
(`//`), multiline type aliases and protected iterator metatables are unsupported.
Generated helpers can also run into compiler register/upvalue limits.

VM output can be much larger and slower than the original. Test your script in
Roblox Studio, especially code that runs every frame. Constants and behavior
can still be recovered, including with rolling decode. Keep secrets and
authoritative game rules on the server. Fresh Studio testing of this update is
pending; there is no 10% total-overhead or whole-game FPS guarantee.

[Test instructions](tests/README.md) · [MIT license](LICENSE)
