# LuauShield — Advanced Luau Obfuscator

**LuauShield** is a professional-grade obfuscation engine designed specifically for Luau, the scripting language used in Roblox Studio. It employs a multi-layered protection system to secure your intellectual property against reverse engineering and unauthorized tampering.

## 🛡️ Key Features

LuauShield features a comprehensive **9-Layer Protection System**:

1.  **Identifier Renaming**: Comprehensive renaming of local and global variables using various entropy-based strategies.
2.  **String Encryption**: Dynamic encryption of all literal strings with runtime decryption.
3.  **Number Obfuscation**: Transformation of numeric constants into complex Mixed Boolean-Arithmetic (MBA) expressions.
4.  **Control Flow Flattening**: Radical restructuring of program logic into a state-machine based dispatch loop.
5.  **Opaque Predicates**: Insertion of branching logic based on values that are constant but difficult for static analyzers to determine.
6.  **Dead Code Injection**: Intelligent injection of non-functional code to confuse deobfuscators and increase analysis time.
7.  **Table Indirection**: Abstracting table accesses through a secure proxy layer.
8.  **Anti-Tamper**: Runtime environment checks to detect hooks, debuggers, and code modification.
9.  **VM Virtualization**: (Premium) A custom-built virtual machine that compiles your Luau code into a private bytecode format executed by a secure interpreter.

## 🚀 Installation

Ensure you have Python 3.8+ installed.

```bash
git clone https://github.com/yourusername/LuauShield.git
cd LuauShield
pip install -r requirements.txt
```

## 💻 Usage

### Basic Obfuscation
```bash
python main.py --input script.lua --output protected.lua
```

### Advanced Configuration
```bash
# Enable VM Virtualization and Anti-Tamper
python main.py -i script.lua -o protected.lua --vm --antitamper

# Set Protection Level (1-4)
python main.py -i script.lua -o protected.lua --level 3

# Process an entire directory recursively
python main.py -i ./src -o ./dist --recursive
```

### CLI Options
| Option | Description |
| --- | --- |
| `--input, -i` | Input file or directory |
| `--output, -o` | Output file or directory |
| `--level, -l` | Protection level (1: Minimal, 4: Paranoid) |
| `--vm` | Enable Layer 9 (Virtualization) |
| `--antitamper` | Enable Layer 8 (Anti-Tamper) |
| `--recursive, -r`| Process directories recursively |
| `--seed` | Random seed for reproducible builds |

## 🛠️ Configuration
You can fine-tune the obfuscation process in `config.py`. The `ObfuscationConfig` class allows you to toggle individual layers and adjust parameters like name length, MBA depth, and dead code density.

## ⚠️ Disclaimer
This tool is intended for educational purposes and for protecting intellectual property in a legal manner. The authors are not responsible for any misuse of this software.

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
