"""
Obscura — Advanced Luau Obfuscator for Roblox Studio
==========================================================
CLI Entry Point

Usage:
    python main.py --input script.lua --output script.obf.lua
    python main.py --input ./scripts/ --output ./obfuscated/ --recursive
    python main.py --input script.lua --level 4 --vm --antitamper --seed 12345
"""

import sys
import time
import pathlib
import click
from colorama import init as colorama_init, Fore, Style

from config import ObfuscationConfig, ProtectionLevel, DeadCodeDensity
from obfuscator import Obfuscator, ObfuscationError

# Initialize colorama for Windows
colorama_init(autoreset=True)

# Banner
BANNER = (
    f"\n{Fore.CYAN}"
    "   ___  _                                \n"
    "  / _ \\| |__  ___  ___ _   _ _ __ __ _ \n"
    " | | | | '_ \\/ __|/ __| | | | '__/ _` |\n"
    " | |_| | |_) \\__ \\ (__| |_| | | | (_| |\n"
    "  \\___/|_.__/|___/\\___|\\__,_|_|  \\__,_|\n"
    f"{Style.RESET_ALL}"
    f"  {Fore.WHITE}Advanced Luau Obfuscator for Roblox Studio{Style.RESET_ALL}\n"
    f"  {Fore.LIGHTBLACK_EX}v1.0.0 -- 9-Layer Protection System{Style.RESET_ALL}\n"
)


def print_status(msg: str, status: str = "info"):
    """Print a colored status message."""
    icons = {
        "info": f"{Fore.CYAN}[*]",
        "ok": f"{Fore.GREEN}[+]",
        "warn": f"{Fore.YELLOW}[!]",
        "error": f"{Fore.RED}[x]",
        "vm": f"{Fore.MAGENTA}[VM]",
    }
    icon = icons.get(status, icons["info"])
    click.echo(f"  {icon} {msg}{Style.RESET_ALL}")


def print_layer(name: str, enabled: bool):
    """Print layer status."""
    if enabled:
        click.echo(f"    {Fore.GREEN}[+] {name}{Style.RESET_ALL}")
    else:
        click.echo(f"    {Fore.LIGHTBLACK_EX}[-] {name}{Style.RESET_ALL}")


@click.command()
@click.option('--input', '-i', 'input_path', required=True,
              help='Input file (.lua/.luau) or directory.')
@click.option('--output', '-o', 'output_path', required=True,
              help='Output file or directory.')
@click.option('--level', '-l', type=click.IntRange(1, 4), default=None,
              help='Protection level: 1=minimal, 2=standard, 3=maximum, 4=paranoid.')
@click.option('--vm', is_flag=True, default=False,
              help='Enable VM virtualization (Layer 9).')
@click.option('--antitamper', is_flag=True, default=False,
              help='Enable anti-tamper protection (Layer 8).')
@click.option('--strings/--no-strings', default=True,
              help='Enable/disable string encryption.')
@click.option('--cff/--no-cff', default=True,
              help='Enable/disable control flow flattening.')
@click.option('--deadcode/--no-deadcode', default=True,
              help='Enable/disable dead code injection.')
@click.option('--seed', type=int, default=None,
              help='Random seed for reproducible builds.')
@click.option('--recursive', '-r', is_flag=True, default=False,
              help='Process entire directory recursively.')
@click.option('--density', type=click.Choice(['low', 'medium', 'high']),
              default='medium', help='Dead code injection density.')
@click.option('--lightweight', is_flag=True, default=False,
              help='Extremely lightweight mode (minimal size overhead).')
@click.option('--quiet', '-q', is_flag=True, default=False,
              help='Suppress banner and verbose output.')
def main(input_path, output_path, level, vm, antitamper, strings, cff,
         deadcode, seed, recursive, density, lightweight, quiet):
    """Obscura — Advanced Luau Obfuscator for Roblox Studio"""

    if not quiet:
        click.echo(BANNER)

    # Build configuration
    config = ObfuscationConfig()

    if level is not None:
        config.level = ProtectionLevel(level)
        config._apply_level(config.level)

    if lightweight:
        config.level = ProtectionLevel.MINIMAL
        config._apply_level(config.level)
        config.obfuscate_numbers = False
        config.control_flow_flatten = False
        config.inject_dead_code = False
        config.opaque_predicates = False
        config.table_indirection = False
        config.anti_tamper = False
        config.virtualize = False
    else:
        # Override individual toggles if specified
        if vm:
            config.virtualize = True
        if antitamper:
            config.anti_tamper = True
        config.encrypt_strings = strings
        config.control_flow_flatten = cff
        config.inject_dead_code = deadcode
        config.dead_code_density = DeadCodeDensity(density)

    if seed is not None:
        config.seed = seed
    config._init_rng()

    # Print configuration
    if not quiet:
        print_status(f"Build ID: {Fore.YELLOW}{config._build_id}", "info")
        print_status(f"Seed: {Fore.YELLOW}{config.seed}", "info")
        click.echo(f"\n  {Fore.WHITE}Layers:{Style.RESET_ALL}")
        print_layer("Layer 1: Identifier Renaming", config.rename_identifiers)
        print_layer("Layer 2: String Encryption", config.encrypt_strings)
        print_layer("Layer 3: Number Obfuscation (MBA)", config.obfuscate_numbers)
        print_layer("Layer 4: Control Flow Flattening", config.control_flow_flatten)
        print_layer("Layer 5: Opaque Predicates", config.opaque_predicates)
        print_layer("Layer 6: Dead Code Injection", config.inject_dead_code)
        print_layer("Layer 7: Table Indirection", config.table_indirection)
        print_layer("Layer 8: Anti-Tamper", config.anti_tamper)
        print_layer("Layer 9: VM Virtualization", config.virtualize)
        click.echo()

    # Create obfuscator
    obfuscator = Obfuscator(config)

    input_p = pathlib.Path(input_path)
    output_p = pathlib.Path(output_path)

    start_time = time.time()
    files_processed = 0
    files_failed = 0

    if input_p.is_file():
        # Single file mode
        files_processed, files_failed = process_file(
            input_p, output_p, obfuscator, quiet
        )
    elif input_p.is_dir():
        if not recursive:
            print_status("Input is a directory. Use --recursive flag.", "error")
            sys.exit(1)
        files_processed, files_failed = process_directory(
            input_p, output_p, obfuscator, quiet
        )
    else:
        print_status(f"Input path not found: {input_path}", "error")
        sys.exit(1)

    elapsed = time.time() - start_time

    # Summary
    if not quiet:
        click.echo()
        click.echo(f"  {Fore.WHITE}{'=' * 50}{Style.RESET_ALL}")
        print_status(
            f"Completed in {Fore.YELLOW}{elapsed:.2f}s{Style.RESET_ALL} -- "
            f"{Fore.GREEN}{files_processed} files processed"
            f"{Style.RESET_ALL}, {Fore.RED}{files_failed} failed{Style.RESET_ALL}",
            "ok"
        )


def process_file(input_path: pathlib.Path, output_path: pathlib.Path,
                 obfuscator: Obfuscator, quiet: bool) -> tuple:
    """Process a single file."""
    try:
        source = input_path.read_text(encoding='utf-8')
        if not quiet:
            print_status(f"Processing: {Fore.WHITE}{input_path.name}", "info")

        result = obfuscator.obfuscate(source)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result, encoding='utf-8')

        orig_size = len(source)
        new_size = len(result)
        ratio = new_size / orig_size if orig_size > 0 else 0

        if not quiet:
            print_status(
                f"Output: {Fore.WHITE}{output_path.name} "
                f"{Fore.LIGHTBLACK_EX}({orig_size}B -> {new_size}B, {ratio:.1f}x)",
                "ok"
            )
        return (1, 0)

    except Exception as e:
        print_status(f"Failed: {input_path.name} -- {e}", "error")
        return (0, 1)


def process_directory(input_dir: pathlib.Path, output_dir: pathlib.Path,
                      obfuscator: Obfuscator, quiet: bool) -> tuple:
    """Process a directory recursively."""
    total_ok = 0
    total_fail = 0

    extensions = {'.lua', '.luau'}

    for lua_file in sorted(input_dir.rglob("*")):
        if lua_file.suffix.lower() not in extensions:
            continue
        if lua_file.is_dir():
            continue

        relative = lua_file.relative_to(input_dir)
        out_file = output_dir / relative

        ok, fail = process_file(lua_file, out_file, obfuscator, quiet)
        total_ok += ok
        total_fail += fail

    return (total_ok, total_fail)


if __name__ == '__main__':
    main()
