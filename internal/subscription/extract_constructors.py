#!/usr/bin/env python3
"""
Extract constructor functions from Go files in service/, handler/, and repository/.
Outputs a list of all constructors with their signatures and file locations.
Useful for building a factory or DI container initialization.
"""

import os
import re
from pathlib import Path

# Directories to scan relative to the script's location (or absolute)
TARGET_DIRS = ["service", "handler", "repository"]
OUTPUT_FILE = "constructors.txt"

# Regex to match Go constructor functions:
# - Starts with "func New" followed by alphanumeric
# - Captures the whole signature until the opening brace '{'
CONSTRUCTOR_RE = re.compile(
    r'func\s+(New\w+)\s*\(([^)]*)\)\s*([^{]*)',
    re.MULTILINE
)

def extract_constructors(file_path: Path) -> list[dict]:
    """
    Extract constructors from a Go file.
    Returns a list of dicts with keys: name, params, returns, file.
    """
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"❌ Error reading {file_path}: {e}")
        return []

    constructors = []
    for match in CONSTRUCTOR_RE.finditer(content):
        name = match.group(1)          # e.g., NewCouponService
        params = match.group(2).strip() # parameter list
        returns = match.group(3).strip() # return types (may be empty or contain braces?)
        # Sometimes the return types include the opening brace, we need to strip it.
        # The pattern stops at the first '{', but the return types might have a '{' 
        # for struct literals? Unlikely in signature. We'll clean.
        returns = returns.split('{')[0].strip()
        constructors.append({
            "name": name,
            "params": params,
            "returns": returns,
            "file": str(file_path.relative_to(Path.cwd()))
        })
    return constructors

def main():
    base_path = Path.cwd()
    all_constructors = []

    for dir_name in TARGET_DIRS:
        target_dir = base_path / dir_name
        if not target_dir.exists():
            print(f"⚠️ Directory not found: {target_dir}")
            continue

        for go_file in target_dir.rglob("*.go"):
            if go_file.name.endswith("_test.go"):
                continue
            cons = extract_constructors(go_file)
            if cons:
                all_constructors.extend(cons)

    # Write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("CONSTRUCTOR FUNCTIONS EXTRACTED FOR FACTORY INIT\n")
        f.write("=" * 80 + "\n\n")

        # Group by file for readability
        by_file = {}
        for c in all_constructors:
            by_file.setdefault(c["file"], []).append(c)

        for file_path, cons_list in sorted(by_file.items()):
            f.write(f"📄 {file_path}\n")
            for c in cons_list:
                f.write(f"  • {c['name']}({c['params']}) {c['returns']}\n")
            f.write("\n")

        # Also produce a simple list of constructors with their dependencies (parameters)
        f.write("\n" + "=" * 80 + "\n")
        f.write("CONSTRUCTOR PARAMETER SUMMARY (for dependency injection)\n")
        f.write("=" * 80 + "\n\n")
        for c in all_constructors:
            f.write(f"{c['name']} ← {c['params']}\n")

    print(f"✅ Extracted {len(all_constructors)} constructors to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()