#!/usr/bin/env python3
import os
import sys

ROOT_DIR = "./service"          # change or pass as argument
OUTPUT_TO_CONSOLE = True           # if True prints names, else writes to file

def should_include_file(filename):
    """Include only .go files."""
    return filename.endswith(".go")

def is_meaningful_content(content):
    """
    Returns True if the file contains more than just a package declaration
    (and maybe a few imports). Based on the logic from the combine script.
    """
    lines = content.splitlines()
    cleaned = [line.strip() for line in lines if line.strip() and not line.strip().startswith("//")]

    # Empty or only package line
    if len(cleaned) == 0:
        return False
    if len(cleaned) == 1 and cleaned[0] == "package repository":
        return False

    # Too small – likely just package + imports
    if len(cleaned) <= 3:
        return False

    return True

def list_meaningful_files(root_dir, output_file=None):
    """
    Walk through root_dir and print/write filenames of .go files
    that contain meaningful content.
    """
    result = []
    for subdir, _, files in os.walk(root_dir):
        for file in files:
            if not should_include_file(file):
                continue
            file_path = os.path.join(subdir, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if is_meaningful_content(content):
                        result.append(file_path)
                        print(f"✅ {file_path}")
            except Exception as e:
                print(f"❌ Error reading {file_path}: {e}", file=sys.stderr)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            for path in result:
                f.write(path + "\n")
        print(f"\n📄 List saved to {output_file}")
    else:
        print("\n📋 Meaningful files found:")
        for path in result:
            print(path)

if __name__ == "__main__":
    # Optional: accept root directory as command-line argument
    root = sys.argv[1] if len(sys.argv) > 1 else ROOT_DIR
    out = sys.argv[2] if len(sys.argv) > 2 else None
    list_meaningful_files(root, out)