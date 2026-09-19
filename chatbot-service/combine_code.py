import os

ROOT_DIR = "."
OUTPUT_FILE = "all_code.txt"

# Files/directories to ignore
IGNORED_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "node_modules",
    "vendor",
}

# Only include these code/config file types
INCLUDED_EXTENSIONS = {
    ".go",
    ".sql",
    ".env",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".md",
    ".txt",
}

# Specific files without extensions
INCLUDED_FILES = {
    "Dockerfile",
    "Makefile",
}


def should_include(filename):
    if filename in INCLUDED_FILES:
        return True

    # .env has no normal extension
    if filename == ".env":
        return True

    _, ext = os.path.splitext(filename)
    return ext.lower() in INCLUDED_EXTENSIONS


def main():
    files = []

    for root, dirs, filenames in os.walk(ROOT_DIR):
        # Remove ignored directories from traversal
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRS
        ]

        for filename in filenames:
            if not should_include(filename):
                continue

            path = os.path.join(root, filename)

            # Don't include the generated output itself
            if os.path.abspath(path) == os.path.abspath(OUTPUT_FILE):
                continue

            files.append(path)

    files.sort()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as output:
        for path in files:
            relative_path = os.path.relpath(path, ROOT_DIR)

            output.write("\n")
            output.write("=" * 80)
            output.write("\n")
            output.write(f"FILE: {relative_path}\n")
            output.write("=" * 80)
            output.write("\n\n")

            try:
                with open(path, "r", encoding="utf-8") as file:
                    output.write(file.read())
            except UnicodeDecodeError:
                output.write("[Skipped: binary/non-UTF-8 file]\n")

            output.write("\n\n")

    print(f"Combined {len(files)} files into {OUTPUT_FILE}")


if __name__ == "__main__":
    main()