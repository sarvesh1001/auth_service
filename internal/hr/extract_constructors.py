import os
import re

ROOT_DIR = "."
OUTPUT_FILE = "factory_dependencies.txt"

GO_FILE = re.compile(r".*\.go$")

# Matches functions that start with "New" and take parameters
FUNC_RE = re.compile(
    r"func\s+New\w+\s*\([^)]*\)\s*[^{]*\{",
    re.MULTILINE,
)


def find_function(source, start):
    """Extract the full function body from the starting position."""
    brace = 0
    i = start

    # Move to the opening brace of the function
    while i < len(source):
        if source[i] == "{":
            brace += 1
            i += 1
            break
        i += 1

    # Scan until the matching closing brace
    while i < len(source):
        if source[i] == "{":
            brace += 1
        elif source[i] == "}":
            brace -= 1
            if brace == 0:
                return source[start:i + 1]
        i += 1

    # Fallback if we never find the closing brace
    return source[start:]


def extract_constructors(path):
    with open(path, "r", encoding="utf8") as f:
        text = f.read()

    constructors = []
    for m in FUNC_RE.finditer(text):
        constructors.append(find_function(text, m.start()))

    return constructors if constructors else None


with open(OUTPUT_FILE, "w", encoding="utf8") as out:
    for root, _, files in os.walk(ROOT_DIR):
        for file in sorted(files):
            if not GO_FILE.match(file):
                continue

            path = os.path.join(root, file)
            constructors = extract_constructors(path)

            if constructors is None:
                continue

            print("Adding", path)

            out.write("=" * 100 + "\n")
            out.write(f"{path}\n")
            out.write("=" * 100 + "\n\n")
            out.write("CONSTRUCTORS\n")
            out.write("-" * 60 + "\n\n")

            for c in constructors:
                out.write(c)
                out.write("\n\n")

print(f"\nDone -> {OUTPUT_FILE}")