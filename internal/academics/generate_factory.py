import os
import re

HANDLER_DIR = "./handler"
OUTPUT_FILE = "combined_handler_constructors.go"

# Regex to capture handler constructors like:
# func NewXYZHandler(...) *XYZHandler { ... }
constructor_pattern = re.compile(
    r'func\s+New[A-Za-z0-9_]+Handler\s*\([^)]*\)\s*\*?[A-Za-z0-9_]+\s*\{(?:[^{}]*|\{[^{}]*\})*\}',
    re.DOTALL
)

def extract_constructors_from_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    matches = constructor_pattern.findall(content)
    return matches


def main():
    all_constructors = []

    for root, dirs, files in os.walk(HANDLER_DIR):
        for file in files:
            if file.endswith("_handler.go"):
                path = os.path.join(root, file)
                constructors = extract_constructors_from_file(path)

                if constructors:
                    print(f"✔ Found {len(constructors)} constructors in {file}")
                    all_constructors.extend(constructors)

    # Write output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("package handler\n\n")
        f.write("// Auto-generated handler constructors\n\n")

        for constructor in all_constructors:
            f.write(constructor)
            f.write("\n\n")

    print(f"\n✅ Done! Extracted {len(all_constructors)} handler constructors into {OUTPUT_FILE}")


if __name__ == "__main__":
    main()