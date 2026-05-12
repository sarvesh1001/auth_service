import os
import re

ROOT_DIR = "./"
OUTPUT_FILE = "constructors_clean.go"

# Matches full constructor function including body
CONSTRUCTOR_REGEX = re.compile(
    r"func\s+New\w+\s*\([^)]*\)\s*[^{]*\{(?:[^{}]*|\{[^{}]*\})*\}",
    re.DOTALL
)

def should_include_file(filename):
    return filename.endswith(".go")

def extract_constructors(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        matches = CONSTRUCTOR_REGEX.findall(content)

        return matches

    except Exception as e:
        print(f"❌ Error reading {file_path}: {e}")
        return []

def get_layer(file_path):
    if "/repository/" in file_path:
        return "REPOSITORY"
    elif "/service/" in file_path:
        return "SERVICE"
    elif "/handler/" in file_path:
        return "HANDLER"
    else:
        return "OTHER"

def combine_constructors(root_dir, output_file):
    grouped = {
        "REPOSITORY": [],
        "SERVICE": [],
        "HANDLER": [],
        "OTHER": []
    }

    for subdir, _, files in os.walk(root_dir):
        for file in files:
            if not should_include_file(file):
                continue

            file_path = os.path.join(subdir, file)
            constructors = extract_constructors(file_path)

            if constructors:
                layer = get_layer(file_path)
                print(f"✅ {len(constructors)} from {file_path}")

                for c in constructors:
                    grouped[layer].append((file_path, c))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("// 🔥 AUTO-GENERATED CONSTRUCTORS\n\n")

        for layer in ["REPOSITORY", "SERVICE", "HANDLER", "OTHER"]:
            if not grouped[layer]:
                continue

            f.write("\n// ================================\n")
            f.write(f"// {layer}\n")
            f.write("// ================================\n\n")

            for file_path, constructor in grouped[layer]:
                f.write(f"// FILE: {file_path}\n")
                f.write(constructor.strip() + "\n\n")

    print(f"\n🔥 Clean constructors file created: {output_file}")

if __name__ == "__main__":
    combine_constructors(ROOT_DIR, OUTPUT_FILE)