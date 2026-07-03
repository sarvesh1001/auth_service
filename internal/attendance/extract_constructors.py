import os
import re

ROOT_DIR = "."
OUTPUT_FILE = "factory_dependencies.txt"

GO_FILE = re.compile(r".*\.go$")

STRUCT_RE = re.compile(
    r"type\s+\w+\s+(?:struct|interface)\s*\{.*?^\}",
    re.MULTILINE | re.DOTALL,
)

FUNC_RE = re.compile(
    r"func\s+New\w+\s*\([^)]*\)\s*[^{]*\{",
    re.MULTILINE,
)


def find_function(source, start):
    brace = 0
    i = start

    while i < len(source):
        if source[i] == "{":
            brace += 1
            i += 1
            break
        i += 1

    while i < len(source):
        if source[i] == "{":
            brace += 1
        elif source[i] == "}":
            brace -= 1
            if brace == 0:
                return source[start:i + 1]
        i += 1

    return source[start:]


def extract_file(path):

    with open(path, "r", encoding="utf8") as f:
        text = f.read()

    structs = STRUCT_RE.findall(text)

    constructors = []

    for m in FUNC_RE.finditer(text):
        constructors.append(find_function(text, m.start()))

    if not structs and not constructors:
        return None

    return structs, constructors


with open(OUTPUT_FILE, "w", encoding="utf8") as out:

    for root, _, files in os.walk(ROOT_DIR):

        for file in sorted(files):

            if not GO_FILE.match(file):
                continue

            path = os.path.join(root, file)

            result = extract_file(path)

            if result is None:
                continue

            structs, constructors = result

            print("Adding", path)

            out.write("=" * 100 + "\n")
            out.write(f"{path}\n")
            out.write("=" * 100 + "\n\n")

            if structs:
                out.write("STRUCTS / INTERFACES\n")
                out.write("-" * 60 + "\n\n")

                for s in structs:
                    out.write(s)
                    out.write("\n\n")

            if constructors:
                out.write("CONSTRUCTORS\n")
                out.write("-" * 60 + "\n\n")

                for c in constructors:
                    out.write(c)
                    out.write("\n\n")

print(f"\nDone -> {OUTPUT_FILE}")