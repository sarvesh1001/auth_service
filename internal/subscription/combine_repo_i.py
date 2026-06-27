import os
import re

ROOT_DIR = "./repository"
OUTPUT_FILE = "combined_repository_interfaces.txt"


def should_include_file(filename):
    return filename.endswith(".go")


def extract_interfaces(content):
    """
    Extract only interface type blocks from Go files.
    Example:
        type SalesRepRepository interface {
            ...
        }
    """

    pattern = r"type\s+\w+\s+interface\s*\{(?:[^{}]|\{[^{}]*\})*\}"

    matches = re.findall(pattern, content, re.DOTALL)

    return matches


def has_meaningful_interfaces(interfaces):
    return len(interfaces) > 0


def combine_repository_interfaces(root_dir, output_file):

    with open(output_file, "w", encoding="utf-8") as outfile:

        for subdir, _, files in os.walk(root_dir):

            for file in files:

                if not should_include_file(file):
                    continue

                file_path = os.path.join(subdir, file)

                try:
                    with open(file_path, "r", encoding="utf-8") as infile:
                        content = infile.read()

                    interfaces = extract_interfaces(content)

                    if not has_meaningful_interfaces(interfaces):
                        continue

                    print(f"✅ Extracting interfaces: {file_path}")

                    outfile.write("\n" + "=" * 80 + "\n")
                    outfile.write(f"FILE: {file_path}\n")
                    outfile.write("=" * 80 + "\n\n")

                    outfile.write("package repository\n\n")

                    for interface_block in interfaces:
                        outfile.write(interface_block)
                        outfile.write("\n\n")

                except Exception as e:
                    print(f"❌ Error reading {file_path}: {e}")

    print(f"\n🔥 Interface-only combined file created: {output_file}")


if __name__ == "__main__":
    combine_repository_interfaces(ROOT_DIR, OUTPUT_FILE)