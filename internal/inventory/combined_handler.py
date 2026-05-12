import os

ROOT_DIR = "./handler"          # 🔥 Only handler folder
OUTPUT_FILE = "combined_handler_code.txt"


def should_include_file(filename):
    return filename.endswith(".go")


def is_meaningful_content(content):
    lines = content.splitlines()

    cleaned = []
    for line in lines:
        line = line.strip()

        # remove empty + comments
        if not line or line.startswith("//"):
            continue

        cleaned.append(line)

    # ❌ No content
    if len(cleaned) == 0:
        return False

    # ❌ Only package handler (or similar)
    if len(cleaned) == 1 and cleaned[0] == "package handler":
        return False

    # ❌ Very small files (like only package + import)
    if len(cleaned) <= 3:
        return False

    return True


def combine_handler_files(root_dir, output_file):
    with open(output_file, "w", encoding="utf-8") as outfile:

        for subdir, _, files in os.walk(root_dir):
            for file in files:

                if not should_include_file(file):
                    continue

                file_path = os.path.join(subdir, file)

                try:
                    with open(file_path, "r", encoding="utf-8") as infile:
                        content = infile.read()

                        # 🔥 Filter only meaningful handler files
                        if not is_meaningful_content(content):
                            continue

                        print(f"✅ Adding: {file_path}")

                        outfile.write("\n" + "=" * 80 + "\n")
                        outfile.write(f"FILE: {file_path}\n")
                        outfile.write("=" * 80 + "\n\n")

                        outfile.write(content)
                        outfile.write("\n\n")

                except Exception as e:
                    print(f"❌ Error reading {file_path}: {e}")

    print(f"\n🔥 Handler combined file created: {output_file}")


if __name__ == "__main__":
    combine_handler_files(ROOT_DIR, OUTPUT_FILE)