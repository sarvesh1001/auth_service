import os

ROOT_DIR = "."
OUTPUT_FILE = "combined_code.txt"

def should_include_file(filename):
    return filename.endswith(".go")

def is_meaningful_content(content):
    lines = content.splitlines()

    # Remove empty lines & comments
    cleaned = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("//"):
            continue
        cleaned.append(line)

    # ❌ Skip if no real content
    if len(cleaned) == 0:
        return False

    # ❌ Skip if only "package xxx"
    if len(cleaned) == 1 and cleaned[0].startswith("package"):
        return False

    # ❌ Skip very small files (adjust if needed)
    if len(cleaned) <= 3:
        return False

    return True


def combine_files(root_dir, output_file):
    with open(output_file, "w", encoding="utf-8") as outfile:
        for subdir, dirs, files in os.walk(root_dir):
            for file in files:
                if should_include_file(file):
                    file_path = os.path.join(subdir, file)

                    try:
                        with open(file_path, "r", encoding="utf-8") as infile:
                            content = infile.read()

                            # 🔥 Apply filter
                            if not is_meaningful_content(content):
                                continue

                            print(f"✅ Adding: {file_path}")

                            outfile.write("\n" + "="*80 + "\n")
                            outfile.write(f"FILE: {file_path}\n")
                            outfile.write("="*80 + "\n\n")

                            outfile.write(content)
                            outfile.write("\n\n")

                    except Exception as e:
                        print(f"Error reading {file_path}: {e}")

    print(f"\n🔥 Clean combined file created: {output_file}")


if __name__ == "__main__":
    combine_files(ROOT_DIR, OUTPUT_FILE)