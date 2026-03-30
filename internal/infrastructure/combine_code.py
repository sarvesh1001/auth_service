import os

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
ROOT_DIR = "."               # current directory (you are inside infrastructure)
OUTPUT_FILE = "combined_code.txt"
# ----------------------------------------------------------------------


def should_include_file(filename: str) -> bool:
    return filename.endswith(".go")


def combine_files(root_dir: str, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as outfile:
        for subdir, _, files in os.walk(root_dir):
            for file in files:
                if not should_include_file(file):
                    continue

                file_path = os.path.join(subdir, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as infile:
                        content = infile.read()
                        # Optionally skip trivial files (uncomment if needed)
                        # if not is_meaningful_content(content):
                        #     continue

                        print(f"✅ Adding: {file_path}")
                        outfile.write(content)
                        outfile.write("\n")   # ensure a newline between files

                except Exception as e:
                    print(f"❌ Error reading {file_path}: {e}")

    print(f"\n🔥 Combined file created: {output_file}")


if __name__ == "__main__":
    combine_files(ROOT_DIR, OUTPUT_FILE)