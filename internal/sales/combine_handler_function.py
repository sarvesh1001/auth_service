import os
import re

ROOT_DIR = "./handler"
OUTPUT_FILE = "combined_handler_signatures.txt"


def should_include_file(filename):
    return filename.endswith(".go")


def extract_handler_signatures(content):
    """
    Extract ONLY handler method signatures (not full bodies).

    Example output:
        func (h *CouponHandler) CreateCoupon(w http.ResponseWriter, r *http.Request)

    """

    pattern = r"func\s+\(h\s+\*\w+Handler\)\s+\w+\s*\([^)]*\)\s*(?:\([^)]*\))?"

    matches = re.findall(pattern, content)

    return matches


def has_meaningful_signatures(signatures):
    return len(signatures) > 0


def combine_handler_signatures(root_dir, output_file):

    with open(output_file, "w", encoding="utf-8") as outfile:

        for subdir, _, files in os.walk(root_dir):

            for file in sorted(files):

                if not should_include_file(file):
                    continue

                file_path = os.path.join(subdir, file)

                try:
                    with open(file_path, "r", encoding="utf-8") as infile:
                        content = infile.read()

                    signatures = extract_handler_signatures(content)

                    if not has_meaningful_signatures(signatures):
                        continue

                    print(f"✅ Extracting handler signatures: {file_path}")

                    outfile.write("\n" + "=" * 80 + "\n")
                    outfile.write(f"FILE: {file_path}\n")
                    outfile.write("=" * 80 + "\n\n")

                    outfile.write("package handler\n\n")

                    for signature in signatures:
                        outfile.write(signature)
                        outfile.write("\n\n")

                except Exception as e:
                    print(f"❌ Error reading {file_path}: {e}")

    print(f"\n🔥 Handler signature-only combined file created: {output_file}")


if __name__ == "__main__":
    combine_handler_signatures(ROOT_DIR, OUTPUT_FILE)