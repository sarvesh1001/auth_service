#!/usr/bin/env python3
"""
Safely refactor sales handlers to use BaseHandler.
Run from project root (where ./handler exists).
"""

import os
import re
import sys

HANDLER_DIR = "./handler"

HELPER_METHODS = [
    "getUserIDFromContext",
    "hasPermission",
    "respondWithJSON",
    "respondWithError",
    "mapServiceError",
    "parseUUIDParam",
    "parsePagination",
    "parseSort",
    "parseTimeRange",
    "getIdempotencyKey",
]

def remove_helper_functions(content):
    """Remove entire helper function blocks including any preceding comment lines."""
    # First, remove the comment line "// ---------- Helper Functions ----------"
    content = re.sub(r'\n\s*//\s*-+\s*Helper Functions\s*-+\s*\n', '\n', content)

    for method in HELPER_METHODS:
        # Match from 'func (h *...' to the closing brace of the function
        pattern = re.compile(
            rf'func\s+\(h\s+\*\w+Handler\)\s+{method}\s*\([^)]*\)\s*(?:\([^)]*\))?\s*\{{',
            re.MULTILINE
        )
        while True:
            match = pattern.search(content)
            if not match:
                break
            start = match.start()
            # Find the matching closing brace
            brace_count = 0
            end = None
            for i in range(match.end() - 1, len(content)):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break
            if end is None:
                break
            # Also remove any blank line after the function (optional)
            while end < len(content) and content[end] in ' \t\r\n':
                end += 1
            content = content[:start] + content[end:]
    return content

def modify_struct(content):
    """Add *BaseHandler to struct, remove logger field."""
    struct_pattern = re.compile(
        r'type\s+(\w+Handler)\s+struct\s*\{([^}]*)\}',
        re.MULTILINE | re.DOTALL
    )
    def repl(match):
        struct_name = match.group(1)
        body = match.group(2)
        if '*BaseHandler' in body:
            return match.group(0)
        # Remove logger line
        lines = body.splitlines()
        new_lines = []
        for line in lines:
            stripped = line.strip()
            if re.search(r'\blogger\s+\*zap\.Logger', stripped):
                continue
            if stripped:
                new_lines.append('\t' + stripped)
        new_body = '\n\t*BaseHandler\n'
        if new_lines:
            new_body += '\n'.join(new_lines) + '\n'
        return f'type {struct_name} struct {{{new_body}}}'
    return struct_pattern.sub(repl, content)

def modify_constructor(content):
    """Initialize BaseHandler in constructor, remove logger assignment."""
    # Match return &HandlerName{ ... }
    constructor_pattern = re.compile(
        r'return\s+&(\w+Handler)\s*\{([^}]*)\}',
        re.MULTILINE | re.DOTALL
    )
    def repl(match):
        handler_name = match.group(1)
        body = match.group(2)
        if 'BaseHandler' in body:
            return match.group(0)
        # Remove logger field assignment
        body = re.sub(
            r'logger\s*:\s*logger(?:\.Named\([^)]+\))?,?\s*\n',
            '',
            body,
            flags=re.MULTILINE
        )
        body = body.rstrip()
        base = f'\n\t\tBaseHandler: &BaseHandler{{ Logger: logger }},'
        if body:
            return f'return &{handler_name}{{{base}\n{body}\n}}'
        else:
            return f'return &{handler_name}{{{base}\n}}'
    return constructor_pattern.sub(repl, content)

def replace_logger_calls(content):
    """Replace h.logger with h.Logger."""
    return re.sub(r'\bh\.logger\b', 'h.Logger', content)

def replace_idempotency_calls(content):
    """Replace r.Header.Get("Idempotency-Key") with h.getIdempotencyKey(r)."""
    return re.sub(
        r'r\.Header\.Get\("Idempotency-Key"\)',
        'h.getIdempotencyKey(r)',
        content
    )

def process_file(filepath, dry_run=False):
    with open(filepath, 'r', encoding='utf-8') as f:
        original = f.read()

    content = original
    content = remove_helper_functions(content)
    content = modify_struct(content)
    content = modify_constructor(content)
    content = replace_logger_calls(content)
    content = replace_idempotency_calls(content)

    if content == original:
        print(f"⏭️  No changes: {filepath}")
        return False

    if dry_run:
        print(f"🔍 Would update: {filepath}")
        return False

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ Updated: {filepath}")
    return True

def main():
    if not os.path.isdir(HANDLER_DIR):
        print(f"Error: {HANDLER_DIR} not found. Run from project root.")
        sys.exit(1)

    dry_run = '--dry-run' in sys.argv

    for filename in os.listdir(HANDLER_DIR):
        if filename.endswith('_handler.go') and filename != 'base_handler.go':
            filepath = os.path.join(HANDLER_DIR, filename)
            process_file(filepath, dry_run)

    if dry_run:
        print("\nDry run completed. Remove --dry-run to apply changes.")
    else:
        print("\n🎉 Refactoring complete. Run `go build ./...` to verify.")

if __name__ == '__main__':
    main()