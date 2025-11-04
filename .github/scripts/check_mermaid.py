#!/usr/bin/env python3
import re, sys, pathlib

root = pathlib.Path(".")
md_files = list(root.glob("**/*.md"))
bad = []

code_block_re = re.compile(r"```mermaid\s*([\s\S]*?)```", re.MULTILINE)

for p in md_files:
    text = p.read_text(encoding="utf-8", errors="ignore")
    for m in code_block_re.finditer(text):
        block = m.group(1)
        # Disallow 'note over' and 'par/and/end' control words
        for line in block.splitlines():
            s = line.strip().lower()
            if s.startswith("note over") or s in ("par", "and", "end"):
                bad.append((str(p), "control_word", line))
        # Disallow edge label pipes like |label|
        if re.search(r"\|[^|]+\|", block):
            bad.append((str(p), "pipe_label", "Use -- label --> format"))
        # Disallow parentheses in node labels [Active (New)]
        if re.search(r"\[[^\]]*\([^)]+?\)[^\]]*\]", block):
            bad.append((str(p), "paren_in_label", "Remove parentheses in node labels"))
if bad:
    print("Mermaid lint found issues:")
    for f, kind, line in bad:
        print(f"- {f}: {kind}: {line}")
    sys.exit(1)
print("Mermaid lint: OK")
