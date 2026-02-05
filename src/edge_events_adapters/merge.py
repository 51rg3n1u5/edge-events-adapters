from __future__ import annotations

from pathlib import Path


def merge_jsonl(out_path: Path, inputs: list[Path]) -> int:
    """Concatenate JSONL files in order. Returns number of lines written."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as out:
        for inp in inputs:
            if not inp.exists():
                continue
            for line in inp.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                out.write(line + "\n")
                n += 1
    return n
