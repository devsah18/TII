#!/usr/bin/env python3
"""Regenerate the bundled demo logs.

    python backend/demo_logs/generate.py

The same generator is what POST /api/simulate uses at runtime, so the files here
always match what the demo produces.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engines.demo import SCENARIOS, generate_log_text  # noqa: E402


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    for scenario in SCENARIOS:
        path = out_dir / f"demo_{scenario}.log"
        path.write_text(generate_log_text(scenario), encoding="utf-8")
        print(f"wrote {path} ({len(path.read_text().splitlines())} lines)")


if __name__ == "__main__":
    main()
