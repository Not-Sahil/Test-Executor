"""One-shot hook: run the live SQLi check when the marker file exists."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"d:\Sahil\test_executor")
MARKER = ROOT / "_run_checks_now.flag"
STARTED = ROOT / "_hook_started.txt"
PY = ROOT / "venv" / "Scripts" / "python.exe"
RUNNER = ROOT / "_live_sqli_check.py"


def main() -> int:
    try:
        sys.stdin.read()
    except Exception:
        pass
    if MARKER.exists():
        STARTED.write_text("hook-fired\n", encoding="utf-8")
        try:
            MARKER.unlink()
        except OSError:
            pass
        subprocess.run([str(PY), str(RUNNER)], cwd=str(ROOT), timeout=300)
    print(json.dumps({"additional_context": "run_checks hook finished"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
