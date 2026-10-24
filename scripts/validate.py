"""Run actual regressions and save truthful machine-readable validation results."""

import argparse
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", choices=["windows", "wsl", "linux"])
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    node = subprocess.run(["node", "--check", str(ROOT / "dashboard" / "app.js")], capture_output=True, text=True) if shutil.which("node") else None
    report = {
        "observed_at": datetime.now(timezone.utc).isoformat(), "host": platform.platform(), "python": platform.python_version(),
        "tests_run": result.testsRun, "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "failures": len(result.failures), "errors": len(result.errors),
        "skipped": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        "javascript_syntax_passed": node.returncode == 0 if node else None,
        "javascript_skip_reason": None if node else "Node is not installed on this validation host",
        "live_linux_container_validated": False, "live_tetragon_validated": False,
        "real_model_call_validated": False, "full_mvp_complete": False,
    }
    suffix = "-" + args.label if args.label else ""
    (ROOT / "docs" / ("validation" + suffix + ".json")).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (ROOT / "docs" / ("test-results" + suffix + ".txt")).write_text(stream.getvalue(), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not result.wasSuccessful():
        print(stream.getvalue())
    if node and node.returncode:
        print(node.stderr)
    return 0 if result.wasSuccessful() and (node is None or node.returncode == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
