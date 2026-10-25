"""Reproducible combined checks with private logs and a sanitized public summary."""

import argparse
import json
import platform
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", choices=("windows", "linux"), required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    logs = root / "var" / "validation" / args.label
    logs.mkdir(parents=True, exist_ok=True)
    temporary = (Path("/var/lib/agentguard") if sys.platform == "linux" else root / "var") / (
        "pytest-" + uuid4().hex
    )
    steps = {
        "pytest": ["pytest", "-q", "--color=no", "--basetemp", str(temporary)],
        "lint": ["ruff", "check", "."],
        "format": ["ruff", "format", "--check", "."],
        "application_types": ["mypy", "--cache-dir", str(logs / "mypy-cache")],
        "contract_compatibility": ["scripts.export_contracts", "--check"],
    }
    report = {
        "observed_at": datetime.now(UTC).isoformat(),
        "platform": platform.system(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "steps": {},
    }
    for name, command in steps.items():
        completed = subprocess.run(  # noqa: S603 - predefined local validation commands
            [sys.executable, "-m", *command],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        (logs / (name + ".log")).write_text(completed.stdout + completed.stderr, encoding="utf-8")
        report["steps"][name] = {
            "passed": completed.returncode == 0,
            "exit_code": completed.returncode,
        }
        if name == "pytest":
            match = re.search(r"^(\d+) passed(?:, (\d+) skipped)?", completed.stdout, re.MULTILINE)
            subtests = re.search(r"(\d+) subtests passed", completed.stdout)
            report["tests"] = {
                "passed": int(match[1]) if match else None,
                "skipped": int(match[2] or 0) if match else None,
                "subtests_passed": int(subtests[1]) if subtests else 0,
            }
            report["warnings"] = (
                ["Starlette TestClient httpx deprecation"]
                if "StarletteDeprecationWarning" in completed.stdout
                else []
            )
    report["passed"] = all(step["passed"] for step in report["steps"].values())
    report["full_protected_mvp_complete"] = False
    output = root / "docs" / "linux" / ("validation_" + args.label + ".json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
