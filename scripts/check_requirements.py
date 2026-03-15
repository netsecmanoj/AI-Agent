#!/usr/bin/env python3
"""Check scanner/tool availability for the current host or container."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

VENV_PYTHON = ROOT_DIR / ".venv" / "bin" / "python"
if (
    os.environ.get("AUDIT_REQUIREMENTS_REEXEC") != "1"
    and VENV_PYTHON.exists()
    and Path(sys.executable) != VENV_PYTHON
):
    env = dict(os.environ)
    env["AUDIT_REQUIREMENTS_REEXEC"] = "1"
    os.execve(str(VENV_PYTHON), [str(VENV_PYTHON), __file__, *sys.argv[1:]], env)

from backend.app.services.preflight_service import RequirementsPreflightService


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify scanner/tool prerequisites.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 1 when any configured tool is missing or invalid.",
    )
    args = parser.parse_args()

    summary = RequirementsPreflightService().build_summary()
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("Scanner requirements preflight")
        print("============================")
        print(summary["summary_text"])
        print()
        for tool in summary["tools"]:
            print(f"- {tool['label']}: {tool['status']}")
            print(f"  configured via {tool['env_var']}={tool['configured_command']}")
            if tool["resolved_path"]:
                print(f"  resolved path: {tool['resolved_path']}")
            if tool["skip_reason"]:
                print(f"  impact: {tool['skip_reason']}")
        if summary["warnings"]:
            print()
            print("Warnings")
            print("--------")
            for warning in summary["warnings"]:
                print(f"- {warning}")

        print()
        print("AI readiness")
        print("------------")
        print(f"Status: {summary['ai']['status_label']}")
        print(f"Provider: {summary['ai']['provider']}")
        print(f"Model: {summary['ai']['model'] or 'n/a'}")
        print(summary["ai"]["summary_text"])
        if summary["ai"]["warnings"]:
            for warning in summary["ai"]["warnings"]:
                print(f"- {warning}")
        if summary["ai"]["show_setup_hint"]:
            print(summary["ai"]["setup_hint"])

    has_issues = not summary["all_available"]
    if args.strict and has_issues:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
