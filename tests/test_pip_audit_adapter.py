"""Unit tests for pip-audit result normalization."""

from pathlib import Path

from backend.app.scanners.pip_audit import PipAuditScannerAdapter


def test_pip_audit_parser_normalizes_python_dependency_findings(tmp_path) -> None:
    manifest_path = tmp_path / "requirements.txt"
    manifest_path.write_text("django==3.2.0\n", encoding="utf-8")
    payload = [
        {
            "name": "django",
            "version": "3.2.0",
            "vulns": [
                {
                    "id": "PYSEC-2024-1",
                    "description": "Example advisory.",
                    "fix_versions": ["3.2.18"],
                    "aliases": ["CVE-2024-0001"],
                }
            ],
        }
    ]

    findings = PipAuditScannerAdapter()._parse_results(
        payload,
        target_path=tmp_path,
        manifest_path=manifest_path,
    )

    assert len(findings) == 1
    assert findings[0].tool_name == "pip-audit"
    assert findings[0].category == "dependency:python"
    assert findings[0].file_path == "requirements.txt"
    assert findings[0].remediation == "Upgrade django to 3.2.18"

