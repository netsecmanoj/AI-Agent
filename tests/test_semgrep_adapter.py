"""Unit tests for the Semgrep adapter normalization logic."""

from backend.app.scanners.semgrep import SemgrepScannerAdapter


def test_semgrep_parser_normalizes_result_payload() -> None:
    adapter = SemgrepScannerAdapter()
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "src/example.py",
                "start": {"line": 12},
                "extra": {
                    "message": "Use of eval detected.",
                    "severity": "ERROR",
                    "metadata": {
                        "category": "security",
                        "fix": "Replace eval with a safer parser.",
                    },
                },
            }
        ]
    }

    findings = adapter._parse_results(payload)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].file_path == "src/example.py"
    assert findings[0].line_number == 12
    assert findings[0].remediation == "Replace eval with a safer parser."
