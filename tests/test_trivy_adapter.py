"""Unit tests for Trivy result normalization."""

from backend.app.scanners.trivy import TrivyScannerAdapter


def test_trivy_parser_normalizes_vulnerability_and_misconfiguration() -> None:
    adapter = TrivyScannerAdapter()
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "Title": "Example vulnerable package",
                        "Description": "Upgrade the package.",
                        "Severity": "CRITICAL",
                        "FixedVersion": "2.0.0",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-DS-0001",
                        "Title": "Dangerous configuration",
                        "Description": "A risky config was found.",
                        "Severity": "HIGH",
                        "Resolution": "Disable the risky option.",
                    }
                ],
            }
        ]
    }

    findings = adapter._parse_results(payload)

    assert len(findings) == 2
    assert findings[0].severity == "critical"
    assert findings[0].category == "dependency:pip"
    assert findings[0].remediation == "Upgrade to 2.0.0"
    assert findings[1].severity == "high"
    assert findings[1].category == "misconfiguration:pip"
    assert findings[1].file_path == "requirements.txt"
