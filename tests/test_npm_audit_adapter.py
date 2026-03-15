"""Unit tests for npm-audit result normalization and skip behavior."""

from backend.app.scanners.npm_audit import NpmAuditScannerAdapter


def test_npm_audit_parser_normalizes_node_dependency_findings(tmp_path) -> None:
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "package-lock.json").write_text('{"name":"demo","lockfileVersion":3}', encoding="utf-8")
    payload = {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "isDirect": True,
                "via": [
                    {
                        "source": 1106913,
                        "name": "lodash",
                        "title": "Prototype Pollution in lodash",
                        "severity": "high",
                        "url": "https://npmjs.com/advisories/1106913",
                    }
                ],
                "effects": [],
                "range": "<4.17.21",
                "nodes": ["node_modules/lodash"],
                "fixAvailable": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "isSemVerMajor": False,
                },
            }
        },
    }

    findings = NpmAuditScannerAdapter()._parse_results(
        payload,
        target_path=tmp_path,
        working_directory=frontend,
    )

    assert len(findings) == 1
    assert findings[0].tool_name == "npm-audit"
    assert findings[0].category == "dependency:node"
    assert findings[0].file_path == "frontend/package-lock.json"
    assert findings[0].remediation == "Upgrade lodash to 4.17.21"
    assert findings[0].raw_payload["dependency"]["name"] == "lodash"
    assert findings[0].raw_payload["ecosystem"] == "node"


def test_npm_audit_skips_cleanly_when_node_lockfile_is_missing(tmp_path) -> None:
    (tmp_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")

    result = NpmAuditScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.partial is False
    assert "no package-lock.json or npm-shrinkwrap.json" in (result.error_message or "")


def test_npm_audit_marks_partial_when_npm_is_missing(tmp_path, monkeypatch) -> None:
    (tmp_path / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"name":"demo","lockfileVersion":3}', encoding="utf-8")
    monkeypatch.setattr("backend.app.scanners.npm_audit.shutil.which", lambda command: None)

    result = NpmAuditScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.partial is True
    assert result.tool_name == "npm-audit"
    assert "npm is not installed" in (result.error_message or "")
