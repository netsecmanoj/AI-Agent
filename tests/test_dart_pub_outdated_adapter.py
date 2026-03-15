"""Tests for Dart/Flutter dependency freshness adapter behavior."""

from backend.app.core.config import get_settings
from backend.app.scanners.dart_pub_outdated import DartPubOutdatedScannerAdapter


def test_dart_pub_outdated_parser_normalizes_outdated_dependency_findings(tmp_path) -> None:
    (tmp_path / "pubspec.lock").write_text("packages:\n  http:\n", encoding="utf-8")
    payload = {
        "packages": [
            {
                "package": "http",
                "kind": "direct",
                "current": {"version": "0.13.0"},
                "upgradable": {"version": "0.13.6"},
                "resolvable": {"version": "0.13.6"},
                "latest": {"version": "1.2.0"},
                "isCurrentAffectedByAdvisory": False,
            },
            {
                "package": "yaml",
                "kind": "transitive",
                "current": {"version": "3.0.0"},
                "latest": {"version": "3.0.0"},
            },
        ]
    }

    findings = DartPubOutdatedScannerAdapter()._parse_results(
        payload,
        target_path=tmp_path,
        manifest_root=tmp_path,
        ecosystem="dart",
    )

    assert len(findings) == 1
    assert findings[0].category == "dependency_outdated"
    assert findings[0].severity == "low"
    assert findings[0].file_path == "pubspec.lock"
    assert findings[0].raw_payload["dependency"]["name"] == "http"
    assert findings[0].raw_payload["ecosystem"] == "dart"


def test_dart_pub_outdated_skips_cleanly_when_lockfile_is_missing(tmp_path) -> None:
    (tmp_path / "pubspec.yaml").write_text("name: demo\n", encoding="utf-8")

    result = DartPubOutdatedScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.partial is False
    assert "no pubspec.lock" in (result.error_message or "")


def test_dart_pub_outdated_marks_partial_when_toolchain_is_missing(tmp_path, monkeypatch) -> None:
    (tmp_path / "pubspec.yaml").write_text("name: demo\n", encoding="utf-8")
    (tmp_path / "pubspec.lock").write_text("packages:\n  http:\n", encoding="utf-8")
    monkeypatch.setattr("backend.app.scanners.dart_pub_outdated.shutil.which", lambda command: None)

    result = DartPubOutdatedScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.partial is True
    assert "Neither Flutter nor Dart is installed" in (result.error_message or "")


def test_dart_pub_outdated_builds_current_cli_compatible_command(tmp_path, monkeypatch) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: mobile_app\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (tmp_path / "pubspec.lock").write_text("packages:\n  flutter:\n", encoding="utf-8")

    adapter = DartPubOutdatedScannerAdapter()
    inventory = adapter.ecosystem_service.detect(tmp_path)
    settings = get_settings()

    monkeypatch.setattr("backend.app.scanners.dart_pub_outdated.shutil.which", lambda command: "/usr/bin/flutter")
    command = adapter._build_command(inventory)

    assert command == [settings.flutter_command, "pub", "outdated", "--json", "--no-up-to-date"]
    assert "--no-transitive" not in command


def test_dart_pub_outdated_builds_dart_fallback_command_without_transitive_flags(
    tmp_path,
    monkeypatch,
) -> None:
    (tmp_path / "pubspec.yaml").write_text("name: package_only\n", encoding="utf-8")
    (tmp_path / "pubspec.lock").write_text("packages:\n  http:\n", encoding="utf-8")
    (tmp_path / "analysis_options.yaml").write_text("linter:\n  rules:\n", encoding="utf-8")

    adapter = DartPubOutdatedScannerAdapter()
    inventory = adapter.ecosystem_service.detect(tmp_path)
    settings = get_settings()

    def fake_which(command: str) -> str | None:
        if command == settings.flutter_command:
            return None
        if command == settings.dart_command:
            return "/usr/bin/dart"
        return None

    monkeypatch.setattr("backend.app.scanners.dart_pub_outdated.shutil.which", fake_which)
    command = adapter._build_command(inventory)

    assert command == [settings.dart_command, "pub", "outdated", "--json", "--no-up-to-date"]
    assert "--transitive" not in command
    assert "--no-transitive" not in command
