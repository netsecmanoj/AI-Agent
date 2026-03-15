"""Tests for Dart/Flutter static analysis adapter behavior."""

from backend.app.scanners.dart_analyze import DartAnalyzeScannerAdapter


def test_dart_analyze_parser_normalizes_flutter_output(tmp_path) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (tmp_path / "pubspec.lock").write_text("packages:\n  flutter:\n", encoding="utf-8")
    analyzer_output = (
        "warning • Unused import • lib/main.dart:3:8 • unused_import\n"
        "error • Undefined name 'foo' • lib/main.dart:7:12 • undefined_identifier\n"
    )

    findings = DartAnalyzeScannerAdapter()._parse_output(
        analyzer_output,
        target_path=tmp_path,
        command_name="flutter",
    )

    assert len(findings) == 2
    assert findings[0].category == "static_analysis"
    assert findings[0].severity == "medium"
    assert findings[0].tool_name == "dart-flutter-analyze"
    assert findings[0].file_path == "lib/main.dart"
    assert findings[0].raw_payload["ecosystem"] == "flutter"
    assert findings[1].severity == "high"


def test_dart_analyze_marks_partial_when_toolchain_is_missing(tmp_path, monkeypatch) -> None:
    (tmp_path / "pubspec.yaml").write_text("name: demo\n", encoding="utf-8")
    (tmp_path / "analysis_options.yaml").write_text("include: package:lints/recommended.yaml\n", encoding="utf-8")
    monkeypatch.setattr("backend.app.scanners.dart_analyze.shutil.which", lambda command: None)

    result = DartAnalyzeScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.partial is True
    assert "Neither Flutter nor Dart is installed" in (result.error_message or "")
