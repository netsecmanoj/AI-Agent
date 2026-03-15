"""Tests for scanner/tool preflight availability checks."""

from backend.app.core.config import get_settings
from backend.app.services.preflight_service import RequirementsPreflightService


def test_preflight_reports_available_missing_and_invalid_paths(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "semgrep_command", "/tmp/does-not-exist/semgrep")
    monkeypatch.setattr(settings, "trivy_command", "trivy")
    monkeypatch.setattr(settings, "pip_audit_command", "pip-audit")
    monkeypatch.setattr(settings, "npm_command", "npm")
    monkeypatch.setattr(settings, "flutter_command", "flutter")
    monkeypatch.setattr(settings, "dart_command", "dart")

    def fake_which(command: str) -> str | None:
        return {
            "trivy": "/usr/local/bin/trivy",
            "dart": "/usr/local/bin/dart",
        }.get(command)

    monkeypatch.setattr("backend.app.services.preflight_service.shutil.which", fake_which)

    summary = RequirementsPreflightService(settings).build_summary()

    assert summary["all_available"] is False
    assert summary["counts"]["invalid_configured_path"] == 1
    assert summary["counts"]["missing"] == 3
    semgrep = next(tool for tool in summary["tools"] if tool["label"] == "Semgrep")
    assert semgrep["status"] == "invalid_configured_path"
    assert "SEMGREP_COMMAND" in semgrep["warning"]
    pip_audit = next(tool for tool in summary["tools"] if tool["label"] == "pip-audit")
    assert pip_audit["status"] == "missing"
    assert "Python dependency auditing" in pip_audit["skip_reason"]


def test_preflight_reports_all_available_when_commands_resolve(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "semgrep_command", "semgrep")
    monkeypatch.setattr(settings, "trivy_command", "trivy")
    monkeypatch.setattr(settings, "pip_audit_command", "pip-audit")
    monkeypatch.setattr(settings, "npm_command", "npm")
    monkeypatch.setattr(settings, "flutter_command", "flutter")
    monkeypatch.setattr(settings, "dart_command", "dart")

    monkeypatch.setattr(
        "backend.app.services.preflight_service.shutil.which",
        lambda command: f"/resolved/{command}",
    )

    summary = RequirementsPreflightService(settings).build_summary()

    assert summary["all_available"] is True
    assert summary["counts"] == {"available": 6, "missing": 0, "invalid_configured_path": 0}
    assert summary["warnings"] == []


def test_preflight_reports_ai_disabled_intentionally(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_enabled", False)
    monkeypatch.setattr(settings, "ai_provider", "disabled")

    summary = RequirementsPreflightService(settings).build_summary()

    assert summary["ai"]["status"] == "disabled_intentionally"
    assert summary["ai"]["status_label"] == "Disabled"
    assert "continue to work without AI" in summary["ai"]["summary_text"]


def test_preflight_reports_ai_missing_required_values(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "ai_provider", "openai")
    monkeypatch.setattr(settings, "ai_model", "")
    monkeypatch.setattr(settings, "ai_base_url", "not-a-url")
    monkeypatch.setattr(settings, "ai_api_key", "")

    summary = RequirementsPreflightService(settings).build_summary()

    assert summary["ai"]["status"] == "missing_required_config"
    assert "AI_MODEL" in summary["ai"]["missing_fields"]
    assert "AI_BASE_URL" in summary["ai"]["missing_fields"]
    assert "AI_API_KEY" in summary["ai"]["missing_fields"]


def test_preflight_reports_ai_ready(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "ai_provider", "ollama")
    monkeypatch.setattr(settings, "ai_model", "llama3.1:8b")
    monkeypatch.setattr(settings, "ai_base_url", "http://127.0.0.1:11434/v1")
    monkeypatch.setattr(settings, "ai_api_key", "")

    summary = RequirementsPreflightService(settings).build_summary()

    assert summary["ai"]["status"] == "ready"
    assert summary["ai"]["status_label"] == "Ready"
    assert "authoritative source of truth" in summary["ai"]["summary_text"]
