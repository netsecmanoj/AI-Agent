"""Operator-facing scanner/tool availability checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
from typing import Any
from urllib.parse import urlparse

from backend.app.core.config import Settings, get_settings


@dataclass(frozen=True)
class ToolRequirementSpec:
    """Describe one operator-managed tool dependency."""

    key: str
    label: str
    env_var: str
    configured_command: str
    affected_scanners: tuple[str, ...]
    affected_features: tuple[str, ...]


class RequirementsPreflightService:
    """Resolve configured tool commands and summarize missing coverage."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def build_summary(self) -> dict[str, Any]:
        """Return a JSON-serializable operator summary."""
        tool_items = [self._build_tool_item(spec) for spec in self._tool_specs()]
        ai_summary = self._build_ai_summary()
        counts = {
            "available": sum(1 for item in tool_items if item["status"] == "available"),
            "missing": sum(1 for item in tool_items if item["status"] == "missing"),
            "invalid_configured_path": sum(
                1 for item in tool_items if item["status"] == "invalid_configured_path"
            ),
        }
        warnings = [
            item["warning"]
            for item in tool_items
            if item["warning"]
        ]
        return {
            "all_available": counts["missing"] == 0 and counts["invalid_configured_path"] == 0,
            "counts": counts,
            "tools": tool_items,
            "ai": ai_summary,
            "warnings": warnings,
            "summary_text": self._build_summary_text(counts),
        }

    def _tool_specs(self) -> list[ToolRequirementSpec]:
        return [
            ToolRequirementSpec(
                key="semgrep",
                label="Semgrep",
                env_var="SEMGREP_COMMAND",
                configured_command=self.settings.semgrep_command,
                affected_scanners=("semgrep",),
                affected_features=("generic code and config scanning",),
            ),
            ToolRequirementSpec(
                key="trivy",
                label="Trivy",
                env_var="TRIVY_COMMAND",
                configured_command=self.settings.trivy_command,
                affected_scanners=("trivy",),
                affected_features=("filesystem dependency and image-style review",),
            ),
            ToolRequirementSpec(
                key="pip_audit",
                label="pip-audit",
                env_var="PIP_AUDIT_COMMAND",
                configured_command=self.settings.pip_audit_command,
                affected_scanners=("pip-audit",),
                affected_features=("Python dependency auditing",),
            ),
            ToolRequirementSpec(
                key="npm",
                label="npm",
                env_var="NPM_COMMAND",
                configured_command=self.settings.npm_command,
                affected_scanners=("npm-audit",),
                affected_features=("Node.js dependency auditing",),
            ),
            ToolRequirementSpec(
                key="flutter",
                label="Flutter",
                env_var="FLUTTER_COMMAND",
                configured_command=self.settings.flutter_command,
                affected_scanners=("dart-analyze", "dart-pub-outdated"),
                affected_features=("Flutter-first static analysis and dependency freshness",),
            ),
            ToolRequirementSpec(
                key="dart",
                label="Dart",
                env_var="DART_COMMAND",
                configured_command=self.settings.dart_command,
                affected_scanners=("dart-analyze", "dart-pub-outdated"),
                affected_features=("Dart fallback analysis and dependency freshness",),
            ),
        ]

    def _build_tool_item(self, spec: ToolRequirementSpec) -> dict[str, Any]:
        status, resolved_path = self._resolve_command(spec.configured_command)
        warning = None
        if status != "available":
            warning = self._build_warning(spec, status)
        return {
            "key": spec.key,
            "label": spec.label,
            "env_var": spec.env_var,
            "configured_command": spec.configured_command,
            "resolved_path": resolved_path,
            "status": status,
            "affected_scanners": list(spec.affected_scanners),
            "affected_features": list(spec.affected_features),
            "skip_reason": None if status == "available" else self._skip_reason(spec),
            "warning": warning,
        }

    def _resolve_command(self, configured_command: str) -> tuple[str, str | None]:
        command = configured_command.strip()
        if not command:
            return "missing", None
        expanded = Path(os.path.expanduser(command))
        if "/" in command:
            if expanded.exists() and os.access(expanded, os.X_OK):
                return "available", str(expanded.resolve())
            return "invalid_configured_path", str(expanded)
        resolved = shutil.which(command)
        if resolved:
            return "available", resolved
        return "missing", None

    def _skip_reason(self, spec: ToolRequirementSpec) -> str:
        scanner_list = ", ".join(spec.affected_scanners)
        feature_list = ", ".join(spec.affected_features)
        return f"{feature_list} may be skipped or reported as partial because {scanner_list} depends on this tool."

    def _build_warning(self, spec: ToolRequirementSpec, status: str) -> str:
        if status == "invalid_configured_path":
            return (
                f"{spec.label} is configured via {spec.env_var} but the path is not executable. "
                f"{self._skip_reason(spec)}"
            )
        return (
            f"{spec.label} is not currently available on PATH or via {spec.env_var}. "
            f"{self._skip_reason(spec)}"
        )

    def _build_summary_text(self, counts: dict[str, int]) -> str:
        issue_total = counts["missing"] + counts["invalid_configured_path"]
        if issue_total == 0:
            return "All configured scanner tools are available."
        if counts["invalid_configured_path"] and counts["missing"]:
            return (
                f"{issue_total} scanner tools need attention: "
                f"{counts['invalid_configured_path']} configured path issues and {counts['missing']} missing tools."
            )
        if counts["invalid_configured_path"]:
            return f"{counts['invalid_configured_path']} scanner tools have invalid configured paths."
        return f"{counts['missing']} scanner tools are missing from the current environment."

    def _build_ai_summary(self) -> dict[str, Any]:
        provider = (self.settings.ai_provider or "disabled").strip().lower()
        enabled = bool(self.settings.ai_enabled) and provider != "disabled"
        api_key_configured = bool(self.settings.ai_api_key.strip())
        missing_fields: list[str] = []
        warnings: list[str] = []
        examples = self._ai_examples()

        if not enabled:
            return {
                "status": "disabled_intentionally",
                "status_label": "Disabled",
                "status_tone": "info",
                "enabled": False,
                "show_setup_hint": True,
                "provider": provider,
                "model": self.settings.ai_model,
                "base_url": self.settings.ai_base_url,
                "api_key_configured": api_key_configured,
                "missing_fields": [],
                "setup_hint": "Set AI_ENABLED=true and configure provider, model, and base URL to enable optional advisory AI summaries.",
                "examples": examples,
                "summary_text": (
                    "AI explanations are intentionally disabled. Core scanning, grouping, comparison, "
                    "and policy evaluation continue to work without AI."
                ),
                "warnings": [],
            }

        if provider not in {"openai", "openai_compatible", "ollama"}:
            return {
                "status": "unsupported_provider",
                "status_label": "Misconfigured",
                "status_tone": "failed",
                "enabled": True,
                "show_setup_hint": True,
                "provider": provider,
                "model": self.settings.ai_model,
                "base_url": self.settings.ai_base_url,
                "api_key_configured": api_key_configured,
                "missing_fields": [],
                "setup_hint": "Set AI_PROVIDER to disabled, ollama, openai, or openai_compatible.",
                "examples": examples,
                "summary_text": f"AI is enabled but provider `{provider}` is not supported by this build.",
                "warnings": [f"Set AI_PROVIDER to `disabled`, `ollama`, `openai`, or `openai_compatible`."],
            }

        if not self.settings.ai_model.strip():
            missing_fields.append("AI_MODEL")
        if not self.settings.ai_base_url.strip():
            missing_fields.append("AI_BASE_URL")
        else:
            parsed = urlparse(self.settings.ai_base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                missing_fields.append("AI_BASE_URL")
                warnings.append("AI_BASE_URL should be a full http(s) URL ending at the OpenAI-compatible API root.")
        if provider == "openai" and not api_key_configured:
            missing_fields.append("AI_API_KEY")

        if missing_fields:
            return {
                "status": "missing_required_config",
                "status_label": "Configured but incomplete",
                "status_tone": "partial",
                "enabled": True,
                "show_setup_hint": True,
                "provider": provider,
                "model": self.settings.ai_model,
                "base_url": self.settings.ai_base_url,
                "api_key_configured": api_key_configured,
                "missing_fields": missing_fields,
                "setup_hint": "Review AI_ENABLED, AI_PROVIDER, AI_MODEL, AI_BASE_URL, and AI_API_KEY. Core scanning still works without AI.",
                "examples": examples,
                "summary_text": (
                    "AI is enabled in config but required values are missing or invalid. "
                    "Scans will continue without reliable AI enrichment."
                ),
                "warnings": warnings or [f"Missing or invalid AI config: {', '.join(missing_fields)}."],
            }

        if provider in {"openai_compatible", "ollama"} and not api_key_configured:
            warnings.append("AI_API_KEY is blank. This is normal for many local endpoints such as Ollama.")

        return {
            "status": "ready",
            "status_label": "Ready",
            "status_tone": "completed",
            "enabled": True,
            "show_setup_hint": False,
            "provider": provider,
            "model": self.settings.ai_model,
            "base_url": self.settings.ai_base_url,
            "api_key_configured": api_key_configured,
            "missing_fields": [],
            "setup_hint": None,
            "examples": examples,
            "summary_text": (
                "AI appears configured and should be available for advisory explanations and summaries. "
                "Policy and raw findings remain the authoritative source of truth."
            ),
            "warnings": warnings,
        }

    def _ai_examples(self) -> dict[str, dict[str, str]]:
        return {
            "disabled": {
                "label": "Disabled/default mode",
                "snippet": "AI_ENABLED=false\nAI_PROVIDER=disabled",
            },
            "ollama": {
                "label": "Local Ollama / OpenAI-compatible",
                "snippet": (
                    "AI_ENABLED=true\n"
                    "AI_PROVIDER=ollama\n"
                    "AI_MODEL=llama3.1:8b\n"
                    "AI_BASE_URL=http://127.0.0.1:11434/v1"
                ),
            },
            "openai_compatible": {
                "label": "Hosted OpenAI-compatible gateway",
                "snippet": (
                    "AI_ENABLED=true\n"
                    "AI_PROVIDER=openai_compatible\n"
                    "AI_MODEL=gpt-4o-mini\n"
                    "AI_BASE_URL=https://your-gateway.example.com/v1\n"
                    "AI_API_KEY=replace-me"
                ),
            },
            "openai": {
                "label": "Hosted OpenAI-style endpoint",
                "snippet": (
                    "AI_ENABLED=true\n"
                    "AI_PROVIDER=openai\n"
                    "AI_MODEL=gpt-4o-mini\n"
                    "AI_BASE_URL=https://api.openai.com/v1\n"
                    "AI_API_KEY=replace-me"
                ),
            },
        }
