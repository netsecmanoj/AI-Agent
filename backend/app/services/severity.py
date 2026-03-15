"""Utilities for severity normalization across tools."""


def normalize_severity(raw_severity: str | None) -> str:
    """Map tool-specific severities onto the shared finding scale."""
    value = (raw_severity or "").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "error": "high",
        "warning": "medium",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return mapping.get(value, "unknown")

