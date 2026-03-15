"""Common scanner adapter interfaces and normalized finding types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class NormalizedFinding:
    """Shared finding structure used by all scanner adapters."""

    title: str
    description: str
    severity: str
    category: str
    tool_name: str
    file_path: str | None = None
    line_number: int | None = None
    remediation: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ToolExecutionResult:
    """Normalized scanner execution result."""

    tool_name: str
    status: str
    command: str | None
    findings: list[NormalizedFinding]
    partial: bool = False
    error_message: str | None = None


class ScannerAdapter(ABC):
    """Base interface for pluggable scanner adapters."""

    tool_name: str

    @abstractmethod
    def scan(self, target_path: Path) -> ToolExecutionResult:
        """Run the scanner against the target path."""

