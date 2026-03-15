"""Reusable scan execution boundary for orchestrating configured scanners."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService
from backend.app.services.scanner_registry import ScannerRegistry


@dataclass(slots=True)
class ScanExecutionSummary:
    """Aggregate execution outcome across multiple scanners."""

    status: str
    partial: bool
    total_findings: int
    error_messages: list[str]
    results: list[ToolExecutionResult]
    ecosystems: list[str] = field(default_factory=list)


class ScanExecutionService:
    """Run all configured scanners against a prepared workspace."""

    def __init__(self, scanners: list[ScannerAdapter] | None = None) -> None:
        self.ecosystem_service = EcosystemDetectionService()
        self.scanner_registry = ScannerRegistry(self.ecosystem_service)
        self.base_scanners = self.scanner_registry.build_base_scanners()
        self.dependency_scanners = self.scanner_registry.build_dependency_scanners()
        self.scanners = scanners

    def execute(self, workspace_path: Path) -> ScanExecutionSummary:
        """Run all scanners and compute the overall scan status."""
        inventory = self.ecosystem_service.detect(workspace_path)
        scanners = self.scanners or [*self.base_scanners, *self.dependency_scanners]
        results = [scanner.scan(workspace_path) for scanner in scanners]
        errors = [
            f"{result.tool_name}: {result.error_message}"
            for result in results
            if result.error_message and (result.partial or result.status in {"failed", "timeout"})
        ]
        completed_count = sum(1 for result in results if result.status == "completed")
        partial = any(
            result.partial or result.status in {"failed", "timeout"} for result in results
        )
        if completed_count == 0 and results:
            status = "failed"
        elif partial:
            status = "partial"
        else:
            status = "completed"
        return ScanExecutionSummary(
            status=status,
            partial=partial,
            total_findings=sum(len(result.findings) for result in results),
            error_messages=errors,
            results=results,
            ecosystems=inventory.ecosystems,
        )

    @staticmethod
    def normalize_findings(result: ToolExecutionResult) -> list[NormalizedFinding]:
        """Keep a stable seam for later enrichment or deduplication."""
        return result.findings
