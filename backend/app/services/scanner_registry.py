"""Static registry for shared and ecosystem-specific scanner adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from backend.app.scanners.base import ScannerAdapter
from backend.app.scanners.composer_review import ComposerReviewScannerAdapter
from backend.app.scanners.dart_analyze import DartAnalyzeScannerAdapter
from backend.app.scanners.dart_pub_outdated import DartPubOutdatedScannerAdapter
from backend.app.scanners.dotnet_project_review import DotnetProjectReviewScannerAdapter
from backend.app.scanners.flutter_mobile_config import FlutterMobileConfigScannerAdapter
from backend.app.scanners.framework_review import FrameworkReviewScannerAdapter
from backend.app.scanners.go_mod_review import GoModReviewScannerAdapter
from backend.app.scanners.maven_pom_review import MavenPomReviewScannerAdapter
from backend.app.scanners.npm_audit import NpmAuditScannerAdapter
from backend.app.scanners.pip_audit import PipAuditScannerAdapter
from backend.app.scanners.semgrep import SemgrepScannerAdapter
from backend.app.scanners.trivy import TrivyScannerAdapter
from backend.app.services.ecosystem_service import EcosystemDetectionService


@dataclass(frozen=True, slots=True)
class ScannerRegistration:
    """Describe one scanner adapter that belongs to the shared scan pipeline."""

    family: str
    factory: Callable[[EcosystemDetectionService], ScannerAdapter]


class ScannerRegistry:
    """Build scanner adapter lists without hardcoding them in execution logic."""

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()
        self._registrations = [
            ScannerRegistration(family="base", factory=lambda _: SemgrepScannerAdapter()),
            ScannerRegistration(family="base", factory=lambda _: TrivyScannerAdapter()),
            ScannerRegistration(family="base", factory=lambda service: DartAnalyzeScannerAdapter(service)),
            ScannerRegistration(family="base", factory=lambda service: FlutterMobileConfigScannerAdapter(service)),
            ScannerRegistration(family="base", factory=lambda service: FrameworkReviewScannerAdapter(service)),
            ScannerRegistration(family="dependency", factory=lambda service: PipAuditScannerAdapter(service)),
            ScannerRegistration(family="dependency", factory=lambda service: NpmAuditScannerAdapter(service)),
            ScannerRegistration(family="dependency", factory=lambda service: DartPubOutdatedScannerAdapter(service)),
            ScannerRegistration(family="dependency", factory=lambda service: MavenPomReviewScannerAdapter(service)),
            ScannerRegistration(family="dependency", factory=lambda service: ComposerReviewScannerAdapter(service)),
            ScannerRegistration(family="dependency", factory=lambda service: GoModReviewScannerAdapter(service)),
            ScannerRegistration(family="dependency", factory=lambda service: DotnetProjectReviewScannerAdapter(service)),
        ]

    def build_base_scanners(self) -> list[ScannerAdapter]:
        """Return the shared base scanners."""
        return self._build_for_family("base")

    def build_dependency_scanners(self) -> list[ScannerAdapter]:
        """Return the ecosystem-specific dependency/config scanners."""
        return self._build_for_family("dependency")

    def build_all_scanners(self) -> list[ScannerAdapter]:
        """Return the default scanner order for one scan job."""
        return [*self.build_base_scanners(), *self.build_dependency_scanners()]

    def _build_for_family(self, family: str) -> list[ScannerAdapter]:
        return [
            registration.factory(self.ecosystem_service)
            for registration in self._registrations
            if registration.family == family
        ]
