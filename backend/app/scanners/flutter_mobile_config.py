"""Static mobile configuration checks for Flutter Android and iOS projects."""

from __future__ import annotations

from pathlib import Path
import plistlib
import xml.etree.ElementTree as ET

from backend.app.scanners.base import NormalizedFinding, ScannerAdapter, ToolExecutionResult
from backend.app.services.ecosystem_service import EcosystemDetectionService

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SENSITIVE_ANDROID_PERMISSIONS = {
    "android.permission.CAMERA": ("medium", "Camera access increases data collection and privacy exposure."),
    "android.permission.RECORD_AUDIO": ("high", "Microphone access can expose sensitive user audio."),
    "android.permission.ACCESS_FINE_LOCATION": ("high", "Precise location access increases privacy exposure."),
    "android.permission.ACCESS_COARSE_LOCATION": ("medium", "Location access increases privacy exposure."),
    "android.permission.READ_CONTACTS": ("high", "Contact access can expose sensitive personal data."),
    "android.permission.WRITE_CONTACTS": ("high", "Contact modification can affect user data integrity."),
    "android.permission.READ_SMS": ("high", "SMS access can expose authentication and personal content."),
    "android.permission.RECEIVE_SMS": ("high", "SMS receipt can expose authentication and personal content."),
    "android.permission.SEND_SMS": ("high", "SMS sending can be abused for fraud or account misuse."),
    "android.permission.READ_PHONE_STATE": ("medium", "Phone state access may expose device identifiers."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("high", "Broad storage access increases data exposure risk."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "External storage write access broadens data access."),
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "External storage read access broadens data access."),
}


class FlutterMobileConfigScannerAdapter(ScannerAdapter):
    """Review Android and iOS app configuration files for first-pass risky settings."""

    tool_name = "flutter-mobile-config"

    def __init__(self, ecosystem_service: EcosystemDetectionService | None = None) -> None:
        self.ecosystem_service = ecosystem_service or EcosystemDetectionService()

    def scan(self, target_path: Path) -> ToolExecutionResult:
        inventory = self.ecosystem_service.detect(target_path)
        if not inventory.has("flutter"):
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command=None,
                findings=[],
                partial=False,
                error_message=None,
            )

        findings: list[NormalizedFinding] = []
        android_manifest = self.ecosystem_service.find_flutter_android_manifest(target_path)
        ios_plist = self.ecosystem_service.find_flutter_ios_info_plist(target_path)

        if android_manifest is not None:
            findings.extend(self._scan_android_manifest(android_manifest, target_path))
        if ios_plist is not None:
            findings.extend(self._scan_ios_plist(ios_plist, target_path))

        if android_manifest is None and ios_plist is None:
            return ToolExecutionResult(
                tool_name=self.tool_name,
                status="skipped",
                command="file review",
                findings=[],
                partial=False,
                error_message="Flutter project detected but no AndroidManifest.xml or Info.plist was found.",
            )

        return ToolExecutionResult(
            tool_name=self.tool_name,
            status="completed",
            command="file review",
            findings=findings,
            partial=False,
            error_message=None,
        )

    def _scan_android_manifest(self, manifest_path: Path, target_path: Path) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        try:
            root = ET.fromstring(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ET.ParseError):
            return [
                NormalizedFinding(
                    title="Android manifest could not be parsed",
                    description="The AndroidManifest.xml file could not be parsed for static configuration review.",
                    severity="medium",
                    category="mobile_config",
                    tool_name=self.tool_name,
                    file_path=self._relative_path(manifest_path, target_path),
                    remediation="Review the AndroidManifest.xml file for malformed XML and rerun the scan.",
                    raw_payload={"platform": "android", "check": "manifest_parse_error"},
                )
            ]

        manifest_label = self._relative_path(manifest_path, target_path)
        application = root.find("application")
        if application is not None:
            if application.get(f"{ANDROID_NS}usesCleartextTraffic") == "true":
                findings.append(
                    self._finding(
                        title="Android cleartext traffic is enabled",
                        description="The application manifest explicitly allows cleartext network traffic.",
                        severity="high",
                        category="mobile_network_security",
                        file_path=manifest_label,
                        remediation="Set android:usesCleartextTraffic to false and enforce TLS for network connections.",
                        raw_payload={"platform": "android", "check": "usesCleartextTraffic", "value": "true"},
                    )
                )
            if application.get(f"{ANDROID_NS}debuggable") == "true":
                findings.append(
                    self._finding(
                        title="Android application is marked debuggable",
                        description="The manifest marks the application as debuggable, which weakens production hardening.",
                        severity="high",
                        category="mobile_debug_configuration",
                        file_path=manifest_label,
                        remediation="Ensure android:debuggable is removed or false in production manifests.",
                        raw_payload={"platform": "android", "check": "debuggable", "value": "true"},
                    )
                )
            if application.get(f"{ANDROID_NS}allowBackup") == "true":
                findings.append(
                    self._finding(
                        title="Android backups are allowed",
                        description="The manifest allows app data backups, which may expose sensitive data on shared backups.",
                        severity="medium",
                        category="mobile_config",
                        file_path=manifest_label,
                        remediation="Set android:allowBackup to false unless backup behavior is explicitly required and reviewed.",
                        raw_payload={"platform": "android", "check": "allowBackup", "value": "true"},
                    )
                )

            for component_tag in ("activity", "service", "receiver", "provider"):
                for component in application.findall(component_tag):
                    if component.get(f"{ANDROID_NS}exported") != "true":
                        continue
                    component_name = component.get(f"{ANDROID_NS}name") or component_tag
                    findings.append(
                        self._finding(
                            title=f"Android exported {component_tag} is enabled",
                            description=f"The {component_tag} {component_name} is marked exported and may be reachable by other apps.",
                            severity="medium",
                            category="mobile_config",
                            file_path=manifest_label,
                            remediation=f"Review whether {component_name} needs to be exported. Restrict or remove exported=true where unnecessary.",
                            raw_payload={
                                "platform": "android",
                                "check": "exported_component",
                                "component_type": component_tag,
                                "component_name": component_name,
                            },
                        )
                    )

        for permission in root.findall("uses-permission"):
            permission_name = permission.get(f"{ANDROID_NS}name")
            if not permission_name or permission_name not in SENSITIVE_ANDROID_PERMISSIONS:
                continue
            severity, description = SENSITIVE_ANDROID_PERMISSIONS[permission_name]
            findings.append(
                self._finding(
                    title=f"Sensitive Android permission declared: {permission_name}",
                    description=description,
                    severity=severity,
                    category="mobile_permissions",
                    file_path=manifest_label,
                    remediation=f"Confirm that {permission_name} is required and document the least-privilege justification.",
                    raw_payload={
                        "platform": "android",
                        "check": "sensitive_permission",
                        "permission": permission_name,
                    },
                )
            )
        return findings

    def _scan_ios_plist(self, plist_path: Path, target_path: Path) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        try:
            payload = plistlib.loads(plist_path.read_bytes())
        except (OSError, plistlib.InvalidFileException):
            return [
                self._finding(
                    title="iOS Info.plist could not be parsed",
                    description="The Info.plist file could not be parsed for static configuration review.",
                    severity="medium",
                    category="mobile_config",
                    file_path=self._relative_path(plist_path, target_path),
                    remediation="Review the Info.plist format and rerun the scan.",
                    raw_payload={"platform": "ios", "check": "plist_parse_error"},
                )
            ]

        plist_label = self._relative_path(plist_path, target_path)
        ats = payload.get("NSAppTransportSecurity") or {}
        if ats.get("NSAllowsArbitraryLoads") is True:
            findings.append(
                self._finding(
                    title="iOS App Transport Security allows arbitrary loads",
                    description="Info.plist allows arbitrary network loads, weakening default TLS protections.",
                    severity="high",
                    category="mobile_network_security",
                    file_path=plist_label,
                    remediation="Remove NSAllowsArbitraryLoads or scope ATS exceptions narrowly to specific domains.",
                    raw_payload={"platform": "ios", "check": "NSAllowsArbitraryLoads", "value": True},
                )
            )

        exception_domains = ats.get("NSExceptionDomains") or {}
        for domain, options in exception_domains.items():
            if not isinstance(options, dict):
                continue
            if options.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                findings.append(
                    self._finding(
                        title=f"iOS ATS exception allows insecure HTTP loads for {domain}",
                        description="Info.plist contains a domain-specific ATS exception that permits insecure HTTP loads.",
                        severity="medium",
                        category="mobile_network_security",
                        file_path=plist_label,
                        remediation="Remove the insecure ATS exception or restrict it to the smallest possible scope.",
                        raw_payload={
                            "platform": "ios",
                            "check": "NSExceptionAllowsInsecureHTTPLoads",
                            "domain": domain,
                        },
                    )
                )

        if payload.get("UIFileSharingEnabled") is True:
            findings.append(
                self._finding(
                    title="iOS file sharing is enabled",
                    description="UIFileSharingEnabled allows user-accessible file sharing and may expose app data on shared devices.",
                    severity="medium",
                    category="mobile_config",
                    file_path=plist_label,
                    remediation="Disable UIFileSharingEnabled unless explicit user-facing file sharing is required and reviewed.",
                    raw_payload={"platform": "ios", "check": "UIFileSharingEnabled", "value": True},
                )
            )
        return findings

    def _finding(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        category: str,
        file_path: str | None,
        remediation: str,
        raw_payload: dict,
    ) -> NormalizedFinding:
        return NormalizedFinding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            tool_name=self.tool_name,
            file_path=file_path,
            remediation=remediation,
            raw_payload=raw_payload,
        )

    @staticmethod
    def _relative_path(path: Path, target_path: Path) -> str | None:
        try:
            return str(path.relative_to(target_path))
        except ValueError:
            return path.name
