"""Detect supported project ecosystems from files present in a scan workspace."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass(slots=True)
class EcosystemDetail:
    """Detailed manifest/audit metadata for one detected ecosystem."""

    manifests: list[Path] = field(default_factory=list)
    audit_files: list[Path] = field(default_factory=list)
    lockfiles: list[Path] = field(default_factory=list)
    project_kind: str | None = None
    markers: list[str] = field(default_factory=list)

    @property
    def audit_ready(self) -> bool:
        """Return whether the ecosystem has direct audit inputs available."""
        return bool(self.audit_files)


@dataclass(slots=True)
class EcosystemInventory:
    """Detected ecosystems and relevant manifest files for a workspace."""

    ecosystems: list[str] = field(default_factory=list)
    manifests: dict[str, list[Path]] = field(default_factory=dict)
    details: dict[str, EcosystemDetail] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    framework_details: dict[str, EcosystemDetail] = field(default_factory=dict)

    def has(self, ecosystem: str) -> bool:
        """Return whether the named ecosystem was detected."""
        return ecosystem in self.ecosystems

    def detail_for(self, ecosystem: str) -> EcosystemDetail:
        """Return detail metadata for one ecosystem, if present."""
        return self.details.get(ecosystem, EcosystemDetail())

    def framework_detail_for(self, framework: str) -> EcosystemDetail:
        """Return detail metadata for one detected framework, if present."""
        return self.framework_details.get(framework, EcosystemDetail())


class EcosystemDetectionService:
    """Detect project ecosystems using deterministic marker files."""

    python_markers = (
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
    )
    node_markers = ("package.json", "package-lock.json", "npm-shrinkwrap.json")
    node_lockfiles = ("package-lock.json", "npm-shrinkwrap.json")
    dart_markers = ("pubspec.yaml", "pubspec.lock", "analysis_options.yaml")
    flutter_platform_directories = ("android", "ios", "linux", "macos", "web", "windows")
    maven_markers = ("pom.xml",)
    composer_markers = ("composer.json", "composer.lock")
    go_markers = ("go.mod", "go.sum")
    dotnet_markers = ("packages.lock.json", "Directory.Packages.props")
    dotnet_project_suffixes = (".csproj", ".sln")

    def detect(self, workspace_path: Path) -> EcosystemInventory:
        """Inspect the workspace and return detected ecosystems."""
        manifests: dict[str, list[Path]] = {}
        details: dict[str, EcosystemDetail] = {}
        ecosystems: list[str] = []

        python_files = self._find_marker_files(workspace_path, self.python_markers)
        if python_files:
            ecosystems.append("python")
            manifests["python"] = python_files
            python_requirements = self.find_python_requirements(workspace_path)
            details["python"] = EcosystemDetail(
                manifests=python_files,
                audit_files=python_requirements,
                lockfiles=[path for path in python_files if path.name in {"poetry.lock", "Pipfile.lock"}],
            )

        node_files = self._find_marker_files(workspace_path, self.node_markers)
        if node_files:
            ecosystems.append("node")
            manifests["node"] = node_files
            node_lockfiles = self.find_node_lockfiles(workspace_path)
            details["node"] = EcosystemDetail(
                manifests=node_files,
                audit_files=node_lockfiles,
                lockfiles=node_lockfiles,
                project_kind="node_project",
                markers=[path.name for path in node_files],
            )

        dart_files = self._find_marker_files(workspace_path, self.dart_markers)
        if dart_files:
            ecosystems.append("dart")
            manifests["dart"] = dart_files
            pub_lockfiles = self.find_dart_lockfiles(workspace_path)
            details["dart"] = EcosystemDetail(
                manifests=dart_files,
                audit_files=pub_lockfiles,
                lockfiles=pub_lockfiles,
                project_kind=self.detect_dart_project_kind(workspace_path),
                markers=self._collect_dart_markers(workspace_path, dart_files),
            )

        flutter_pubspecs = self.find_flutter_pubspecs(workspace_path)
        if flutter_pubspecs:
            ecosystems.append("flutter")
            flutter_manifests = sorted(
                set(
                    [
                        *flutter_pubspecs,
                        *self._find_marker_files(workspace_path, ("pubspec.lock", "analysis_options.yaml")),
                    ]
                )
            )
            flutter_lockfiles = [
                path
                for path in self.find_dart_lockfiles(workspace_path)
                if any(path.is_relative_to(pubspec.parent) for pubspec in flutter_pubspecs)
            ]
            details["flutter"] = EcosystemDetail(
                manifests=flutter_manifests,
                audit_files=flutter_lockfiles,
                lockfiles=flutter_lockfiles,
                project_kind=self.detect_flutter_project_kind(workspace_path),
                markers=self._collect_flutter_markers(workspace_path, flutter_pubspecs),
            )
            manifests["flutter"] = flutter_manifests

        maven_poms = self.find_maven_poms(workspace_path)
        if maven_poms or self.find_directories_by_name(workspace_path, ".mvn"):
            ecosystems.append("maven")
            maven_manifests = sorted(set([*maven_poms, *self.find_directories_by_name(workspace_path, ".mvn")]))
            manifests["maven"] = maven_manifests
            details["maven"] = EcosystemDetail(
                manifests=maven_manifests,
                audit_files=maven_poms,
                lockfiles=[],
                project_kind=self.detect_maven_project_kind(workspace_path),
                markers=self._collect_marker_names(maven_manifests),
            )

        composer_files = self._find_marker_files(workspace_path, self.composer_markers)
        if composer_files:
            ecosystems.append("composer")
            manifests["composer"] = composer_files
            composer_lockfiles = self.find_composer_lockfiles(workspace_path)
            details["composer"] = EcosystemDetail(
                manifests=composer_files,
                audit_files=composer_lockfiles or self.find_composer_manifests(workspace_path),
                lockfiles=composer_lockfiles,
                project_kind="php_composer_project",
                markers=self._collect_marker_names(composer_files),
            )

        go_files = self._find_marker_files(workspace_path, self.go_markers)
        if go_files:
            ecosystems.append("go")
            manifests["go"] = go_files
            details["go"] = EcosystemDetail(
                manifests=go_files,
                audit_files=self.find_go_mod_files(workspace_path),
                lockfiles=self.find_go_sum_files(workspace_path),
                project_kind="go_module_project",
                markers=self._collect_marker_names(go_files),
            )

        dotnet_files = self.find_dotnet_manifests(workspace_path)
        if dotnet_files:
            ecosystems.append("dotnet")
            manifests["dotnet"] = dotnet_files
            details["dotnet"] = EcosystemDetail(
                manifests=dotnet_files,
                audit_files=self.find_dotnet_project_files(workspace_path),
                lockfiles=self.find_dotnet_lockfiles(workspace_path),
                project_kind=self.detect_dotnet_project_kind(workspace_path),
                markers=self._collect_marker_names(dotnet_files),
            )

        frameworks, framework_details = self.detect_frameworks(workspace_path, ecosystems, details)
        return EcosystemInventory(
            ecosystems=ecosystems,
            manifests=manifests,
            details=details,
            frameworks=frameworks,
            framework_details=framework_details,
        )

    def find_python_requirements(self, workspace_path: Path) -> list[Path]:
        """Return manifest files that can be audited directly by pip-audit."""
        return self._find_marker_files(workspace_path, ("requirements.txt", "requirements-dev.txt"))

    def find_node_lockfiles(self, workspace_path: Path) -> list[Path]:
        """Return Node lockfiles that can be audited by npm audit."""
        return self._find_marker_files(workspace_path, self.node_lockfiles)

    def find_node_manifests(self, workspace_path: Path) -> list[Path]:
        """Return Node package manifests used for ecosystem detection."""
        return self._find_marker_files(workspace_path, ("package.json",))

    def find_dart_lockfiles(self, workspace_path: Path) -> list[Path]:
        """Return Dart lockfiles that support dependency visibility commands."""
        return self._find_marker_files(workspace_path, ("pubspec.lock",))

    def find_dart_pubspecs(self, workspace_path: Path) -> list[Path]:
        """Return Dart/Flutter pubspec manifests."""
        return self._find_marker_files(workspace_path, ("pubspec.yaml",))

    def find_maven_poms(self, workspace_path: Path) -> list[Path]:
        """Return Maven pom.xml manifests."""
        return self._find_marker_files(workspace_path, self.maven_markers)

    def find_composer_manifests(self, workspace_path: Path) -> list[Path]:
        """Return Composer manifests."""
        return self._find_marker_files(workspace_path, ("composer.json",))

    def find_composer_lockfiles(self, workspace_path: Path) -> list[Path]:
        """Return Composer lockfiles."""
        return self._find_marker_files(workspace_path, ("composer.lock",))

    def find_flutter_pubspecs(self, workspace_path: Path) -> list[Path]:
        """Return pubspec manifests that look like Flutter projects."""
        flutter_pubspecs: list[Path] = []
        for pubspec in self.find_dart_pubspecs(workspace_path):
            if self._is_flutter_pubspec(pubspec):
                flutter_pubspecs.append(pubspec)
                continue
            root = pubspec.parent
            if any((root / directory_name).is_dir() for directory_name in self.flutter_platform_directories):
                flutter_pubspecs.append(pubspec)
        return sorted(set(flutter_pubspecs))

    def find_go_mod_files(self, workspace_path: Path) -> list[Path]:
        """Return Go module manifests."""
        return self._find_marker_files(workspace_path, ("go.mod",))

    def find_go_sum_files(self, workspace_path: Path) -> list[Path]:
        """Return Go checksum files."""
        return self._find_marker_files(workspace_path, ("go.sum",))

    def find_dotnet_project_files(self, workspace_path: Path) -> list[Path]:
        """Return .NET project manifests."""
        return sorted(
            set(
                path
                for suffix in (".csproj",)
                for path in workspace_path.rglob(f"*{suffix}")
                if path.is_file()
            )
        )

    def find_dotnet_solution_files(self, workspace_path: Path) -> list[Path]:
        """Return .NET solution files."""
        return sorted(set(path for path in workspace_path.rglob("*.sln") if path.is_file()))

    def find_dotnet_lockfiles(self, workspace_path: Path) -> list[Path]:
        """Return .NET lockfiles and central package manifests."""
        return self._find_marker_files(workspace_path, ("packages.lock.json", "Directory.Packages.props"))

    def find_dotnet_manifests(self, workspace_path: Path) -> list[Path]:
        """Return all files used to detect a .NET / NuGet workspace."""
        return sorted(
            set(
                [
                    *self.find_dotnet_project_files(workspace_path),
                    *self.find_dotnet_solution_files(workspace_path),
                    *self.find_dotnet_lockfiles(workspace_path),
                ]
            )
        )

    def find_flutter_android_manifest(self, workspace_path: Path) -> Path | None:
        """Return the primary Android manifest for a Flutter app if present."""
        candidates = sorted(
            path
            for path in workspace_path.rglob("AndroidManifest.xml")
            if "android/app/src/main" in path.as_posix()
        )
        return candidates[0] if candidates else None

    def find_flutter_ios_info_plist(self, workspace_path: Path) -> Path | None:
        """Return the primary iOS Info.plist for a Flutter app if present."""
        candidates = sorted(
            path
            for path in workspace_path.rglob("Info.plist")
            if "ios/Runner" in path.as_posix()
        )
        return candidates[0] if candidates else None

    def find_spring_config_files(self, workspace_path: Path) -> list[Path]:
        """Return common Spring configuration files."""
        return sorted(
            set(
                [
                    *self._find_marker_files(workspace_path, ("application.properties", "application.yml", "application.yaml")),
                    *self._find_marker_files(workspace_path, ("bootstrap.properties", "bootstrap.yml", "bootstrap.yaml")),
                ]
            )
        )

    def find_laravel_env_files(self, workspace_path: Path) -> list[Path]:
        """Return Laravel environment files commonly committed to repositories."""
        return sorted(
            set(
                path
                for name in (".env", ".env.example")
                for path in workspace_path.rglob(name)
                if path.is_file()
            )
        )

    def find_express_entrypoints(self, workspace_path: Path) -> list[Path]:
        """Return common Express application entrypoints."""
        return sorted(
            set(
                path
                for name in ("app.js", "server.js", "index.js")
                for path in workspace_path.rglob(name)
                if path.is_file()
            )
        )

    def find_flutter_dart_sources(self, workspace_path: Path) -> list[Path]:
        """Return Dart source files under common Flutter source directories."""
        return sorted(
            set(
                path
                for path in workspace_path.rglob("*.dart")
                if "/lib/" in path.as_posix()
            )
        )

    def detect_dart_project_kind(self, workspace_path: Path) -> str:
        """Return a simple Dart project type classification."""
        if self.find_flutter_pubspecs(workspace_path):
            return "flutter_project"
        if self._find_marker_files(workspace_path, ("analysis_options.yaml",)):
            return "dart_project"
        return "dart_package"

    def detect_flutter_project_kind(self, workspace_path: Path) -> str:
        """Return a simple Flutter project type classification."""
        for pubspec in self.find_flutter_pubspecs(workspace_path):
            root = pubspec.parent
            if any((root / directory_name).is_dir() for directory_name in ("android", "ios")):
                return "flutter_application"
        return "flutter_package"

    def detect_maven_project_kind(self, workspace_path: Path) -> str:
        """Return a simple Maven project type classification."""
        for pom_path in self.find_maven_poms(workspace_path):
            try:
                content = pom_path.read_text(encoding="utf-8").lower()
            except OSError:
                continue
            if "spring-boot" in content:
                return "spring_maven_project"
        return "maven_project"

    def detect_dotnet_project_kind(self, workspace_path: Path) -> str:
        """Return a simple .NET project type classification."""
        for project_path in self.find_dotnet_project_files(workspace_path):
            try:
                content = project_path.read_text(encoding="utf-8").lower()
            except OSError:
                continue
            if "microsoft.net.sdk.web" in content:
                return "aspnet_project"
            if "microsoft.net.sdk" in content:
                return "dotnet_project"
        return "dotnet_solution"

    def detect_frameworks(
        self,
        workspace_path: Path,
        ecosystems: list[str],
        details: dict[str, EcosystemDetail],
    ) -> tuple[list[str], dict[str, EcosystemDetail]]:
        """Detect supported frameworks from ecosystem manifests and config structure."""
        frameworks: list[str] = []
        framework_details: dict[str, EcosystemDetail] = {}

        if "maven" in ecosystems:
            spring_detail = self.detect_spring_framework(workspace_path, details.get("maven"))
            if spring_detail is not None:
                frameworks.append("spring")
                framework_details["spring"] = spring_detail

        if "composer" in ecosystems:
            laravel_detail = self.detect_laravel_framework(workspace_path, details.get("composer"))
            if laravel_detail is not None:
                frameworks.append("laravel")
                framework_details["laravel"] = laravel_detail

        if "node" in ecosystems:
            express_detail = self.detect_express_framework(workspace_path, details.get("node"))
            if express_detail is not None:
                frameworks.append("express")
                framework_details["express"] = express_detail

        if "flutter" in ecosystems:
            flutter_detail = self.detect_flutter_framework(workspace_path, details.get("flutter"))
            if flutter_detail is not None:
                frameworks.append("flutter_app")
                framework_details["flutter_app"] = flutter_detail

        return frameworks, framework_details

    def detect_spring_framework(
        self,
        workspace_path: Path,
        maven_detail: EcosystemDetail | None,
    ) -> EcosystemDetail | None:
        """Return Spring detail when Spring Boot markers are present."""
        manifests = list(maven_detail.manifests) if maven_detail else []
        config_files = self.find_spring_config_files(workspace_path)
        if not manifests or not any(self._file_contains(path, "spring-boot") for path in manifests):
            return None
        marker_set = set(path.name for path in manifests)
        marker_set.update(path.name for path in config_files)
        return EcosystemDetail(
            manifests=sorted(set([*manifests, *config_files])),
            audit_files=config_files or manifests,
            project_kind="spring_boot_application",
            markers=sorted(marker_set),
        )

    def detect_laravel_framework(
        self,
        workspace_path: Path,
        composer_detail: EcosystemDetail | None,
    ) -> EcosystemDetail | None:
        """Return Laravel detail when Laravel dependencies and structure are present."""
        manifests = list(composer_detail.manifests) if composer_detail else []
        composer_json = next((path for path in manifests if path.name == "composer.json"), None)
        if composer_json is None or not self._file_contains(composer_json, "laravel/framework"):
            return None
        audit_files: list[Path] = []
        markers = {"composer.json"}
        artisan = next((path for path in workspace_path.rglob("artisan") if path.is_file()), None)
        if artisan is not None:
            audit_files.append(artisan)
            markers.add("artisan")
        bootstrap_app = next((path for path in workspace_path.rglob("bootstrap/app.php") if path.is_file()), None)
        if bootstrap_app is not None:
            audit_files.append(bootstrap_app)
            markers.add("bootstrap/app.php")
        env_files = self.find_laravel_env_files(workspace_path)
        audit_files.extend(env_files)
        markers.update(path.name for path in env_files)
        return EcosystemDetail(
            manifests=sorted(set([*manifests, *audit_files])),
            audit_files=sorted(set(audit_files or manifests)),
            project_kind="laravel_application",
            markers=sorted(markers),
        )

    def detect_express_framework(
        self,
        workspace_path: Path,
        node_detail: EcosystemDetail | None,
    ) -> EcosystemDetail | None:
        """Return Express detail when package and entrypoint hints are present."""
        manifests = list(node_detail.manifests) if node_detail else []
        package_json = next((path for path in manifests if path.name == "package.json"), None)
        if package_json is None or not self._package_json_has_dependency(package_json, "express"):
            return None
        entrypoints = self.find_express_entrypoints(workspace_path)
        markers = {"package.json", "express"}
        markers.update(path.name for path in entrypoints[:5])
        return EcosystemDetail(
            manifests=sorted(set([*manifests, *entrypoints])),
            audit_files=entrypoints or [package_json],
            project_kind="express_application",
            markers=sorted(markers),
        )

    def detect_flutter_framework(
        self,
        workspace_path: Path,
        flutter_detail: EcosystemDetail | None,
    ) -> EcosystemDetail | None:
        """Return deeper Flutter detail when a Flutter app structure exists."""
        if flutter_detail is None or flutter_detail.project_kind != "flutter_application":
            return None
        dart_sources = self.find_flutter_dart_sources(workspace_path)
        markers = set(flutter_detail.markers)
        if dart_sources:
            markers.add("lib/*.dart")
        return EcosystemDetail(
            manifests=sorted(set([*flutter_detail.manifests, *dart_sources[:10]])),
            audit_files=dart_sources or list(flutter_detail.manifests),
            project_kind="flutter_application",
            markers=sorted(markers),
        )

    def _find_marker_files(self, workspace_path: Path, marker_names: tuple[str, ...]) -> list[Path]:
        matches: list[Path] = []
        for marker_name in marker_names:
            matches.extend(path for path in workspace_path.rglob(marker_name) if path.is_file())
        return sorted(set(matches))

    def find_directories_by_name(self, workspace_path: Path, directory_name: str) -> list[Path]:
        """Return directories that match the provided name."""
        return sorted(
            set(
                path
                for path in workspace_path.rglob(directory_name)
                if path.is_dir()
            )
        )

    def _collect_dart_markers(self, workspace_path: Path, dart_files: list[Path]) -> list[str]:
        markers = {path.name for path in dart_files}
        if any(path.name == "pubspec.yaml" for path in dart_files):
            markers.add("pubspec.yaml")
        return sorted(markers)

    def _collect_flutter_markers(self, workspace_path: Path, flutter_pubspecs: list[Path]) -> list[str]:
        markers = {"pubspec.yaml"}
        for pubspec in flutter_pubspecs:
            root = pubspec.parent
            for directory_name in self.flutter_platform_directories:
                if (root / directory_name).is_dir():
                    markers.add(f"{directory_name}/")
            if (root / "lib").is_dir():
                markers.add("lib/")
            analysis_options = root / "analysis_options.yaml"
            if analysis_options.is_file():
                markers.add("analysis_options.yaml")
            lockfile = root / "pubspec.lock"
            if lockfile.is_file():
                markers.add("pubspec.lock")
        return sorted(markers)

    @staticmethod
    def _collect_marker_names(paths: list[Path]) -> list[str]:
        return sorted({f"{path.name}/" if path.is_dir() else path.name for path in paths})

    @staticmethod
    def _is_flutter_pubspec(pubspec_path: Path) -> bool:
        try:
            content = pubspec_path.read_text(encoding="utf-8")
        except OSError:
            return False
        lowered = content.lower()
        return "sdk: flutter" in lowered or "\nflutter:" in lowered or lowered.startswith("flutter:")

    @staticmethod
    def _file_contains(path: Path, needle: str) -> bool:
        try:
            return needle.lower() in path.read_text(encoding="utf-8").lower()
        except OSError:
            return False

    @staticmethod
    def _package_json_has_dependency(package_json_path: Path, dependency_name: str) -> bool:
        try:
            payload = json.loads(package_json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        for section_name in ("dependencies", "devDependencies", "optionalDependencies"):
            section = payload.get(section_name)
            if isinstance(section, dict) and dependency_name in section:
                return True
        return False
