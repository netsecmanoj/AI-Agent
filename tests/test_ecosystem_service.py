"""Tests for workspace ecosystem detection."""

from backend.app.services.ecosystem_service import EcosystemDetectionService


def test_detects_python_and_node_ecosystems(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (tmp_path / "frontend" / "package-lock.json").write_text('{"name":"demo","lockfileVersion":3}', encoding="utf-8")

    inventory = EcosystemDetectionService().detect(tmp_path)

    assert inventory.ecosystems == ["python", "node"]
    assert any(path.name == "requirements.txt" for path in inventory.manifests["python"])
    assert any(path.name == "package.json" for path in inventory.manifests["node"])
    assert inventory.detail_for("python").audit_ready is True
    assert inventory.detail_for("node").audit_ready is True
    assert any(path.name == "package-lock.json" for path in inventory.detail_for("node").lockfiles)


def test_detects_dart_and_flutter_ecosystems(tmp_path) -> None:
    flutter_app = tmp_path / "mobile_app"
    flutter_app.mkdir()
    (flutter_app / "pubspec.yaml").write_text(
        "name: mobile_app\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (flutter_app / "pubspec.lock").write_text("packages:\n  flutter:\n    dependency: direct main\n", encoding="utf-8")
    (flutter_app / "analysis_options.yaml").write_text("include: package:flutter_lints/flutter.yaml\n", encoding="utf-8")
    (flutter_app / "lib").mkdir()
    (flutter_app / "android").mkdir()
    (flutter_app / "ios").mkdir()

    inventory = EcosystemDetectionService().detect(tmp_path)

    assert inventory.ecosystems == ["dart", "flutter"]
    assert inventory.detail_for("dart").project_kind == "flutter_project"
    assert inventory.detail_for("flutter").project_kind == "flutter_application"
    assert inventory.detail_for("dart").audit_ready is True
    assert inventory.detail_for("flutter").audit_ready is True
    assert "android/" in inventory.detail_for("flutter").markers


def test_detects_maven_and_composer_ecosystems(tmp_path) -> None:
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><artifactId>demo</artifactId></project>",
        encoding="utf-8",
    )
    (backend / ".mvn").mkdir()
    php_app = tmp_path / "php-app"
    php_app.mkdir()
    (php_app / "composer.json").write_text('{"name":"demo/app"}', encoding="utf-8")
    (php_app / "composer.lock").write_text('{"packages":[]}', encoding="utf-8")

    inventory = EcosystemDetectionService().detect(tmp_path)

    assert inventory.ecosystems == ["maven", "composer"]
    assert inventory.detail_for("maven").project_kind == "maven_project"
    assert inventory.detail_for("maven").audit_ready is True
    assert any(path.name == "pom.xml" for path in inventory.detail_for("maven").audit_files)
    assert inventory.detail_for("composer").project_kind == "php_composer_project"
    assert inventory.detail_for("composer").audit_ready is True
    assert any(path.name == "composer.lock" for path in inventory.detail_for("composer").lockfiles)


def test_detects_go_and_dotnet_ecosystems(tmp_path) -> None:
    go_service = tmp_path / "go-service"
    go_service.mkdir()
    (go_service / "go.mod").write_text("module example.com/service\n\ngo 1.22\n", encoding="utf-8")
    (go_service / "go.sum").write_text("github.com/example/lib h1:abcdef\n", encoding="utf-8")
    dotnet_service = tmp_path / "dotnet-service"
    dotnet_service.mkdir()
    (dotnet_service / "Demo.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>',
        encoding="utf-8",
    )
    (dotnet_service / "Demo.sln").write_text("Microsoft Visual Studio Solution File", encoding="utf-8")
    (dotnet_service / "packages.lock.json").write_text('{"version":1}', encoding="utf-8")

    inventory = EcosystemDetectionService().detect(tmp_path)

    assert inventory.ecosystems == ["go", "dotnet"]
    assert inventory.detail_for("go").project_kind == "go_module_project"
    assert inventory.detail_for("go").audit_ready is True
    assert any(path.name == "go.mod" for path in inventory.detail_for("go").audit_files)
    assert inventory.detail_for("dotnet").project_kind == "dotnet_project"
    assert inventory.detail_for("dotnet").audit_ready is True
    assert any(path.name == "packages.lock.json" for path in inventory.detail_for("dotnet").lockfiles)


def test_detects_supported_frameworks_from_repo_structure(tmp_path) -> None:
    spring_app = tmp_path / "spring-app"
    spring_app.mkdir()
    (spring_app / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>",
        encoding="utf-8",
    )
    (spring_app / "application.properties").write_text(
        "management.endpoints.web.exposure.include=*\n",
        encoding="utf-8",
    )

    laravel_app = tmp_path / "laravel-app"
    (laravel_app / "bootstrap").mkdir(parents=True)
    (laravel_app / "composer.json").write_text(
        '{"require":{"laravel/framework":"^11.0"}}',
        encoding="utf-8",
    )
    (laravel_app / "artisan").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    (laravel_app / "bootstrap" / "app.php").write_text("<?php\n", encoding="utf-8")
    (laravel_app / ".env.example").write_text("APP_DEBUG=true\n", encoding="utf-8")

    express_app = tmp_path / "express-app"
    express_app.mkdir()
    (express_app / "package.json").write_text(
        '{"dependencies":{"express":"^4.19.0"}}',
        encoding="utf-8",
    )
    (express_app / "app.js").write_text("const express = require('express');\n", encoding="utf-8")

    flutter_app = tmp_path / "flutter-app"
    (flutter_app / "lib").mkdir(parents=True)
    (flutter_app / "android").mkdir()
    (flutter_app / "ios").mkdir()
    (flutter_app / "pubspec.yaml").write_text(
        "name: mobile_app\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (flutter_app / "lib" / "main.dart").write_text("void main() {}\n", encoding="utf-8")

    inventory = EcosystemDetectionService().detect(tmp_path)

    assert inventory.frameworks == ["spring", "laravel", "express", "flutter_app"]
    assert inventory.framework_detail_for("spring").project_kind == "spring_boot_application"
    assert "application.properties" in inventory.framework_detail_for("spring").markers
    assert inventory.framework_detail_for("laravel").project_kind == "laravel_application"
    assert "artisan" in inventory.framework_detail_for("laravel").markers
    assert inventory.framework_detail_for("express").project_kind == "express_application"
    assert "express" in inventory.framework_detail_for("express").markers
    assert inventory.framework_detail_for("flutter_app").project_kind == "flutter_application"
    assert "lib/*.dart" in inventory.framework_detail_for("flutter_app").markers
