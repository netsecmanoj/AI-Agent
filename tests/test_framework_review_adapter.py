"""Tests for deterministic framework-aware review checks."""

from backend.app.scanners.framework_review import FrameworkReviewScannerAdapter


def test_framework_review_scans_supported_framework_configs_and_sources(tmp_path) -> None:
    spring_app = tmp_path / "spring-app"
    spring_app.mkdir()
    (spring_app / "pom.xml").write_text(
        "<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>",
        encoding="utf-8",
    )
    (spring_app / "application.properties").write_text(
        "\n".join(
            [
                "management.endpoints.web.exposure.include=*",
                "spring.profiles.active=dev",
                "management.server.address=0.0.0.0",
            ]
        ),
        encoding="utf-8",
    )

    laravel_app = tmp_path / "laravel-app"
    (laravel_app / "app" / "Http" / "Middleware").mkdir(parents=True)
    (laravel_app / "bootstrap").mkdir(exist_ok=True)
    (laravel_app / "composer.json").write_text(
        '{"require":{"laravel/framework":"^11.0"}}',
        encoding="utf-8",
    )
    (laravel_app / "artisan").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    (laravel_app / "bootstrap" / "app.php").write_text("<?php\n", encoding="utf-8")
    (laravel_app / ".env").write_text("APP_DEBUG=true\nAPP_URL=http://demo.internal\n", encoding="utf-8")
    (laravel_app / "app" / "Http" / "Middleware" / "TrustProxies.php").write_text(
        "<?php\nprotected $proxies = '*';\n",
        encoding="utf-8",
    )

    express_app = tmp_path / "express-app"
    express_app.mkdir()
    (express_app / "package.json").write_text(
        '{"dependencies":{"express":"^4.19.0"}}',
        encoding="utf-8",
    )
    (express_app / "app.js").write_text(
        "\n".join(
            [
                "app.set('trust proxy', true);",
                "app.use(session({ cookie: { httpOnly: false, secure: false } }));",
            ]
        ),
        encoding="utf-8",
    )

    flutter_app = tmp_path / "flutter-app"
    (flutter_app / "lib").mkdir(parents=True)
    (flutter_app / "android").mkdir()
    (flutter_app / "ios").mkdir()
    (flutter_app / "pubspec.yaml").write_text(
        "name: mobile_app\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (flutter_app / "lib" / "main.dart").write_text(
        "\n".join(
            [
                'const String apiKey = "supersecret12345";',
                'final serviceUrl = "http://api.internal.local";',
                'debugPrint("token=$apiKey");',
            ]
        ),
        encoding="utf-8",
    )

    result = FrameworkReviewScannerAdapter().scan(tmp_path)

    assert result.status == "completed"
    assert result.partial is False
    titles = {finding.title for finding in result.findings}
    assert "Spring actuator web endpoints are broadly exposed" in titles
    assert "Spring dev profile is enabled in configuration" in titles
    assert "Laravel APP_DEBUG is enabled" in titles
    assert "Laravel trusts all proxies" in titles
    assert "Express trust proxy is globally enabled" in titles
    assert "Express cookie/session configuration disables httpOnly" in titles
    assert "Flutter source uses a cleartext HTTP endpoint" in titles
    assert "Flutter source appears to contain a hardcoded secret" in titles
    assert "Flutter source logs sensitive authentication material" in titles
    assert all(finding.tool_name == "framework-review" for finding in result.findings)


def test_framework_review_skips_when_no_supported_framework_is_detected(tmp_path) -> None:
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")

    result = FrameworkReviewScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.findings == []
    assert result.error_message is None
