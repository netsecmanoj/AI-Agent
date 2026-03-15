"""Tests for Composer manifest review adapter."""

import json

from backend.app.scanners.composer_review import ComposerReviewScannerAdapter


def test_composer_review_parses_abandoned_packages_and_insecure_config(tmp_path) -> None:
    (tmp_path / "composer.json").write_text(
        json.dumps(
            {
                "name": "demo/app",
                "config": {
                    "secure-http": False,
                    "allow-plugins": {"*": True},
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "composer.lock").write_text(
        json.dumps(
            {
                "packages": [
                    {"name": "vendor/legacy-lib", "version": "1.2.3", "abandoned": "vendor/new-lib"},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = ComposerReviewScannerAdapter().scan(tmp_path)

    assert result.status == "completed"
    assert result.partial is False
    assert len(result.findings) == 3
    assert any(finding.title == "Composer secure-http is disabled" for finding in result.findings)
    assert any(finding.title == "Composer allow-plugins permits all plugins" for finding in result.findings)
    assert any(finding.title == "vendor/legacy-lib is marked abandoned" for finding in result.findings)


def test_composer_review_skips_without_manifests(tmp_path) -> None:
    result = ComposerReviewScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.findings == []
