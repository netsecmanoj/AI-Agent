"""Tests for Go module review adapter."""

from backend.app.scanners.go_mod_review import GoModReviewScannerAdapter


def test_go_mod_review_parses_replace_and_pseudo_version_risks(tmp_path) -> None:
    (tmp_path / "go.mod").write_text(
        """module example.com/demo

go 1.22
toolchain default

require github.com/example/lib v0.0.0-20240301010203-abcdef123456

replace github.com/example/local => ../local-lib
""",
        encoding="utf-8",
    )

    result = GoModReviewScannerAdapter().scan(tmp_path)

    assert result.status == "completed"
    assert result.partial is False
    assert len(result.findings) == 3
    assert any(finding.title == "Go toolchain is not pinned" for finding in result.findings)
    assert any(finding.title == "github.com/example/lib uses a Go pseudo-version" for finding in result.findings)
    assert any(finding.title == "Go module uses a local replace directive" for finding in result.findings)


def test_go_mod_review_skips_without_manifest(tmp_path) -> None:
    result = GoModReviewScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.findings == []
