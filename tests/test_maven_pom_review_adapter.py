"""Tests for Maven pom.xml review adapter."""

from backend.app.scanners.maven_pom_review import MavenPomReviewScannerAdapter


def test_maven_pom_review_parses_dependency_and_repository_risks(tmp_path) -> None:
    (tmp_path / "pom.xml").write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <repositories>
    <repository>
      <id>legacy-repo</id>
      <url>http://repo.example.com/maven2</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>floating-lib</artifactId>
      <version>LATEST</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>system-lib</artifactId>
      <version>1.0.0</version>
      <scope>system</scope>
    </dependency>
  </dependencies>
</project>
""",
        encoding="utf-8",
    )

    result = MavenPomReviewScannerAdapter().scan(tmp_path)

    assert result.status == "completed"
    assert result.partial is False
    assert len(result.findings) == 3
    assert {finding.category for finding in result.findings} == {"dependency_risk", "build_configuration"}
    assert any(finding.title == "org.example:floating-lib uses a floating Maven version" for finding in result.findings)
    assert any(finding.title == "Maven repository legacy-repo uses insecure HTTP" for finding in result.findings)


def test_maven_pom_review_skips_without_manifest(tmp_path) -> None:
    result = MavenPomReviewScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.findings == []
