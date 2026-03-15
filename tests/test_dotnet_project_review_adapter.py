"""Tests for .NET / NuGet project review adapter."""

from backend.app.scanners.dotnet_project_review import DotnetProjectReviewScannerAdapter


def test_dotnet_project_review_parses_floating_prerelease_and_restore_source_risks(tmp_path) -> None:
    (tmp_path / "Demo.csproj").write_text(
        """<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <RestoreSources>https://api.nuget.org/v3/index.json;http://legacy.example/v3/index.json</RestoreSources>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Contoso.Core" Version="1.*" />
    <PackageReference Include="Contoso.PreRelease" Version="2.0.0-preview.1" />
  </ItemGroup>
</Project>
""",
        encoding="utf-8",
    )

    result = DotnetProjectReviewScannerAdapter().scan(tmp_path)

    assert result.status == "completed"
    assert result.partial is False
    assert len(result.findings) == 3
    assert any(finding.title == "Contoso.Core uses a floating NuGet version" for finding in result.findings)
    assert any(finding.title == "Contoso.PreRelease uses a pre-release NuGet version" for finding in result.findings)
    assert any(finding.title == "Dotnet restore sources include insecure HTTP" for finding in result.findings)


def test_dotnet_project_review_skips_without_manifest(tmp_path) -> None:
    result = DotnetProjectReviewScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.findings == []
