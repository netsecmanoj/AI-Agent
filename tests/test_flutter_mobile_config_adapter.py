"""Tests for Flutter mobile configuration review adapter behavior."""

from backend.app.scanners.flutter_mobile_config import FlutterMobileConfigScannerAdapter


def test_flutter_mobile_config_parses_android_and_ios_risky_settings(tmp_path) -> None:
    manifest_path = tmp_path / "android" / "app" / "src" / "main"
    manifest_path.mkdir(parents=True)
    (manifest_path / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <uses-permission android:name="android.permission.CAMERA" />
  <application
      android:usesCleartextTraffic="true"
      android:debuggable="true"
      android:allowBackup="true">
      <activity android:name=".MainActivity" android:exported="true" />
  </application>
</manifest>""",
        encoding="utf-8",
    )

    plist_path = tmp_path / "ios" / "Runner"
    plist_path.mkdir(parents=True)
    (plist_path / "Info.plist").write_bytes(
        b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
    <key>NSExceptionDomains</key>
    <dict>
      <key>example.com</key>
      <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key>
        <true/>
      </dict>
    </dict>
  </dict>
  <key>UIFileSharingEnabled</key>
  <true/>
</dict>
</plist>"""
    )

    (tmp_path / "pubspec.yaml").write_text(
        "name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (tmp_path / "pubspec.lock").write_text("packages:\n  flutter:\n", encoding="utf-8")
    (tmp_path / "lib").mkdir()

    result = FlutterMobileConfigScannerAdapter().scan(tmp_path)

    assert result.status == "completed"
    assert result.tool_name == "flutter-mobile-config"
    titles = {finding.title for finding in result.findings}
    assert "Android cleartext traffic is enabled" in titles
    assert "Android application is marked debuggable" in titles
    assert "Android backups are allowed" in titles
    assert "Android exported activity is enabled" in titles
    assert "Sensitive Android permission declared: android.permission.CAMERA" in titles
    assert "iOS App Transport Security allows arbitrary loads" in titles
    assert "iOS ATS exception allows insecure HTTP loads for example.com" in titles
    assert "iOS file sharing is enabled" in titles
    assert any(finding.category == "mobile_network_security" for finding in result.findings)
    assert any(finding.category == "mobile_permissions" for finding in result.findings)


def test_flutter_mobile_config_skips_when_mobile_files_are_absent(tmp_path) -> None:
    (tmp_path / "pubspec.yaml").write_text(
        "name: demo\ndependencies:\n  flutter:\n    sdk: flutter\n",
        encoding="utf-8",
    )
    (tmp_path / "pubspec.lock").write_text("packages:\n  flutter:\n", encoding="utf-8")
    (tmp_path / "lib").mkdir()

    result = FlutterMobileConfigScannerAdapter().scan(tmp_path)

    assert result.status == "skipped"
    assert result.partial is False
    assert "no AndroidManifest.xml or Info.plist" in (result.error_message or "")
