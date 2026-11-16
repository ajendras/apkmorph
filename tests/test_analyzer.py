"""Tests for APKAnalyzer.

Covers decompilation, component extraction, keyword search and string resource
parsing (including the XML/string_resources support added for AI-driven edits).
Uses mocks and tmp_path so tests run reliably in CI without requiring Apktool,
Java, real APKs or network.
"""

import pytest
from pathlib import Path
from subprocess import CalledProcessError
from unittest.mock import MagicMock, patch

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def analyzer(tmp_path: Path) -> APKAnalyzer:
    """Return an analyzer using a temporary working directory."""
    return APKAnalyzer(working_dir=tmp_path / "decompiled")


def test_analyzer_init(tmp_path: Path) -> None:
    """Test initializer creates working directory."""
    work_dir = tmp_path / "custom_decomp"
    analyzer = APKAnalyzer(working_dir=work_dir)
    assert analyzer.working_dir == work_dir
    assert work_dir.exists()


def test_decompile_missing_apk(analyzer: APKAnalyzer) -> None:
    """Decompile should raise clear error when APK is missing."""
    with pytest.raises(FileNotFoundError, match="APK file not found"):
        analyzer.decompile("nonexistent.apk")


def test_decompile_invalid_extension(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Decompile should reject non-.apk files."""
    bad_file = tmp_path / "data.txt"
    bad_file.touch()
    with pytest.raises(ValueError, match="Input must be a valid .apk file"):
        analyzer.decompile(str(bad_file))


@patch("apkmorph.analyzer.run_apktool")
def test_decompile_apktool_not_found(mock_run: MagicMock, analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Missing apktool should raise actionable FileNotFoundError."""
    mock_run.side_effect = FileNotFoundError("apktool")
    apk_path = tmp_path / "test.apk"
    apk_path.touch()
    with pytest.raises(FileNotFoundError, match="Apktool not found"):
        analyzer.decompile(str(apk_path))


@patch("apkmorph.analyzer.run_apktool")
def test_decompile_apktool_failure(mock_run: MagicMock, analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Apktool CalledProcessError should be wrapped with stderr."""
    mock_run.side_effect = CalledProcessError(
        1, ["apktool"], stderr=b"decompile failed: bad manifest"
    )
    apk_path = tmp_path / "test.apk"
    apk_path.touch()
    with pytest.raises(RuntimeError, match="Apktool decompilation failed"):
        analyzer.decompile(str(apk_path))


@patch("apkmorph.analyzer.APK")
@patch("apkmorph.analyzer.run_apktool")
def test_decompile_androguard_failure(
    mock_run: MagicMock, mock_apk: MagicMock, analyzer: APKAnalyzer, tmp_path: Path
) -> None:
    """Androguard exceptions should be wrapped."""
    apk_path = tmp_path / "test.apk"
    apk_path.touch()
    mock_run.return_value = None
    mock_apk.side_effect = Exception("invalid dex")
    with pytest.raises(RuntimeError, match="Androguard parsing failed"):
        analyzer.decompile(str(apk_path))


@patch("apkmorph.analyzer.APK")
@patch("apkmorph.analyzer.run_apktool")
def test_decompile_full(
    mock_run: MagicMock, mock_apk: MagicMock, analyzer: APKAnalyzer, tmp_path: Path
) -> None:
    """Full decompilation flow with mocked tools and fake decompiled tree.

    Verifies metadata, components, strings, string_resources and that
    the new XML resource extraction works.
    """
    apk_path = tmp_path / "test.apk"
    apk_path.touch()
    mtime = int(apk_path.stat().st_mtime)
    decomp_dir = analyzer.working_dir / f"apk_test_{mtime}"
    decomp_dir.mkdir(parents=True, exist_ok=True)

    # Fake manifest
    (decomp_dir / "AndroidManifest.xml").write_text(
        '<manifest package="com.test.app"/>'
    )

    # Fake Smali (including multidex-style path)
    smali_dir = decomp_dir / "smali" / "com" / "test" / "app"
    smali_dir.mkdir(parents=True)
    (smali_dir / "MainActivity.smali").write_text(
        ".class public Lcom/test/app/MainActivity;"
    )
    (smali_dir / "Analytics.smali").write_text(
        ".class public Lcom/test/app/Analytics;"
    )

    # Fake string resources (tests the new _extract_string_resources logic)
    values_dir = decomp_dir / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="analytics_id">UA-12345678</string>
    <string name="ad_banner">Advertisement</string>
    <string-array name="menu_items">
        <item>Item One</item>
        <item>Item Two</item>
    </string-array>
</resources>"""
    )

    # Mock Androguard
    mock_apk_instance = MagicMock()
    mock_apk.return_value = mock_apk_instance
    mock_apk_instance.get_package.return_value = "com.test.app"
    mock_apk_instance.get_androidversion_name.return_value = "1.2.3"
    mock_apk_instance.get_androidversion_code.return_value = 123
    mock_apk_instance.get_min_sdk_version.return_value = 24
    mock_apk_instance.get_target_sdk_version.return_value = 34
    mock_apk_instance.get_main_activity.return_value = "com.test.app.MainActivity"
    mock_apk_instance.get_activities.return_value = [
        "com.test.app.MainActivity",
        "com.test.app.SettingsActivity",
    ]
    mock_apk_instance.get_services.return_value = ["com.test.app.BackgroundService"]
    mock_apk_instance.get_receivers.return_value = []
    mock_apk_instance.get_providers.return_value = []
    mock_apk_instance.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk_instance.is_signed.return_value = True
    mock_cert = MagicMock()
    mock_cert.get_fingerprint.return_value = "SHA-256:AA:BB:CC:DD"
    mock_apk_instance.get_certificates.return_value = [mock_cert]

    mock_run.return_value = None

    report: AnalysisReport = analyzer.decompile(str(apk_path))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.test.app"
    assert report.version_name == "1.2.3"
    assert report.version_code == 123
    assert report.min_sdk == 24
    assert report.target_sdk == 34
    assert report.main_activity == "com.test.app.MainActivity"
    assert len(report.activities) == 2
    assert len(report.services) == 1
    assert len(report.permissions) == 1
    assert len(report.components) >= 4  # manifest + smali
    assert "com.test.app.Analytics" in report.components
    assert len(report.strings) >= 4
    assert "Test App" in report.strings
    assert "UA-12345678" in report.strings
    assert "Item One" in report.strings  # from <item>
    assert report.string_resources["app_name"] == "Test App"
    assert report.string_resources["analytics_id"] == "UA-12345678"
    assert report.string_resources["ad_banner"] == "Advertisement"
    assert report.metadata["is_signed"] is True
    assert report.metadata["smali_classes"] >= 2
    assert "regenerated by Apktool" in report.metadata["resources_arsc"]
    assert report.size_bytes == apk_path.stat().st_size
    assert str(report.decompiled_dir).endswith(str(decomp_dir))

    mock_run.assert_called_once_with(
        ["d", str(apk_path), "-o", str(decomp_dir), "-f", "--no-src"]
    )
    mock_apk.assert_called_once_with(str(apk_path))

    # Verify keyword search works on the produced tree
    matches = analyzer.find_by_keyword("analytics", report.decompiled_dir)
    assert any("Analytics" in m for m in matches)
    assert any("resource:strings.xml" in m for m in matches)


def test_extract_components(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Component extraction from smali* directories (including multidex)."""
    for variant in ("smali", "smali_classes2"):
        base = tmp_path / variant / "com" / "example"
        base.mkdir(parents=True)
        (base / "Utils.smali").write_text(".class public Lcom/example/Utils;")
        (base / "V2.smali").write_text(".class public Lcom/example/V2;")

    components = analyzer.extract_components(tmp_path)
    assert "com.example.Utils" in components
    assert "com.example.V2" in components
    assert len(components) == 2  # deduplicated


def test_extract_components_missing_dir(analyzer: APKAnalyzer) -> None:
    """Missing or None decompiled_dir returns empty list."""
    assert analyzer.extract_components(None) == []  # type: ignore
    assert analyzer.extract_components(Path("/nonexistent")) == []


def test_find_by_keyword(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Case-insensitive search over components and XML content."""
    smali_dir = tmp_path / "smali" / "com" / "test"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Tracker.smali").write_text("invoke-static ... analytics")

    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<manifest><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>'
        '<string name="ad_id">ca-app-pub-123</string></manifest>'
    )

    matches = analyzer.find_by_keyword("tracker", tmp_path)
    assert any("Tracker" in m for m in matches)

    matches = analyzer.find_by_keyword("location", tmp_path)
    assert any("resource:AndroidManifest.xml" in m for m in matches)

    matches = analyzer.find_by_keyword("ad_id", tmp_path)
    assert any("resource:AndroidManifest.xml" in m for m in matches)

    assert analyzer.find_by_keyword("") == []
    assert analyzer.find_by_keyword("   ") == []


def test_find_by_keyword_no_dir(analyzer: APKAnalyzer) -> None:
    """When no decompiled_dir is supplied we return empty list."""
    assert analyzer.find_by_keyword("anything") == []


def test_extract_string_resources(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Parse strings.xml (and other values XML) for the string_resources dict."""
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">TestApp</string>
    <string name="welcome">Hello, world!</string>
    <string-array name="options">
        <item>First</item>
        <item>Second</item>
    </string-array>
    <string name="empty"></string>
</resources>"""
    )

    strings, string_map = analyzer._extract_string_resources(tmp_path)

    assert len(strings) >= 4
    assert "TestApp" in strings
    assert "Hello, world!" in strings
    assert "First" in strings
    assert "Second" in strings
    assert string_map["app_name"] == "TestApp"
    assert string_map["welcome"] == "Hello, world!"
    assert "options" not in string_map  # array itself has no text
    assert "empty" not in string_map  # after strip() it is empty


def test_extract_string_resources_bad_xml(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Malformed XML is gracefully skipped."""
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text("<resources><string name=unclosed")

    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert strings == []
    assert string_map == {}


def test_extract_string_resources_no_values_dir(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    """Missing res/values returns empty collections."""
    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert strings == []
    assert string_map == {}
