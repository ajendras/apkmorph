"""Tests for APKAnalyzer.

Covers decompilation error paths, component extraction from Smali,
string parsing, keyword search, and integration with AnalysisReport.
Uses temporary directories with synthetic Smali/XML fixtures to avoid
requiring real APKs or external tools in unit tests.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def tmp_working_dir(tmp_path: Path) -> Path:
    """Temporary working directory for decompiled artifacts."""
    wd = tmp_path / "working"
    wd.mkdir()
    return wd


@pytest.fixture
def fake_decompiled(tmp_path: Path) -> Path:
    """Create a realistic-looking decompiled APK tree for testing."""
    root = tmp_path / "fake_decompiled"
    root.mkdir()

    # Smali structure
    smali = root / "smali" / "com" / "example"
    smali.mkdir(parents=True)
    (smali / "MainActivity.smali").write_text(
        ".class public Lcom/example/MainActivity;\n"
        ".method public onCreate(Landroid/os/Bundle;)V\n"
        "    .locals 2\n"
        "    invoke-static {p0}, Lcom/example/Analytics;->track()V\n"
        "    return-void\n"
        ".end method\n"
    )
    (smali / "Analytics.smali").write_text(
        ".class public Lcom/example/Analytics;\n"
        ".method public static track()V\n"
        "    return-void\n"
        ".end method\n"
    )
    # Multidex variant
    smali2 = root / "smali_classes2" / "com" / "example" / "ads"
    smali2.mkdir(parents=True)
    (smali2 / "AdManager.smali").write_text(
        ".class public Lcom/example/ads/AdManager;\n"
    )

    # Resources
    values = root / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test Game</string>
    <string name="analytics_key">UA-12345678-9</string>
    <string name="ads_banner_id">ca-app-pub-1234567890</string>
</resources>
"""
    )

    # Manifest
    (root / "AndroidManifest.xml").write_text(
        '<manifest package="com.example.testapp"/>'
    )

    return root


def test_analyzer_init_creates_working_dir(tmp_working_dir: Path):
    analyzer = APKAnalyzer(working_dir=tmp_working_dir / "newdir")
    assert (tmp_working_dir / "newdir").exists()
    assert analyzer.working_dir == (tmp_working_dir / "newdir")


def test_extract_components_parses_smali(fake_decompiled: Path):
    analyzer = APKAnalyzer()
    components = analyzer.extract_components(fake_decompiled)

    assert "com.example.MainActivity" in components
    assert "com.example.Analytics" in components
    assert "com.example.ads.AdManager" in components
    assert len(components) == 3


def test_extract_components_handles_multiple_smali_dirs(tmp_path: Path):
    root = tmp_path / "multi"
    root.mkdir()
    (root / "smali_classes2" / "com" / "util").mkdir(parents=True)
    (root / "smali_classes2" / "com" / "util" / "Helper.smali").write_text(
        ".class public Lcom/util/Helper;"
    )

    analyzer = APKAnalyzer()
    components = analyzer.extract_components(root)
    assert "com.util.Helper" in components


def test_walk_smali_skips_non_smali(tmp_path: Path):
    root = tmp_path / "bad"
    root.mkdir()
    (root / "smali" / "com" / "test").mkdir(parents=True)
    (root / "smali" / "com" / "test" / "README.txt").write_text("ignore me")

    analyzer = APKAnalyzer()
    components = analyzer.extract_components(root)
    assert not components  # no .smali files


def test_find_by_keyword_components_and_resources(fake_decompiled: Path):
    analyzer = APKAnalyzer()
    matches = analyzer.find_by_keyword("analytics", fake_decompiled)

    assert any("Analytics" in m for m in matches)
    assert any("resource:strings.xml" in m for m in matches)
    assert len(matches) <= 30


def test_find_by_keyword_empty_term_returns_empty():
    analyzer = APKAnalyzer()
    assert analyzer.find_by_keyword("") == []
    assert analyzer.find_by_keyword("   ") == []


def test_extract_strings_parses_xml(fake_decompiled: Path):
    analyzer = APKAnalyzer()
    strings = analyzer._extract_strings(fake_decompiled)

    assert "Test Game" in strings
    assert "UA-12345678-9" in strings
    assert "ca-app-pub-1234567890" in strings
    assert all(len(s) < 120 for s in strings)


def test_extract_strings_handles_malformed_xml(tmp_path: Path):
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "bad.xml").write_text("<string>unclosed")

    analyzer = APKAnalyzer()
    strings = analyzer._extract_strings(tmp_path)
    assert not strings  # gracefully skips parse errors


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_decompile_success(mock_apk_cls, mock_run, tmp_path: Path, fake_decompiled: Path):
    apk_file = tmp_path / "test.apk"
    apk_file.touch()

    # Mock Apktool
    mock_run.return_value = "I: Baksmaling..."

    # Mock Androguard APK
    mock_apk = MagicMock()
    mock_apk_cls.return_value = mock_apk
    mock_apk.get_package.return_value = "com.example.testapp"
    mock_apk.get_activities.return_value = ["com.example.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk.get_main_activity.return_value = "com.example.MainActivity"
    mock_apk.get_androidversion_name.return_value = "1.2.3"
    mock_apk.get_androidversion_code.return_value = 123
    mock_apk.get_min_sdk_version.return_value = 21
    mock_apk.get_target_sdk_version.return_value = 33
    mock_apk.is_signed.return_value = True
    mock_apk.get_certificates.return_value = []

    analyzer = APKAnalyzer(working_dir=tmp_path / "decomp")
    report = analyzer.decompile(str(apk_file))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.testapp"
    assert report.version_name == "1.2.3"
    assert "com.example.MainActivity" in report.components
    assert "android.permission.INTERNET" in report.permissions
    assert report.decompiled_dir.name.startswith("apk_test_")
    mock_run.assert_called_once()
    mock_apk_cls.assert_called_once()


def test_decompile_missing_apk_raises(tmp_path: Path):
    analyzer = APKAnalyzer(working_dir=tmp_path)
    with pytest.raises(FileNotFoundError, match="APK file not found"):
        analyzer.decompile("nonexistent.apk")


def test_decompile_non_apk_file_raises(tmp_path: Path):
    txt = tmp_path / "data.txt"
    txt.touch()

    analyzer = APKAnalyzer(working_dir=tmp_path)
    with pytest.raises(ValueError, match="Input must be a valid .apk file"):
        analyzer.decompile(str(txt))


@patch("apkmorph.analyzer.run_apktool")
def test_decompile_apktool_failure(mock_run, tmp_path: Path):
    apk_file = tmp_path / "bad.apk"
    apk_file.touch()
    mock_run.side_effect = subprocess.CalledProcessError(
        1, ["apktool"], stderr=b"Apktool error: invalid zip"
    )

    analyzer = APKAnalyzer(working_dir=tmp_path)
    with pytest.raises(RuntimeError, match="Apktool decompilation failed"):
        analyzer.decompile(str(apk_file))


@patch("apkmorph.analyzer.APK")
@patch("apkmorph.analyzer.run_apktool")
def test_decompile_androguard_failure(mock_run, mock_apk_cls, tmp_path: Path):
    apk_file = tmp_path / "test.apk"
    apk_file.touch()
    mock_run.return_value = "success"

    mock_apk_cls.side_effect = Exception("Androguard crashed")

    analyzer = APKAnalyzer(working_dir=tmp_path)
    with pytest.raises(RuntimeError, match="Androguard parsing failed"):
        analyzer.decompile(str(apk_file))


def test_analysis_report_helpers():
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test.app",
        decompiled_dir=Path("/tmp/decomp"),
        components=["com.test.Main", "com.test.Ads"],
        permissions=["INTERNET"],
        strings=["hello", "world"],
        size_bytes=1024 * 1024,
    )

    assert "com.test.app" in report.summary()
    assert len(report.find_components("ads")) == 1
    assert "Main" in report.find_components("main", limit=5)[0]
    md = report.to_markdown()
    assert "# Analysis Report" in md
    assert "com.test.Main" in md
