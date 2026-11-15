"""Tests for the APK analyzer.

Uses mocks for Apktool, Androguard and filesystem operations so that tests
run reliably in CI without requiring Java, apktool, or real APK fixtures.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


def test_analyzer_init(tmp_path: Path) -> None:
    """Test that the analyzer initializes with a working directory."""
    work_dir = tmp_path / "decompiled"
    analyzer = APKAnalyzer(working_dir=work_dir)
    assert analyzer.working_dir == work_dir
    assert analyzer.working_dir.exists()


def test_decompile_invalid_inputs(tmp_path: Path) -> None:
    """Test early validation errors for bad input paths."""
    analyzer = APKAnalyzer(working_dir=tmp_path)

    with pytest.raises(FileNotFoundError, match="APK file not found"):
        analyzer.decompile("nonexistent.apk")

    fake_txt = tmp_path / "not_an_apk.txt"
    fake_txt.touch()
    with pytest.raises(ValueError, match="Input must be a valid .apk file"):
        analyzer.decompile(str(fake_txt))


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_decompile_success(
    mock_apk: MagicMock, mock_run: MagicMock, tmp_path: Path
) -> None:
    """Test full decompilation flow with mocked external tools."""
    mock_run.return_value = None

    mock_apk_instance = MagicMock()
    mock_apk.return_value = mock_apk_instance
    mock_apk_instance.get_package.return_value = "com.example.app"
    mock_apk_instance.get_androidversion_name.return_value = "1.0"
    mock_apk_instance.get_androidversion_code.return_value = 1
    mock_apk_instance.get_min_sdk_version.return_value = 21
    mock_apk_instance.get_target_sdk_version.return_value = 33
    mock_apk_instance.get_main_activity.return_value = "com.example.MainActivity"
    mock_apk_instance.get_activities.return_value = ["com.example.MainActivity"]
    mock_apk_instance.get_services.return_value = []
    mock_apk_instance.get_receivers.return_value = []
    mock_apk_instance.get_providers.return_value = []
    mock_apk_instance.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk_instance.is_signed.return_value = True
    mock_apk_instance.get_certificates.return_value = []

    analyzer = APKAnalyzer(working_dir=tmp_path)

    with patch.object(
        analyzer, "extract_components", return_value=["com.example.MainActivity"]
    ):
        with patch.object(
            analyzer, "_extract_strings", return_value=["Hello", "World"]
        ):
            report = analyzer.decompile("test.apk")

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.app"
    assert report.version_name == "1.0"
    assert report.version_code == 1
    assert report.min_sdk == 21
    assert report.target_sdk == 33
    assert "com.example.MainActivity" in report.components
    assert "Hello" in report.strings
    assert report.metadata["is_signed"] is True
    assert isinstance(report.decompiled_dir, Path)


def test_extract_components(tmp_path: Path) -> None:
    """Test Smali directory walking and class-name conversion."""
    analyzer = APKAnalyzer()

    # Fake multi-dex layout
    smali_dir = tmp_path / "smali_classes2" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "MainActivity.smali").write_text(
        ".class public Lcom/example/MainActivity;"
    )
    (smali_dir / "utils" / "Helper.smali").mkdir(parents=True)
    (smali_dir / "utils" / "Helper.smali").write_text(
        ".class public Lcom/example/utils/Helper;"
    )

    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components
    assert "com.example.utils.Helper" in components


def test_find_by_keyword(tmp_path: Path) -> None:
    """Test keyword search over components and XML resources."""
    analyzer = APKAnalyzer()

    # Fake XML resources
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        '<string name="app_name">Test App</string>\n'
        '<string name="analytics">analytics tracker</string>'
    )
    (values_dir / "colors.xml").write_text('<color name="primary">#000000</color>')

    # Also create a smali file so component search works
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Analytics.smali").write_text(
        ".class public Lcom/example/Analytics;"
    )

    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert len(matches) > 0
    assert any("Analytics" in m for m in matches)
    assert any("resource:" in m for m in matches)

    matches = analyzer.find_by_keyword("primary", tmp_path)
    assert any("resource:colors.xml" in m for m in matches)

    assert len(analyzer.find_by_keyword("", tmp_path)) == 0


def test_extract_strings(tmp_path: Path) -> None:
    """Test parsing of strings.xml with length filtering."""
    analyzer = APKAnalyzer()

    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test Application</string>
    <string name="welcome">Welcome to the app!</string>
    <string name="very_long_string">"""
        + "x" * 200
        + """</string>
    <string-array name="options">
        <item>Option One</item>
        <item>Option Two</item>
    </string-array>
</resources>
"""
    )

    strings = analyzer._extract_strings(tmp_path)
    assert "Test Application" in strings
    assert "Welcome to the app!" in strings
    assert "Option One" in strings
    assert not any(len(s) >= 120 for s in strings)
    # The very_long_string should have been filtered
    assert not any("x" * 50 in s for s in strings)
