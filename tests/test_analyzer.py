"""Tests for APKAnalyzer.

Covers decompilation (with mocks), component extraction, string resource parsing,
keyword search, runtime observation (both real Frida path and simulation fallback).
Uses pytest mocks so the suite runs cleanly in CI without real APKs, Ollama or
a USB device. Updated to exercise the new Frida guard, string_resources and
the broader exception handling added for Python 3.12 compatibility.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer, _FRIDA_AVAILABLE
from apkmorph.models import AnalysisReport


@pytest.fixture
def tmp_decomp(tmp_path):
    (tmp_path / "res" / "values").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def mock_apk_obj():
    apk = MagicMock()
    apk.get_activities.return_value = ["com.example.MainActivity"]
    apk.get_services.return_value = []
    apk.get_receivers.return_value = []
    apk.get_providers.return_value = []
    apk.get_permissions.return_value = ["android.permission.INTERNET"]
    apk.get_package.return_value = "com.example.app"
    apk.get_androidversion_name.return_value = "1.0"
    apk.get_androidversion_code.return_value = "1"
    apk.get_min_sdk_version.return_value = 24
    apk.get_target_sdk_version.return_value = 34
    apk.get_main_activity.return_value = "com.example.MainActivity"
    apk.is_signed.return_value = True
    apk.get_certificates.return_value = []
    return apk


def test_analyzer_init(tmp_path):
    analyzer = APKAnalyzer(working_dir=tmp_path / "decomp")
    assert analyzer.working_dir == tmp_path / "decomp"
    assert analyzer.working_dir.exists()


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
@patch("apkmorph.analyzer.APKAnalyzer._extract_string_resources")
@patch("apkmorph.analyzer.APKAnalyzer.extract_components")
def test_decompile(
    mock_extract_comp,
    mock_extract_str,
    mock_apk_class,
    mock_run,
    tmp_path,
    mock_apk_obj,
):
    mock_apk_class.return_value = mock_apk_obj
    mock_extract_str.return_value = (
        ["hello world", "Advertisement"],
        {"app_name": "Test App", "ad_text": "Advertisement"},
    )
    mock_extract_comp.return_value = ["com.example.MainActivity", "com.example.Utils"]

    analyzer = APKAnalyzer(working_dir=tmp_path)
    report = analyzer.decompile("fake.apk")

    assert report.package_name == "com.example.app"
    assert report.version_name == "1.0"
    assert report.version_code == "1"
    assert len(report.strings) == 2
    assert report.string_resources["app_name"] == "Test App"
    assert "smali_classes" in report.metadata
    assert len(report.components) == 3
    mock_run.assert_called_once()
    mock_extract_comp.assert_called_once()


def test_extract_components(tmp_path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "MainActivity.smali").write_text("# stub")
    (smali_dir / "Utils.smali").write_text("# stub")

    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components
    assert "com.example.Utils" in components


def test_extract_string_resources(tmp_decomp):
    analyzer = APKAnalyzer()
    strings_xml = tmp_decomp / "res" / "values" / "strings.xml"
    strings_xml.write_text("""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="ad_text">Advertisement</string>
    <string-array name="menu_items">
        <item>First</item>
        <item>Second</item>
    </string-array>
</resources>""")

    strings, string_map = analyzer._extract_string_resources(tmp_decomp)
    assert "Test App" in strings
    assert "Advertisement" in strings
    assert "First" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map["ad_text"] == "Advertisement"


def test_find_by_keyword(tmp_path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "Analytics.smali").write_text("analytics code")
    (tmp_path / "AndroidManifest.xml").write_text("<manifest>analytics</manifest>")

    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert any("Analytics" in m for m in matches)
    assert any("resource:AndroidManifest.xml" in m for m in matches)


def test_observe_runtime_simulation():
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.app",
        decompiled_dir=Path("/tmp/decomp"),
        strings=["firebase", "ad", "crash"],
        string_resources={"ad_text": "Ad"},
        metadata={},
        size_bytes=1024,
    )

    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", False):
        updated = analyzer.observe_runtime(report, duration=1)

    assert len(updated.runtime_observations) >= 3
    assert any("ad" in obs for obs in updated.runtime_observations)
    assert any("analytics" in obs.lower() for obs in updated.runtime_observations)
    assert updated.metadata.get("runtime_observed") is True
    assert updated.metadata.get("frida_used") is False


@patch("apkmorph.analyzer.frida")
@patch("apkmorph.analyzer.time.sleep")
def test_observe_runtime_frida_path(mock_sleep, mock_frida_module):
    # Mock a successful Frida run (no real device needed)
    mock_device = MagicMock()
    mock_frida_module.get_usb_device.return_value = mock_device
    mock_device.spawn.return_value = 999
    mock_session = MagicMock()
    mock_device.attach.return_value = mock_session
    mock_script = MagicMock()
    mock_session.create_script.return_value = mock_script

    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.app",
        decompiled_dir=Path("/tmp/decomp"),
        strings=[],
        string_resources={},
        metadata={},
        size_bytes=1024,
    )

    # Force _FRIDA_AVAILABLE True for this test
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", True):
        updated = analyzer.observe_runtime(report, duration=1)

    assert len(updated.runtime_observations) > 0
    mock_frida_module.get_usb_device.assert_called_once()
    mock_script.load.assert_called_once()
