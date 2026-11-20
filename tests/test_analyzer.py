"""Tests for APK analysis module.

Covers decompilation mocking, component extraction, string resource parsing,
keyword search, and the Frida simulation fallback used in CI environments
without device access.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def mock_report():
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.app",
        version_name="1.0",
        version_code="1",
        min_sdk=24,
        target_sdk=34,
        decompiled_dir=Path("/tmp/decompiled_test"),
        main_activity="com.example.app.MainActivity",
        activities=["com.example.app.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=["android.permission.INTERNET"],
        components=["com.example.app.MainActivity"],
        strings=["analytics", "ad", "firebase"],
        string_resources={"app_name": "Test App", "ad_text": "Advertisement"},
        metadata={"is_signed": True, "smali_classes": 5},
        size_bytes=2048,
        runtime_observations=[],
    )


def test_decompile(tmp_path: Path):
    apk_path = tmp_path / "test.apk"
    apk_path.touch()

    with patch("apkmorph.analyzer.run_apktool") as mock_apktool, \
         patch("apkmorph.analyzer.APK") as mock_apk_class, \
         patch("apkmorph.analyzer.APKAnalyzer.extract_components") as mock_extract, \
         patch("apkmorph.analyzer.APKAnalyzer._extract_string_resources") as mock_strings:

        mock_apktool.return_value = None
        mock_apk = MagicMock()
        mock_apk_class.return_value = mock_apk
        mock_apk.get_activities.return_value = ["com.example.MainActivity"]
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []
        mock_apk.get_providers.return_value = []
        mock_apk.get_permissions.return_value = []
        mock_apk.get_package.return_value = "com.example.app"
        mock_apk.get_androidversion_name.return_value = "1.0"
        mock_apk.get_androidversion_code.return_value = "1"
        mock_apk.get_min_sdk_version.return_value = 24
        mock_apk.get_target_sdk_version.return_value = 34
        mock_apk.get_main_activity.return_value = "com.example.MainActivity"
        mock_apk.is_signed.return_value = True
        mock_apk.get_certificates.return_value = []
        mock_extract.return_value = ["com.example.MainActivity"]
        mock_strings.return_value = (["test string"], {"test": "string"})

        analyzer = APKAnalyzer(working_dir=tmp_path / "decomp")
        report = analyzer.decompile(str(apk_path))

        assert report.package_name == "com.example.app"
        assert report.strings
        assert isinstance(report.decompiled_dir, Path)
        mock_apktool.assert_called()
        mock_apk_class.assert_called()


def test_extract_components(tmp_path: Path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali_classes2" / "com" / "example" / "utils"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Helper.smali").write_text(
        ".class public Lcom/example/utils/Helper;\n.method public static helper()V"
    )
    components = analyzer.extract_components(tmp_path)
    assert "com.example.utils.Helper" in components


def test_find_by_keyword_with_xml(tmp_path: Path):
    analyzer = APKAnalyzer()
    xml_path = tmp_path / "AndroidManifest.xml"
    xml_path.write_text(
        '<manifest package="com.example.app">'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        "</manifest>"
    )
    matches = analyzer.find_by_keyword("camera", tmp_path)
    assert any("resource" in m for m in matches) or any("camera" in m for m in matches)


def test_extract_string_resources(tmp_path: Path):
    analyzer = APKAnalyzer()
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources>\n'
        '    <string name="app_name">APK Morph</string>\n'
        '    <string name="analytics_disabled">Analytics disabled</string>\n'
        '</resources>'
    )
    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert any("APK Morph" in s for s in strings)
    assert string_map.get("app_name") == "APK Morph"
    assert "analytics_disabled" in string_map


def test_observe_runtime_simulation(mock_report: AnalysisReport):
    analyzer = APKAnalyzer()
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", False):
        updated_report = analyzer.observe_runtime(mock_report, duration=1)
        assert len(updated_report.runtime_observations) > 2
        assert updated_report.metadata["runtime_observed"] is True
        assert updated_report.metadata["frida_used"] is False
        obs = " ".join(updated_report.runtime_observations).lower()
        assert "analytics" in obs or "ad" in obs or "oncreate" in obs


def test_observe_runtime_with_frida_available(mock_report: AnalysisReport):
    analyzer = APKAnalyzer()
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", True), \
         patch("apkmorph.analyzer.frida") as mock_frida:

        mock_device = MagicMock()
        mock_frida.get_usb_device.return_value = mock_device
        mock_device.spawn.return_value = 1234
        mock_session = MagicMock()
        mock_device.attach.return_value = mock_session
        mock_script = MagicMock()
        mock_session.create_script.return_value = mock_script

        with patch.object(analyzer, "_run_frida_observation", return_value=["observed: test hook"]):
            updated = analyzer.observe_runtime(mock_report, duration=1)
            assert "test hook" in updated.runtime_observations[0]
            assert updated.metadata["frida_used"] is True
