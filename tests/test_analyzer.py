"""Tests for the APKAnalyzer."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def temp_apk(tmp_path):
    apk = tmp_path / "testapp.apk"
    apk.write_text("dummy apk content")
    return apk


@pytest.fixture
def mock_run_apktool():
    with patch("apkmorph.analyzer.run_apktool") as m:
        yield m


@pytest.fixture
def mock_apk_class():
    with patch("apkmorph.analyzer.APK") as m:
        instance = MagicMock()
        instance.get_package.return_value = "com.test.app"
        instance.get_androidversion_name.return_value = "2.1.0"
        instance.get_androidversion_code.return_value = "21"
        instance.get_min_sdk_version.return_value = 24
        instance.get_target_sdk_version.return_value = 34
        instance.get_main_activity.return_value = "com.test.app.MainActivity"
        instance.get_activities.return_value = ["com.test.app.MainActivity", "com.test.app.SettingsActivity"]
        instance.get_services.return_value = ["com.test.app.BackgroundService"]
        instance.get_receivers.return_value = []
        instance.get_providers.return_value = []
        instance.get_permissions.return_value = ["android.permission.INTERNET"]
        instance.is_signed.return_value = True
        instance.get_certificates.return_value = [MagicMock()]
        m.return_value = instance
        yield m


@pytest.fixture
def decompiled_fixture(tmp_path):
    d = tmp_path / "decompiled_testapp_12345678"
    d.mkdir()
    (d / "smali").mkdir()
    smali_file = d / "smali" / "com" / "test" / "app"
    smali_file.mkdir(parents=True)
    (smali_file / "MainActivity.smali").write_text(
        ".class public Lcom/test/app/MainActivity;\n.method public onCreate"
    )
    res_values = d / "res" / "values"
    res_values.mkdir(parents=True)
    (res_values / "strings.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources>\n'
        '    <string name="app_name">Test APK Morph</string>\n'
        '    <string name="welcome">Welcome to the app</string>\n'
        '</resources>'
    )
    return d


def test_decompile(
    temp_apk, mock_run_apktool, mock_apk_class, decompiled_fixture, tmp_path
):
    analyzer = APKAnalyzer(working_dir=tmp_path)
    with patch.object(analyzer, "_extract_string_resources", return_value=(["Test APK Morph", "Welcome to the app"], {"app_name": "Test APK Morph"})):
        with patch.object(analyzer, "extract_components", return_value=["com.test.app.MainActivity"]):
            report = analyzer.decompile(str(temp_apk))
    assert report.package_name == "com.test.app"
    assert report.version_name == "2.1.0"
    assert len(report.activities) == 2
    assert len(report.strings) >= 2
    assert report.string_resources["app_name"] == "Test APK Morph"
    assert any("MainActivity" in c for c in report.components)
    assert report.metadata["is_signed"] is True


def test_extract_components(decompiled_fixture):
    analyzer = APKAnalyzer()
    components = analyzer.extract_components(decompiled_fixture)
    assert any(c.endswith("MainActivity") for c in components)


def test_find_by_keyword(decompiled_fixture):
    analyzer = APKAnalyzer()
    matches = analyzer.find_by_keyword("welcome", decompiled_fixture)
    assert len(matches) > 0
    matches2 = analyzer.find_by_keyword("mainactivity", decompiled_fixture)
    assert len(matches2) > 0


def test_string_resource_extraction(decompiled_fixture):
    analyzer = APKAnalyzer()
    strings, mapping = analyzer._extract_string_resources(decompiled_fixture)
    assert "Test APK Morph" in strings
    assert "welcome" in mapping
    assert mapping["welcome"] == "Welcome to the app"


def test_observe_runtime_with_simulation():
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=Path("/tmp"),
        strings=["firebase", "analytics", "ads", "crash reporting"],
        metadata={},
    )
    enriched = analyzer.observe_runtime(report, duration=2)
    assert len(enriched.runtime_observations) >= 3
    obs_text = " ".join(enriched.runtime_observations).lower()
    assert "ad" in obs_text or "analytics" in obs_text
    assert enriched.metadata.get("runtime_observed") is True
    assert enriched.metadata.get("frida_used") is False


def test_observe_runtime_frida_fallback():
    analyzer = APKAnalyzer()
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", True), patch(
        "apkmorph.analyzer.frida"
    ) as mock_frida:
        mock_device = MagicMock()
        mock_frida.get_usb_device.return_value = mock_device
        mock_device.spawn.side_effect = Exception("No device in CI")
        report = AnalysisReport(
            apk_path=Path("test.apk"),
            package_name="com.example.testapp",
            decompiled_dir=Path.cwd(),
            strings=["track"],
            metadata={},
        )
        enriched = analyzer.observe_runtime(report)
        assert any("observed" in o.lower() for o in enriched.runtime_observations)
