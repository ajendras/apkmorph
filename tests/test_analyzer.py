"""Tests for APKAnalyzer.

Uses mocks to avoid requiring Apktool, Java, Frida server or real APKs in CI.
Covers decompilation, string resource extraction, runtime observation (simulation
fallback), keyword search and component extraction.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def mock_androguard():
    with patch("apkmorph.analyzer.APK") as mock_apk_cls:
        instance = MagicMock()
        instance.get_package.return_value = "com.example.testapp"
        instance.get_androidversion_name.return_value = "1.0"
        instance.get_androidversion_code.return_value = 100
        instance.get_min_sdk_version.return_value = 24
        instance.get_target_sdk_version.return_value = 34
        instance.get_main_activity.return_value = "com.example.testapp.MainActivity"
        instance.get_activities.return_value = ["com.example.testapp.MainActivity"]
        instance.get_services.return_value = []
        instance.get_receivers.return_value = []
        instance.get_providers.return_value = []
        instance.get_permissions.return_value = ["android.permission.INTERNET"]
        instance.is_signed.return_value = True
        instance.get_certificates.return_value = []
        mock_apk_cls.return_value = instance
        yield mock_apk_cls


@pytest.fixture
def mock_apktool_run():
    with patch("apkmorph.analyzer.run_apktool") as mock:
        yield mock


def test_decompile_success(temp_dir, mock_androguard, mock_apktool_run):
    analyzer = APKAnalyzer(working_dir=temp_dir)
    apk_path = temp_dir / "test.apk"
    apk_path.touch()

    with patch.object(
        analyzer,
        "_extract_string_resources",
        return_value=(["sample string"], {"app_name": "TestApp"}),
    ), patch.object(
        analyzer, "extract_components", return_value=["com.example.testapp.MainActivity"]
    ):
        report = analyzer.decompile(str(apk_path))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.testapp"
    assert report.version_name == "1.0"
    assert report.strings == ["sample string"]
    assert report.string_resources == {"app_name": "TestApp"}
    assert len(report.components) > 0
    assert "runtime_observations" in report.model_fields_set


def test_observe_runtime_simulation():
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("fake.apk"),
        package_name="com.example.fake",
        decompiled_dir=Path("/tmp"),
        components=["com.example.fake.MainActivity"],
        strings=["ad", "analytics", "firebase"],
        string_resources={},
        metadata={},
    )
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", False):
        updated = analyzer.observe_runtime(report, duration=1)
    assert len(updated.runtime_observations) > 2
    assert any("ad" in obs.lower() for obs in updated.runtime_observations)
    assert any("analytics" in obs.lower() for obs in updated.runtime_observations)
    assert updated.metadata["runtime_observed"] is True


def test_extract_string_resources(temp_dir):
    analyzer = APKAnalyzer()
    values = temp_dir / "res" / "values"
    values.mkdir(parents=True)
    xml = values / "strings.xml"
    xml.write_text(
        '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">APK Morph</string>
    <string name="ad_text">Advertisement</string>
    <item>extra</item>
</resources>'''
    )
    strings, mapping = analyzer._extract_string_resources(temp_dir)
    assert "APK Morph" in strings
    assert "Advertisement" in strings
    assert mapping["app_name"] == "APK Morph"


def test_find_by_keyword(temp_dir):
    analyzer = APKAnalyzer()
    smali_d = temp_dir / "smali" / "com" / "example"
    smali_d.mkdir(parents=True)
    (smali_d / "Main.smali").write_text(".class Lcom/example/Main;")

    matches = analyzer.find_by_keyword("main", temp_dir)
    assert len(matches) > 0
    assert any("Main" in m for m in matches)


def test_simulate_observations():
    analyzer = APKAnalyzer()
    obs = analyzer._simulate_observations("com.test.app", ["ad", "crash", "analytics"])
    assert any("ad" in o for o in obs)
    assert any("crash_reporting" in o for o in obs)
    assert any("analytics" in o for o in obs)
    assert len(obs) >= 4
