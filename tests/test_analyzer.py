"""Tests for APKAnalyzer.

Covers decompilation, component extraction, keyword search, string resource
extraction, runtime observation (Frida + simulation fallback) and the
new XML/resource support. All external tools and Frida are mocked so the
suite runs cleanly in CI.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def analyzer(tmp_path: Path) -> APKAnalyzer:
    return APKAnalyzer(working_dir=tmp_path / "decompiled")


@pytest.fixture
def sample_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "test.apk"
    apk.touch()
    return apk


@pytest.fixture
def mock_apk_class():
    with patch("apkmorph.analyzer.APK") as mock:
        instance = MagicMock()
        instance.get_package.return_value = "com.example.test"
        instance.get_activities.return_value = ["com.example.MainActivity"]
        instance.get_services.return_value = []
        instance.get_receivers.return_value = []
        instance.get_providers.return_value = []
        instance.get_permissions.return_value = ["android.permission.INTERNET"]
        instance.get_main_activity.return_value = "com.example.MainActivity"
        instance.get_androidversion_name.return_value = "1.0"
        instance.get_androidversion_code.return_value = "1"
        instance.get_min_sdk_version.return_value = 24
        instance.get_target_sdk_version.return_value = 34
        instance.is_signed.return_value = True
        instance.get_certificates.return_value = []
        mock.return_value = instance
        yield mock


def test_analyzer_init(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    assert analyzer.working_dir == tmp_path / "decompiled"
    assert analyzer.working_dir.exists()


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APKAnalyzer.extract_components")
@patch("apkmorph.analyzer.APKAnalyzer._extract_string_resources")
def test_decompile(
    mock_extract_strings,
    mock_extract_components,
    mock_run_apktool,
    analyzer: APKAnalyzer,
    sample_apk: Path,
    mock_apk_class,
) -> None:
    mock_extract_components.return_value = ["com.example.MainActivity", "com.example.Utils"]
    mock_extract_strings.return_value = (
        ["Test App", "Hello World"],
        {"app_name": "Test App", "greeting": "Hello World"},
    )

    report = analyzer.decompile(str(sample_apk))

    assert report.package_name == "com.example.test"
    assert report.version_name == "1.0"
    assert report.main_activity == "com.example.MainActivity"
    assert "com.example.MainActivity" in report.components
    assert "Test App" in report.strings
    assert report.string_resources["app_name"] == "Test App"
    assert "smali_classes" in report.metadata
    assert report.decompiled_dir is not None
    mock_run_apktool.assert_called_once()
    mock_extract_components.assert_called_once()
    mock_extract_strings.assert_called_once()


def test_extract_components(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "com").mkdir(parents=True)
    main_smali = smali_dir / "com" / "example" / "MainActivity.smali"
    main_smali.parent.mkdir(parents=True, exist_ok=True)
    main_smali.write_text(".class public Lcom/example/MainActivity;")

    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components


def test_find_by_keyword(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir(parents=True)
    (smali_dir / "AnalyticsTracker.smali").write_text("invoke-static")
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest package="com.test"><uses-permission android:name="android.permission.INTERNET"/></manifest>'
    )
    (tmp_path / "res" / "values" / "strings.xml").parent.mkdir(parents=True)
    (tmp_path / "res" / "values" / "strings.xml").write_text(
        '<resources><string name="ad_unit">ca-app-pub-xxx</string></resources>'
    )

    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert any("AnalyticsTracker" in m for m in matches)

    matches = analyzer.find_by_keyword("ad_unit", tmp_path)
    assert any("resource:strings.xml" in m for m in matches)

    matches = analyzer.find_by_keyword("internet", tmp_path)
    assert any("resource:AndroidManifest.xml" in m for m in matches)


def test_extract_string_resources(analyzer: APKAnalyzer, tmp_path: Path) -> None:
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    strings_xml = values_dir / "strings.xml"
    strings_xml.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">TestApp</string>
    <string name="greeting">Hello, World!</string>
    <string-array name="options"><item>Option1</item></string-array>
</resources>"""
    )

    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert "TestApp" in strings
    assert "Hello, World!" in strings
    assert "Option1" in strings
    assert string_map["app_name"] == "TestApp"
    assert string_map["greeting"] == "Hello, World!"


def test_observe_runtime(analyzer: APKAnalyzer) -> None:
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.test",
        decompiled_dir=Path("/tmp/decomp"),
        components=[],
        strings=["analytics", "ad"],
        string_resources={},
        metadata={},
        size_bytes=1024,
    )

    with patch.object(analyzer, "_run_frida_observation") as mock_run:
        mock_run.return_value = [
            "observed: analytics - FirebaseAnalytics.logEvent",
            "observed: ad - AdView.loadAd",
        ]
        updated = analyzer.observe_runtime(report, duration=2)
        assert len(updated.runtime_observations) == 2
        assert updated.metadata.get("runtime_observed") is True
        assert updated.metadata.get("frida_used") is not None


def test_run_frida_observation_simulation(analyzer: APKAnalyzer) -> None:
    strings = ["firebase", "admob", "crashlytics"]
    obs = analyzer._simulate_observations("com.example.test", strings)
    assert any("onCreate" in o for o in obs)
    assert any("ad" in o.lower() for o in obs)
    assert any("analytics" in o.lower() for o in obs)
    assert any("crash_reporting" in o.lower() for o in obs)
    assert any("hooks triggered" in o for o in obs)


@patch("apkmorph.analyzer._FRIDA_AVAILABLE", True)
@patch("apkmorph.analyzer.frida")
def test_run_frida_observation_real_path(mock_frida, analyzer: APKAnalyzer) -> None:
    mock_device = MagicMock()
    mock_session = MagicMock()
    mock_script = MagicMock()
    mock_frida.get_usb_device.return_value = mock_device
    mock_device.spawn.return_value = 1234
    mock_device.attach.return_value = mock_session
    mock_session.create_script.return_value = mock_script

    obs = analyzer._run_frida_observation("com.example.test", duration=1, strings=[])
    assert len(obs) > 0
    mock_device.spawn.assert_called_once()
    mock_script.load.assert_called_once()
