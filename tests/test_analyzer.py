"""Tests for the APKAnalyzer.

Covers decompilation (with mocks), component extraction, string resource parsing,
keyword search, and runtime observation (simulation fallback)."""
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def analyzer(temp_dir):
    return APKAnalyzer(working_dir=temp_dir)


@pytest.fixture
def sample_report(temp_dir):
    return AnalysisReport(
        apk_path=Path("sample.apk"),
        package_name="com.example.app",
        decompiled_dir=temp_dir / "decompiled_sample",
        size_bytes=1024,
        strings=["ad", "analytics", "firebase analytics"],
        string_resources={"app_name": "Sample App", "ad_text": "Click here to win!"},
        components=["com.example.app.MainActivity", "com.example.app.AdManager"],
        runtime_observations=["observed: ad - loadAd()"],
        metadata={},
    )


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_decompile(mock_apk_class, mock_run, analyzer, temp_dir):
    dummy_apk = temp_dir / "dummy.apk"
    dummy_apk.touch()

    mock_apk = mock_apk_class.return_value
    mock_apk.get_activities.return_value = ["com.example.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk.get_package.return_value = "com.example.app"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 21
    mock_apk.get_target_sdk_version.return_value = 33
    mock_apk.get_main_activity.return_value = "com.example.MainActivity"
    mock_apk.is_signed.return_value = True
    mock_apk.get_certificates.return_value = []

    report = analyzer.decompile(str(dummy_apk))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.app"
    assert report.version_name == "1.0"
    assert len(report.components) >= 1
    assert "smali_classes" in report.metadata
    mock_run.assert_called_once()


def test_extract_components(analyzer, temp_dir):
    smali_dir = temp_dir / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "MainActivity.smali").write_text(
        ".class public Lcom/example/MainActivity;"
    )
    utils_dir = smali_dir / "utils"
    utils_dir.mkdir()
    (utils_dir / "Helper.smali").write_text(
        ".class public Lcom/example/utils/Helper;"
    )

    components = analyzer.extract_components(temp_dir)
    assert "com.example.MainActivity" in components
    assert "com.example.utils.Helper" in components


def test_extract_string_resources(analyzer, temp_dir):
    values_dir = temp_dir / "res" / "values"
    values_dir.mkdir(parents=True)
    strings_xml = values_dir / "strings.xml"
    strings_xml.write_text("""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">APK Morph</string>
    <string name="welcome">Welcome to the app</string>
    <string-array name="options">
        <item>Option 1</item>
    </string-array>
</resources>""")

    strings, string_map = analyzer._extract_string_resources(temp_dir)
    assert "APK Morph" in strings
    assert "Welcome to the app" in strings
    assert "Option 1" in strings
    assert string_map["app_name"] == "APK Morph"
    assert len(string_map) >= 1


def test_find_by_keyword(analyzer, temp_dir):
    smali_dir = temp_dir / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "AdActivity.smali").write_text("ad related code")
    (temp_dir / "AndroidManifest.xml").write_text("<manifest><application android:label=\"ad label\"/></manifest>")

    matches = analyzer.find_by_keyword("ad", temp_dir)
    assert any("AdActivity" in m for m in matches)
    assert any("resource:" in m for m in matches) or len(matches) > 0


def test_observe_runtime_simulation(sample_report, analyzer):
    with patch.object(analyzer, "_run_frida_observation") as mock_run:
        mock_run.return_value = [
            "observed: ad - com.google.android.gms.ads.AdView.loadAd() called 4 times",
            "observed: analytics - FirebaseAnalytics.logEvent() called with screen_view and user_engagement",
        ]
        updated = analyzer.observe_runtime(sample_report, duration=2)
        assert isinstance(updated, AnalysisReport)
        assert len(updated.runtime_observations) == 2
        assert updated.metadata.get("runtime_observed") is True
        assert "frida_used" in updated.metadata


def test_simulate_observations(analyzer):
    strings = ["This app uses firebase analytics and shows ads", "crash reporting enabled"]
    obs = analyzer._simulate_observations("com.test.app", strings)
    assert any("onCreate" in o for o in obs)
    assert any("ad" in o.lower() for o in obs)
    assert any("analytics" in o.lower() for o in obs)
    assert any("crash_reporting" in o for o in obs)
    assert len(obs) >= 5
