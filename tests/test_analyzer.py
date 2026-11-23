"""Tests for the APKAnalyzer.

Covers decompilation, component extraction, keyword search, string resource
parsing, runtime observation (with/without frida), and simulation fallback.
All external calls are mocked so the tests collect and run reliably in CI
without real APKs, Apktool, Androguard, or the optional frida package.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def temp_dir(tmp_path):
    """Temporary directory for decompilation artifacts."""
    return tmp_path


@pytest.fixture
def analyzer(temp_dir):
    """Analyzer instance using temporary working directory."""
    return APKAnalyzer(working_dir=temp_dir / "decompiled")


@pytest.fixture
def mock_apk_path(tmp_path):
    """Mock APK file that exists on disk."""
    apk = tmp_path / "test.apk"
    apk.touch()
    return apk


def test_decompile(analyzer, mock_apk_path):
    """Test full decompilation flow with mocked tools and Androguard."""
    with patch("apkmorph.analyzer.run_apktool") as mock_run, \
         patch("apkmorph.analyzer.APK") as mock_apk_class, \
         patch.object(analyzer, "_extract_string_resources") as mock_extract, \
         patch.object(analyzer, "extract_components") as mock_comp:

        # Mock Androguard APK object
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = "com.example.testapp"
        mock_apk.get_activities.return_value = ["com.example.MainActivity"]
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []
        mock_apk.get_providers.return_value = []
        mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
        mock_apk.get_main_activity.return_value = "com.example.MainActivity"
        mock_apk.get_androidversion_name.return_value = "1.0"
        mock_apk.get_androidversion_code.return_value = "1"
        mock_apk.get_min_sdk_version.return_value = 21
        mock_apk.get_target_sdk_version.return_value = 33
        mock_apk.is_signed.return_value = True
        mock_apk.get_certificates.return_value = []
        mock_apk_class.return_value = mock_apk

        mock_extract.return_value = (["Test string"], {"app_name": "Test App"})
        mock_comp.return_value = ["com.example.MainActivity", "com.example.Utils"]

        report = analyzer.decompile(str(mock_apk_path))

        assert report.package_name == "com.example.testapp"
        assert report.version_name == "1.0"
        assert report.main_activity == "com.example.MainActivity"
        assert len(report.components) >= 1
        assert len(report.strings) > 0
        assert "app_name" in report.string_resources
        assert isinstance(report.decompiled_dir, Path)
        assert report.metadata["is_signed"] is True
        mock_run.assert_called_once()
        mock_extract.assert_called_once()


def test_extract_components(analyzer, temp_dir):
    """Test Smali component extraction from multidex directories."""
    smali_dir = temp_dir / "smali"
    smali_dir.mkdir()
    (smali_dir / "com").mkdir()
    (smali_dir / "com" / "example").mkdir()
    test_smali = smali_dir / "com" / "example" / "TestClass.smali"
    test_smali.touch()

    components = analyzer.extract_components(temp_dir)
    assert "com.example.TestClass" in components


def test_find_by_keyword(analyzer, temp_dir):
    """Test keyword search in components and XML resources."""
    smali_dir = temp_dir / "smali"
    smali_dir.mkdir(parents=True, exist_ok=True)
    (smali_dir / "AnalyticsHelper.smali").touch()

    values_dir = temp_dir / "res" / "values"
    values_dir.mkdir(parents=True, exist_ok=True)
    manifest = temp_dir / "AndroidManifest.xml"
    manifest.write_text("<manifest><application android:name='com.test.App'/></manifest>")

    matches = analyzer.find_by_keyword("analytics", temp_dir)
    assert len(matches) > 0
    assert any("AnalyticsHelper" in m for m in matches) or any("resource" in m for m in matches)


def test_extract_string_resources(analyzer, temp_dir):
    """Test parsing of strings.xml and other values XML files."""
    values_dir = temp_dir / "res" / "values"
    values_dir.mkdir(parents=True, exist_ok=True)
    strings_xml = values_dir / "strings.xml"
    strings_xml.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources>\n'
        '    <string name="app_name">Test App</string>\n'
        '    <string name="welcome">Welcome to the app</string>\n'
        '</resources>',
        encoding="utf-8"
    )

    strings, string_map = analyzer._extract_string_resources(temp_dir)
    assert "Test App" in strings
    assert "Welcome to the app" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map["welcome"] == "Welcome to the app"


def test_observe_runtime_with_simulation(analyzer):
    """Test runtime observation fallback when frida is unavailable."""
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=Path("/tmp/decomp"),
        components=["com.example.MainActivity"],
        strings=["ad", "firebase analytics", "crash"],
        string_resources={},
        metadata={},
        size_bytes=1024,
        runtime_observations=[],
    )

    with patch.object(analyzer, "_run_frida_observation") as mock_run:
        mock_run.return_value = (
            [
                "observed: com.example.testapp.MainActivity.onCreate() invoked",
                "observed: ad - com.google.android.gms.ads.AdView.loadAd() called 4 times",
                "observed: analytics - FirebaseAnalytics.logEvent() called with screen_view and user_engagement",
                "observed: 5 total hooks triggered in com.example.testapp during observation window",
            ],
            False,
        )
        updated = analyzer.observe_runtime(report, duration=1)
        assert len(updated.runtime_observations) >= 3
        assert any("ad" in obs for obs in updated.runtime_observations)
        assert any("analytics" in obs for obs in updated.runtime_observations)
        assert updated.metadata.get("frida_used") is False
        assert updated.metadata.get("runtime_observed") is True


def test_frida_observation_fallback(analyzer):
    """Direct test of simulation path (frida import failure simulated)."""
    strings = ["Remove these ads please", "GA tracking enabled", "report crash"]
    observations = analyzer._simulate_observations("com.example.testapp", strings)
    assert len(observations) >= 4
    assert any("onCreate" in o for o in observations)
    assert any("ad" in o.lower() for o in observations)
    assert any("analytics" in o.lower() for o in observations)
    assert any("crash_reporting" in o for o in observations)


def test_find_by_keyword_no_dir(analyzer):
    """Test keyword search when no decompiled_dir is supplied."""
    matches = analyzer.find_by_keyword("analytics")
    assert isinstance(matches, list)
    assert len(matches) == 0
