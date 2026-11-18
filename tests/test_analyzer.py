"""Tests for APKAnalyzer.

Covers decompilation (with mocks), component extraction, string resource parsing,
keyword search, and runtime observation (Frida simulation fallback used in CI).
Uses unittest.mock to keep tests fast, hermetic and independent of external
tools or a physical device.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Temporary directory for test artifacts."""
    return tmp_path


@pytest.fixture
def fake_apk(temp_dir: Path) -> Path:
    """Create a minimal fake APK file."""
    apk_path = temp_dir / "test.apk"
    apk_path.write_bytes(b"PK\x03\x04fake apk content")
    return apk_path


def test_analyzer_initialization(temp_dir: Path) -> None:
    """Test that the analyzer creates its working directory."""
    analyzer = APKAnalyzer(working_dir=temp_dir / "decompiled")
    assert analyzer.working_dir == (temp_dir / "decompiled").resolve()
    assert analyzer.working_dir.exists()


def test_decompile_rejects_invalid_input() -> None:
    """Validate early error paths for bad APK arguments."""
    analyzer = APKAnalyzer()

    with pytest.raises(FileNotFoundError, match="APK file not found"):
        analyzer.decompile("nonexistent.apk")

    with pytest.raises(ValueError, match="must be a valid .apk file"):
        analyzer.decompile("file.txt")


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_decompile_success(
    mock_apk_class: MagicMock, mock_run_apktool: MagicMock, fake_apk: Path, temp_dir: Path
) -> None:
    """Happy path for decompile: mocks external tools and validates the produced report."""
    # Mock Androguard APK object
    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.example.app"
    mock_apk.get_androidversion_name.return_value = "1.2.3"
    mock_apk.get_androidversion_code.return_value = "123"
    mock_apk.get_min_sdk_version.return_value = 24
    mock_apk.get_target_sdk_version.return_value = 34
    mock_apk.get_main_activity.return_value = "com.example.app.MainActivity"
    mock_apk.get_activities.return_value = ["com.example.app.MainActivity"]
    mock_apk.get_services.return_value = ["com.example.app.BackgroundService"]
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk.is_signed.return_value = True
    mock_apk.get_certificates.return_value = []
    mock_apk_class.return_value = mock_apk

    analyzer = APKAnalyzer(working_dir=temp_dir)

    # Bypass real filesystem walks and XML parsing for speed/determinism
    with patch.object(analyzer, "extract_components", return_value=["com.example.app.Utils"]):
        with patch.object(
            analyzer,
            "_extract_string_resources",
            return_value=(["Hello world", "Ad banner"], {"greeting": "Hello world"}),
        ):
            report = analyzer.decompile(str(fake_apk))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.app"
    assert report.version_name == "1.2.3"
    assert report.min_sdk == 24
    assert report.target_sdk == 34
    assert "com.example.app.MainActivity" in report.components
    assert "com.example.app.Utils" in report.components
    assert "Hello world" in report.strings
    assert report.string_resources == {"greeting": "Hello world"}
    assert report.metadata["is_signed"] is True
    assert report.metadata["smali_classes"] == 1
    assert report.size_bytes == len(fake_apk.read_bytes())

    mock_run_apktool.assert_called_once()
    # Apktool was called with the expected decompile flags
    args = mock_run_apktool.call_args[0][0]
    assert args[0] == "d"
    assert "-f" in args
    assert "--no-src" in args


def test_extract_components(temp_dir: Path) -> None:
    """Verify Smali walking discovers fully-qualified class names (including multidex)."""
    analyzer = APKAnalyzer()

    # Fake a multidex layout
    smali1 = temp_dir / "smali" / "com" / "example" / "MainActivity.smali"
    smali1.parent.mkdir(parents=True)
    smali1.write_text(".class public Lcom/example/MainActivity;")

    smali2 = temp_dir / "smali_classes2" / "com" / "example" / "utils" / "Helper.smali"
    smali2.parent.mkdir(parents=True)
    smali2.write_text(".class public Lcom/example/utils/Helper;")

    components = analyzer.extract_components(temp_dir)
    assert "com.example.MainActivity" in components
    assert "com.example.utils.Helper" in components


def test_find_by_keyword(temp_dir: Path) -> None:
    """Case-insensitive search across Smali and XML resources."""
    analyzer = APKAnalyzer()

    # Fake Smali with analytics call
    smali_dir = temp_dir / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Analytics.smali").write_text(
        "invoke-static {}, Lcom/google/firebase/analytics/FirebaseAnalytics;"
    )

    # Fake strings.xml
    values_dir = temp_dir / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        '<string name="analytics_id">UA-123456</string>'
    )

    matches = analyzer.find_by_keyword("analytics", temp_dir)
    assert any("Analytics" in m for m in matches)
    assert any("resource:strings.xml" in m for m in matches)
    assert len(matches) <= 30


def test_extract_string_resources(temp_dir: Path) -> None:
    """Parse strings.xml (and other values XML) into flat list and key map."""
    analyzer = APKAnalyzer()

    values_dir = temp_dir / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        """<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="app_name">Test App</string>
            <string name="ad_banner">Advertisement</string>
            <string-array name="menu_items">
                <item>Item One</item>
                <item>Item Two</item>
            </string-array>
        </resources>
        """
    )

    strings, string_map = analyzer._extract_string_resources(temp_dir)

    assert "Test App" in strings
    assert "Advertisement" in strings
    assert "Item One" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map["ad_banner"] == "Advertisement"
    # string-array items have no name attribute so are absent from the map
    assert "menu_items" not in string_map


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_observe_runtime_simulation(
    mock_apk_class: MagicMock, mock_run_apktool: MagicMock, fake_apk: Path, temp_dir: Path
) -> None:
    """Runtime observation falls back to realistic simulation when Frida is unavailable.

    This path is exercised in CI (no USB device) and guarantees the LLM always
    receives some runtime context.
    """
    # Minimal APK mock (we only need the report object)
    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.example.testapp"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 21
    mock_apk.get_target_sdk_version.return_value = 34
    mock_apk.get_main_activity.return_value = None
    mock_apk.get_activities.return_value = []
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = []
    mock_apk.is_signed.return_value = False
    mock_apk.get_certificates.return_value = []
    mock_apk_class.return_value = mock_apk

    analyzer = APKAnalyzer(working_dir=temp_dir)

    with patch.object(analyzer, "extract_components", return_value=[]):
        with patch.object(
            analyzer,
            "_extract_string_resources",
            return_value=(["ad", "analytics", "crash"], {}),
        ):
            report = analyzer.decompile(str(fake_apk))

    # Force simulation path (mirrors CI where no device is present)
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", False):
        enriched: AnalysisReport = analyzer.observe_runtime(report, duration=1)

    assert isinstance(enriched, AnalysisReport)
    assert len(enriched.runtime_observations) >= 4
    assert any("onCreate" in obs for obs in enriched.runtime_observations)
    assert any("onResume" in obs for obs in enriched.runtime_observations)
    assert any("ad -" in obs for obs in enriched.runtime_observations)
    assert any("analytics -" in obs for obs in enriched.runtime_observations)
    assert any("crash_reporting" in obs for obs in enriched.runtime_observations)
    assert enriched.metadata["runtime_observed"] is True
    assert enriched.metadata["frida_used"] is False


def test_simulate_observations_directly() -> None:
    """Direct test of the simulation helper (used when Frida is unavailable)."""
    analyzer = APKAnalyzer()
    strings = ["firebase analytics", "banner ad", "crashlytics"]

    observations = analyzer._simulate_observations("com.test.app", strings)

    assert any("MainActivity.onCreate()" in o for o in observations)
    assert any("MainActivity.onResume()" in o for o in observations)
    assert any("ad -" in o for o in observations)
    assert any("analytics -" in o for o in observations)
    assert any("crash_reporting -" in o for o in observations)
    assert any("total hooks triggered" in o for o in observations)
