import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def mock_apk():
    with patch("apkmorph.analyzer.APK") as mock_apk_class:
        mock_instance = MagicMock()
        mock_instance.get_package.return_value = "com.example.testapp"
        mock_instance.get_androidversion_name.return_value = "2.1.0"
        mock_instance.get_androidversion_code.return_value = 210
        mock_instance.get_min_sdk_version.return_value = 24
        mock_instance.get_target_sdk_version.return_value = 34
        mock_instance.get_main_activity.return_value = "com.example.testapp.MainActivity"
        mock_instance.get_activities.return_value = ["com.example.testapp.MainActivity"]
        mock_instance.get_services.return_value = []
        mock_instance.get_receivers.return_value = []
        mock_instance.get_providers.return_value = []
        mock_instance.get_permissions.return_value = ["android.permission.INTERNET"]
        mock_instance.is_signed.return_value = True
        mock_instance.get_certificates.return_value = []
        mock_apk_class.return_value = mock_instance
        yield mock_apk_class


@pytest.fixture
def mock_run_apktool():
    with patch("apkmorph.utils.run_apktool") as mock:
        yield mock


@pytest.fixture
def temp_working_dir(tmp_path):
    return tmp_path / "decompiled"


def test_analyzer_init(temp_working_dir):
    analyzer = APKAnalyzer(working_dir=temp_working_dir)
    assert analyzer.working_dir == temp_working_dir
    assert temp_working_dir.exists()


def test_decompile_creates_report(
    mock_apk, mock_run_apktool, temp_working_dir
):
    analyzer = APKAnalyzer(working_dir=temp_working_dir)
    apk_file = temp_working_dir.parent / "test.apk"
    apk_file.touch()

    report = analyzer.decompile(str(apk_file))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.testapp"
    assert report.version_name == "2.1.0"
    assert report.version_code == 210
    assert report.min_sdk == 24
    assert "android.permission.INTERNET" in report.permissions
    assert len(report.components) >= 1
    assert "MainActivity" in report.main_activity
    assert report.decompiled_dir is not None
    mock_run_apktool.assert_called_once()
    mock_apk.assert_called_once()


def test_extract_string_resources(temp_working_dir):
    analyzer = APKAnalyzer()
    values_dir = temp_working_dir / "res" / "values"
    values_dir.mkdir(parents=True, exist_ok=True)
    strings_file = values_dir / "strings.xml"
    strings_file.write_text(
        '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="welcome">Welcome to the app</string>
    <string name="ad_text">Buy now!</string>
</resources>'''
    )

    strings, string_map = analyzer._extract_string_resources(temp_working_dir)
    assert len(strings) == 3
    assert "Test App" in strings
    assert "Buy now!" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map["ad_text"] == "Buy now!"


def test_find_by_keyword(temp_working_dir):
    analyzer = APKAnalyzer()
    (temp_working_dir / "smali/com/example").mkdir(parents=True, exist_ok=True)
    smali_file = temp_working_dir / "smali/com/example/Analytics.smali"
    smali_file.write_text("invoke-static {p0}, Lcom/example/Analytics;->track()V")

    matches = analyzer.find_by_keyword("analytics", temp_working_dir)
    assert len(matches) > 0
    assert any("Analytics" in m for m in matches)


def test_observe_runtime_uses_simulation():
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=Path("/tmp/decomp"),
        strings=["firebase", "analytics", "ad", "crash"],
        activities=["com.example.testapp.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["com.example.testapp.MainActivity"],
        string_resources={"app_name": "Test"},
        metadata={},
    )

    updated = analyzer.observe_runtime(report, duration=1)
    assert isinstance(updated, AnalysisReport)
    assert len(updated.runtime_observations) >= 3
    obs_text = " ".join(updated.runtime_observations).lower()
    assert "analytics" in obs_text or "firebase" in obs_text
    assert "ad" in obs_text
    assert updated.metadata.get("runtime_observed") is True
    assert "frida_used" in updated.metadata
