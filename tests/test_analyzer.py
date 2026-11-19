"""Tests for APKAnalyzer.

Covers decompilation (with mocks), component extraction, keyword search,
string resource parsing, runtime observation (simulation path used in CI),
and the new helper methods on AnalysisReport.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def tmp_decompile_dir(tmp_path):
    return tmp_path / "decompiled"


@pytest.fixture
def mock_apk():
    with patch("apkmorph.analyzer.APK") as mock_apk_cls:
        instance = mock_apk_cls.return_value
        instance.get_package.return_value = "com.example.app"
        instance.get_androidversion_name.return_value = "1.2.3"
        instance.get_androidversion_code.return_value = "123"
        instance.get_min_sdk_version.return_value = 24
        instance.get_target_sdk_version.return_value = 34
        instance.get_main_activity.return_value = "com.example.MainActivity"
        instance.get_activities.return_value = ["com.example.MainActivity"]
        instance.get_services.return_value = ["com.example.MyService"]
        instance.get_receivers.return_value = []
        instance.get_providers.return_value = []
        instance.get_permissions.return_value = ["android.permission.INTERNET"]
        instance.is_signed.return_value = True
        instance.get_certificates.return_value = []
        yield instance


@pytest.fixture
def mock_run_apktool():
    with patch("apkmorph.analyzer.run_apktool") as mock:
        yield mock


def test_analyzer_init(tmp_path):
    analyzer = APKAnalyzer(working_dir=tmp_path / "work")
    assert analyzer.working_dir == tmp_path / "work"
    assert analyzer.working_dir.exists()


def test_decompile(mock_apk, mock_run_apktool, tmp_path):
    apk_file = tmp_path / "test.apk"
    apk_file.touch()

    analyzer = APKAnalyzer(working_dir=tmp_path / "decomp")
    report = analyzer.decompile(str(apk_file))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.app"
    assert report.version_name == "1.2.3"
    assert len(report.activities) == 1
    assert "com.example.MainActivity" in report.components
    assert len(report.strings) >= 0
    assert isinstance(report.string_resources, dict)
    assert report.metadata["is_signed"] is True
    assert "smali_classes" in report.metadata
    mock_run_apktool.assert_called_once()
    assert mock_run_apktool.call_args[0][0][0] == "d"


def test_extract_components(tmp_path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True, exist_ok=True)
    (smali_dir / "MainActivity.smali").touch()
    (smali_dir / "utils$Helper.smali").touch()

    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components
    assert "com.example.utils$Helper" in components


def test_find_by_keyword(tmp_path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "Analytics.smali").write_text("firebase analytics code", encoding="utf-8")
    (tmp_path / "AndroidManifest.xml").write_text(
        "<manifest><uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\"/></manifest>",
        encoding="utf-8",
    )

    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert any("Analytics" in m for m in matches)

    xml_matches = analyzer.find_by_keyword("permission", tmp_path)
    assert any("resource:AndroidManifest.xml" in m for m in xml_matches)


def test_extract_string_resources(tmp_path):
    analyzer = APKAnalyzer()
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    strings_xml = values_dir / "strings.xml"
    strings_xml.write_text(
        '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="ad_text">Advertisement</string>
    <string-array name="options">
        <item>Option 1</item>
        <item>Option 2</item>
    </string-array>
</resources>''',
        encoding="utf-8",
    )

    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert "Test App" in strings
    assert "Advertisement" in strings
    assert "Option 1" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map.get("ad_text") == "Advertisement"


def test_observe_runtime_simulation():
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.app",
        decompiled_dir=Path("/tmp/decomp"),
        size_bytes=102400,
        strings=["firebase", "admob", "crashlytics"],
        string_resources={"app_name": "Test"},
        components=["com.example.MainActivity"],
        metadata={},
    )

    updated = analyzer.observe_runtime(report, duration=0)
    assert isinstance(updated, AnalysisReport)
    assert len(updated.runtime_observations) >= 3
    assert any("onCreate" in o for o in updated.runtime_observations)
    assert any("ad" in o.lower() for o in updated.runtime_observations)
    assert any("analytics" in o.lower() for o in updated.runtime_observations)
    assert updated.metadata["runtime_observed"] is True
    assert updated.metadata["frida_used"] is False


def test_report_helpers(sample_report):
    assert "Package: com.example.app" in sample_report.summary()
    md = sample_report.to_markdown()
    assert "# Analysis Report" in md
    assert "com.example.app" in md
    assert "firebase" in md
    found = sample_report.find_components("main", limit=5)
    assert any("MainActivity" in c for c in found)


@pytest.fixture
def sample_report(tmp_path):
    return AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.app",
        decompiled_dir=tmp_path / "decomp",
        size_bytes=102400,
        strings=["firebase", "admob", "crashlytics"],
        string_resources={"app_name": "Test", "ad_text": "Advertisement"},
        components=["com.example.MainActivity", "com.google.ads.AdView"],
        activities=["com.example.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=["android.permission.INTERNET"],
        metadata={"runtime_observed": True},
        main_activity="com.example.MainActivity",
        version_name="1.0",
        version_code="1",
        min_sdk=24,
        target_sdk=34,
    )
