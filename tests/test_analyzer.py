"""Tests for the APKAnalyzer.

Covers decompilation with Apktool/Androguard, component extraction from Smali,
string resource parsing from values/*.xml, keyword search, metadata generation
(including certificate fingerprints), and the Frida runtime observation path
(with realistic simulation fallback used in CI environments).
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


def _make_test_report(**kwargs) -> AnalysisReport:
    """Helper to create a valid AnalysisReport for tests (all fields required
    by the current Pydantic model are supplied with sensible defaults).
    """
    defaults = {
        "apk_path": Path("test.apk"),
        "package_name": "com.example.testapp",
        "version_name": "1.0",
        "version_code": "1",
        "min_sdk": 21,
        "target_sdk": 34,
        "decompiled_dir": Path("/tmp/decompiled"),
        "main_activity": "MainActivity",
        "activities": ["MainActivity"],
        "services": [],
        "receivers": [],
        "providers": [],
        "permissions": ["android.permission.INTERNET"],
        "components": ["MainActivity"],
        "strings": ["firebase analytics", "ad banner"],
        "string_resources": {"app_name": "TestApp", "ad_text": "Advertisement"},
        "metadata": {},
        "size_bytes": 1024,
        "runtime_observations": [],
    }
    defaults.update(kwargs)
    return AnalysisReport(**defaults)


def test_analyzer_init():
    analyzer = APKAnalyzer(working_dir="test_decompiled")
    assert analyzer.working_dir.name == "test_decompiled"
    assert analyzer.working_dir.exists()


def test_decompile_invalid_inputs():
    analyzer = APKAnalyzer()
    with pytest.raises(FileNotFoundError):
        analyzer.decompile("nonexistent.apk")
    with pytest.raises(ValueError, match="Input must be a valid .apk file"):
        analyzer.decompile("not_an_apk.txt")


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_decompile_success(mock_apk_class, mock_run_apktool, tmp_path):
    mock_run_apktool.return_value = None

    mock_apk = MagicMock()
    mock_apk_class.return_value = mock_apk
    mock_apk.get_package.return_value = "com.example.testapp"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 21
    mock_apk.get_target_sdk_version.return_value = 34
    mock_apk.get_main_activity.return_value = "MainActivity"
    mock_apk.get_activities.return_value = ["MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk.is_signed.return_value = True

    mock_cert = MagicMock()
    mock_cert.get_certificate.return_value = b"fake_cert_data"
    mock_apk.get_certificates.return_value = [mock_cert]

    analyzer = APKAnalyzer(working_dir=tmp_path)

    with patch.object(analyzer, "extract_components", return_value=["com.example.testapp.MainActivity"]):
        with patch.object(
            analyzer,
            "_extract_string_resources",
            return_value=(["TestApp", "Advertisement"], {"app_name": "TestApp"}),
        ):
            report = analyzer.decompile("test.apk")

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.testapp"
    assert report.version_name == "1.0"
    assert report.strings == ["TestApp", "Advertisement"]
    assert report.string_resources == {"app_name": "TestApp"}
    assert report.metadata["is_signed"] is True
    assert len(report.metadata["cert_fingerprints"]) == 1
    assert len(report.metadata["cert_fingerprints"][0]) == 64  # SHA-256 hex digest
    assert report.metadata["smali_classes"] == 1
    assert "resources_arsc" in report.metadata


def test_extract_components(tmp_path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "com/example/Test.smali").write_text(".class public Lcom/example/Test;")

    components = analyzer.extract_components(tmp_path)
    assert "com.example.Test" in components


def test_find_by_keyword(tmp_path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "com/example/AdActivity.smali").write_text("class AdActivity")

    matches = analyzer.find_by_keyword("ad", tmp_path)
    assert any("AdActivity" in m for m in matches)

    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text('<string name="ad_text">Advertisement</string>')
    matches = analyzer.find_by_keyword("advert", tmp_path)
    assert any("resource:strings.xml" in m for m in matches)


def test_string_resources_extraction(tmp_path):
    analyzer = APKAnalyzer()
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    strings_xml = values_dir / "strings.xml"
    strings_xml.write_text("""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="ad_text">Advertisement</string>
    <string-array name="options">
        <item>First</item>
        <item>Second</item>
    </string-array>
</resources>""")

    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert "Test App" in strings
    assert "Advertisement" in strings
    assert "First" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map.get("ad_text") == "Advertisement"


def test_observe_runtime_simulation():
    analyzer = APKAnalyzer()
    report = _make_test_report(strings=["firebase analytics", "ad banner"])
    updated = analyzer.observe_runtime(report, duration=0)

    assert isinstance(updated, AnalysisReport)
    assert len(updated.runtime_observations) >= 4
    assert any("onCreate" in o for o in updated.runtime_observations)
    assert any("onResume" in o for o in updated.runtime_observations)
    assert any("ad -" in o for o in updated.runtime_observations)
    assert any("analytics -" in o for o in updated.runtime_observations)
    assert updated.metadata["runtime_observed"] is True
    assert updated.metadata["frida_used"] is False


def test_observe_runtime_frida_path(monkeypatch):
    monkeypatch.setattr("apkmorph.analyzer._FRIDA_AVAILABLE", True)
    monkeypatch.setattr("apkmorph.analyzer.frida", MagicMock())

    analyzer = APKAnalyzer()
    report = _make_test_report()

    with patch.object(
        analyzer,
        "_run_frida_observation",
        return_value=["observed: analytics - logEvent", "observed: ad - loadAd"],
    ):
        updated = analyzer.observe_runtime(report, duration=1)

    assert "observed: analytics - logEvent" in updated.runtime_observations
    assert "observed: ad - loadAd" in updated.runtime_observations
    assert updated.metadata["frida_used"] is True
