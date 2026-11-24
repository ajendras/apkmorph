"""Tests for the APKAnalyzer.

Covers decompilation, caching, component extraction (parallel and single-threaded),
string resource parsing, keyword search, and runtime observation (with frida simulation fallback).
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture(scope="function")
def temp_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "test_app.apk"
    apk.write_bytes(b"PK\x03\x04fake apk content")
    return apk


@pytest.fixture
def mock_androguard_apk():
    mock = MagicMock()
    mock.get_package.return_value = "com.example.testapp"
    mock.get_androidversion_name.return_value = "2.1.0"
    mock.get_androidversion_code.return_value = "210"
    mock.get_min_sdk_version.return_value = 24
    mock.get_target_sdk_version.return_value = 34
    mock.get_main_activity.return_value = "com.example.testapp.MainActivity"
    mock.get_activities.return_value = [
        "com.example.testapp.MainActivity",
        "com.example.testapp.SettingsActivity",
    ]
    mock.get_services.return_value = ["com.example.testapp.BackgroundService"]
    mock.get_receivers.return_value = []
    mock.get_providers.return_value = []
    mock.get_permissions.return_value = [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ]
    mock.is_signed.return_value = True
    mock.get_certificates.return_value = [b"certdata"]
    return mock


def test_decompile(
    temp_apk: Path, mock_androguard_apk: MagicMock, tmp_path: Path
):
    analyzer = APKAnalyzer(working_dir=tmp_path / "output")
    with patch("apkmorph.analyzer.run_apktool") as mock_run, patch(
        "apkmorph.analyzer.APK", return_value=mock_androguard_apk
    ):
        report = analyzer.decompile(str(temp_apk), force=True)

    assert report.package_name == "com.example.testapp"
    assert report.version_name == "2.1.0"
    assert report.main_activity == "com.example.testapp.MainActivity"
    assert len(report.activities) == 2
    assert len(report.permissions) == 2
    assert "com.example.testapp.BackgroundService" in report.components
    assert report.metadata["is_signed"] is True
    assert len(report.metadata["cert_fingerprints"]) > 0
    mock_run.assert_called()


def test_decompilation_cache(tmp_path: Path):
    analyzer = APKAnalyzer(working_dir=tmp_path)
    decomp = tmp_path / "cached_apk"
    decomp.mkdir()
    manifest = decomp / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")
    (decomp / "smali").mkdir()
    (decomp / "res" / "values").mkdir(parents=True)
    apk = tmp_path / "app.apk"
    apk.touch()

    with patch.object(Path, "stat") as patched_stat:
        patched_stat.return_value.st_mtime = 100.0
        assert analyzer._is_decompilation_valid(decomp, apk) is True

    manifest.write_text("")
    assert analyzer._is_decompilation_valid(decomp, apk) is False


def test_extract_components(tmp_path: Path):
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "com/example").mkdir(parents=True)
    for name in ["MainActivity", "Utils"]:
        p = smali_dir / "com" / "example" / f"{name}.smali"
        p.write_text(f".class Lcom/example/{name};")

    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components
    assert "com.example.Utils" in components


def test_parallel_component_extraction(tmp_path: Path):
    analyzer = APKAnalyzer()
    analyzer.parallel_enabled = True
    for suffix in ["", "_classes2"]:
        d = tmp_path / f"smali{suffix}"
        d.mkdir()
        p = d / "com" / "example" / "Test.smali"
        p.parent.mkdir(parents=True)
        p.write_text(".class public Lcom/example/Test;")

    components = analyzer.extract_components(tmp_path)
    assert components.count("com.example.Test") == 1


def test_find_by_keyword(tmp_path: Path):
    analyzer = APKAnalyzer()
    smali_d = tmp_path / "smali"
    smali_d.mkdir()
    (smali_d / "com.example.Analytics.smali").write_text(
        "invoke-static analytics"
    )
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest><uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/></manifest>'
    )

    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert any("Analytics" in m for m in matches)
    assert any("resource:" in m for m in matches)


def test_string_resources(tmp_path: Path):
    analyzer = APKAnalyzer()
    vdir = tmp_path / "res" / "values"
    vdir.mkdir(parents=True)
    (vdir / "strings.xml").write_text(
        '<?xml version="1.0"?><resources>'
        '<string name="app_name">TestApp</string>'
        '<string name="ad_text">Buy now!</string>'
        "</resources>"
    )

    strings, mapping = analyzer._extract_string_resources(tmp_path)
    assert "TestApp" in strings
    assert "Buy now!" in strings
    assert mapping["app_name"] == "TestApp"
    assert mapping["ad_text"] == "Buy now!"


def test_observe_runtime_with_simulation(tmp_path: Path):
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.testapp",
        version_name="1.0",
        version_code="1",
        min_sdk=24,
        target_sdk=34,
        decompiled_dir=tmp_path,
        main_activity="MainActivity",
        activities=["MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["MainActivity"],
        strings=["firebase", "crash", "admob"],
        string_resources={},
        metadata={},
        size_bytes=1024,
    )

    updated = analyzer.observe_runtime(report, duration=1)
    assert len(updated.runtime_observations) >= 2
    assert any(
        "analytics" in o or "ad" in o or "crash" in o
        for o in updated.runtime_observations
    )
    assert updated.metadata["frida_used"] is False
    assert updated.metadata["runtime_observed"] is True


def test_frida_fallback():
    analyzer = APKAnalyzer()
    obs, frida_used = analyzer._run_frida_observation(
        "com.test.app", strings=["analytics"]
    )
    assert frida_used is False
    assert len(obs) > 0
    assert any("observed:" in o for o in obs)


def test_frida_script():
    analyzer = APKAnalyzer()
    script = analyzer._frida_script()
    assert script.startswith("Java.perform")
    assert "FirebaseAnalytics" in script
    assert "AdView" in script
