"""Tests for APKAnalyzer.

Covers decompilation, cache optimisation, parallel Smali extraction,
component discovery, string resource parsing, keyword search and
runtime observation (with Frida fallback).
"""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def temp_working_dir(tmp_path: Path) -> Path:
    wd = tmp_path / "decompiled"
    wd.mkdir(parents=True, exist_ok=True)
    return wd


@pytest.fixture
def sample_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "sample.apk"
    # Fake APK with ZIP header so Androguard does not immediately explode
    apk.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    return apk


def test_decompile_creates_valid_report(
    sample_apk: Path, temp_working_dir: Path
) -> None:
    analyzer = APKAnalyzer(working_dir=temp_working_dir)

    mock_apk = MagicMock()
    mock_apk.get_activities.return_value = ["com.example.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk.get_package.return_value = "com.example.app"
    mock_apk.get_main_activity.return_value = ".MainActivity"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 21
    mock_apk.get_target_sdk_version.return_value = 33
    mock_apk.is_signed.return_value = True
    mock_apk.get_certificates.return_value = []

    with patch("apkmorph.analyzer.run_apktool") as mock_run_apktool:
        with patch("apkmorph.analyzer.APK", return_value=mock_apk):
            report = analyzer.decompile(str(sample_apk))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.app"
    assert report.version_name == "1.0"
    assert len(report.components) >= 1
    assert "com.example.MainActivity" in report.components
    assert report.size_bytes > 0
    mock_run_apktool.assert_called_once()


def test_decompile_reuses_cache(
    sample_apk: Path, temp_working_dir: Path
) -> None:
    analyzer = APKAnalyzer(working_dir=temp_working_dir)

    # Create a realistic cached tree
    decomp_name = f"apk_sample_{int(sample_apk.stat().st_mtime)}"
    decomp_dir: Path = temp_working_dir / decomp_name
    decomp_dir.mkdir(parents=True)
    (decomp_dir / "AndroidManifest.xml").write_text(
        '<?xml version="1.0"?><manifest package="com.example.app"/>'
    )
    (decomp_dir / "smali").mkdir()
    (decomp_dir / "res" / "values").mkdir(parents=True)
    (decomp_dir / "res" / "values" / "strings.xml").write_text(
        "<resources><string name=\"app_name\">Test</string></resources>"
    )

    # Make cache appear newer than APK
    cache_mtime = time.time() + 10
    decomp_dir.touch()
    decomp_dir.stat = lambda: MagicMock(st_mtime=cache_mtime)  # type: ignore[method-assign]

    with patch.object(analyzer, "_is_decompilation_valid", return_value=True):
        with patch("apkmorph.analyzer.run_apktool") as mock_run:
            with patch("apkmorph.analyzer.APK") as mock_apk_cls:
                mock_apk = MagicMock()
                mock_apk.get_activities.return_value = []
                mock_apk.get_services.return_value = []
                mock_apk.get_receivers.return_value = []
                mock_apk.get_providers.return_value = []
                mock_apk.get_permissions.return_value = []
                mock_apk.get_package.return_value = "com.example.app"
                mock_apk.get_main_activity.return_value = None
                mock_apk.get_androidversion_name.return_value = "1.0"
                mock_apk.get_androidversion_code.return_value = "1"
                mock_apk.get_min_sdk_version.return_value = 21
                mock_apk.get_target_sdk_version.return_value = 33
                mock_apk.is_signed.return_value = False
                mock_apk.get_certificates.return_value = []
                mock_apk_cls.return_value = mock_apk

                report = analyzer.decompile(str(sample_apk))

    assert mock_run.call_count == 0
    assert report.package_name == "com.example.app"
    assert str(report.decompiled_dir) == str(decomp_dir.absolute())


def test_decompile_force_bypasses_cache(
    sample_apk: Path, temp_working_dir: Path
) -> None:
    analyzer = APKAnalyzer(working_dir=temp_working_dir)

    with patch("apkmorph.analyzer.run_apktool") as mock_run:
        with patch("apkmorph.analyzer.APK") as mock_apk_cls:
            mock_apk = MagicMock()
            mock_apk.get_activities.return_value = []
            mock_apk.get_services.return_value = []
            mock_apk.get_receivers.return_value = []
            mock_apk.get_providers.return_value = []
            mock_apk.get_permissions.return_value = []
            mock_apk.get_package.return_value = "com.example.app"
            mock_apk.get_main_activity.return_value = None
            mock_apk.get_androidversion_name.return_value = None
            mock_apk.get_androidversion_code.return_value = None
            mock_apk.get_min_sdk_version.return_value = None
            mock_apk.get_target_sdk_version.return_value = None
            mock_apk.is_signed.return_value = False
            mock_apk.get_certificates.return_value = []
            mock_apk_cls.return_value = mock_apk

            report = analyzer.decompile(str(sample_apk), force=True)

    assert mock_run.call_count == 1
    assert isinstance(report, AnalysisReport)


def test_extract_components_parallel(temp_working_dir: Path) -> None:
    analyzer = APKAnalyzer(working_dir=temp_working_dir)

    # Fake multidex layout
    (temp_working_dir / "smali" / "com" / "example").mkdir(parents=True)
    (temp_working_dir / "smali" / "com" / "example" / "MainActivity.smali").write_text(
        '.class public Lcom/example/MainActivity;'
    )
    (temp_working_dir / "smali_classes2" / "com" / "utils").mkdir(parents=True)
    (
        temp_working_dir / "smali_classes2" / "com" / "utils" / "Helper.smali"
    ).write_text('.class public Lcom/utils/Helper;')

    components = analyzer.extract_components(temp_working_dir)

    assert "com.example.MainActivity" in components
    assert "com.utils.Helper" in components
    assert len(components) == 2


def test_extract_components_single_dir(temp_working_dir: Path) -> None:
    analyzer = APKAnalyzer(working_dir=temp_working_dir)
    analyzer.parallel_enabled = False  # force serial path

    smali_dir = temp_working_dir / "smali" / "com" / "test"
    smali_dir.mkdir(parents=True)
    (smali_dir / "App.smali").write_text('.class public Lcom/test/App;')

    components = analyzer.extract_components(temp_working_dir)
    assert "com.test.App" in components


def test_find_by_keyword(temp_working_dir: Path) -> None:
    analyzer = APKAnalyzer(working_dir=temp_working_dir)

    # Create minimal XML with searchable content
    values = temp_working_dir / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        '<resources><string name="hello">Hello Analytics</string></resources>'
    )
    (temp_working_dir / "AndroidManifest.xml").write_text(
        '<manifest><uses-permission android:name="android.permission.INTERNET"/></manifest>'
    )

    matches = analyzer.find_by_keyword("analytics", temp_working_dir)
    assert any("analytics" in m.lower() for m in matches)


def test__extract_string_resources(temp_working_dir: Path) -> None:
    analyzer = APKAnalyzer(working_dir=temp_working_dir)
    values = temp_working_dir / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        """<resources>
            <string name="app_name">Test App</string>
            <string name="welcome">Welcome!</string>
        </resources>"""
    )

    strings, mapping = analyzer._extract_string_resources(temp_working_dir)
    assert "Test App" in strings
    assert "Welcome!" in strings
    assert mapping.get("app_name") == "Test App"
    assert mapping.get("welcome") == "Welcome!"


def test_observe_runtime_fallback_simulation() -> None:
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("dummy.apk"),
        package_name="com.example.dummy",
        decompiled_dir=Path("/tmp"),
        components=[],
        strings=["firebase", "ad"],
        string_resources={},
        size_bytes=1024,
    )

    with patch("apkmorph.analyzer.APKAnalyzer._run_frida_observation") as mock_frida:
        mock_frida.return_value = ([], False)  # force simulation path
        enriched = analyzer.observe_runtime(report, duration=1)

    assert len(enriched.runtime_observations) > 0
    assert any("ad" in obs for obs in enriched.runtime_observations)
    assert any("analytics" in obs for obs in enriched.runtime_observations)
