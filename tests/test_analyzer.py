"""Tests for the APKAnalyzer.

Covers decompilation (with mocks), component extraction, string resource parsing,
keyword search, and runtime observation (with simulation fallback for CI).
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer, _FRIDA_AVAILABLE
from apkmorph.models import AnalysisReport


@pytest.fixture
def tmp_decompile(tmp_path: Path) -> Path:
    """Create a minimal decompiled APK tree for extraction tests."""
    (tmp_path / "smali" / "com" / "example").mkdir(parents=True)
    (tmp_path / "smali" / "com" / "example" / "MainActivity.smali").write_text(
        ".class public Lcom/example/MainActivity;"
    )
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        """<resources>
    <string name="app_name">Test App</string>
    <string name="ad_text">Advertisement</string>
</resources>"""
    )
    (tmp_path / "AndroidManifest.xml").write_text('<manifest package="com.example.test"/>')
    return tmp_path


def test_analyzer_instantiation(tmp_path: Path) -> None:
    analyzer = APKAnalyzer(working_dir=tmp_path / "work")
    assert analyzer.working_dir == (tmp_path / "work")
    assert analyzer.working_dir.exists()


def test_extract_components(tmp_decompile: Path) -> None:
    analyzer = APKAnalyzer()
    components = analyzer.extract_components(tmp_decompile)
    assert "com.example.MainActivity" in components


def test_extract_string_resources(tmp_decompile: Path) -> None:
    analyzer = APKAnalyzer()
    strings, string_map = analyzer._extract_string_resources(tmp_decompile)
    assert "Test App" in strings
    assert "Advertisement" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map["ad_text"] == "Advertisement"


def test_find_by_keyword(tmp_decompile: Path) -> None:
    analyzer = APKAnalyzer()
    matches = analyzer.find_by_keyword("app_name", tmp_decompile)
    assert any("resource" in m for m in matches)
    matches = analyzer.find_by_keyword("mainactivity", tmp_decompile)
    assert any("MainActivity" in m for m in matches)


@patch("apkmorph.analyzer._FRIDA_AVAILABLE", False)
def test_observe_runtime_simulation() -> None:
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("dummy.apk"),
        package_name="com.example.test",
        decompiled_dir=Path("/tmp/dummy"),
        size_bytes=1024,
        strings=["firebase", "ad", "analytics"],
        metadata={},
    )
    enriched = analyzer.observe_runtime(report, duration=0)
    assert isinstance(enriched, AnalysisReport)
    assert len(enriched.runtime_observations) >= 3
    obs_text = " ".join(enriched.runtime_observations).lower()
    assert "ad" in obs_text
    assert "analytics" in obs_text
    assert enriched.metadata.get("runtime_observed") is True
    assert enriched.metadata.get("frida_used") is False


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_decompile(mock_apk_cls: MagicMock, mock_run: MagicMock, tmp_path: Path) -> None:
    apk_file = tmp_path / "test.apk"
    apk_file.touch()

    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.example.test"
    mock_apk.get_activities.return_value = ["com.example.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = []
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 24
    mock_apk.get_target_sdk_version.return_value = 34
    mock_apk.get_main_activity.return_value = "com.example.MainActivity"
    mock_apk.is_signed.return_value = True
    mock_apk.get_certificates.return_value = []
    mock_apk_cls.return_value = mock_apk

    # Make decompiled dir deterministic
    with patch.object(Path, "stat") as mock_stat:
        mock_stat.return_value.st_mtime = 0
        analyzer = APKAnalyzer(working_dir=tmp_path)
        report = analyzer.decompile(str(apk_file))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.test"
    assert report.version_name == "1.0"
    assert "com.example.MainActivity" in report.components
    assert report.min_sdk == 24
    mock_run.assert_called_once()
    mock_apk_cls.assert_called_once()
