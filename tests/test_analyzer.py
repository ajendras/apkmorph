"""Tests for APKAnalyzer.

Covers decompilation (mocked), component extraction, keyword search,
string resource parsing, runtime observation (Frida simulation path),
and error handling. Uses stdlib mocks so tests run in CI without
external tools or devices.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def tmp_analyzer(tmp_path: Path) -> APKAnalyzer:
    return APKAnalyzer(working_dir=tmp_path / "decompiled")


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    return AnalysisReport(
        apk_path=Path("dummy.apk"),
        package_name="com.example.testapp",
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=34,
        decompiled_dir=tmp_path,
        main_activity="com.example.testapp.MainActivity",
        activities=["com.example.testapp.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=["android.permission.INTERNET"],
        components=["com.example.testapp.MainActivity"],
        strings=["hello", "ad", "analytics"],
        string_resources={"app_name": "Test App", "greeting": "Hello"},
        metadata={"is_signed": True, "smali_classes": 5},
        size_bytes=1024,
        runtime_observations=[],
    )


def test_analyzer_init(tmp_path: Path) -> None:
    analyzer = APKAnalyzer(working_dir=str(tmp_path))
    assert analyzer.working_dir == tmp_path
    assert analyzer.working_dir.exists()


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
@patch.object(APKAnalyzer, "_extract_string_resources")
@patch.object(APKAnalyzer, "extract_components")
def test_decompile(
    mock_extract_components,
    mock_extract_strings,
    mock_apk_class,
    mock_run,
    tmp_analyzer: APKAnalyzer,
    tmp_path: Path,
) -> None:
    apk_file = tmp_path / "testapp.apk"
    apk_file.touch()

    mock_extract_strings.return_value = (
        ["Test string", "ad banner"],
        {"app_name": "Test App"},
    )
    mock_extract_components.return_value = ["com.example.testapp.MainActivity"]

    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.example.testapp"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 21
    mock_apk.get_target_sdk_version.return_value = 34
    mock_apk.get_main_activity.return_value = "com.example.testapp.MainActivity"
    mock_apk.get_activities.return_value = ["com.example.testapp.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk.is_signed.return_value = True
    mock_apk.get_certificates.return_value = []
    mock_apk_class.return_value = mock_apk

    report = tmp_analyzer.decompile(str(apk_file))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.testapp"
    assert report.version_name == "1.0"
    assert len(report.components) >= 1
    assert "Test string" in report.strings
    assert report.string_resources["app_name"] == "Test App"
    mock_run.assert_called_once()
    mock_apk_class.assert_called_once_with(str(apk_file))


def test_extract_components(tmp_analyzer: APKAnalyzer, tmp_path: Path) -> None:
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True, exist_ok=True)
    (smali_dir / "MainActivity.smali").touch()
    (smali_dir / "utils" / "Helper.smali").mkdir(parents=True)
    (smali_dir / "utils" / "Helper.smali").touch()

    components = tmp_analyzer.extract_components(tmp_path)
    assert any("com.example.MainActivity" in c for c in components)
    assert any("com.example.utils.Helper" in c for c in components)


def test_walk_smali(tmp_analyzer: APKAnalyzer, tmp_path: Path) -> None:
    smali_root = tmp_path / "smali"
    smali_root.mkdir()
    (smali_root / "com").mkdir()
    test_file = smali_root / "com" / "TestClass.smali"
    test_file.write_text("# test smali")

    components: list[str] = []
    tmp_analyzer._walk_smali(smali_root, components)
    assert "com.TestClass" in components


def test_find_by_keyword(tmp_analyzer: APKAnalyzer, tmp_path: Path) -> None:
    (tmp_path / "smali" / "com" / "example").mkdir(parents=True)
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text('<manifest package="com.example.app"/>')

    matches = tmp_analyzer.find_by_keyword("example", tmp_path)
    assert len(matches) > 0
    assert any("example" in m.lower() for m in matches)


def test_extract_string_resources(tmp_analyzer: APKAnalyzer, tmp_path: Path) -> None:
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    strings_xml = values_dir / "strings.xml"
    strings_xml.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="greeting">Hello World</string>
    <string-array name="options">
        <item>Option 1</item>
    </string-array>
</resources>"""
    )

    strings, string_map = tmp_analyzer._extract_string_resources(tmp_path)
    assert "Test App" in strings
    assert "Hello World" in strings
    assert "Option 1" in strings
    assert string_map["app_name"] == "Test App"
    assert string_map["greeting"] == "Hello World"


def test_observe_runtime(sample_report: AnalysisReport, tmp_analyzer: APKAnalyzer) -> None:
    with patch.object(
        tmp_analyzer, "_run_frida_observation"
    ) as mock_run_frida:
        mock_run_frida.return_value = [
            "observed: analytics - FirebaseAnalytics.logEvent()",
            "observed: ad - AdView.loadAd()",
        ]
        updated = tmp_analyzer.observe_runtime(sample_report, duration=2)
        assert len(updated.runtime_observations) == 2
        assert updated.metadata.get("runtime_observed") is True
        assert "frida_used" in updated.metadata


def test_run_frida_observation_simulation(tmp_analyzer: APKAnalyzer) -> None:
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", False):
        observations = tmp_analyzer._run_frida_observation(
            "com.example.testapp", duration=1, strings=["ad", "firebase", "crash"]
        )
        assert any("ad" in obs for obs in observations)
        assert any("analytics" in obs for obs in observations)
        assert any("crash_reporting" in obs for obs in observations)
        assert any("total hooks" in obs for obs in observations)


def test_simulate_observations(tmp_analyzer: APKAnalyzer) -> None:
    obs = tmp_analyzer._simulate_observations(
        "com.example.testapp", ["ad banner", "firebase analytics", "crash report"]
    )
    assert len(obs) >= 5
    assert any("ad" in o.lower() for o in obs)
    assert any("analytics" in o.lower() for o in obs)
    assert any("crash_reporting" in o.lower() for o in obs)


def test_decompile_missing_apk(tmp_analyzer: APKAnalyzer) -> None:
    with pytest.raises(FileNotFoundError):
        tmp_analyzer.decompile("nonexistent.apk")


@patch("apkmorph.analyzer.run_apktool")
def test_decompile_apktool_failure(mock_run, tmp_analyzer: APKAnalyzer, tmp_path: Path) -> None:
    mock_run.side_effect = RuntimeError("apktool failed")
    apk = tmp_path / "bad.apk"
    apk.touch()
    with pytest.raises(RuntimeError, match="Apktool decompilation failed"):
        tmp_analyzer.decompile(str(apk))
