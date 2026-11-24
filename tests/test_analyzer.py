"""Tests for APKAnalyzer.

Covers decompilation (with caching and string resource extraction),
component extraction (including parallel smali parsing), keyword search,
certificate fingerprinting, and runtime observation (Frida simulation
fallback, as the CI environment does not install the optional frida extra).
Uses mocks for Apktool, Androguard and Frida to ensure tests are hermetic
and run without real APKs or external tools.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


def test_init(tmp_path: Path) -> None:
    analyzer = APKAnalyzer(working_dir=tmp_path / "decomp")
    assert analyzer.working_dir == tmp_path / "decomp"
    assert analyzer.cache_enabled is True
    assert analyzer.parallel_enabled is True


@patch("apkmorph.analyzer.run_apktool")
@patch("apkmorph.analyzer.APK")
def test_decompile(mock_apk_class: MagicMock, mock_run_apktool: MagicMock, tmp_path: Path) -> None:
    apk_path = tmp_path / "test.apk"
    apk_path.write_text("dummy apk content")
    mtime = int(apk_path.stat().st_mtime)
    decomp_name = f"apk_test_{mtime}"
    decomp_dir = tmp_path / "decompiled" / decomp_name
    decomp_dir.mkdir(parents=True)
    (decomp_dir / "AndroidManifest.xml").write_text("<manifest package='com.test.app'/>")
    smali_dir = decomp_dir / "smali"
    smali_dir.mkdir()
    (smali_dir / "com/test/App.smali").write_text(".class public Lcom/test/App;")
    values_dir = decomp_dir / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="greeting">Hello World</string>
</resources>""")

    mock_apk = MagicMock()
    mock_apk.get_activities.return_value = ["com.test.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
    mock_apk.get_package.return_value = "com.test.app"
    mock_apk.get_androidversion_name.return_value = "1.0.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 24
    mock_apk.get_target_sdk_version.return_value = 34
    mock_apk.get_main_activity.return_value = ".MainActivity"
    mock_apk.is_signed.return_value = True
    mock_apk.get_certificates.return_value = [b"fake-cert-bytes"]
    mock_apk_class.return_value = mock_apk

    analyzer = APKAnalyzer(working_dir=tmp_path / "decompiled")
    report = analyzer.decompile(str(apk_path), force=True)

    assert report.package_name == "com.test.app"
    assert report.version_name == "1.0.0"
    assert "com.test.MainActivity" in report.components
    assert any("Test App" in s for s in report.strings)
    assert "app_name" in report.string_resources
    assert report.metadata["is_signed"] is True
    assert len(report.metadata["cert_fingerprints"]) > 0
    assert str(report.decompiled_dir).endswith(decomp_name)
    mock_run_apktool.assert_called_once()


@patch("apkmorph.analyzer.APK")
def test_decompile_cache(mock_apk_class: MagicMock, tmp_path: Path) -> None:
    apk_path = tmp_path / "test.apk"
    apk_path.write_text("dummy apk content")
    mtime = int(apk_path.stat().st_mtime)
    decomp_name = f"apk_test_{mtime}"
    decomp_dir = tmp_path / "decompiled" / decomp_name
    decomp_dir.mkdir(parents=True)
    (decomp_dir / "AndroidManifest.xml").write_text("<manifest/>")
    (decomp_dir / "smali").mkdir()
    (decomp_dir / "res" / "values").mkdir(parents=True)

    mock_apk = MagicMock()
    mock_apk.get_activities.return_value = []
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = []
    mock_apk.get_package.return_value = "com.test.app"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_main_activity.return_value = None
    mock_apk.is_signed.return_value = False
    mock_apk.get_certificates.return_value = []
    mock_apk_class.return_value = mock_apk

    analyzer = APKAnalyzer(working_dir=tmp_path / "decompiled")
    with patch("apkmorph.analyzer.run_apktool") as mock_run:
        report = analyzer.decompile(str(apk_path))
        mock_run.assert_not_called()

    assert report.package_name == "com.test.app"
    assert report.metadata["is_signed"] is False


def test_extract_components(tmp_path: Path) -> None:
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "com/example/MainActivity.smali").write_text("")
    (smali_dir / "com/example/Utils$Inner.smali").write_text("")

    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components
    assert "com.example.Utils$Inner" in components


def test_find_by_keyword(tmp_path: Path) -> None:
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir()
    (smali_dir / "com/test/Analytics.smali").write_text("trackEvent")
    xml_file = tmp_path / "res/values/strings.xml"
    xml_file.parent.mkdir(parents=True)
    xml_file.write_text("<string name='analytics'>track</string>")

    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert any("Analytics" in m for m in matches)
    matches = analyzer.find_by_keyword("track", tmp_path)
    assert any("resource:" in m for m in matches)


def test_extract_string_resources(tmp_path: Path) -> None:
    analyzer = APKAnalyzer()
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">My App</string>
    <string name="welcome">Welcome</string>
    <string-array name="options">
        <item>One</item>
        <item>Two</item>
    </string-array>
</resources>""")

    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert len(strings) >= 3
    assert "My App" in strings
    assert "app_name" in string_map
    assert string_map["app_name"] == "My App"


def test_observe_runtime_simulation() -> None:
    analyzer = APKAnalyzer()
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test.app",
        decompiled_dir=Path("/tmp"),
        components=[],
        strings=["firebase", "admob", "crashlytics"],
        string_resources={},
        metadata={},
        size_bytes=1000,
        main_activity=None,
        activities=[],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        version_name=None,
        version_code=None,
        min_sdk=None,
        target_sdk=None,
        runtime_observations=[],
    )
    with patch.object(analyzer, "_run_frida_observation") as mock_run:
        mock_run.return_value = (["observed: analytics"], False)
        updated = analyzer.observe_runtime(report, duration=1)
        assert len(updated.runtime_observations) > 0
        assert updated.metadata.get("frida_used") is False
        assert updated.metadata.get("runtime_observed") is True


def test_cert_fingerprint() -> None:
    analyzer = APKAnalyzer()

    class FakeCert:
        def dump(self) -> bytes:
            return b"fake-der"

    assert len(analyzer._cert_fingerprint(FakeCert())) == 64
    assert len(analyzer._cert_fingerprint(b"raw-bytes")) == 64

    class Other:
        pass

    fp = analyzer._cert_fingerprint(Other())
    assert len(fp) == 64

    with patch("hashlib.sha256", side_effect=ValueError("simulated failure")):
        assert analyzer._cert_fingerprint(b"boom") == "0" * 64


def test_simulate_observations() -> None:
    analyzer = APKAnalyzer()
    strings = ["firebase analytics", "admob banner", "crash report"]
    obs = analyzer._simulate_observations("com.test.app", strings)
    assert any("onCreate" in o for o in obs)
    assert any("onResume" in o for o in obs)
    assert any("ad -" in o for o in obs)
    assert any("analytics" in o for o in obs)
    assert any("crash_reporting" in o for o in obs)
    assert any("total hooks" in o for o in obs)
