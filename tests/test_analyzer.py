"""Tests for APKAnalyzer.

Covers decompilation, cache validity, component extraction (including
parallel multidex handling), keyword search, string resource parsing,
runtime observation (simulation fallback), and certificate fingerprinting
that works with androguard 4.1.4 on Python 3.12.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def analyzer(tmp_path: Path) -> APKAnalyzer:
    return APKAnalyzer(working_dir=tmp_path / "decompiled")


@pytest.fixture
def mock_apk():
    with patch("apkmorph.analyzer.APK") as mock:
        instance = MagicMock()
        instance.get_package.return_value = "com.example.app"
        instance.get_androidversion_name.return_value = "1.0"
        instance.get_androidversion_code.return_value = "1"
        instance.get_min_sdk_version.return_value = 24
        instance.get_target_sdk_version.return_value = 34
        instance.get_main_activity.return_value = ".MainActivity"
        instance.get_activities.return_value = [".MainActivity"]
        instance.get_services.return_value = []
        instance.get_receivers.return_value = []
        instance.get_providers.return_value = []
        instance.get_permissions.return_value = ["android.permission.INTERNET"]
        instance.is_signed.return_value = True
        instance.get_certificates.return_value = [b"fake-cert-bytes"]
        yield instance


def test_decompile_missing_file(analyzer: APKAnalyzer):
    with pytest.raises(FileNotFoundError, match="APK file not found"):
        analyzer.decompile("nonexistent.apk")


def test_decompile_invalid_extension(analyzer: APKAnalyzer, tmp_path: Path):
    bad_file = tmp_path / "bad.txt"
    bad_file.write_text("not an apk")
    with pytest.raises(ValueError, match="Input must be a valid .apk file"):
        analyzer.decompile(str(bad_file))


@patch("apkmorph.analyzer.run_apktool")
def test_decompile_creates_report(mock_run, analyzer: APKAnalyzer, mock_apk, tmp_path: Path):
    apk_file = tmp_path / "test.apk"
    apk_file.touch()

    with patch.object(analyzer, "extract_components", return_value=["com.example.MainActivity"]):
        with patch.object(
            analyzer, "_extract_string_resources", return_value=(["Hello"], {"greeting": "Hello"})
        ):
            report = analyzer.decompile(str(apk_file), force=True)

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "com.example.app"
    assert report.version_name == "1.0"
    assert report.main_activity == ".MainActivity"
    assert "com.example.MainActivity" in report.components
    assert report.strings == ["Hello"]
    assert report.string_resources == {"greeting": "Hello"}
    assert report.metadata["is_signed"] is True
    assert len(report.metadata["cert_fingerprints"]) == 1
    assert len(report.metadata["cert_fingerprints"][0]) == 64


def test_cache_validity(analyzer: APKAnalyzer, tmp_path: Path):
    apk = tmp_path / "app.apk"
    apk.touch()
    cache_dir = tmp_path / "cache_test"
    cache_dir.mkdir()
    (cache_dir / "AndroidManifest.xml").write_text("<manifest package='com.test'/>")
    (cache_dir / "smali").mkdir()
    (cache_dir / "res" / "values").mkdir(parents=True)
    (cache_dir / "smali" / "Test.smali").write_text(".class Lcom/test/Test;")

    # cache newer than apk
    cache_dir.touch()
    assert analyzer._is_decompilation_valid(cache_dir, apk) is True

    # missing manifest -> invalid
    (cache_dir / "AndroidManifest.xml").unlink()
    assert analyzer._is_decompilation_valid(cache_dir, apk) is False


@patch("apkmorph.analyzer.run_apktool")
def test_cache_skips_apktool(mock_run, analyzer: APKAnalyzer, tmp_path: Path, mock_apk):
    apk = tmp_path / "app.apk"
    apk.touch()
    cache_dir = tmp_path / "cached"
    cache_dir.mkdir(parents=True)
    (cache_dir / "AndroidManifest.xml").write_text("<manifest/>")
    (cache_dir / "smali").mkdir()
    (cache_dir / "res/values").mkdir(parents=True)

    # make cache look valid
    cache_dir.touch()

    with patch.object(analyzer, "extract_components", return_value=[]):
        with patch.object(analyzer, "_extract_string_resources", return_value=([], {})):
            analyzer.decompile(str(apk))  # should hit cache, no apktool call

    mock_run.assert_not_called()


def test_extract_components(analyzer: APKAnalyzer, tmp_path: Path):
    smali_root = tmp_path / "smali"
    smali_root.mkdir()
    (smali_root / "com" / "example").mkdir(parents=True)
    (smali_root / "com" / "example" / "MainActivity.smali").write_text(
        ".class public Lcom/example/MainActivity;"
    )
    (smali_root / "com" / "example" / "utils" / "Helper.smali").write_text(
        ".class public Lcom/example/utils/Helper;"
    )

    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components
    assert "com.example.utils.Helper" in components


def test_extract_components_multidex_parallel(analyzer: APKAnalyzer, tmp_path: Path):
    analyzer.parallel_enabled = True
    for i in range(2):
        d = tmp_path / f"smali_classes{i+1}"
        d.mkdir(parents=True)
        (d / "com" / f"Class{i}.smali").write_text(f".class Lcom/Class{i};")

    components = analyzer.extract_components(tmp_path)
    assert len(components) == 2
    assert any("Class0" in c for c in components)
    assert any("Class1" in c for c in components)


def test_find_by_keyword(analyzer: APKAnalyzer, tmp_path: Path):
    smali = tmp_path / "smali"
    smali.mkdir()
    (smali / "Analytics.smali").write_text("invoke-static analytics")
    (tmp_path / "res" / "values" / "strings.xml").mkdir(parents=True)
    (tmp_path / "res" / "values" / "strings.xml").write_text(
        '<string name="ad">banner</string>'
    )

    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert any("Analytics" in m for m in matches)

    matches = analyzer.find_by_keyword("ad", tmp_path)
    assert any("strings.xml" in m for m in matches)


def test_extract_string_resources(analyzer: APKAnalyzer, tmp_path: Path):
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        '''<?xml version="1.0"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="welcome">Hello World</string>
</resources>'''
    )

    strings, mapping = analyzer._extract_string_resources(tmp_path)
    assert "Test App" in strings
    assert "Hello World" in strings
    assert mapping["app_name"] == "Test App"


def test_observe_runtime_simulation(analyzer: APKAnalyzer):
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test.app",
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=34,
        decompiled_dir=Path("/tmp/decomp"),
        main_activity=".Main",
        activities=[".Main"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=[".Main"],
        strings=["firebase", "ad"],
        string_resources={},
        metadata={},
        size_bytes=1024,
        runtime_observations=[],
    )

    enriched = analyzer.observe_runtime(report, duration=0)
    assert len(enriched.runtime_observations) >= 3
    obs_text = " ".join(enriched.runtime_observations).lower()
    assert "ad" in obs_text or "analytics" in obs_text
    assert enriched.metadata["frida_used"] is False


def test_cert_fingerprint_various_types(analyzer: APKAnalyzer):
    # bytes
    fp1 = analyzer._cert_fingerprint(b"testcert")
    assert len(fp1) == 64

    # asn1crypto style
    class ASN1Cert:
        def dump(self):
            return b"asn1data"

    fp2 = analyzer._cert_fingerprint(ASN1Cert())
    assert len(fp2) == 64

    # get_certificate style
    class WrapperCert:
        def get_certificate(self):
            class Inner:
                def dump(self):
                    return b"inner"
            return Inner()

    fp3 = analyzer._cert_fingerprint(WrapperCert())
    assert len(fp3) == 64

    # fallback
    fp4 = analyzer._cert_fingerprint("plainstring")
    assert len(fp4) == 64
