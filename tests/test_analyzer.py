"""Tests for APKAnalyzer."""

import pytest
from pathlib import Path
from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def analyzer():
    return APKAnalyzer(working_dir=Path("test_decompiled"))


@pytest.fixture
def sample_report():
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=Path("test_decompiled/apk_test_123"),
        main_activity="com.example.testapp.MainActivity",
        activities=["com.example.testapp.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=["android.permission.INTERNET"],
        components=["com.example.testapp.MainActivity"],
        strings=["hello", "ad banner", "analytics event", "track user"],
        string_resources={"app_name": "Test App", "ad_text": "Click here"},
        metadata={},
        size_bytes=1024,
    )


def test_decompile_validates_input(analyzer):
    with pytest.raises(ValueError, match="Input must be a valid .apk file"):
        analyzer.decompile("invalid.txt")
    with pytest.raises(FileNotFoundError):
        analyzer.decompile("nonexistent.apk")


def test_extract_components(analyzer, tmp_path):
    smali_dir = tmp_path / "smali/com/example"
    smali_dir.mkdir(parents=True, exist_ok=True)
    (smali_dir / "MainActivity.smali").write_text(
        ".class public Lcom/example/MainActivity;"
    )
    components = analyzer.extract_components(tmp_path)
    assert "com.example.MainActivity" in components


def test_find_by_keyword(analyzer, tmp_path):
    smali_dir = tmp_path / "smali"
    smali_dir.mkdir(exist_ok=True)
    (smali_dir / "Analytics.smali").write_text("invoke-static analytics code here")
    matches = analyzer.find_by_keyword("analytics", tmp_path)
    assert any("Analytics" in m for m in matches)


def test_extract_string_resources(analyzer, tmp_path):
    values_dir = tmp_path / "res/values"
    values_dir.mkdir(parents=True, exist_ok=True)
    (values_dir / "strings.xml").write_text(
        """
        <resources>
            <string name="app_name">TestApp</string>
            <string name="ad_banner">Advertisement</string>
        </resources>
        """
    )
    strings, string_map = analyzer._extract_string_resources(tmp_path)
    assert "TestApp" in strings
    assert string_map.get("ad_banner") == "Advertisement"


def test_observe_runtime(sample_report, analyzer):
    enriched = analyzer.observe_runtime(sample_report, duration=1)
    assert isinstance(enriched, AnalysisReport)
    assert len(enriched.runtime_observations) > 0
    assert any("observed" in obs.lower() for obs in enriched.runtime_observations)
    assert enriched.metadata.get("runtime_observed") is True
    assert "frida_used" in enriched.metadata


def test_observe_runtime_fallback_no_strings(analyzer):
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.app",
        decompiled_dir=Path("/tmp"),
        strings=[],
    )
    enriched = analyzer.observe_runtime(report, duration=1)
    assert len(enriched.runtime_observations) > 0
    assert any("onCreate" in obs for obs in enriched.runtime_observations)
