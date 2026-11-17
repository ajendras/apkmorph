"""Tests for the APKAnalyzer."""

import pytest
from pathlib import Path
from unittest.mock import patch

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    return AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.testapp",
        decompiled_dir=tmp_path,
        components=["com.example.MainActivity", "com.example.Analytics"],
        strings=["ad", "analytics", "firebase", "crash"],
        string_resources={"app_name": "Test App", "ad_banner": "Advertisement"},
        metadata={},
    )


def test_extract_string_resources(tmp_path: Path) -> None:
    values_dir = tmp_path / "res" / "values"
    values_dir.mkdir(parents=True)
    (values_dir / "strings.xml").write_text(
        '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">TestApp</string>
    <string name="welcome">Welcome to the app</string>
    <item name="ad_text" type="string">Buy now!</item>
</resources>''',
        encoding="utf-8",
    )

    analyzer = APKAnalyzer()
    strings, mapping = analyzer._extract_string_resources(tmp_path)
    assert len(strings) == 3
    assert "TestApp" in strings
    assert "Buy now!" in strings
    assert mapping["app_name"] == "TestApp"
    assert mapping["ad_text"] == "Buy now!"


def test_simulate_observations() -> None:
    analyzer = APKAnalyzer()
    obs = analyzer._simulate_observations(
        "com.example.app", ["ad mob", "google analytics", "crash report"]
    )
    assert any("ad" in o for o in obs)
    assert any("analytics" in o for o in obs)
    assert any("crash_reporting" in o for o in obs)
    assert len(obs) >= 4


def test_observe_runtime_simulation(sample_report: AnalysisReport) -> None:
    analyzer = APKAnalyzer()
    with patch("apkmorph.analyzer._FRIDA_AVAILABLE", False):
        updated_report = analyzer.observe_runtime(sample_report, duration=1)
    assert len(updated_report.runtime_observations) > 0
    assert updated_report.metadata["runtime_observed"] is True
    assert updated_report.metadata["frida_used"] is False


def test_find_by_keyword(tmp_path: Path) -> None:
    analyzer = APKAnalyzer()
    # create some smali
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Analytics.smali").write_text(".class Lcom/example/Analytics;")

    matches = analyzer.find_by_keyword("analytic", tmp_path)
    assert any("Analytics" in m for m in matches)

    matches2 = analyzer.find_by_keyword("no_such", tmp_path)
    assert len(matches2) == 0


def test_extract_components(tmp_path: Path) -> None:
    analyzer = APKAnalyzer()
    smali_dir = tmp_path / "smali_classes2" / "com" / "example"
    smali_dir.mkdir(parents=True)
    (smali_dir / "Utils.smali").write_text(".class public Lcom/example/Utils;")

    components = analyzer.extract_components(tmp_path)
    assert "com.example.Utils" in components
