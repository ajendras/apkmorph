"""Tests for the APKAnalyzer."""

import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


def test_decompile_creates_report(tmp_path: Path) -> None:
    """Test that decompile produces a valid AnalysisReport with string_resources."""
    # Create a minimal fake APK structure
    apk_path = tmp_path / "test.apk"
    apk_path.write_text("fake apk content", encoding="utf-8")

    decompiled = tmp_path / "decompiled_test"
    decompiled.mkdir()

    # Create a strings.xml with known content
    values = decompiled / "res" / "values"
    values.mkdir(parents=True)
    strings_xml = values / "strings.xml"
    strings_xml.write_text(
        '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="ad_text">Advertisement</string>
    <string name="analytics_id">UA-123456</string>
</resources>''',
        encoding="utf-8",
    )

    analyzer = APKAnalyzer(working_dir=tmp_path / "work")
    # Monkey-patch the decompile internals for test
    report = analyzer.decompile(str(apk_path))

    assert isinstance(report, AnalysisReport)
    assert report.package_name == "unknown.package"
    assert len(report.strings) >= 3
    assert "Test App" in report.strings
    assert report.string_resources["app_name"] == "Test App"
    assert report.string_resources["ad_text"] == "Advertisement"
    assert "resources_arsc" in report.metadata
    assert "will be regenerated" in report.metadata["resources_arsc"]


def test_extract_string_resources(tmp_path: Path) -> None:
    """Test _extract_string_resources returns both list and dict."""
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="hello">Hello World</string>
    <string name="cancel">Cancel</string>
</resources>''',
        encoding="utf-8",
    )

    analyzer = APKAnalyzer()
    strings, resources = analyzer._extract_string_resources(tmp_path)

    assert "Hello World" in strings
    assert "Cancel" in strings
    assert resources["hello"] == "Hello World"
    assert resources["cancel"] == "Cancel"


def test_find_by_keyword(tmp_path: Path) -> None:
    """Test keyword search includes XML resources."""
    values = tmp_path / "res" / "values"
    values.mkdir(parents=True)
    (values / "strings.xml").write_text(
        '<resources><string name="ad">Ad</string></resources>',
        encoding="utf-8",
    )

    analyzer = APKAnalyzer()
    matches = analyzer.find_by_keyword("ad", decompiled_dir=tmp_path)
    assert any("ad" in m.lower() for m in matches)
    assert any("resource:" in m for m in matches)
