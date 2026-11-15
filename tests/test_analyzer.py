"""Tests for the APKAnalyzer.

Covers decompilation flow (with mocks for Apktool and Androguard), component
extraction from Smali (including multidex), string resource parsing, keyword
search, and error handling. All tests are self-contained and do not require
external tools or fixture APKs.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import AnalysisReport


class TestAPKAnalyzer:
    def test_init(self, tmp_path: Path) -> None:
        working_dir = tmp_path / "work"
        analyzer = APKAnalyzer(working_dir)
        assert analyzer.working_dir == working_dir
        assert working_dir.exists()

    def test_init_with_str(self, tmp_path: Path) -> None:
        """Test that str is also accepted for working_dir."""
        analyzer = APKAnalyzer(str(tmp_path))
        assert isinstance(analyzer.working_dir, Path)

    @patch("apkmorph.analyzer.run_apktool")
    @patch("apkmorph.analyzer.APK")
    def test_decompile(
        self, mock_apk_class: MagicMock, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        apk_file = tmp_path / "test.apk"
        apk_file.touch()
        mtime = 1234567890

        decomp_dir = tmp_path / f"apk_test_{mtime}"
        decomp_dir.mkdir(parents=True, exist_ok=True)

        # Create fake smali
        smali_file = decomp_dir / "smali" / "com" / "example" / "MainActivity.smali"
        smali_file.parent.mkdir(parents=True, exist_ok=True)
        smali_file.write_text(
            ".class public Lcom/example/MainActivity;\n"
            ".method public onCreate()V\n"
            "    return-void\n"
            ".end method\n"
        )

        # fake strings
        strings_file = decomp_dir / "res" / "values" / "strings.xml"
        strings_file.parent.mkdir(parents=True, exist_ok=True)
        strings_file.write_text(
            '<?xml version="1.0"?>\n<resources>\n'
            '  <string name="app_name">TestApp</string>\n'
            "</resources>"
        )

        # Setup Androguard mock
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = "com.example.testapp"
        mock_apk.get_androidversion_name.return_value = "1.2.3"
        mock_apk.get_androidversion_code.return_value = 123
        mock_apk.get_min_sdk_version.return_value = 24
        mock_apk.get_target_sdk_version.return_value = 34
        mock_apk.get_main_activity.return_value = "com.example.testapp.MainActivity"
        mock_apk.get_activities.return_value = ["com.example.testapp.MainActivity"]
        mock_apk.get_services.return_value = ["com.example.testapp.BackgroundService"]
        mock_apk.get_receivers.return_value = []
        mock_apk.get_providers.return_value = []
        mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
        mock_apk.is_signed.return_value = True
        mock_cert = MagicMock()
        mock_cert.get_fingerprint.return_value = "SHA1:deadbeef"
        mock_apk.get_certificates.return_value = [mock_cert]
        mock_apk_class.return_value = mock_apk

        with patch.object(Path, "stat") as mock_stat:
            mock_stat.return_value.st_mtime = mtime
            analyzer = APKAnalyzer(tmp_path)
            report = analyzer.decompile(str(apk_file))

        assert isinstance(report, AnalysisReport)
        assert report.package_name == "com.example.testapp"
        assert report.version_name == "1.2.3"
        assert report.version_code == 123
        assert "com.example.testapp.MainActivity" in report.components
        assert "com.example.testapp.BackgroundService" in report.components
        assert "TestApp" in report.strings
        assert report.decompiled_dir == decomp_dir.absolute()
        mock_run.assert_called_once()

    def test_extract_components(self, tmp_path: Path) -> None:
        analyzer = APKAnalyzer(tmp_path)
        smali_dir = tmp_path / "smali" / "com" / "example"
        smali_dir.mkdir(parents=True)
        (smali_dir / "Main.smali").touch()
        helper_dir = smali_dir / "utils"
        helper_dir.mkdir()
        (helper_dir / "Helper.smali").touch()

        components = analyzer.extract_components(tmp_path)
        assert len(components) == 2
        assert "com.example.Main" in components
        assert "com.example.utils.Helper" in components

    def test_extract_components_multidex(self, tmp_path: Path) -> None:
        analyzer = APKAnalyzer(tmp_path)
        for variant in ["smali", "smali_classes2", "smali_classes3"]:
            d = tmp_path / variant / "com" / "example"
            d.mkdir(parents=True)
            (d / f"Class{variant[-1] if variant != 'smali' else '1'}.smali").touch()

        components = analyzer.extract_components(tmp_path)
        assert len(components) == 3
        assert any("Class1" in c for c in components)
        assert any("Class2" in c for c in components)
        assert any("Class3" in c for c in components)

    def test_extract_strings(self, tmp_path: Path) -> None:
        analyzer = APKAnalyzer(tmp_path)
        values_dir = tmp_path / "res" / "values"
        values_dir.mkdir(parents=True)
        (values_dir / "strings.xml").write_text(
            """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Test App</string>
    <string name="greeting">Hello, world!</string>
    <string-array name="options">
        <item>Option 1</item>
        <item>Option 2</item>
    </string-array>
</resources>"""
        )

        strings = analyzer._extract_strings(tmp_path)
        assert "Test App" in strings
        assert "Hello, world!" in strings
        assert "Option 1" in strings
        assert "Option 2" in strings
        assert not any(len(s) >= 120 for s in strings)

    def test_find_by_keyword(self, tmp_path: Path) -> None:
        analyzer = APKAnalyzer(tmp_path)
        # setup smali
        smali_dir = tmp_path / "smali" / "com" / "example" / "analytics"
        smali_dir.mkdir(parents=True)
        (smali_dir / "Tracker.smali").touch()

        # setup xml
        xml_dir = tmp_path / "res" / "xml"
        xml_dir.mkdir(parents=True)
        (xml_dir / "tracker.xml").write_text("<tracker>enabled</tracker>")

        matches = analyzer.find_by_keyword("track", tmp_path)
        assert len(matches) > 0
        assert any("Tracker" in m for m in matches)
        assert any("resource:tracker.xml" in m for m in matches)

    def test_find_by_keyword_empty(self, tmp_path: Path) -> None:
        analyzer = APKAnalyzer(tmp_path)
        assert analyzer.find_by_keyword("") == []
        assert analyzer.find_by_keyword("   ") == []

    def test_decompile_file_not_found(self, tmp_path: Path) -> None:
        analyzer = APKAnalyzer(tmp_path)
        with pytest.raises(FileNotFoundError, match="APK file not found"):
            analyzer.decompile("missing.apk")

    def test_decompile_invalid_file(self, tmp_path: Path) -> None:
        analyzer = APKAnalyzer(tmp_path)
        bad = tmp_path / "not_an_apk.txt"
        bad.touch()
        with pytest.raises(ValueError, match="Input must be a valid .apk file"):
            analyzer.decompile(str(bad))

    @patch("apkmorph.analyzer.run_apktool")
    def test_decompile_apktool_failure(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["apktool"], stderr=b"apktool error"
        )
        analyzer = APKAnalyzer(tmp_path)
        apk = tmp_path / "test.apk"
        apk.touch()
        with pytest.raises(RuntimeError, match="Apktool decompilation failed"):
            analyzer.decompile(str(apk))
