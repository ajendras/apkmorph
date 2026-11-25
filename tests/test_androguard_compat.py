"""Androguard compatibility tests.

Focused on certificate fingerprinting paths exercised by APKAnalyzer on
Python 3.12 with androguard 4.1.4 + apkInspector. Also validates that
decompile() never fails due to cert parsing errors.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from apkmorph.analyzer import APKAnalyzer


def test_cert_fingerprint_asn1crypto():
    analyzer = APKAnalyzer()
    cert = MagicMock()
    cert.dump.return_value = b"fake-der-bytes"
    fp = analyzer._cert_fingerprint(cert)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_cert_fingerprint_with_get_certificate():
    analyzer = APKAnalyzer()
    inner = MagicMock()
    inner.dump.return_value = b"inner-der"
    cert = MagicMock()
    cert.get_certificate.return_value = inner
    fp = analyzer._cert_fingerprint(cert)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_cert_fingerprint_bytes():
    analyzer = APKAnalyzer()
    cert = b"raw-bytes-cert-data"
    fp = analyzer._cert_fingerprint(cert)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_cert_fingerprint_fallback():
    analyzer = APKAnalyzer()
    cert = object()  # arbitrary object with no special methods
    fp = analyzer._cert_fingerprint(cert)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_cert_fingerprint_on_error():
    analyzer = APKAnalyzer()
    cert = MagicMock()
    cert.dump.side_effect = RuntimeError("simulated py312 cert error")
    fp = analyzer._cert_fingerprint(cert)
    assert fp == "0000000000000000000000000000000000000000000000000000000000000000"


@pytest.mark.parametrize("force", [True, False])
def test_decompile_with_cert_error(tmp_path: Path, force: bool):
    """Ensure decompile succeeds even when androguard certificate handling raises
    (the exact error seen on Python 3.12). Metadata contains a safe fallback.
    """
    apk_path = tmp_path / "test.apk"
    apk_path.write_text("dummy apk content")  # just needs to exist

    decomp_dir = tmp_path / "decomp_dummy"
    decomp_dir.mkdir()
    (decomp_dir / "AndroidManifest.xml").write_text("<manifest package='com.example'/>")
    (decomp_dir / "smali").mkdir()
    (decomp_dir / "res" / "values").mkdir(parents=True)
    (decomp_dir / "res" / "values" / "strings.xml").write_text(
        '<resources><string name="app_name">Test</string></resources>'
    )

    mock_apk = MagicMock()
    mock_apk.get_activities.return_value = ["com.example.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_permissions.return_value = []
    mock_apk.get_package.return_value = "com.example"
    mock_apk.get_androidversion_name.return_value = "1.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = 24
    mock_apk.get_target_sdk_version.return_value = 34
    mock_apk.get_main_activity.return_value = "com.example.MainActivity"
    mock_apk.is_signed.side_effect = RuntimeError("cert parse failed on py3.12")
    mock_apk.get_certificates.side_effect = RuntimeError("cert parse failed on py3.12")

    analyzer = APKAnalyzer(working_dir=tmp_path / "work")
    with patch("apkmorph.analyzer.APK", return_value=mock_apk):
        with patch.object(analyzer, "_is_decompilation_valid", return_value=True):
            with patch.object(
                analyzer, "extract_components", return_value=["com.example.MainActivity"]
            ):
                with patch.object(
                    analyzer,
                    "_extract_string_resources",
                    return_value=(["Test App"], {"app_name": "Test"}),
                ):
                    report = analyzer.decompile(str(apk_path), force=force)

    assert report.package_name == "com.example"
    assert report.components == ["com.example.MainActivity", "com.example.MainActivity"]
    assert "cert_error" in report.metadata
    assert "cert parse failed on py3.12" in report.metadata["cert_error"]
    assert report.metadata["is_signed"] is False
    assert report.metadata["cert_fingerprints"] == []
    assert report.metadata["smali_classes"] == 1
