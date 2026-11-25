"""Tests for patch generation, validation, simulation, application,
rollback, gallery integration and the new custom-plugin prompt-fragment
feature.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator
from apkmorph.plugins import (
    get_custom_prompt_fragments,
    list_custom_patch_types,
    register_custom_patch_type,
)


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    decomp = tmp_path / "decompiled_app"
    decomp.mkdir()
    (decomp / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.test",
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=34,
        decompiled_dir=decomp.absolute(),
        main_activity="com.example.test.MainActivity",
        activities=["com.example.test.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=["android.permission.INTERNET"],
        components=["com.example.test.MainActivity"],
        strings=["hello", "ad"],
        string_resources={"app_name": "Test"},
        metadata={},
        size_bytes=1024,
        runtime_observations=["observed: analytics call"],
    )


def test_from_description_includes_custom_fragments(sample_report: AnalysisReport) -> None:
    """Register a custom type with a prompt fragment and verify it appears
    in the LLM system prompt.
    """
    fragment = (
        "Use 'network_security_injector' for requests about certificate "
        "pinning or cleartext traffic. Supply params: pin, domain, "
        "allow_cleartext (bool)."
    )

    @register_custom_patch_type("network_security_injector", prompt_fragment=fragment)
    def dummy_handler(mod: Modification, decompiled_dir: Path) -> bool:
        return True

    generator = PatchGenerator(model="llama3.2")

    with patch.object(generator.llm, "query") as mock_query:
        mock_query.return_value = json.dumps(
            [
                {
                    "edit_type": "network_security_injector",
                    "target": "res/xml/network_security_config.xml",
                    "description": "inject pinning",
                    "params": {"pin": "sha256/abc", "domain": "example.com"},
                    "rationale": "User asked for secure connections",
                    "confidence": 0.9,
                }
            ]
        )
        plan = generator.from_description("enable certificate pinning for example.com", sample_report)

    # The fragment must have been part of the prompt
    prompt_text = mock_query.call_args[0][0]  # user prompt
    system_text = mock_query.call_args[1].get("system", "")
    assert "network_security_injector" in system_text
    assert "certificate pinning" in system_text
    assert "network_security_injector" in get_custom_prompt_fragments()
    assert plan.modifications[0].edit_type == "network_security_injector"
    assert plan.modifications[0].params["pin"] == "sha256/abc"


def test_custom_patch_handler_dispatch(sample_report: AnalysisReport, tmp_path: Path) -> None:
    """A registered custom handler is called during apply_plan."""

    called = []

    @register_custom_patch_type("color_tinter", prompt_fragment="Use for any color-tinting request")
    def tinter(mod: Modification, decompiled_dir: Path) -> bool:
        called.append(mod.params.get("color"))
        return True

    generator = PatchGenerator()
    mod = Modification(
        edit_type="color_tinter",
        target="res/values/colors.xml",
        description="change primary color",
        params={"color": "#FF5722"},
        rationale="user requested orange theme",
        confidence=0.88,
    )
    plan = PatchPlan(
        description="orange theme",
        modifications=[mod],
        rationale="test",
        confidence=0.9,
        model_used="llama3.2",
    )

    # Mock rebuild so we don't need real tools
    with patch.object(generator.builder, "rebuild_and_sign", return_value=tmp_path / "out.apk"):
        result = generator.apply_plan(plan, sample_report)

    assert result["success"] is True
    assert result["applied"] == 1
    assert called == ["#FF5722"]


def test_prompt_fragment_fallback_when_none_supplied(sample_report: AnalysisReport) -> None:
    """When a plugin registers without a fragment a sensible default is used."""

    @register_custom_patch_type("generic_plugin")
    def handler(mod: Modification, decompiled_dir: Path) -> bool:
        return True

    fragments = get_custom_prompt_fragments()
    assert "generic_plugin" in fragments
    assert "specialized generic_plugin modifications" in fragments


def test_list_custom_patch_types() -> None:
    before = set(list_custom_patch_types())

    @register_custom_patch_type("test_list")
    def _dummy(_m: Modification, _d: Path) -> bool:
        return True

    after = list_custom_patch_types()
    assert "test_list" in after
    # cleanup not needed for test


def test_validate_rejects_invalid_confidence(sample_report: AnalysisReport) -> None:
    generator = PatchGenerator()
    mod = Modification(
        edit_type="smali",
        target="Lcom/example/Foo;",
        description="test",
        params={},
        rationale="test",
        confidence=1.3,  # out of range
    )
    plan = PatchPlan(
        description="bad",
        modifications=[mod],
        rationale="bad",
        confidence=0.5,
        model_used="test",
    )
    generator.validate(plan)
    assert plan.modifications[0].confidence == 1.0


@patch("apkmorph.patch_generator.safe_copytree")
@patch("apkmorph.patch_generator.shutil")
def test_rollback_on_failure(mock_shutil: MagicMock, mock_safe_copytree: MagicMock, sample_report: AnalysisReport) -> None:
    generator = PatchGenerator()

    def failing_handler(_mod: Modification, _dir: Path) -> bool:
        raise RuntimeError("handler crash")

    @register_custom_patch_type("failing_type")
    def _failing(_m: Modification, _d: Path) -> bool:
        return failing_handler(_m, _d)

    mod = Modification(
        edit_type="failing_type",
        target="fail",
        description="will fail",
        params={},
        rationale="test rollback",
        confidence=0.6,
    )
    plan = PatchPlan(
        description="fail test",
        modifications=[mod],
        rationale="",
        confidence=0.5,
        model_used="test",
    )

    with pytest.raises(RuntimeError, match="rolled back"):
        generator.apply_plan(plan, sample_report)

    mock_shutil.rmtree.assert_called()
    assert mock_safe_copytree.call_count >= 2
