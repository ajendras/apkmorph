"""Tests for patch generation, validation, simulation and the new plugin API."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator
from apkmorph.plugins import (
    get_custom_patch_handler,
    list_custom_patch_types,
    register_custom_patch_type,
)
from apkmorph.smali import SmaliEditor


def test_custom_patch_type_registration():
    """Test the plugin decorator and lookup functions."""
    calls = []

    @register_custom_patch_type("test_theme")
    def mock_theme_handler(mod: Modification, decomp_dir: Path) -> bool:
        calls.append(mod.params.get("primary_color"))
        return True

    assert "test_theme" in list_custom_patch_types()
    assert get_custom_patch_handler("test_theme") is mock_theme_handler
    assert get_custom_patch_handler("nonexistent") is None

    # Cleanup global state for other tests
    if "test_theme" in list_custom_patch_types():
        del list_custom_patch_types.__globals__["_custom_patch_handlers"]["test_theme"]


def test_plugin_handler_called_on_apply():
    """Integration test that a registered plugin is invoked by the editor."""
    calls = []

    @register_custom_patch_type("color_injector")
    def color_injector(mod: Modification, decomp_dir: Path) -> bool:
        calls.append((mod.params.get("color"), str(decomp_dir)))
        return True

    mod = Modification(
        class_name="Theme",
        method="applyTheme",
        edit_type="color_injector",
        diff="color changed",
        description="inject primary color",
        params={"color": "#FF9800"},
        file_path=Path("res/values/colors.xml"),
        confidence=0.9,
    )

    with tempfile.TemporaryDirectory() as tmp:
        decomp = Path(tmp)
        editor = SmaliEditor()
        success = editor.apply_modification(mod, decomp)
        assert success is True
        assert calls == [("#FF9800", str(decomp))]

    # Cleanup
    if "color_injector" in list_custom_patch_types():
        del list_custom_patch_types.__globals__["_custom_patch_handlers"][
            "color_injector"
        ]


def test_patch_generator_from_description_and_validate():
    """Test that from_description calls the LLM and validate passes a good plan."""
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.test",
        decompiled_dir=Path("/tmp/decomp"),
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=34,
        main_activity="MainActivity",
        activities=[],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["com.example.MainActivity"],
        strings=["hello"],
        string_resources={"app_name": "Test"},
        metadata={},
        size_bytes=1024,
        runtime_observations=["observed: analytics call"],
    )

    mod = Modification(
        class_name="com.example.Analytics",
        method="logEvent",
        edit_type="smali",
        diff="- invoke ...",
        description="disable analytics",
        original_snippet="invoke ...",
        patched_snippet="return-void",
        confidence=0.85,
        file_path=Path("smali/com/example/Analytics.smali"),
    )

    plan = PatchPlan(
        description="disable analytics",
        rationale="Used runtime observation to target live method",
        confidence=0.88,
        modifications=[mod],
    )

    with patch("apkmorph.patch_generator.LLMClient") as mock_llm_class:
        mock_llm = MagicMock()
        mock_llm.generate_patch.return_value = plan
        mock_llm_class.return_value = mock_llm

        generator = PatchGenerator(model="llama3.2")
        # Patch the observe_runtime call so we don't require Frida
        with patch(
            "apkmorph.patch_generator.APKAnalyzer.observe_runtime",
            return_value=report,
        ):
            generated_plan = generator.from_description("disable analytics", report)

    assert generated_plan.id == plan.id
    assert generated_plan.confidence == 0.88
    assert len(generated_plan.modifications) == 1

    # validate should pass
    generator.validate(generated_plan)


def test_validate_rejects_low_confidence():
    """Validation should raise for plans with low confidence mods."""
    mod = Modification(
        class_name="Test",
        method="test",
        edit_type="smali",
        diff="",
        description="bad",
        confidence=0.3,
        file_path=Path("test.smali"),
    )
    plan = PatchPlan(
        description="bad plan",
        rationale="",
        confidence=0.4,
        modifications=[mod],
    )
    generator = PatchGenerator()
    with pytest.raises(ValueError, match="confidence too low"):
        generator.validate(plan)


def test_simulate_apply():
    """simulate_apply returns structured dry-run information."""
    mod = Modification(
        class_name="Ads",
        method="show",
        edit_type="smali",
        diff="removed ad call",
        description="remove ads",
        confidence=0.92,
        file_path=Path("smali/Ads.smali"),
    )
    plan = PatchPlan(
        description="remove ads",
        rationale="observed ad call",
        confidence=0.9,
        modifications=[mod],
    )
    generator = PatchGenerator()
    result = generator.simulate_apply(plan, Path("/tmp"))
    assert result["would_modify"] == 1
    assert result["overall_confidence"] == 0.9
    assert result["applied"][0]["uses_plugin"] is False


def test_batch_processing():
    """Batch should process multiple APKs and return per-apk results."""
    with patch("apkmorph.patch_generator.PatchGenerator.from_description") as mock_from:
        with patch("apkmorph.patch_generator.PatchGenerator.apply_plan") as mock_apply:
            mock_from.return_value = PatchPlan(
                description="test",
                rationale="",
                confidence=0.8,
                modifications=[],
            )
            mock_apply.return_value = Path("patched_test.apk")

            generator = PatchGenerator()
            results = generator.batch(
                description="disable ads",
                apk_paths=["app1.apk", "app2.apk"],
                output_dir=Path("/tmp/batch"),
                observe_runtime=False,
            )

    assert len(results) == 2
    assert results[0]["success"] is True
    assert "output_apk" in results[0]
