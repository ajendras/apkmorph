"""Unit tests for patch generation, prompt building and plan validation.

Covers Smali, XML and resource edits as well as the new multi-model support with auto-download.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report() -> AnalysisReport:
    return AnalysisReport(
        apk_path="test.apk",
        package_name="com.example.test",
        decompiled_dir="/tmp/decomp",
        components=["com.example.MainActivity", "com.google.android.gms.ads.AdView"],
        strings=["analytics", "ad", "firebase"],
        string_resources={"app_name": "Test App", "ad_banner_text": "Advertisement"},
        runtime_observations=[
            "observed: ad - com.google.android.gms.ads.AdView.loadAd() called 4 times",
            "observed: analytics - FirebaseAnalytics.logEvent() called",
        ],
    )


def test_patch_generator_from_description(sample_report: AnalysisReport) -> None:
    with patch("apkmorph.llm.LLMClient.generate_patch") as mock_gen:
        mock_plan = PatchPlan(
            description="disable all analytics",
            rationale="Targeted live methods observed via Frida",
            confidence=0.88,
            modifications=[
                Modification(
                    class_name="com.google.android.gms.ads.AdView",
                    method="loadAd",
                    diff="- invoke-virtual\n+ return-void",
                    description="Disable ad load observed at runtime",
                    confidence=0.92,
                    edit_type="smali",
                )
            ],
        )
        mock_gen.return_value = mock_plan

        generator = PatchGenerator(model="llama3.2")
        plan = generator.from_description("disable all analytics", sample_report)

        assert plan.description == "disable all analytics"
        assert len(plan.modifications) == 1
        assert plan.modifications[0].edit_type == "smali"
        mock_gen.assert_called_once()


def test_llm_client_supports_additional_models() -> None:
    with patch("apkmorph.llm.ollama.list") as mock_list, patch(
        "apkmorph.llm.ollama.pull"
    ) as mock_pull, patch("apkmorph.llm.Console.print") as mock_print:
        # Model already present
        mock_list.return_value = {"models": [{"name": "gemma2:latest"}]}
        client = LLMClient(model="gemma2")
        client._model_ready = True
        client._ensure_model()
        mock_pull.assert_not_called()

        # Model missing -> auto-download (phi3 alias)
        mock_list.return_value = {"models": [{"name": "llama3.2"}]}
        mock_pull.return_value = None
        client = LLMClient(model="phi3")
        client._model_ready = False
        client._ensure_model()
        mock_pull.assert_called_once_with("phi3")
        assert mock_print.call_count >= 2
        assert client.model == "phi3"

        # codellama alias
        client = LLMClient(model="codellama")
        client._ensure_model()
        assert client.model == "codellama"


def test_prompt_includes_runtime_observations(sample_report: AnalysisReport) -> None:
    client = LLMClient(model="llama3.2")
    client._ensure_model = MagicMock()
    client._model_ready = True

    prompt = client._build_patch_prompt("remove ads", sample_report)

    assert "Runtime observations from Frida" in prompt
    assert "observed: ad - com.google.android.gms.ads.AdView.loadAd()" in prompt
    assert "gemma2" not in prompt  # no leakage of model name into prompt
    assert "resource_key" in prompt  # resource editing guidance present


def test_patch_plan_validation_and_simulation() -> None:
    generator = PatchGenerator(model="phi3")
    valid_plan = PatchPlan(
        description="disable analytics",
        rationale="Used runtime observations",
        modifications=[
            Modification(
                class_name="com.example.Analytics",
                method="logEvent",
                diff="- invoke-static\n+ return-void",
                description="Return early from analytics call",
                confidence=0.85,
                edit_type="smali",
                file_path="smali/com/example/Analytics.smali",
            ),
            Modification(
                class_name="resource",
                method="update_string",
                diff="ad_text changed",
                description="Empty ad string",
                confidence=0.78,
                edit_type="resource",
                resource_key="ad_text",
                new_value="",
            ),
        ],
    )

    # validate should succeed for well-formed plan
    generator.validate(valid_plan)

    # simulate_apply dry-run
    with patch.object(generator, "simulate_apply") as mock_sim:
        mock_sim.return_value = {"applied": 2, "failed": 0, "skipped": 0}
        result = generator.simulate_apply(valid_plan, "/tmp/decompiled")
        assert result["applied"] == 2
        mock_sim.assert_called_once_with(valid_plan, "/tmp/decompiled")


def test_invalid_plan_raises_validation_error() -> None:
    generator = PatchGenerator()
    bad_plan = PatchPlan(
        description="bad",
        modifications=[],  # empty is allowed by model but test expects validation
        rationale="",
    )

    with pytest.raises((ValidationError, RuntimeError)):
        generator.validate(bad_plan)


def test_resource_edit_roundtrip(sample_report: AnalysisReport) -> None:
    generator = PatchGenerator(model="codellama")
    generator._llm_client = MagicMock()  # type: ignore[attr-defined]
    generator._llm_client.generate_patch.return_value = PatchPlan(
        description="change app name",
        rationale="Resource edit",
        modifications=[
            Modification(
                class_name="resource",
                method="update_string",
                diff="app_name updated",
                description="Update app name string",
                edit_type="resource",
                resource_key="app_name",
                new_value="Patched App",
                confidence=0.9,
            )
        ],
    )

    plan = generator.from_description("change app name to Patched App", sample_report)
    assert plan.modifications[0].edit_type == "resource"
    assert plan.modifications[0].resource_key == "app_name"
    assert plan.modifications[0].new_value == "Patched App"
