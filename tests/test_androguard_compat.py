"""Regression tests for androguard import compatibility.

androguard 4.x (pinned in pyproject.toml) moved ``APK`` from
``androguard.core.bytecodes.apk`` to ``androguard.core.apk``. Importing the
old path broke test collection for every module that imports the analyzer.
"""

import importlib


def test_analyzer_module_imports():
    module = importlib.import_module("apkmorph.analyzer")
    assert hasattr(module, "APKAnalyzer")


def test_analyzer_uses_androguard_apk_class():
    from apkmorph import analyzer

    assert analyzer.APK.__name__ == "APK"
    assert analyzer.APK.__module__.startswith("androguard.core")


def test_patch_generator_module_imports():
    module = importlib.import_module("apkmorph.patch_generator")
    assert hasattr(module, "PatchGenerator")
