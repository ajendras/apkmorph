"""Shared utilities for APK Morph.

Includes helpers for running Apktool, generating markdown reports,
and safe filesystem operations. Now also exports a helper that can
be used by the UI to render diffs (kept for future expansion).
"""

import subprocess
from pathlib import Path
from typing import List

from apkmorph.models import AnalysisReport


def run_apktool(args: List[str]) -> None:
    """Run apktool with the supplied arguments.

    Raises CalledProcessError on non-zero exit.
    """
    cmd = ["apktool"] + args
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def generate_report_md(report: AnalysisReport) -> str:
    """Return a Markdown representation of an AnalysisReport.

    Used by the CLI when --output ends with .md.
    """
    return report.to_markdown()


def safe_copytree(src: Path, dst: Path) -> None:
    """Copy a directory tree, ignoring common build artifacts."""
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns("*.apk", "build", "__pycache__", "*.pyc"),
    )


def render_diff_html(modification) -> str:
    """Placeholder for future non-SmaliEditor diff rendering.

    Currently the SmaliEditor.get_diff_html is used by the UI.
    """
    # This function is kept for API compatibility with older UI code.
    # The real implementation lives in SmaliEditor.
    return "<p>Diff viewer not available in this context.</p>"
