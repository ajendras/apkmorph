"""Utility functions used across APK Morph.

Includes helpers for running Apktool, ADB, generating reports and safe file ops.
"""

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from apkmorph.models import AnalysisReport


def run_apktool(args: List[str]) -> None:
    """Execute apktool with the provided arguments.

    Raises helpful errors if the binary is missing or it fails.
    """
    cmd = ["apktool"] + args
    try:
        subprocess.run(
            cmd, check=True, capture_output=True, text=True, timeout=120
        )
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            "apktool command not found. Install from https://ibotpeaches.github.io/Apktool/install/"
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or "Unknown error"
        raise RuntimeError(f"Apktool execution failed:\n{stderr}") from exc


def run_adb(args: List[str], timeout: int = 30) -> str:
    """Run an ADB command. Returns stdout on success.

    Provides specific errors for common device issues.
    """
    cmd = ["adb"] + args
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except FileNotFoundError as exc:
        raise RuntimeError(
            "adb not found. Please install Android platform-tools and add adb to your PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"ADB command timed out after {timeout}s") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        if "no devices" in stderr.lower() or "found" in stderr.lower():
            raise RuntimeError(
                "No connected Android device or emulator detected.\n"
                "Run `adb devices` to verify connection and USB debugging."
            ) from exc
        raise RuntimeError(f"ADB error: {stderr or str(exc)}") from exc


def generate_report_md(report: "AnalysisReport") -> str:
    """Generate a Markdown summary of the analysis report."""
    md = f"""# APK Analysis Report

**Package:** {report.package_name}

**Version:** {report.version_name or 'N/A'} (code: {report.version_code or 'N/A'})

**Size:** {report.size_bytes} bytes

**Main Activity:** {report.main_activity or 'Not found'}

## Components ({len(report.components)})

"""
    for comp in report.components[:20]:
        md += f"- {comp}\n"
    if len(report.components) > 20:
        md += f"\n... and {len(report.components)-20} more.\n"
    md += f"\n## Permissions ({len(report.permissions)})\n"
    for perm in report.permissions:
        md += f"- {perm}\n"
    md += "\n## Runtime Observations\n"
    for obs in report.runtime_observations:
        md += f"- {obs}\n"
    return md


def safe_copytree(src: Path, dst: Path) -> None:
    """Copy directory tree safely, skipping if source missing."""
    if not src.exists():
        return
    import shutil

    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("*.tmp"))
