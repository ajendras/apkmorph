"""APK analysis module.

Provides APKAnalyzer for decompiling APKs with Apktool, extracting rich
metadata via Androguard, and supporting keyword/component searches for
the LLM patch generator.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
from typing import Any, Dict, List

from androguard.core.bytecodes.apk import APK

from apkmorph.models import AnalysisReport
from apkmorph.utils import run_apktool


class APKAnalyzer:
    """Analyzes Android APKs by decompiling with Apktool and parsing with Androguard.

    Produces an immutable AnalysisReport containing manifest data, components,
    permissions, strings, and a reference to the decompiled source tree.
    All operations are local and deterministic.
    """

    def __init__(self, working_dir: str | Path = Path("decompiled")) -> None:
        """Initialize analyzer with a working directory for decompiled artifacts.

        Args:
            working_dir: Base directory for decompiled APKs (default: ./decompiled).
                         Accepts str or Path.
        """
        self.working_dir = Path(working_dir)
        self.working_dir.mkdir(parents=True, exist_ok=True)

    def decompile(self, apk_path: str) -> AnalysisReport:
        """Decompile APK and return a complete AnalysisReport.

        Uses Apktool for Smali/XML resources and Androguard for manifest metadata.
        Creates a unique output directory based on APK name and mtime.

        Args:
            apk_path: Filesystem path to the APK (must exist and end in .apk)

        Returns:
            AnalysisReport with all extracted metadata and decompiled_dir reference

        Raises:
            FileNotFoundError: If APK or required tools are missing
            ValueError: If input is not a valid APK
            RuntimeError: If decompilation or parsing fails
        """
        path = Path(apk_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"APK file not found: {path}")
        if path.suffix.lower() != ".apk":
            raise ValueError("Input must be a valid .apk file")

        # Unique decompile directory prevents collisions across runs
        decompiled_dir = self.working_dir / f"apk_{path.stem}_{int(path.stat().st_mtime)}"
        decompiled_dir.mkdir(parents=True, exist_ok=True)

        # Decompile with Apktool (forces overwrite, skips Java source)
        try:
            run_apktool(
                ["d", str(path), "-o", str(decompiled_dir), "-f", "--no-src"]
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"Apktool decompilation failed: {exc.stderr}") from exc
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                "Apktool not found. Please install Apktool and ensure it is on PATH."
            ) from exc

        # Parse manifest and metadata with Androguard
        try:
            apk_obj = APK(str(path))
        except Exception as exc:
            raise RuntimeError(f"Androguard parsing failed: {exc}") from exc

        activities: List[str] = apk_obj.get_activities()
        services: List[str] = apk_obj.get_services()
        receivers: List[str] = apk_obj.get_receivers()
        providers: List[str] = apk_obj.get_providers()
        permissions: List[str] = apk_obj.get_permissions()

        all_components = activities + services + receivers + providers

        # Augment with classes discovered from Smali files
        smali_components = self.extract_components(decompiled_dir)
        for comp in smali_components:
            if comp not in all_components:
                all_components.append(comp)

        strings = self._extract_strings(decompiled_dir)

        report = AnalysisReport(
            apk_path=path,
            package_name=apk_obj.get_package() or "unknown.package",
            version_name=apk_obj.get_androidversion_name(),
            version_code=apk_obj.get_androidversion_code(),
            min_sdk=apk_obj.get_min_sdk_version(),
            target_sdk=apk_obj.get_target_sdk_version(),
            decompiled_dir=decompiled_dir.absolute(),
            main_activity=apk_obj.get_main_activity(),
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers,
            permissions=permissions,
            components=all_components,
            strings=strings[:250],  # reasonable limit for LLM context
            metadata={
                "is_signed": apk_obj.is_signed(),
                "cert_fingerprints": [
                    cert.get_fingerprint() for cert in apk_obj.get_certificates()
                ],
                "smali_classes": len(smali_components),
            },
            size_bytes=path.stat().st_size,
        )

        return report

    def extract_components(self, decompiled_dir: Path) -> List[str]:
        """Extract fully-qualified class names by walking all smali* directories.

        Supports multidex (smali, smali_classes2, ...).

        Args:
            decompiled_dir: Root of the decompiled APK (must contain smali*/)

        Returns:
            List of class names (e.g. com.example.MainActivity)
        """
        if not decompiled_dir or not decompiled_dir.exists():
            return []

        components: List[str] = []
        for smali_variant in decompiled_dir.glob("smali*"):
            if smali_variant.is_dir():
                self._walk_smali(smali_variant, components)
        return components

    def _walk_smali(self, root: Path, components: List[str]) -> None:
        """Recursively walk smali tree and convert paths to class names.

        Uses relative_to(root) so smali*/ prefix is automatically omitted.
        """
        for smali_file in root.rglob("*.smali"):
            try:
                rel = smali_file.relative_to(root)
                class_name = (
                    str(rel)
                    .replace("/", ".")
                    .replace(".smali", "")
                )
                if class_name not in components:
                    components.append(class_name)
            except ValueError:
                continue  # path not under expected root

    def find_by_keyword(self, term: str, decompiled_dir: Path | None = None) -> List[str]:
        """Case-insensitive search for a term across components and string resources.

        If decompiled_dir is provided, also scans Smali content for the term.

        Args:
            term: Keyword to search for
            decompiled_dir: Optional decompiled APK root for deeper search

        Returns:
            List of matching component names or resource strings (max 30)
        """
        if not term or not term.strip():
            return []

        keyword = term.lower().strip()
        matches: List[str] = []

        # First use components from report if we had one, but since we don't,
        # fall back to scanning the directory if provided
        if decompiled_dir and decompiled_dir.exists():
            for comp in self.extract_components(decompiled_dir):
                if keyword in comp.lower():
                    matches.append(comp)

            # Also search strings.xml and AndroidManifest.xml
            for xml_file in decompiled_dir.rglob("*.xml"):
                try:
                    content = xml_file.read_text(encoding="utf-8", errors="ignore")
                    if keyword in content.lower():
                        matches.append(f"resource:{xml_file.name}")
                        if len(matches) > 30:
                            break
                except Exception:
                    continue

        return matches[:30]

    def _extract_strings(self, decompiled_dir: Path) -> List[str]:
        """Parse strings.xml (and other values XML) for translatable strings.

        Used to give the LLM semantic context about the app.
        """
        strings: List[str] = []
        values_dir = decompiled_dir / "res" / "values"

        if not values_dir.exists():
            return strings

        for xml_file in values_dir.glob("*.xml"):
            try:
                tree = ET.parse(xml_file)
                for elem in tree.iter():
                    if elem.tag in ("string", "string-array", "item") and elem.text:
                        text = elem.text.strip()
                        if text and len(text) < 120:  # avoid huge blobs
                            strings.append(text)
            except (ET.ParseError, OSError):
                continue

        return strings
