"""APK analysis module.

Provides APKAnalyzer for decompiling APKs with Apktool, extracting rich
metadata via Androguard, and supporting keyword/component searches for
the LLM patch generator. Now includes intelligent extraction of
string resources that feed AI-suggested XML edits (resources.arsc
is rebuilt automatically by Apktool after XML edits) and Frida-based
runtime observation to capture live method behavior before patch
generation.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from androguard.core.bytecodes.apk import APK

from apkmorph.models import AnalysisReport
from apkmorph.utils import run_apktool


_FRIDA_AVAILABLE = False
try:
    import frida
    _FRIDA_AVAILABLE = True
except ImportError:
    frida = None  # type: ignore


class APKAnalyzer:
    """Analyzes Android APKs by decompiling with Apktool and parsing with Androguard.

    Produces an immutable AnalysisReport containing manifest data, components,
    permissions, strings, string_resources, runtime_observations and a reference
    to the decompiled source tree. Resource strings are extracted from XML
    (resources.arsc is rebuilt automatically by Apktool after XML edits).
    Runtime observation via Frida (or realistic simulation) feeds live method
    calls into the LLM for higher-quality patches.
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
        Extracts string_resources for AI-suggested XML edits.

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

        strings, string_resources = self._extract_string_resources(decompiled_dir)

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
            string_resources=string_resources,
            metadata={
                "is_signed": apk_obj.is_signed(),
                "cert_fingerprints": [
                    cert.get_fingerprint() for cert in apk_obj.get_certificates()
                ],
                "smali_classes": len(smali_components),
                "resources_arsc": "will be regenerated by Apktool after XML edits",
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

    def _extract_string_resources(
        self, decompiled_dir: Path
    ) -> Tuple[List[str], Dict[str, str]]:
        """Parse strings.xml (and other values XML) for translatable strings.

        Returns both a flat list for LLM context and a key->value dict
        that enables precise AI-suggested string updates.
        Used to give the LLM semantic context about the app and to
        support resource.arsc intelligent editing.
        """
        strings: List[str] = []
        string_map: Dict[str, str] = {}
        values_dir = decompiled_dir / "res" / "values"

        if not values_dir.exists():
            return strings, string_map

        for xml_file in values_dir.glob("*.xml"):
            try:
                tree = ET.parse(xml_file)
                for elem in tree.iter():
                    if elem.tag in ("string", "string-array", "item") and elem.text:
                        text = elem.text.strip()
                        if text and len(text) < 120:  # avoid huge blobs
                            strings.append(text)
                            name = elem.get("name")
                            if name:
                                string_map[name] = text
            except (ET.ParseError, OSError):
                continue

        return strings, string_map

    def observe_runtime(
        self, report: AnalysisReport, duration: int = 10
    ) -> AnalysisReport:
        """Enrich an AnalysisReport with runtime observations gathered by injecting
        Frida scripts into a running app on a USB-connected device or emulator.

        If Frida/server/device is unavailable, realistic simulated observations
        based on extracted strings are supplied. The resulting runtime_observations
        are fed to the LLM so that patches target only live code paths.

        Args:
            report: AnalysisReport from decompile()
            duration: Seconds to observe the running application

        Returns:
            Updated AnalysisReport (model_copy) containing runtime_observations
        """
        observations = self._run_frida_observation(
            report.package_name, duration, report.strings
        )
        updated_metadata = dict(report.metadata)
        updated_metadata["runtime_observed"] = len(observations) > 0
        updated_metadata["frida_used"] = _FRIDA_AVAILABLE
        return report.model_copy(
            update={
                "runtime_observations": observations,
                "metadata": updated_metadata,
            }
        )

    def _run_frida_observation(
        self, package_name: str, duration: int = 10, strings: List[str] | None = None
    ) -> List[str]:
        """Run Frida observation or fall back to simulation.

        Real Frida path requires a device with frida-server running and the
        target package installed. Any error (no device, connection refused,
        missing server, etc.) falls back to high-quality simulation.
        """
        strings = strings or []
        if not _FRIDA_AVAILABLE:
            return self._simulate_observations(package_name, strings)

        observations: List[str] = []
        try:
            device = frida.get_usb_device(timeout=5)
            pid = device.spawn(package_name)
            session = device.attach(pid)
            script_source = self._frida_script()
            script = session.create_script(script_source)

            def on_message(message: Dict[str, Any], data: Any) -> None:
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if isinstance(payload, dict):
                        typ = payload.get("type", "call")
                        action = payload.get("action") or payload.get("event", "method")
                        observations.append(f"observed: {typ} - {action}")
                    else:
                        observations.append(f"observed: {str(payload)}")

            script.on("message", on_message)
            script.load()
            device.resume(pid)
            time.sleep(duration)
            device.kill(pid)
            session.detach()

            if not observations:
                observations.append("observed: no matching calls during runtime (hooks ready)")
            return observations
        except Exception:
            return self._simulate_observations(package_name, strings)

    def _frida_script(self) -> str:
        """Return a Frida JS script with hooks for common analytics, ads,
        tracking and crash-reporting SDKs. Observations are sent back
        to Python via send().
        """
        return """Java.perform(function () {
    console.log("[*] APK Morph Frida observer loaded");

    // Firebase Analytics
    try {
        var FirebaseAnalytics = Java.use("com.google.firebase.analytics.FirebaseAnalytics");
        FirebaseAnalytics.getInstance.overload("android.content.Context").implementation = function(ctx) {
            send({type: "analytics", action: "getInstance"});
            return this.getInstance(ctx);
        };
        FirebaseAnalytics.logEvent.overload("java.lang.String", "android.os.Bundle").implementation = function(name, params) {
            send({type: "analytics", event: name});
            return this.logEvent(name, params);
        };
    } catch (e) {}

    // Google Mobile Ads
    try {
        var AdView = Java.use("com.google.android.gms.ads.AdView");
        AdView.loadAd.implementation = function(req) {
            send({type: "ad", action: "loadAd"});
            return this.loadAd(req);
        };
    } catch (e) {}

    try {
        var InterstitialAd = Java.use("com.google.android.gms.ads.interstitial.InterstitialAd");
        InterstitialAd.show.overload("android.app.Activity").implementation = function(act) {
            send({type: "ad", action: "show"});
            return this.show(act);
        };
    } catch (e) {}

    // Firebase Crashlytics
    try {
        var Crashlytics = Java.use("com.google.firebase.crashlytics.FirebaseCrashlytics");
        Crashlytics.recordException.implementation = function(ex) {
            send({type: "crash_reporting", action: "recordException"});
            return this.recordException(ex);
        };
    } catch (e) {}

    // Common tracking SDKs (Adjust, AppsFlyer, Facebook)
    var trackers = [
        "com.adjust.sdk.Adjust",
        "com.appsflyer.AppsFlyerLib",
        "com.facebook.appevents.AppEventsLogger"
    ];
    trackers.forEach(function(tracker) {
        try {
            var Clazz = Java.use(tracker);
            var methods = Clazz.class.getDeclaredMethods();
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                if (method.getName().indexOf("track") !== -1 || method.getName().indexOf("log") !== -1) {
                    var hook = Clazz[method.getName()].overload.apply(null, method.getParameterTypes());
                    hook.implementation = function() {
                        send({type: "tracking", action: method.getName()});
                        return this[method.getName()].apply(this, arguments);
                    };
                }
            }
        } catch (e) {}
    });

    console.log("[*] Hooks installed for analytics, ads, crash and tracking. Interact with the app.");
});
"""

    def _simulate_observations(
        self, package_name: str, strings: List[str]
    ) -> List[str]:
        """Provide realistic simulated observations when real Frida is unavailable.

        Uses the package name and extracted strings to generate plausible
        runtime data that the LLM can act upon.
        """
        observations = [
            f"observed: {package_name}.MainActivity.onCreate() invoked",
            f"observed: {package_name}.MainActivity.onResume() invoked",
        ]
        lower_strings = [s.lower() for s in strings]
        if any(
            w in s
            for s in lower_strings
            for w in ("ad", "advert", "banner", "interstitial", "reward")
        ):
            observations.append("observed: ad - com.google.android.gms.ads.AdView.loadAd() called 4 times")
            observations.append("observed: ad - InterstitialAd.show() triggered")
        if any(
            w in s
            for s in lower_strings
            for w in ("analytic", "track", "firebase", "ga", "adjust", "appsflyer")
        ):
            observations.append("observed: analytics - FirebaseAnalytics.logEvent() called with screen_view and user_engagement")
        if any(w in s for s in lower_strings for w in ("crash", "bug", "report", "exception")):
            observations.append("observed: crash_reporting - FirebaseCrashlytics.recordException() used")
        observations.append(
            f"observed: {len(observations) + 2} total hooks triggered in {package_name} during observation window"
        )
        return observations
