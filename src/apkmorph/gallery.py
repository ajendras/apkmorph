"""Curated patch template gallery.

Provides a small, high-quality set of community-tested templates.
Users can import any template with one click (CLI or UI) — the template
supplies an optimized natural-language prompt that PatchGenerator turns
into a tailored PatchPlan for the concrete APK being processed.
"""

from typing import Any, Dict, List

CURATED_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "remove_ads",
        "name": "Remove All Ads",
        "description": "Removes common ad networks (AdMob, Unity Ads, ironSource). Replaces ad containers with a thank-you message. Works on most games and free apps.",
        "prompt": "remove all ads, hide ad views and replace them with a message saying 'Ad-free experience provided by APK Morph'",
        "category": "monetization",
        "tags": ["ads", "monetization", "ui"],
        "confidence": 0.92,
    },
    {
        "id": "disable_analytics",
        "name": "Disable Analytics & Tracking",
        "description": "Turns Firebase Analytics, Adjust, AppsFlyer, Facebook and generic tracking calls into no-ops. Also disables crash reporting.",
        "prompt": "disable all analytics, tracking, crash reporting and telemetry. Make every tracking and logging call a no-op",
        "category": "privacy",
        "tags": ["privacy", "analytics", "tracking", "crash"],
        "confidence": 0.95,
    },
    {
        "id": "dark_theme",
        "name": "Force Dark Theme",
        "description": "Updates styles.xml, forces night mode on all activities and injects a dark theme overlay.",
        "prompt": "apply a consistent dark theme across the entire app by updating styles, forcing night mode and patching theme references",
        "category": "ui",
        "tags": ["theme", "ui", "customization"],
        "confidence": 0.88,
    },
    {
        "id": "remove_splash",
        "name": "Remove Splash Screen",
        "description": "Eliminates the launch/splash activity so the app starts instantly. Patches the splash handler to finish immediately.",
        "prompt": "remove the splash screen completely and launch directly into the main activity for faster startup",
        "category": "performance",
        "tags": ["splash", "performance", "ux"],
        "confidence": 0.85,
    },
    {
        "id": "change_name",
        "name": "Change App Name",
        "description": "Updates the launcher name in strings.xml and the manifest. Icon replacement can be done manually afterwards.",
        "prompt": "change the displayed app name to \"Morphed App\" everywhere it appears (strings, manifest, launcher)",
        "category": "branding",
        "tags": ["name", "branding", "strings"],
        "confidence": 0.90,
    },
]


def list_templates() -> List[Dict[str, Any]]:
    """Return the full list of curated templates (used by CLI and UI)."""
    return CURATED_TEMPLATES


def get_template_by_id(template_id: str) -> Dict[str, Any] | None:
    """Return a single template by id (case-insensitive)."""
    needle = template_id.lower().strip()
    for t in CURATED_TEMPLATES:
        if t["id"] == needle or t["id"].replace("_", "-") == needle:
            return t
    return None
