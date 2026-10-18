"""Core scanning logic: parse deps, fetch npm registry metadata, score lure signals."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

AI_LURE_RE = re.compile(
    r"(nebula|llm|gpt|open[-_]?ai|anthropic|claude|gemini|chat[-_]?gpt|"
    r"copilot|agent[-_]?sdk|ai[-_]?sdk|ai[-_]?agent|llm[-_]?ops|"
    r"prompt[-_]?engine)",
    re.IGNORECASE,
)

INSTALL_SCRIPTS = {"preinstall", "install", "postinstall"}
NEW_PACKAGE_DAYS = 14
LOW_DOWNLOAD_THRESHOLD = 1000

REGISTRY_URL = "https://registry.npmjs.org/{name}"
DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week/{name}"


def parse_deps(path: str | Path) -> list[tuple[str, str]]:
    """Return [(name, version_spec)] from a package.json or package-lock.json."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    deps: list[tuple[str, str]] = []

    packages = data.get("packages")
    if isinstance(packages, dict):  # package-lock v2/v3
        for key, val in packages.items():
            if key.startswith("node_modules/") and isinstance(val, dict):
                name = key[len("node_modules/"):]
                deps.append((name, str(val.get("version", ""))))
    if isinstance(data.get("dependencies"), dict):  # package-lock v1 or package.json
        for name, spec in data["dependencies"].items():
            if isinstance(spec, dict):
                deps.append((name, str(spec.get("version", ""))))
            else:
                deps.append((name, str(spec)))
    for field in ("devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in data.get(field, {}).items():
            deps.append((name, str(spec)))

    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for name, ver in deps:
        if name not in seen:
            seen.add(name)
            out.append((name, ver))
    return out


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def fetch_metadata(name: str, offline: dict | None = None) -> dict:
    """Fetch registry metadata for a package.

    Returns a normalized dict:
      {name, latest_version, latest_published (datetime|None), weekly_downloads (int|None),
       install_scripts (list[str]), maintainers (int)}
    Raises RuntimeError if the registry cannot be reached.
    """
    if offline is not None:
        entry = offline.get(name)
        if entry is None:
            raise RuntimeError(f"offline fixture has no entry for {name!r}")
        pub = entry.get("latest_published")
        return {
            "name": name,
            "latest_version": entry.get("latest_version", ""),
            "latest_published": _parse_iso(pub) if pub else None,
            "weekly_downloads": entry.get("weekly_downloads"),
            "install_scripts": list(entry.get("install_scripts", [])),
            "maintainers": int(entry.get("maintainers", 0)),
        }

    try:
        packument = requests.get(REGISTRY_URL.format(name=name), timeout=20).json()
        latest = packument.get("dist-tags", {}).get("latest", "")
        times = packument.get("time", {})
        published_raw = times.get(latest)
        scripts = packument.get("versions", {}).get(latest, {}).get("scripts", {}) or {}
        maintainers = packument.get("maintainers", []) or []
        dl = requests.get(DOWNLOADS_URL.format(name=name), timeout=20).json()
    except requests.RequestException as exc:  # pragma: no cover - network failure path
        raise RuntimeError(f"registry request failed for {name!r}: {exc}") from exc

    return {
        "name": name,
        "latest_version": latest,
        "latest_published": _parse_iso(published_raw) if published_raw else None,
        "weekly_downloads": dl.get("downloads"),
        "install_scripts": sorted(set(scripts) & INSTALL_SCRIPTS),
        "maintainers": len(maintainers),
    }


def score_package(meta: dict, now: datetime | None = None) -> dict:
    """Score a package's metadata. Returns {name, severity, signals:[{signal, evidence}]}."""
    now = now or datetime.now(timezone.utc)
    name = meta["name"]
    signals: list[dict] = []

    m = AI_LURE_RE.search(name)
    if m:
        signals.append({
            "signal": "ai_lure_name",
            "evidence": f"package name matches AI-lure pattern (matched {m.group(0)!r})",
        })

    pub = meta.get("latest_published")
    if pub is not None:
        age_days = (now - pub).days
        if age_days < NEW_PACKAGE_DAYS:
            signals.append({
                "signal": "published_recently",
                "evidence": (
                    f"latest version {meta.get('latest_version')} published "
                    f"{age_days} day(s) ago (< {NEW_PACKAGE_DAYS} days)"
                ),
            })

    downloads = meta.get("weekly_downloads")
    if downloads is not None and downloads < LOW_DOWNLOAD_THRESHOLD:
        signals.append({
            "signal": "low_downloads",
            "evidence": f"{downloads} downloads in the last week (< {LOW_DOWNLOAD_THRESHOLD})",
        })

    hooks = meta.get("install_scripts") or []
    if hooks:
        signals.append({
            "signal": "install_scripts",
            "evidence": f"declares install hook(s): {', '.join(hooks)} (runs code at install time)",
        })

    n = len(signals)
    severity = "HIGH" if n >= 4 else "MEDIUM" if n >= 2 else "LOW" if n == 1 else "CLEAN"
    return {"name": name, "severity": severity, "signals": signals}


def scan_deps(deps: list[tuple[str, str]], offline: dict | None = None) -> list[dict]:
    results = []
    for name, _ver in deps:
        try:
            meta = fetch_metadata(name, offline=offline)
        except RuntimeError as exc:
            results.append({"name": name, "severity": "UNKNOWN", "signals": [],
                            "error": str(exc)})
            continue
        results.append(score_package(meta))
    return results


def format_report(results: list[dict]) -> str:
    lines = []
    lines.append(f"{'PACKAGE':<35} {'SEVERITY':<9} EVIDENCE")
    lines.append("-" * 100)
    for r in results:
        first = True
        if r.get("error"):
            lines.append(f"{r['name']:<35} {'UNKNOWN':<9} {r['error']}")
            continue
        if r["severity"] == "CLEAN":
            lines.append(f"{r['name']:<35} {'CLEAN':<9} no lure signals")
            continue
        for s in r["signals"]:
            tag = f"{r['name']:<35} {r['severity']:<9} " if first else " " * 46
            lines.append(f"{tag}{s['signal']}: {s['evidence']}")
            first = False
    highs = sum(1 for r in results if r.get("severity") == "HIGH")
    lines.append("-" * 100)
    lines.append(f"scanned {len(results)} package(s); {highs} HIGH severity")
    return "\n".join(lines)
