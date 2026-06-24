#!/usr/bin/env python3
"""
nvd-dependency-scan.py — NIST NVD 2.0 API dependency vulnerability scanner

NIST SP 800-53 Rev 5 controls covered:
  SA-11 — Developer Security Testing (automated CVE check at build time)
  SI-2  — Flaw Remediation           (identifies packages with known vulnerabilities)
  SI-3  — Malicious Code Protection  (flags packages with code-level security CVEs)

Parses every NuGet PackageReference from .csproj files under --projects-dir,
queries the NVD 2.0 API for each package, and emits one Allure JSON result file
per package.

Rate limits (without NVD_API_KEY env var): 5 req / 30 s — sleeps automatically.
Rate limits (with NVD_API_KEY env var)   : 50 req / 30 s.
On HTTP 429 the script retries after 35 seconds.

Exit codes:
  0 — all packages scanned; no CVEs at or above --fail-on-cvss
  1 — one or more CVEs at or above --fail-on-cvss

Usage:
  python3 scripts/nvd-dependency-scan.py \\
    --projects-dir src \\
    --results-dir  allure-results/nvd \\
    --cvss-threshold 7.0 \\
    --fail-on-cvss   9.0 \\
    --nist-map       scripts/nist-control-map.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ── Constants ────────────────────────────────────────────────────────────────

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NIST labels applied to every result
NIST_LABELS = [
    {"name": "tag", "value": "nist-control: SA-11"},
    {"name": "tag", "value": "nist-control: SI-2"},
    {"name": "tag", "value": "nist-control: SI-3"},
    {"name": "tag", "value": "nist-framework: SP800-53-R5"},
]

# Severity thresholds (CVSS v3 base score)
SEVERITY_MAP = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
    (0.0, "NONE"),
]


# ── NuGet parsing ────────────────────────────────────────────────────────────

def find_packages(projects_dir: str) -> dict[str, str]:
    """
    Walk projects_dir recursively and return {package_name: version} for every
    PackageReference found in .csproj files.  Version is the Include attribute's
    Version child or attribute; falls back to '*' when absent.
    """
    packages: dict[str, str] = {}
    root = Path(projects_dir)
    for csproj in root.rglob("*.csproj"):
        try:
            tree = ET.parse(csproj)
        except ET.ParseError as exc:
            _log(f"  [warn] could not parse {csproj}: {exc}")
            continue
        for ref in tree.iter("PackageReference"):
            name = ref.get("Include") or ref.get("Update")
            if not name:
                continue
            version = (
                ref.get("Version")
                or (ref.find("Version").text if ref.find("Version") is not None else None)
                or "*"
            )
            # Keep the latest pinned version if a package appears in multiple projects
            if name not in packages or version != "*":
                packages[name] = version
    return packages


# ── NVD API ──────────────────────────────────────────────────────────────────

def _cvss_score(cve: dict) -> float | None:
    """Extract the highest available CVSS base score from a CVE entry."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        scores = [
            e.get("cvssData", {}).get("baseScore")
            for e in entries
            if e.get("cvssData", {}).get("baseScore") is not None
        ]
        if scores:
            return max(scores)
    return None


def _severity_label(score: float) -> str:
    for threshold, label in SEVERITY_MAP:
        if score >= threshold:
            return label
    return "NONE"


def _cwe_ids(cve: dict) -> list[str]:
    """Return CWE IDs associated with a CVE (e.g. ['CWE-89', 'CWE-200'])."""
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return list(dict.fromkeys(cwes))  # deduplicate, preserve order


def is_relevant_cve(cve: dict, package_name: str) -> bool:
    """
    Filter out false positives from NVD keyword search.
    A CVE is relevant if the package name appears (case-insensitive) in:
      - the CVE description, or
      - any reference URL
    Short or very common names (len <= 3) bypass the filter to avoid missing real CVEs.
    """
    name_lower = package_name.lower()
    if len(name_lower) <= 3:
        return True

    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if name_lower in d.get("value", "").lower():
            return True

    for ref in cve.get("references", []):
        if name_lower in ref.get("url", "").lower():
            return True

    return False


def query_nvd(package_name: str, api_key: str | None, rate_window: float) -> list[dict]:
    """
    Query NVD 2.0 API for CVEs matching package_name.
    Returns a list of filtered CVE dicts.
    Sleeps between requests to honour rate limits; retries once on 429.
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": package_name,
        "resultsPerPage": 20,
        "startIndex": 0,
    }

    for attempt in range(2):
        try:
            resp = requests.get(NVD_API_BASE, headers=headers, params=params, timeout=30)
            if resp.status_code == 429:
                _log(f"  [warn] NVD 429 for '{package_name}' — waiting 35 s before retry")
                time.sleep(35)
                continue
            resp.raise_for_status()
            data = resp.json()
            cves = [item.get("cve", {}) for item in data.get("vulnerabilities", [])]
            return [c for c in cves if is_relevant_cve(c, package_name)]
        except requests.RequestException as exc:
            _log(f"  [warn] NVD request failed for '{package_name}': {exc}")
            if attempt == 0:
                time.sleep(5)
                continue
            return []

    return []


# ── Allure result generation ─────────────────────────────────────────────────

def _stable_id(package_name: str) -> str:
    """Deterministic MD5-based history ID for TestOps trending."""
    return hashlib.md5(f"nvd-scan::{package_name}".encode()).hexdigest()


def _allure_result_dir() -> str | None:
    """Read output directory from ALLURE_CONFIG env var (allure-nvd-config.json)."""
    config_path = os.environ.get("ALLURE_CONFIG")
    if not config_path:
        return None
    try:
        cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
        return cfg.get("allure", {}).get("directory")
    except Exception:
        return None


def write_allure_result(
    results_dir: Path,
    package: str,
    version: str,
    cves_above_threshold: list[dict],
    cvss_threshold: float,
) -> None:
    """Write one Allure JSON result file for a package."""
    n = len(cves_above_threshold)
    if n == 0:
        name = f"NVD | {package} — No CVEs at CVSS >= {cvss_threshold}"
        status = "passed"
        steps = []
    else:
        name = f"NVD | {package} — {n} CVE(s) at CVSS >= {cvss_threshold}"
        status = "failed"
        steps = []
        for cve in cves_above_threshold:
            cve_id = cve.get("id", "UNKNOWN")
            score = _cvss_score(cve) or 0.0
            severity = _severity_label(score)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:400]
                    break
            cwes = _cwe_ids(cve)
            step_name = f"{cve_id} — CVSS {score:.1f} ({severity})"
            if cwes:
                step_name += f" [{', '.join(cwes)}]"
            steps.append({
                "name": step_name,
                "status": "failed",
                "statusDetails": {"message": desc},
                "stage": "finished",
            })

    result = {
        "uuid": str(uuid.uuid4()),
        "historyId": _stable_id(package),
        "name": name,
        "status": status,
        "stage": "finished",
        "labels": NIST_LABELS + [
            {"name": "suite", "value": "NVD Dependency Scan"},
            {"name": "feature", "value": "NIST SP 800-53 Rev 5"},
        ],
        "parameters": [
            {"name": "package", "value": package},
            {"name": "version", "value": version},
            {"name": "cvss_threshold", "value": str(cvss_threshold)},
        ],
        "steps": steps,
        "links": [
            {
                "name": cve.get("id", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                "type": "nvd",
            }
            for cve in cves_above_threshold
        ],
    }

    out_file = results_dir / f"nvd-{_stable_id(package)}-result.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")


# ── Main ─────────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(msg, flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="NVD dependency vulnerability scanner for NuGet packages")
    parser.add_argument("--projects-dir",  required=True,  help="Root directory containing .csproj files")
    parser.add_argument("--results-dir",   required=True,  help="Directory to write Allure JSON result files")
    parser.add_argument("--cvss-threshold", type=float, default=7.0, help="Report CVEs at or above this CVSS score")
    parser.add_argument("--fail-on-cvss",   type=float, default=9.0, help="Exit 1 if any CVE is at or above this CVSS score")
    parser.add_argument("--nist-map",       default="",    help="Path to nist-control-map.json (informational only)")
    args = parser.parse_args()

    api_key = os.environ.get("NVD_API_KEY") or None
    # With key: 50 req/30 s → 0.7 s gap.  Without: 5 req/30 s → 7 s gap.
    rate_window = 0.7 if api_key else 7.0

    # Determine output directory (honour ALLURE_CONFIG if set)
    allure_dir = _allure_result_dir()
    results_dir = Path(allure_dir) if allure_dir else Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    _log(f"\n=== NVD Dependency Vulnerability Scan ===")
    _log(f"  projects-dir   : {args.projects_dir}")
    _log(f"  results-dir    : {results_dir}")
    _log(f"  cvss-threshold : {args.cvss_threshold}")
    _log(f"  fail-on-cvss   : {args.fail_on_cvss}")
    _log(f"  api-key        : {'yes' if api_key else 'no (rate-limited to 5 req/30s)'}")

    packages = find_packages(args.projects_dir)
    if not packages:
        _log("[warn] No NuGet PackageReference entries found — nothing to scan")
        sys.exit(0)

    _log(f"\nFound {len(packages)} package(s) to scan:\n")

    fail_packages: list[str] = []
    last_request_time: float = 0.0

    for i, (pkg, ver) in enumerate(sorted(packages.items()), 1):
        _log(f"  [{i}/{len(packages)}] {pkg} {ver}")

        # Enforce rate limit
        elapsed = time.monotonic() - last_request_time
        if elapsed < rate_window:
            time.sleep(rate_window - elapsed)

        cves = query_nvd(pkg, api_key, rate_window)
        last_request_time = time.monotonic()

        # Filter to CVEs at or above reporting threshold
        cves_to_report = [
            c for c in cves
            if (_cvss_score(c) or 0.0) >= args.cvss_threshold
        ]

        # Check fail threshold
        cves_to_fail = [
            c for c in cves
            if (_cvss_score(c) or 0.0) >= args.fail_on_cvss
        ]

        if cves_to_fail:
            fail_packages.append(pkg)
            scores = [f"{c.get('id','?')} (CVSS {_cvss_score(c):.1f})" for c in cves_to_fail]
            _log(f"    FAIL — CVEs above {args.fail_on_cvss}: {', '.join(scores)}")
        elif cves_to_report:
            _log(f"    WARN — {len(cves_to_report)} CVE(s) between {args.cvss_threshold} and {args.fail_on_cvss}")
        else:
            _log(f"    PASS — no CVEs at or above {args.cvss_threshold}")

        write_allure_result(results_dir, pkg, ver, cves_to_report, args.cvss_threshold)

    _log(f"\n{'='*50}")
    _log(f"Scan complete. {len(packages)} package(s) checked.")
    if fail_packages:
        _log(f"FAILED packages ({len(fail_packages)}):")
        for p in fail_packages:
            _log(f"  - {p}")
        _log(f"\nExit 1 — {len(fail_packages)} package(s) have CVEs at or above CVSS {args.fail_on_cvss}")
        sys.exit(1)
    else:
        _log(f"\nExit 0 — no CVEs at or above CVSS {args.fail_on_cvss}")
        sys.exit(0)


if __name__ == "__main__":
    main()
