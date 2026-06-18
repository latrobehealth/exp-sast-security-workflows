#!/usr/bin/env python3
"""
allure-testops-sync.py — Allure TestOps OWASP Security Scan Sync

Idempotently syncs CodeQL SARIF scan results to Allure TestOps:
  Project    — found by name; created if absent
  Test cases — 10 OWASP classes; found by name; created if absent
  Test plan  — per version/branch; found by name; created if absent
  Launch     — created fresh per GitHub Actions run; linked to test plan

Pass/fail logic:
  application scan  PASS = zero production findings for the rule
                    FAIL = >=1 finding in production code
                          (excluded: OwaspV2ValidationController, SastCanaryController paths)
  canary scan       PASS = rule fired in CodeQL analysis
                    FAIL = rule did not fire (scanner regression)

Never fails CI — uses continue-on-error in the calling workflow step.
Allure sync failure is logged as a step summary warning and exits 0.

Required environment variables:
  ALLURE_TESTOPS_URL         Base URL, e.g. https://allure.example.com
  ALLURE_TESTOPS_API_TOKEN   Allure TestOps API token

Usage:
  python3 allure-testops-sync.py \\
    --sarif      sarif-results/csharp.sarif \\
    --project    exp-membership-service \\
    --version    develop \\
    --scan-type  application \\
    --run-id     12345 \\
    --run-url    https://github.com/org/repo/actions/runs/12345
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ── OWASP / CodeQL test case catalogue ───────────────────────────────────────
# Stable catalogue — externalId never changes; name is used as the idempotency
# key in Allure TestOps (queried by exact match on GET /api/testcase).

OWASP_TEST_CASES: list[dict] = [
    {
        "externalId":    "codeql-cs-path-injection",
        "name":          "A01 — Path Traversal (cs/path-injection)",
        "owasp":         "A01:2025",
        "owaspCategory": "Broken Access Control",
        "rule":          "cs/path-injection",
        "severity":      "critical",
        "tags":          ["OWASP-A01", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
        "description":   (
            "CWE-22: User-controlled file path reaches File.ReadAllText / File.Open "
            "without sanitisation. Allows an attacker to read arbitrary files from the server."
        ),
    },
    {
        "externalId":    "codeql-cs-missing-access-control",
        "name":          "A01 — Missing Access Control (cs/web/missing-function-level-access-control)",
        "owasp":         "A01:2025",
        "owaspCategory": "Broken Access Control",
        "rule":          "cs/web/missing-function-level-access-control",
        "severity":      "critical",
        "tags":          ["OWASP-A01", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
        "description":   (
            "CWE-284: HTTP DELETE (or other mutating) action on a controller with no "
            "[Authorize] attribute — any anonymous caller can invoke it."
        ),
    },
    {
        "externalId":    "codeql-cs-weak-crypto",
        "name":          "A02 — Weak Cryptographic Algorithm (cs/use-of-broken-or-weak-cryptographic-algorithm)",
        "owasp":         "A02:2025",
        "owaspCategory": "Cryptographic Failures",
        "rule":          "cs/use-of-broken-or-weak-cryptographic-algorithm",
        "severity":      "high",
        "tags":          ["OWASP-A02", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A02_2025-Cryptographic_Failures/",
        "description":   (
            "CWE-327: Use of MD5 or SHA1 hash algorithms. "
            "These are cryptographically broken and unsuitable for password hashing or "
            "integrity verification."
        ),
    },
    {
        "externalId":    "codeql-cs-hardcoded-credentials",
        "name":          "A02 — Hardcoded Credentials (cs/hardcoded-credentials)",
        "owasp":         "A02:2025",
        "owaspCategory": "Cryptographic Failures",
        "rule":          "cs/hardcoded-credentials",
        "severity":      "critical",
        "tags":          ["OWASP-A02", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A02_2025-Cryptographic_Failures/",
        "description":   (
            "CWE-798: Literal string password passed to a network authentication API "
            "(e.g. NetworkCredential, SqlConnection). Credentials exposed in source code."
        ),
    },
    {
        "externalId":    "codeql-cs-sql-injection",
        "name":          "A03 — SQL Injection (cs/sql-injection)",
        "owasp":         "A03:2025",
        "owaspCategory": "Injection",
        "rule":          "cs/sql-injection",
        "severity":      "critical",
        "tags":          ["OWASP-A03", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A03_2025-Injection/",
        "description":   (
            "CWE-89: User-controlled input flows into a raw SQL string (EF Core "
            "FromSqlRaw, ADO.NET ExecuteNonQuery). Allows database enumeration or destruction."
        ),
    },
    {
        "externalId":    "codeql-cs-command-injection",
        "name":          "A03 — OS Command Injection (cs/command-line-injection)",
        "owasp":         "A03:2025",
        "owaspCategory": "Injection",
        "rule":          "cs/command-line-injection",
        "severity":      "critical",
        "tags":          ["OWASP-A03", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A03_2025-Injection/",
        "description":   (
            "CWE-78: User-controlled input in ProcessStartInfo.Arguments. "
            "Allows remote code execution by injecting shell metacharacters."
        ),
    },
    {
        "externalId":    "codeql-cs-xss",
        "name":          "A03 — Cross-Site Scripting (cs/web/xss)",
        "owasp":         "A03:2025",
        "owaspCategory": "Injection",
        "rule":          "cs/web/xss",
        "severity":      "high",
        "tags":          ["OWASP-A03", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A03_2025-Injection/",
        "description":   (
            "CWE-79: Reflected XSS — user-controlled input rendered in an HTML response "
            "(text/html) without HTML-encoding. Allows session hijacking or phishing."
        ),
    },
    {
        "externalId":    "codeql-cs-unvalidated-redirect",
        "name":          "A05 — Unvalidated Redirect (cs/web/unvalidated-url-redirect)",
        "owasp":         "A05:2025",
        "owaspCategory": "Security Misconfiguration",
        "rule":          "cs/web/unvalidated-url-redirect",
        "severity":      "medium",
        "tags":          ["OWASP-A05", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A05_2025-Security_Misconfiguration/",
        "description":   (
            "CWE-601: Open redirect — user-controlled URL passed to Redirect() without "
            "validation. Allows phishing via trusted domain links."
        ),
    },
    {
        "externalId":    "codeql-cs-log-forging",
        "name":          "A07/A09 — Log Forging (cs/log-forging)",
        "owasp":         "A07:2025",
        "owaspCategory": "Identification and Authentication Failures",
        "rule":          "cs/log-forging",
        "severity":      "high",
        "tags":          ["OWASP-A07", "OWASP-A09", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A07_2025-Identification_and_Authentication_Failures/",
        "description":   (
            "CWE-117: Unsanitised HTTP input (credentials, paths, auth tokens) written to "
            "structured logs. Enables log injection attacks and sensitive data leakage."
        ),
    },
    {
        "externalId":    "codeql-cs-xpath-injection",
        "name":          "A08 — XPath Injection (cs/xml-injection)",
        "owasp":         "A08:2025",
        "owaspCategory": "Software and Data Integrity Failures",
        "rule":          "cs/xml-injection",
        "severity":      "high",
        "tags":          ["OWASP-A08", "CodeQL", "SAST", "security-extended"],
        "owaspUrl":      "https://owasp.org/Top10/A08_2025-Software_and_Data_Integrity_Failures/",
        "description":   (
            "CWE-643: User-controlled input concatenated into an XPath expression "
            "(XmlDocument.SelectSingleNode). Allows bypassing auth or data exfiltration. "
            "Note: cs/xml-injection = XPath injection, not XXE."
        ),
    },
]

EXPECTED_RULE_IDS: set[str] = {tc["rule"] for tc in OWASP_TEST_CASES}

# File path substrings that indicate test/validation-only code.
# Findings in these files are excluded from the application scan pass/fail count.
EXCLUDED_PATH_PATTERNS: tuple[str, ...] = (
    "OwaspV2ValidationController",
    "OwaspValidationController",
    "SastCanaryController",
    "_owasp-v2",
    "_sast-canary",
    "sast-canary-src",
    "canary/Controllers",
    "canary\\Controllers",
)


# ── Allure TestOps REST client ────────────────────────────────────────────────

class AllureClient:
    """Thin wrapper around the Allure TestOps REST API."""

    def __init__(self, base_url: str, api_token: str) -> None:
        self.base = base_url.rstrip("/")
        self._s = requests.Session()
        self._s.headers.update({
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })
        jwt = self._exchange_token(api_token)
        self._s.headers.update({"Authorization": f"Bearer {jwt}"})

    def _exchange_token(self, api_token: str) -> str:
        """Exchange an Allure API token for a short-lived JWT Bearer token."""
        resp = requests.post(
            f"{self.base}/api/uaa/oauth/token",
            data={"grant_type": "apitoken", "scope": "openid", "token": api_token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def get(self, path: str, **params) -> dict | list:
        resp = self._s.get(f"{self.base}{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, body: dict | None = None) -> dict:
        resp = self._s.post(f"{self.base}{path}", json=body, timeout=30)
        resp.raise_for_status()
        return resp.json() if resp.text.strip() else {}

    def patch(self, path: str, body: dict) -> dict:
        resp = self._s.patch(f"{self.base}{path}", json=body, timeout=30)
        resp.raise_for_status()
        return resp.json() if resp.text.strip() else {}


# ── Idempotent entity helpers ─────────────────────────────────────────────────

def get_or_create_project(client: AllureClient, name: str) -> int:
    """Return the numeric project ID, creating the project if it does not exist."""
    results = client.get("/api/project/suggest", name=name)
    items = results if isinstance(results, list) else results.get("content", [])
    for p in items:
        if p.get("name", "").lower() == name.lower():
            _log(f"  project found: '{name}' (id={p['id']})")
            return p["id"]

    _log(f"  project not found — attempting to create '{name}' ...")
    try:
        project = client.post("/api/project", {"name": name})
        _log(f"  project created: id={project['id']}")
        return project["id"]
    except Exception as e:
        raise RuntimeError(
            f"Project '{name}' not found and could not be created ({e}). "
            "Create it in the Allure TestOps portal and re-run."
        ) from e


def _paginate(client: AllureClient, path: str, **params) -> list[dict]:
    """Fetch all pages from a paginated endpoint."""
    items: list[dict] = []
    page = 0
    while True:
        resp = client.get(path, page=page, size=100, **params)
        batch = resp.get("content", [])
        items.extend(batch)
        if resp.get("last", True) or not batch:
            break
        page += 1
    return items


def get_or_create_test_cases(
    client: AllureClient, project_id: int
) -> dict[str, int]:
    """
    Return mapping externalId -> Allure test case ID.
    Missing test cases are created; existing ones (matched by name) are reused.
    """
    existing = _paginate(client, "/api/testcase", projectId=project_id)
    by_name: dict[str, int] = {tc["name"]: tc["id"] for tc in existing}

    result: dict[str, int] = {}
    for defn in OWASP_TEST_CASES:
        if defn["name"] in by_name:
            tc_id = by_name[defn["name"]]
            _log(f"  test case exists: '{defn['name'][:60]}' (id={tc_id})")
        else:
            _log(f"  creating test case: '{defn['name'][:60]}' ...")
            tc = client.post("/api/testcase", {
                "projectId":   project_id,
                "name":        defn["name"],
                "description": defn["description"],
            })
            tc_id = tc["id"]
            _log(f"    created id={tc_id}")
            _add_tags(client, project_id, tc_id, defn["tags"] + [defn["owasp"]])
        result[defn["externalId"]] = tc_id

    return result


def _add_tags(
    client: AllureClient,
    project_id: int,
    tc_id: int,
    tags: list[str],
) -> None:
    """Add tags to a test case via the confirmed bulk tag endpoint (idempotent)."""
    try:
        client.post("/api/v2/test-case/bulk/tag/add", {
            "selection": {
                "projectId":        project_id,
                "testCasesInclude": [tc_id],
                "inverted":         False,
            },
            "tags": [{"name": t} for t in tags],
        })
    except Exception as e:
        _log(f"    [warn] tag-add failed (non-fatal): {e}")


def get_or_create_test_plan(
    client: AllureClient, project_id: int, plan_name: str
) -> int:
    """Return the test plan ID, creating it if it does not exist."""
    plans = _paginate(client, "/api/testplan", projectId=project_id)
    for p in plans:
        if p.get("name") == plan_name:
            _log(f"  test plan found: '{plan_name}' (id={p['id']})")
            return p["id"]

    _log(f"  creating test plan: '{plan_name}' ...")
    plan = client.post("/api/testplan", {"projectId": project_id, "name": plan_name})
    _log(f"  test plan created: id={plan['id']}")
    return plan["id"]


def link_cases_to_plan(
    client: AllureClient, plan_id: int, tc_ids: list[int]
) -> None:
    """Attach test cases to a test plan. Tries several known endpoint shapes."""
    attempts = [
        lambda: client.post(f"/api/testplan/{plan_id}/test-cases", {"testCasesIds": tc_ids}),
        lambda: client.post(f"/api/testplan/{plan_id}/test-cases", {"ids": tc_ids}),
        lambda: client.post(f"/api/v2/testplan/{plan_id}/test-cases", {"testCasesIds": tc_ids}),
        lambda: client.patch(f"/api/testplan/{plan_id}", {"testCasesIds": tc_ids}),
    ]
    for attempt in attempts:
        try:
            attempt()
            _log(f"  linked {len(tc_ids)} test cases to plan {plan_id}")
            return
        except Exception:
            pass
    _log("  [warn] could not link test cases to test plan — link manually in the portal")


# ── SARIF parsing ─────────────────────────────────────────────────────────────

def parse_application_scan(sarif_path: str) -> dict[str, list[dict]]:
    """
    Return rule_id -> list of production findings.
    Findings from EXCLUDED_PATH_PATTERNS are omitted (they are test/validation code).
    """
    with open(sarif_path, encoding="utf-8") as fh:
        sarif = json.load(fh)

    findings: dict[str, list[dict]] = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            if rule_id not in EXPECTED_RULE_IDS:
                continue

            locations = result.get("locations", [])
            excluded = any(
                any(pat in loc.get("physicalLocation", {})
                                .get("artifactLocation", {})
                                .get("uri", "")
                    for pat in EXCLUDED_PATH_PATTERNS)
                for loc in locations
            )
            if excluded:
                continue

            loc0 = locations[0] if locations else {}
            phys = loc0.get("physicalLocation", {})
            uri  = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)
            msg  = result.get("message", {}).get("text", "")

            findings.setdefault(rule_id, []).append(
                {"file": uri, "line": line, "message": msg}
            )

    return findings


def parse_canary_scan(sarif_path: str) -> set[str]:
    """Return the set of CodeQL rule IDs that fired in the canary SARIF."""
    with open(sarif_path, encoding="utf-8") as fh:
        sarif = json.load(fh)

    fired: set[str] = set()
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rid = result.get("ruleId", "")
            if rid:
                fired.add(rid)
    return fired


# ── Allure 2 result file generation ──────────────────────────────────────────

def _make_result(
    tc_def: dict,
    status: str,
    message: str,
    trace: str = "",
    run_url: str = "",
) -> dict:
    now_ms = int(time.time() * 1000)
    return {
        "uuid":               str(uuid.uuid4()),
        "historyId":          tc_def["externalId"],
        "testCaseExternalId": tc_def["externalId"],
        "fullName":           f"owasp.sast.{tc_def['externalId']}",
        "name":               tc_def["name"],
        "description":        tc_def["description"],
        "status":             status,
        "statusDetails":      {"message": message, "trace": trace},
        "start":              now_ms - 1000,
        "stop":               now_ms,
        "labels": [
            {"name": "suite",    "value": f"{tc_def['owasp']} {tc_def['owaspCategory']}"},
            {"name": "severity", "value": tc_def["severity"]},
            *[{"name": "tag", "value": t} for t in tc_def["tags"]],
        ],
        "links": [
            {"name": f"OWASP {tc_def['owasp']}",
             "url":  tc_def["owaspUrl"],
             "type": "issue"},
            *([{"name": "GitHub Actions Run", "url": run_url, "type": "tms"}]
              if run_url else []),
        ],
        "parameters":  [],
        "attachments": [],
        "steps":       [],
    }


def generate_application_results(
    findings: dict[str, list[dict]], run_url: str
) -> list[dict]:
    out = []
    for tc_def in OWASP_TEST_CASES:
        hits = findings.get(tc_def["rule"], [])
        if hits:
            f0 = hits[0]
            message = (
                f"FAIL: {len(hits)} production finding(s) — "
                f"first at {f0['file']}:{f0['line']}: {f0['message']}"
            )
            trace  = "\n".join(
                f"{f['file']}:{f['line']}: {f['message']}" for f in hits
            )
            status = "failed"
        else:
            message = f"PASS: No {tc_def['rule']} findings in production code."
            trace   = ""
            status  = "passed"
        out.append(_make_result(tc_def, status, message, trace, run_url))
    return out


def generate_canary_results(fired: set[str], run_url: str) -> list[dict]:
    out = []
    for tc_def in OWASP_TEST_CASES:
        rule = tc_def["rule"]
        if rule in fired:
            message = f"PASS: CodeQL rule `{rule}` fired — scanner coverage confirmed."
            trace   = ""
            status  = "passed"
        else:
            message = f"FAIL: CodeQL rule `{rule}` did NOT fire — possible scanner regression."
            trace   = (
                "The canary pattern for this rule may be misconfigured, or the rule "
                "was removed from the security-extended query suite."
            )
            status  = "failed"
        out.append(_make_result(tc_def, status, message, trace, run_url))
    return out


# ── Launch management ─────────────────────────────────────────────────────────

def create_launch(
    client: AllureClient,
    project_id: int,
    name: str,
    description: str,
) -> int:
    launch = client.post("/api/launch", {
        "projectId":   project_id,
        "name":        name,
        "description": description,
    })
    return launch["id"]


def upload_results_to_launch(
    client: AllureClient,
    launch_id: int,
    result_files: list[Path],
    project_id: int = 0,
    launch_name: str = "",
) -> bool:
    """
    Upload Allure 2 JSON result files to an open launch.
    Tries two endpoint shapes — gracefully returns False on failure.
    """
    if not result_files:
        return False

    # Approach 1: JSON body with inline results array
    try:
        payload = [json.loads(f.read_text(encoding="utf-8")) for f in result_files]
        client.post(f"/api/launch/{launch_id}/upload", {"results": payload})
        _log(f"  uploaded {len(result_files)} result(s) via /api/launch/{launch_id}/upload")
        return True
    except Exception as e1:
        _log(f"  [warn] JSON upload failed: {e1}")

    # Approach 2: multipart /api/rs/launch/upload (community-documented path)
    try:
        auth_header = client._s.headers.get("Authorization", "")
        info = json.dumps({
            "id":        launch_id,
            "name":      launch_name or f"launch-{launch_id}",
            "projectId": project_id or None,
        })
        files: list = [("info", (None, info, "application/json"))]
        for f in result_files:
            files.append(("results", (f.name, f.read_bytes(), "application/json")))
        resp = requests.post(
            f"{client.base}/api/rs/launch/upload",
            files=files,
            headers={"Authorization": auth_header},
            timeout=60,
        )
        if resp.status_code < 300:
            _log(f"  uploaded {len(result_files)} result(s) via /api/rs/launch/upload")
            return True
        _log(f"  [warn] multipart upload returned HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e2:
        _log(f"  [warn] multipart upload failed: {e2}")

    return False


def link_launch_to_plan(
    client: AllureClient, launch_id: int, plan_id: int
) -> None:
    """Attach a launch to a test plan (best-effort, two endpoint shapes tried)."""
    for attempt in (
        lambda: client.patch(f"/api/launch/{launch_id}", {"testPlanId": plan_id}),
        lambda: client.post(f"/api/testplan/{plan_id}/launch/{launch_id}"),
    ):
        try:
            attempt()
            _log(f"  launch {launch_id} linked to test plan {plan_id}")
            return
        except Exception:
            pass
    _log(f"  [warn] could not link launch {launch_id} to test plan {plan_id}")


def close_launch(client: AllureClient, launch_id: int) -> None:
    try:
        client.post(f"/api/launch/{launch_id}/close")
        _log(f"  launch {launch_id} closed")
    except Exception as e:
        _log(f"  [warn] close launch failed: {e}")


# ── GitHub step summary ───────────────────────────────────────────────────────

def write_step_summary(
    scan_type: str,
    project: str,
    version: str,
    plan_name: str,
    launch_id: int | None,
    results: list[dict],
    upload_ok: bool,
    base_url: str,
) -> None:
    passed = sum(1 for r in results if r["status"] == "passed")
    total  = len(results)
    icon   = "✅" if passed == total else "❌"
    label  = "Application Security Scan" if scan_type == "application" else "SAST Canary Coverage"

    lines = [
        f"## {icon} Allure TestOps — {label}",
        f"> **Project**: `{project}` &nbsp;|&nbsp; "
        f"**Version**: `{version}` &nbsp;|&nbsp; "
        f"**Plan**: {plan_name}",
        "",
        f"**{passed}/{total} checks {'passed' if passed == total else 'passed (failures above)'}**",
        "",
        "| OWASP | Test Case | Status |",
        "|---|---|---|",
    ]
    for r in results:
        status_cell = "✅ Pass" if r["status"] == "passed" else "❌ Fail"
        lines.append(f"| — | {r['name']} | {status_cell} |")

    if not upload_ok:
        lines += [
            "",
            "> ⚠️ Result files could not be uploaded to Allure TestOps. "
            "Test cases and test plan were created/verified. "
            "Upload manually using `allurectl upload` if required.",
        ]

    if launch_id:
        lines += ["", f"> 🔗 [View launch in Allure TestOps]({base_url}/launch/{launch_id})"]

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n\n")

    print("\n".join(lines))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(msg, flush=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Sync CodeQL SARIF results to Allure TestOps")
    p.add_argument("--sarif",       required=True,
                   help="Path to the CodeQL SARIF file")
    p.add_argument("--project",     required=True,
                   help="Allure TestOps project name")
    p.add_argument("--version",     required=True,
                   help="Branch or release version (e.g. develop, v1.2.0)")
    p.add_argument("--scan-type",   required=True, choices=["application", "canary"],
                   help="'application' checks prod code is clean; 'canary' checks scanner coverage")
    p.add_argument("--run-id",      required=True,
                   help="GitHub Actions run ID")
    p.add_argument("--run-url",     default="",
                   help="GitHub Actions run URL (added as a link to each result)")
    p.add_argument("--results-dir", default="./allure-results",
                   help="Directory for Allure 2 result JSON files (default: ./allure-results)")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    base_url  = os.environ.get("ALLURE_TESTOPS_URL", "").rstrip("/")
    api_token = os.environ.get("ALLURE_TESTOPS_API_TOKEN", "")

    if not base_url or not api_token:
        print(
            "ERROR: ALLURE_TESTOPS_URL and ALLURE_TESTOPS_API_TOKEN must be set.",
            file=sys.stderr,
        )
        return 1

    if not os.path.exists(args.sarif):
        print(f"ERROR: SARIF file not found: {args.sarif}", file=sys.stderr)
        return 1

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    _log("\n=== Allure TestOps — OWASP Scan Sync ===")
    _log(f"  Project   : {args.project}")
    _log(f"  Version   : {args.version}")
    _log(f"  Scan type : {args.scan_type}")
    _log(f"  Run ID    : {args.run_id}")
    _log(f"  SARIF     : {args.sarif}")
    _log(f"  Endpoint  : {base_url}")

    # ── Authenticate ──────────────────────────────────────────────────────────
    _log("\nAuthenticating ...")
    try:
        client = AllureClient(base_url, api_token)
        _log("  JWT obtained")
    except Exception as e:
        print(f"ERROR: Authentication failed: {e}", file=sys.stderr)
        return 1

    # ── Project ───────────────────────────────────────────────────────────────
    _log(f"\nEnsuring project '{args.project}' ...")
    try:
        project_id = get_or_create_project(client, args.project)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # ── Test cases ────────────────────────────────────────────────────────────
    _log(f"\nEnsuring {len(OWASP_TEST_CASES)} OWASP test cases ...")
    try:
        tc_map = get_or_create_test_cases(client, project_id)
    except Exception as e:
        print(f"ERROR: Test case sync failed: {e}", file=sys.stderr)
        return 1

    # ── Test plan ─────────────────────────────────────────────────────────────
    if args.scan_type == "application":
        plan_name = f"OWASP Security — {args.version}"
    else:
        plan_name = f"SAST Scanner Coverage — {args.version}"

    _log(f"\nEnsuring test plan '{plan_name}' ...")
    plan_id: int | None = None
    try:
        plan_id = get_or_create_test_plan(client, project_id, plan_name)
        link_cases_to_plan(client, plan_id, list(tc_map.values()))
    except Exception as e:
        _log(f"  [warn] test plan sync failed (non-fatal): {e}")

    # ── Parse SARIF ───────────────────────────────────────────────────────────
    _log("\nParsing SARIF ...")
    if args.scan_type == "application":
        scan_data = parse_application_scan(args.sarif)
        results   = generate_application_results(scan_data, args.run_url)
        prod_hits = sum(len(v) for v in scan_data.values())
        _log(f"  {prod_hits} production finding(s) across {len(scan_data)} rule(s)")
    else:
        fired   = parse_canary_scan(args.sarif)
        results = generate_canary_results(fired, args.run_url)
        _log(f"  {len(fired)} rule(s) fired in canary SARIF")

    # ── Write Allure result files ─────────────────────────────────────────────
    _log(f"\nWriting result files to {results_dir} ...")
    result_files: list[Path] = []
    for r in results:
        path = results_dir / f"{r['historyId']}-result.json"
        path.write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
        result_files.append(path)
    _log(f"  {len(result_files)} file(s) written")

    # ── Launch lifecycle ──────────────────────────────────────────────────────
    _log("\nCreating launch ...")
    launch_id: int | None = None
    upload_ok = False
    try:
        passed_count = sum(1 for r in results if r["status"] == "passed")
        scan_label   = ("Application Security Scan"
                        if args.scan_type == "application"
                        else "SAST Canary Coverage")
        launch_name  = f"{scan_label} — {args.version} — run #{args.run_id}"
        description  = (
            f"CodeQL security-extended | "
            f"{passed_count}/{len(results)} checks passed | "
            f"GitHub run {args.run_id}"
        )
        launch_id = create_launch(client, project_id, launch_name, description)
        _log(f"  launch created: id={launch_id}")

        _log("\nUploading results ...")
        upload_ok = upload_results_to_launch(
            client, launch_id, result_files, project_id, launch_name
        )

        if plan_id:
            link_launch_to_plan(client, launch_id, plan_id)

        close_launch(client, launch_id)

    except Exception as e:
        _log(f"  [warn] launch lifecycle error (non-fatal): {e}")

    # ── GitHub step summary ───────────────────────────────────────────────────
    _log("\nWriting step summary ...")
    write_step_summary(
        scan_type=args.scan_type,
        project=args.project,
        version=args.version,
        plan_name=plan_name,
        launch_id=launch_id,
        results=results,
        upload_ok=upload_ok,
        base_url=base_url,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
