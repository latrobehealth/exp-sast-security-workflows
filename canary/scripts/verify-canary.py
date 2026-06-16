#!/usr/bin/env python3
"""
verify-canary.py  —  SAST Canary OWASP Coverage Checker

Parses the CodeQL SARIF output produced by the verify-canary CI job and
confirms that each expected OWASP Top 10:2025 vulnerability class was detected
by the security-extended query suite.

Exits 0 when all classes are detected; exits 1 when any class is missed
so that the CI job fails and alerts the team to a scanner regression.

Usage:
    python3 verify-canary.py <path-to-sarif>
"""
import json
import os
import sys

# ── Expected CodeQL rules → OWASP Top 10:2025 mapping ────────────────────────
# Key   = CodeQL rule ID from the SARIF results
# Value = (OWASP 2025 category, human-readable description)
# Only rules in the security-extended suite are listed here.
# Rules that need security-and-quality (e.g. cs/stack-trace-exposure,
# cs/empty-catch-block) are marked as BONUS — skipped from the pass/fail count.
EXPECTED: dict[str, tuple[str, str]] = {
    # A01 — Broken Access Control
    "cs/path-injection":                            ("A01", "Path Traversal"),
    "cs/web/missing-function-level-access-control": ("A01", "Missing Access Control"),
    # A02 — Cryptographic Failures
    "cs/use-of-broken-or-weak-cryptographic-algorithm": ("A02", "Weak Cryptographic Algorithm (MD5)"),
    "cs/hardcoded-credentials":                     ("A02", "Hardcoded Credentials"),
    # A03 — Injection
    "cs/sql-injection":                             ("A03", "SQL Injection"),
    "cs/command-line-injection":                    ("A03", "OS Command Injection"),
    "cs/web/xss":                                   ("A03", "Cross-Site Scripting (XSS)"),
    # A05 — Security Misconfiguration
    "cs/web/unvalidated-url-redirect":              ("A05", "Unvalidated Redirect"),
    # A07 / A09 — Auth Failures / Logging Failures
    "cs/log-forging":                               ("A07/A09", "Log Forging (credentials / sensitive data)"),
    # A08 — Software and Data Integrity
    "cs/xml-injection":                             ("A08", "XML External Entity (XXE)"),
}

# Rules that ARE in the canary but require security-and-quality suite;
# included in the summary table as informational only.
BONUS: dict[str, tuple[str, str]] = {
    "cs/stack-trace-exposure": ("A05", "Stack Trace Exposure (needs security-and-quality suite)"),
    "cs/ssrf":                 ("A10", "SSRF (CodeQL model coverage varies by version)"),
}


def load_rule_ids(sarif_path: str) -> set[str]:
    with open(sarif_path, encoding="utf-8") as fh:
        sarif = json.load(fh)
    rule_ids: set[str] = set()
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            if rule_id:
                rule_ids.add(rule_id)
    return rule_ids


def build_table(
    expected: dict[str, tuple[str, str]],
    bonus: dict[str, tuple[str, str]],
    found: set[str],
) -> tuple[list[str], int, int]:
    rows: list[str] = []
    passed = failed = 0

    for rule_id, (owasp, label) in expected.items():
        if rule_id in found:
            rows.append(f"| {owasp} | {label} | `{rule_id}` | ✅ Detected |")
            passed += 1
        else:
            rows.append(f"| {owasp} | {label} | `{rule_id}` | ❌ **Missed** |")
            failed += 1

    for rule_id, (owasp, label) in bonus.items():
        status = "✅ Detected" if rule_id in found else "⚪ Not expected (bonus)"
        rows.append(f"| {owasp} | {label} | `{rule_id}` | {status} |")

    return rows, passed, failed


def write_summary(lines: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def main() -> int:
    sarif_path = sys.argv[1] if len(sys.argv) > 1 else "canary-sarif/csharp.sarif"

    if not os.path.exists(sarif_path):
        print(f"ERROR: SARIF file not found: {sarif_path}", file=sys.stderr)
        return 1

    found = load_rule_ids(sarif_path)
    rows, passed, total = build_table(EXPECTED, BONUS, found)

    header = [
        "## SAST Canary — OWASP Top 10:2025 Coverage",
        f"> CodeQL `security-extended` · SARIF: `{sarif_path}`",
        "",
        "| OWASP 2025 | Vulnerability Class | CodeQL Rule | Status |",
        "|---|---|---|---|",
        *rows,
        "",
        f"**{passed}/{total} required vulnerability classes detected by CodeQL**",
    ]

    if passed < total:
        missed = total - passed
        header += [
            "",
            f"> ⚠️ **{missed} class(es) missed** — the `security-extended` query suite "
            "may be degraded or the canary pattern was not taint-reachable.",
            "> Review the CodeQL findings above and update the canary if a query was "
            "intentionally removed from the suite.",
        ]
    else:
        header += ["", "> ✅ All required vulnerability classes detected — scanner is healthy."]

    print("\n".join(header))
    write_summary(header)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
