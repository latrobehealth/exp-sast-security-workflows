#!/usr/bin/env python3
"""
Enriches CodeQL SARIF output with OWASP Top 10:2025 tags and references.

For each SARIF rule that carries a CodeQL CWE tag (external/cwe/cwe-NNN),
this script:
  1. Resolves the CWE to an OWASP Top 10:2025 category via cwe-to-owasp-2025.json
  2. Appends the category ID (e.g. "A05:2025") to the rule's properties.tags array
     — these surface in GitHub's "Tags" chip row on the code-scanning alert page.
  3. Appends a markdown reference block containing the category name and a
     clickable URL to the rule's help.markdown field
     — this surfaces in the alert detail panel under "Show more".

Usage:
    python3 enrich-sarif-owasp.py <sarif-output-dir>

GitHub rendering notes:
  - Tags (properties.tags): plain-text chips; not hyperlinked by GitHub.
  - Weaknesses (CWE-NN): populated from external/cwe/* tags only; GitHub does
    not render non-CWE taxonomy entries there, so OWASP goes in Tags instead.
  - help.markdown: rendered as Markdown in the alert detail panel, so the OWASP
    URL becomes a real clickable link.
"""
import json
import re
import sys
from pathlib import Path

MAPPING_FILE = Path(__file__).parent.parent / "codeql" / "cwe-to-owasp-2025.json"
CWE_TAG_RE = re.compile(r"^external/cwe/cwe-(\d+)$", re.IGNORECASE)

OWASP_MD_HEADER = "\n\n---\n\n**OWASP Top 10:2025 References**\n"
OWASP_MD_SENTINEL = "OWASP Top 10:2025"


def load_mapping():
    with open(MAPPING_FILE) as fh:
        data = json.load(fh)
    categories = data["categories"]
    # Pre-build: cwe_number_str -> {"id": ..., "name": ..., "url": ...}
    mapping = {}
    for cwe_str, cat_id in data["cwe_map"].items():
        cat = categories[cat_id]
        mapping[cwe_str] = {"id": cat_id, "name": cat["name"], "url": cat["url"]}
    return mapping


def cwe_ids_from_tags(tags):
    ids = []
    for tag in tags:
        m = CWE_TAG_RE.match(tag)
        if m:
            ids.append(str(int(m.group(1))))  # strip leading zeros: "078" -> "78"
    return ids


def enrich_rule(rule, mapping):
    """Mutates rule in place. Returns True if any OWASP data was added."""
    props = rule.setdefault("properties", {})
    tags = props.setdefault("tags", [])

    cwe_ids = cwe_ids_from_tags(tags)
    if not cwe_ids:
        return False

    # Collect unique OWASP categories for this rule's CWEs (preserve order)
    seen = set()
    owasp_entries = []
    for cwe in cwe_ids:
        entry = mapping.get(cwe)
        if entry and entry["id"] not in seen:
            seen.add(entry["id"])
            owasp_entries.append(entry)

    if not owasp_entries:
        return False

    # 1. Inject OWASP category IDs as tags (e.g. "A05:2025")
    for entry in owasp_entries:
        if entry["id"] not in tags:
            tags.append(entry["id"])

    # 2. Append OWASP references to help.markdown so they render as links
    help_obj = rule.setdefault("help", {"text": ""})
    existing_md = help_obj.get("markdown", help_obj.get("text", ""))

    if OWASP_MD_SENTINEL not in existing_md:
        ref_lines = [OWASP_MD_HEADER]
        for entry in owasp_entries:
            ref_lines.append(f"- [{entry['id']}: {entry['name']}]({entry['url']})")
        owasp_block = "\n".join(ref_lines)
        help_obj["markdown"] = existing_md + owasp_block
        # keep text in sync for tools that only read plain text
        if not help_obj.get("text"):
            help_obj["text"] = help_obj["markdown"]

    return True


def enrich_sarif_file(path, mapping):
    with open(path, encoding="utf-8") as fh:
        sarif = json.load(fh)

    enriched = 0
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            if enrich_rule(rule, mapping):
                enriched += 1
        for ext in run.get("tool", {}).get("extensions", []):
            for rule in ext.get("rules", []):
                if enrich_rule(rule, mapping):
                    enriched += 1

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)

    return enriched


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <sarif-dir>", file=sys.stderr)
        sys.exit(1)

    sarif_dir = Path(sys.argv[1])
    if not sarif_dir.is_dir():
        print(f"Error: '{sarif_dir}' is not a directory", file=sys.stderr)
        sys.exit(1)

    try:
        mapping = load_mapping()
    except FileNotFoundError:
        print(f"Error: mapping file not found at {MAPPING_FILE}", file=sys.stderr)
        sys.exit(1)

    sarif_files = sorted(sarif_dir.rglob("*.sarif"))
    if not sarif_files:
        print(f"No .sarif files found in {sarif_dir}")
        return

    total = 0
    for sarif_file in sarif_files:
        try:
            count = enrich_sarif_file(sarif_file, mapping)
            print(f"  {sarif_file.name}: {count} rule(s) tagged with OWASP Top 10:2025")
            total += count
        except Exception as exc:
            print(f"  Warning: could not process {sarif_file.name}: {exc}", file=sys.stderr)

    print(f"Done: {total} rule(s) enriched across {len(sarif_files)} file(s)")


if __name__ == "__main__":
    main()
