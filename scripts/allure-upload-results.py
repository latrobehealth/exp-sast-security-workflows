#!/usr/bin/env python3
"""
allure-upload-results.py — CI helper for Allure TestOps result upload

Used by GitHub Actions after each test run to:
  1. Create an open launch via REST API
  2. Upload allure-results/ via allurectl (REST upload not supported on this instance)
  3. Close the launch
  4. Link the launch to the appropriate test plan

Required environment variables:
  ALLURE_TESTOPS_URL         Base URL, e.g. https://allure.example.com
  ALLURE_TESTOPS_API_TOKEN   Allure TestOps API token

Usage:
  python3 scripts/allure-upload-results.py \\
    --results-dir     allure-results/unit \\
    --launch-name     "Membership Service Unit Tests — develop #42" \\
    --plan-name       "Membership Service Unit Testing" \\
    --project-id      67 \\
    --run-url         https://github.com/org/repo/actions/runs/42
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests", file=sys.stderr)
    sys.exit(1)


# ── Allure TestOps client (minimal) ──────────────────────────────────────────

class AllureClient:
    def __init__(self, base: str, api_token: str):
        self.base = base.rstrip("/")
        self._s = requests.Session()
        jwt = self._exchange_token(api_token)
        self._s.headers.update({"Authorization": f"Bearer {jwt}"})

    def _exchange_token(self, api_token: str) -> str:
        resp = requests.post(
            f"{self.base}/api/uaa/oauth/token",
            data={"grant_type": "apitoken", "scope": "openid", "token": api_token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def post(self, path: str, body: dict | None = None) -> dict:
        resp = self._s.post(f"{self.base}{path}", json=body, timeout=30)
        resp.raise_for_status()
        return resp.json() if resp.text.strip() else {}

    def patch(self, path: str, body: dict) -> dict:
        resp = self._s.patch(f"{self.base}{path}", json=body, timeout=30)
        resp.raise_for_status()
        return resp.json() if resp.text.strip() else {}

    def get(self, path: str, **params) -> dict:
        resp = self._s.get(f"{self.base}{path}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()


def _paginate(client: AllureClient, path: str, **params) -> list[dict]:
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


def _log(msg: str) -> None:
    print(msg, flush=True)


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


def close_launch(client: AllureClient, launch_id: int) -> None:
    try:
        client.post(f"/api/launch/{launch_id}/close")
        _log(f"  launch {launch_id} closed")
    except Exception as e:
        _log(f"  [warn] could not close launch {launch_id}: {e}")


def find_test_plan_id(
    client: AllureClient, project_id: int, plan_name: str
) -> int | None:
    plans = _paginate(client, "/api/testplan", projectId=project_id)
    for p in plans:
        if p.get("name") == plan_name:
            return p["id"]
    return None


def link_launch_to_plan(
    client: AllureClient, launch_id: int, plan_id: int
) -> None:
    try:
        client.patch(f"/api/launch/{launch_id}", {"testPlanId": plan_id})
        _log(f"  launch {launch_id} linked to test plan {plan_id}")
    except Exception as e:
        _log(f"  [warn] could not link launch to plan: {e}")


# ── allurectl upload ──────────────────────────────────────────────────────────

def upload_via_allurectl(
    allurectl_path: str,
    endpoint: str,
    token: str,
    project_id: int,
    launch_id: int,
    results_dir: str,
) -> bool:
    """
    Upload allure result files to an existing open launch using allurectl.
    REST upload endpoints are not supported on this Allure instance.
    """
    cmd = [
        allurectl_path, "upload",
        "--endpoint",   endpoint,
        "--token",      token,
        "--project-id", str(project_id),
        "--launch-id",  str(launch_id),
        results_dir,
    ]
    _log(f"  running: {' '.join(cmd[:6])} <token hidden> {' '.join(cmd[7:])}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        _log(result.stdout)
    if result.stderr:
        _log(result.stderr)
    if result.returncode != 0:
        _log(f"  [warn] allurectl exited with code {result.returncode}")
        return False
    return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Upload test results to Allure TestOps")
    parser.add_argument("--results-dir",  required=True,  help="Path to allure-results directory")
    parser.add_argument("--launch-name",  required=True,  help="Name for the Allure launch")
    parser.add_argument("--plan-name",    required=True,  help="Test plan name to link the launch to")
    parser.add_argument("--project-id",   required=True,  type=int, help="Allure TestOps project ID")
    parser.add_argument("--run-url",      default="",     help="GitHub Actions run URL for reference")
    parser.add_argument("--allurectl",    default="allurectl", help="Path to allurectl binary")
    args = parser.parse_args()

    url   = os.environ.get("ALLURE_TESTOPS_URL", "").rstrip("/")
    token = os.environ.get("ALLURE_TESTOPS_API_TOKEN", "")
    if not url or not token:
        print(
            "ERROR: ALLURE_TESTOPS_URL and ALLURE_TESTOPS_API_TOKEN must be set.",
            file=sys.stderr,
        )
        sys.exit(1)

    results_path = Path(args.results_dir)
    if not results_path.exists() or not any(results_path.iterdir()):
        _log(f"[warn] No allure results found in '{args.results_dir}' — skipping upload")
        sys.exit(0)

    _log(f"\n=== Allure TestOps result upload ===")
    _log(f"  endpoint    : {url}")
    _log(f"  project id  : {args.project_id}")
    _log(f"  launch name : {args.launch_name}")
    _log(f"  plan name   : {args.plan_name}")
    _log(f"  results dir : {args.results_dir}")

    client = AllureClient(url, token)

    # 1. Create launch
    _log("\n[1] Creating launch ...")
    description = f"Automated test run. {args.run_url}".strip()
    launch_id = create_launch(client, args.project_id, args.launch_name, description)
    _log(f"  launch created: id={launch_id}")

    # 2. Upload via allurectl
    _log("\n[2] Uploading results via allurectl ...")
    upload_ok = upload_via_allurectl(
        allurectl_path=args.allurectl,
        endpoint=url,
        token=token,
        project_id=args.project_id,
        launch_id=launch_id,
        results_dir=args.results_dir,
    )
    if not upload_ok:
        _log("  [warn] Upload had errors — launch will still be closed and linked")

    # 3. Close launch
    _log("\n[3] Closing launch ...")
    close_launch(client, launch_id)

    # 4. Link launch to test plan
    _log(f"\n[4] Linking launch to test plan '{args.plan_name}' ...")
    plan_id = find_test_plan_id(client, args.project_id, args.plan_name)
    if plan_id is None:
        _log(f"  [warn] Test plan '{args.plan_name}' not found — run allure-unit-integration-setup.py first")
    else:
        link_launch_to_plan(client, launch_id, plan_id)

    _log(f"\nDone. Launch ID: {launch_id}")
    # Write launch ID to file for downstream steps
    Path("allure-launch-id.txt").write_text(str(launch_id), encoding="utf-8")


if __name__ == "__main__":
    main()
