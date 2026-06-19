# SAST Security Workflow — Implementation Guide

**Repository:** `latrobehealth/exp-sast-security-workflows`  
**Audience:** DevOps Engineers · Software Engineers · Tech Leads  
**Standard:** [OWASP Top 10:2025](https://owasp.org/Top10/2025/)

---

## Contents

1. [The Problem This Solves](#1-the-problem-this-solves)
2. [Solution Architecture](#2-solution-architecture)
3. [Code Walkthrough — How Everything Works](#3-code-walkthrough--how-everything-works)
   - [3.1 codeql-reusable.yml](#31-codeql-reusableyml)
   - [3.2 dependency-review-reusable.yml](#32-dependency-review-reusableyml)
   - [3.3 enrich-sarif-owasp.py](#33-enrich-sarif-owasppy)
   - [3.4 cwe-to-owasp-2025.json](#34-cwe-to-owasp-2025json)
   - [3.5 SAST Canary — SastCanaryController.cs](#35-sast-canary--sastcanarycontrollercs)
   - [3.6 verify-canary.py](#36-verify-canarypy)
   - [3.7 allure-testops-sync.py](#37-allure-testops-syncpy)
4. [DevOps Engineer Guide](#4-devops-engineer-guide)
   - [4.1 Prerequisites](#41-prerequisites)
   - [4.2 GitHub Repository Settings](#42-github-repository-settings)
   - [4.3 Secrets and Variables](#43-secrets-and-variables)
   - [4.4 Onboarding Checklist](#44-onboarding-checklist)
5. [Software Engineer Guide](#5-software-engineer-guide)
   - [5.1 .NET C# — Azure API App](#51-net-c--azure-api-app)
   - [5.2 .NET C# — Azure Functions](#52-net-c--azure-functions)
   - [5.3 Next.js — Azure Web App](#53-nextjs--azure-web-app)
   - [5.4 Blazor — Azure Web App](#54-blazor--azure-web-app)
6. [Understanding and Resolving Security Alerts](#6-understanding-and-resolving-security-alerts)
7. [Allure TestOps Dashboard](#7-allure-testops-dashboard)
8. [Maintaining the Solution](#8-maintaining-the-solution)

---

## 1. The Problem This Solves

### 1.1 Security at Scale

As an organisation grows, two things become true simultaneously: the attack surface expands and the time available for manual security review per feature shrinks. Without automated controls, a single developer introducing `ProcessStartInfo("cmd.exe", userInput)` into a codebase can create a Remote Code Execution vulnerability that ships to production undetected.

The OWASP Top 10 — published every few years with the latest edition in 2025 — catalogues the ten most critical web application security risk categories, derived from analysis of hundreds of thousands of real-world applications. These are not theoretical risks; they are the categories most commonly exploited in breaches.

### 1.2 What Goes Wrong Without This Solution

| Scenario | What happens | Impact |
|---|---|---|
| Developer concatenates user input into a SQL query | No automated check catches it; code reviewer may not notice | SQL injection; data breach |
| MD5 is used to hash passwords in a new service | No rule flags it; MD5 is considered "good enough" by the developer | Cryptographic failure; rainbow table attack |
| `Redirect(returnUrl)` added to an OAuth flow | Passes code review; no one checks for open redirect | Phishing via trusted domain |
| A new dependency with a critical CVE is pulled in | Dependabot is not configured; no PR check catches it | Supply chain compromise |
| The security scanner is misconfigured and silently stops scanning | Nobody notices for months | False confidence; growing undetected vulnerability backlog |

### 1.3 What This Solution Provides

This repository provides a **centralised library of reusable GitHub Actions security workflows** that any application repository in the organisation can adopt with a two-file change. It provides:

1. **Static Application Security Testing (SAST)** via [GitHub CodeQL](https://codeql.github.com/) — analyses source code to detect security vulnerabilities before they ship. Runs on every push to `main` and every pull request.

2. **OWASP Top 10:2025 tagging** — every alert in GitHub Advanced Security is automatically tagged with the OWASP category (e.g. `A05:2025`) and a clickable URL to the OWASP reference page, so developers can immediately understand the category of risk and how to fix it.

3. **Dependency supply chain scanning** — every pull request is checked for newly introduced dependencies with known CVEs and licence policy violations.

4. **Scanner integrity verification (SAST Canary)** — a self-contained project containing intentional vulnerabilities is scanned on demand to confirm that CodeQL would actually detect each OWASP class if it appeared in production code.

5. **Allure TestOps integration** — security scan results are synchronised to Allure TestOps, enabling trending, triage tracking, and consolidated reporting alongside functional test results.

### 1.4 Who Is Responsible for What

| Responsibility | Owner |
|---|---|
| Maintaining and updating these workflows | Security Engineering / DevOps |
| Adopting the workflows in application repos | Application team DevOps / tech lead |
| Resolving security alerts raised by the scans | Application team software engineers |
| Triaging and dismissing false positives | Application tech lead + Security Engineering |
| Monitoring scanner health (canary) | Security Engineering |

---

## 2. Solution Architecture

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  latrobehealth/exp-sast-security-workflows  (this repo)             │
│                                                                     │
│  .github/workflows/                                                 │
│    codeql-reusable.yml          ← Called by every app repo         │
│    dependency-review-reusable.yml ← Called by every app repo       │
│                                                                     │
│  .github/scripts/                                                   │
│    enrich-sarif-owasp.py        ← Runs inside codeql-reusable      │
│  .github/codeql/                                                    │
│    cwe-to-owasp-2025.json       ← 160+ CWE → OWASP 2025 mappings  │
│                                                                     │
│  scripts/                                                           │
│    allure-testops-sync.py       ← Runs inside codeql-reusable      │
│                                                                     │
│  canary/                        ← SAST scanner health check        │
│    Controllers/SastCanaryController.cs  ← Intentional vulns        │
│    scripts/verify-canary.py     ← Assert all rules fired           │
└─────────────────────────────────────────────────────────────────────┘
            ↑ called via uses:
┌─────────────────────────────────┐
│  latrobehealth/your-app-repo    │
│                                 │
│  .github/workflows/             │
│    security-sast.yml            │  ← The only file you write
│    security-deps.yml            │  ← The only file you write
└─────────────────────────────────┘
```

### 2.2 Data Flow — What Happens on Every Push

```
Developer pushes code
        │
        ▼
GitHub Actions triggers security-sast.yml in the app repo
        │
        ▼
codeql-reusable.yml runs in exp-sast-security-workflows
        │
        ├─► CodeQL initialises and analyses source code
        │       │
        │       ▼
        │   SARIF file saved locally (not yet uploaded)
        │       │
        │       ▼
        │   enrich-sarif-owasp.py runs:
        │     • Reads CWE tags from each rule
        │     • Looks up OWASP 2025 category in cwe-to-owasp-2025.json
        │     • Injects OWASP ID as tag (e.g. "A05:2025")
        │     • Appends OWASP URL to rule help markdown
        │       │
        │       ▼
        │   Enriched SARIF uploaded to GitHub Advanced Security
        │       │
        │       ▼
        │   Alerts appear in app repo: Security → Code scanning
        │     • Tags chip shows: correctness  security  A05:2025
        │     • "Show more" shows: OWASP A05:2025 Injection [link]
        │
        └─► allure-testops-sync.py runs (if allure-project-name set):
              • Authenticates with Allure TestOps
              • Creates/finds project, test cases, test plan
              • Parses SARIF for production findings
              • PASS per OWASP class = zero findings; FAIL = findings found
              • Creates launch, uploads results, closes launch
              • Writes summary table to GitHub Actions job summary
```

### 2.3 Data Flow — Pull Request Dependency Scan

```
Developer opens a PR
        │
        ▼
dependency-review-reusable.yml runs
        │
        ▼
actions/dependency-review-action compares dependency manifests
between PR base and head commits
        │
        ├─► Any added dependency with severity ≥ high?  → Fail the PR check
        ├─► Any dependency with blocked licence?        → Fail the PR check
        └─► All clear                                   → Pass; post summary comment on PR
```

---

## 3. Code Walkthrough — How Everything Works

### 3.1 `codeql-reusable.yml`

This is the main reusable workflow. It defines two jobs: `analyze` (runs on every call) and `verify-canary` (runs only when the caller opts in).

#### Inputs and secrets declaration

```yaml
on:
  workflow_call:
    inputs:
      languages:           # Required. JSON array: '["csharp","javascript-typescript"]'
      build-mode:          # none | autobuild | manual. Default: none
      runner:              # Runner label. Default: ubuntu-latest
      query-suite:         # CodeQL suite. Default: security-extended
      verify-canary:       # boolean. Runs the canary job. Default: false
      allure-project-name: # string. Project name in Allure TestOps. Empty = skip sync
    secrets:
      canary-token:        # PAT for checking out this repo (private repos only)
      ALLURE_TESTOPS_URL:  # Allure base URL
      ALLURE_TESTOPS_API_TOKEN: # Allure API token
```

The `workflow_call` trigger is what makes this a reusable workflow — it can only be called by another workflow using `uses:`, not triggered directly by a push or PR.

#### The `analyze` job — step by step

**Step 1 — Checkout the calling repository**
```yaml
- uses: actions/checkout@v4
```
Checks out the application repo (not this security repo). This is the code being scanned.

**Step 2 — Initialise CodeQL**
```yaml
- uses: github/codeql-action/init@v3
  with:
    languages:  ${{ matrix.language }}
    build-mode: ${{ inputs.build-mode }}
    queries:    ${{ inputs.query-suite }}
```
Sets up CodeQL's database extraction infrastructure. The `queries` parameter determines which query pack runs — `security-extended` covers ~200 security queries; `security-and-quality` covers ~400. A matrix is used so that if `languages: '["csharp","javascript-typescript"]'` is passed, two parallel jobs run, one per language.

**Step 3 — Build (manual mode only)**
```yaml
- if: ${{ inputs.build-mode == 'manual' && matrix.language == 'csharp' }}
  run: dotnet build --configuration Release /p:UseSharedCompilation=false
```
Only runs for .NET when `build-mode: manual`. The flag `/p:UseSharedCompilation=false` disables the Roslyn shared compiler process, which is required because CodeQL needs to intercept compilation calls individually. If you have a complex build (solution files, pre-build code generation, etc.) you will extend this step.

**Step 4 — Run CodeQL analysis (no upload yet)**
```yaml
- uses: github/codeql-action/analyze@v3
  with:
    category: "/language:${{ matrix.language }}"
    upload:   false          # ← Key: save SARIF locally, don't upload yet
    output:   sarif-results  # ← Directory where SARIF file is written
```
This is the core analysis step. CodeQL builds a semantic model of the code (the CodeQL database) and runs all queries against it. The results are written as a SARIF file — a JSON format standardised for security tool interoperability. By setting `upload: false`, we retain the SARIF file locally for the enrichment step.

**Step 5 — Checkout the security scripts**
```yaml
- uses: actions/checkout@v4
  with:
    repository: latrobehealth/exp-sast-security-workflows
    ref:        main
    path:       sast-security-scripts
    token:      ${{ secrets.canary-token || github.token }}
```
The enrichment and Allure sync scripts live in this repository, not in the application repo. This step checks them out into the `sast-security-scripts/` subdirectory so they can be executed. This checkout happens **after** CodeQL analysis so the extra directory does not affect the source code snapshot CodeQL has already processed.

**Step 6 — Enrich SARIF with OWASP tags**
```yaml
- run: python3 sast-security-scripts/.github/scripts/enrich-sarif-owasp.py sarif-results
```
Runs the enrichment script against the `sarif-results/` directory. See [Section 3.3](#33-enrich-sarif-owasppy) for a full walkthrough.

**Step 7 — Upload enriched SARIF**
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sarif-results
    category:   "/language:${{ matrix.language }}"
```
Uploads the enriched SARIF to GitHub Advanced Security. Results appear in the app repo under **Security → Code scanning** within a few seconds.

**Step 8 — Allure TestOps sync (C# only, optional)**
```yaml
- if: ${{ inputs.allure-project-name != '' && matrix.language == 'csharp' }}
  continue-on-error: true  # ← Never blocks CI
  run: |
    python3 sast-security-scripts/scripts/allure-testops-sync.py \
      --sarif     sarif-results/csharp.sarif \
      --project   "${{ inputs.allure-project-name }}" \
      --scan-type application ...
```
The `continue-on-error: true` is critical — if Allure TestOps is unreachable or credentials are missing, this step logs a warning and exits 0. The security scan result itself always uploads to GitHub regardless of Allure availability.

#### The `verify-canary` job

Only runs when the calling workflow sets `verify-canary: true`. It checks out this repository, builds the canary project, runs CodeQL on it, and then asserts every expected rule fired. See [Section 3.5](#35-sast-canary--sastcanarycontrollercs) for details.

---

### 3.2 `dependency-review-reusable.yml`

Simpler than the CodeQL workflow. It wraps [actions/dependency-review-action](https://github.com/actions/dependency-review-action).

```yaml
- uses: actions/dependency-review-action@v4
  with:
    fail-on-severity:     ${{ inputs.fail-on-severity }}   # high by default
    allow-licenses:       ${{ inputs.allow-licenses }}     # empty = allow all
    deny-packages:        ${{ inputs.deny-packages }}      # empty = block none
    comment-summary-in-pr: ${{ inputs.comment-summary-in-pr }}
```

The action compares the dependency manifest (`package.json`, `*.csproj`, `go.mod`, etc.) between the PR base commit and head commit. For any **newly added** dependency, it checks the GitHub Advisory Database. If the dependency has a known vulnerability at or above `fail-on-severity`, the PR check fails and the developer is shown what to do.

> **Why only PRs?** Dependency Review requires two commits to compare. On a direct push to `main`, there is no base commit available to compare against, so the action is a no-op. Configure Dependabot to catch vulnerabilities in existing dependencies on a schedule.

---

### 3.3 `enrich-sarif-owasp.py`

#### What is SARIF?

SARIF (Static Analysis Results Interchange Format) is a JSON file format standardised by OASIS. A CodeQL SARIF file has this structure:

```json
{
  "runs": [{
    "tool": {
      "driver": {
        "rules": [
          {
            "id": "cs/command-line-injection",
            "name": "CommandLineInjection",
            "properties": {
              "tags": ["correctness", "security", "external/cwe/cwe-078", "external/cwe/cwe-088"]
            },
            "helpUri": "https://codeql.github.com/codeql-query-help/csharp/cs-command-line-injection/"
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "cs/command-line-injection",
        "message": { "text": "This argument to 'ProcessStartInfo' depends on a user-provided value." },
        "locations": [{ "physicalLocation": { ... } }]
      }
    ]
  }]
}
```

Each **rule** defines a type of vulnerability. Each **result** is a specific instance of that rule firing in the code. The `external/cwe/cwe-078` tag on the rule tells GitHub to show "CWE-78" in the **Weaknesses** section of the alert.

#### What the script does

The script processes every `*.sarif` file in the output directory:

```python
CWE_TAG_RE = re.compile(r"^external/cwe/cwe-(\d+)$", re.IGNORECASE)

def cwe_ids_from_tags(tags):
    ids = []
    for tag in tags:
        m = CWE_TAG_RE.match(tag)
        if m:
            ids.append(str(int(m.group(1))))  # "078" → "78"
    return ids
```

1. For each rule, it extracts CWE numbers from the `external/cwe/cwe-NNN` tags using a regex.
2. It strips leading zeros (`078` → `78`) to match the keys in `cwe-to-owasp-2025.json`.
3. It looks up the OWASP 2025 category for each CWE.
4. **Tags injection** — adds the OWASP category ID to `properties.tags`:

```python
tags.append(entry["id"])  # e.g. "A05:2025"
```

   This is what makes `A05:2025` appear as a chip in GitHub's Tags row.

5. **Help markdown injection** — appends a reference block to `help.markdown`:

```python
help_obj["markdown"] = existing_md + "\n\n---\n\n**OWASP Top 10:2025 References**\n\n- [A05:2025: Injection](https://owasp.org/...)"
```

   The `help.markdown` field is rendered in the GitHub alert's "Show more" panel as formatted Markdown, so the OWASP URL becomes a real clickable link.

6. Writes the modified SARIF back to disk. The enriched file is then uploaded by the next workflow step.

---

### 3.4 `cwe-to-owasp-2025.json`

The mapping file has three sections:

```json
{
  "_meta": { ... },        // Documentation only — ignored by the script
  "categories": {          // Canonical OWASP category data
    "A05:2025": {
      "name": "Injection",
      "url":  "https://owasp.org/Top10/2025/A05_2025-Injection/"
    }
  },
  "cwe_map": {             // CWE number (string) → OWASP category ID
    "78":  "A05:2025",     // OS Command Injection
    "88":  "A05:2025",     // Argument Injection
    "89":  "A05:2025",     // SQL Injection
    "79":  "A05:2025",     // XSS
    "22":  "A01:2025",     // Path Traversal
    "327": "A04:2025"      // Weak Cryptographic Algorithm
    // ... 160+ entries
  }
}
```

The `cwe_map` contains 160+ entries sourced directly from the official OWASP Top 10:2025 pages. Each key is a CWE number with no leading zeros (matching what the enrichment script produces after stripping). The script pre-processes this into a flat lookup: `cwe_id → {id, name, url}`.

To add a new CWE mapping, add a line to `cwe_map` using the CWE number as the key and the appropriate OWASP 2025 category ID as the value.

---

### 3.5 SAST Canary — `SastCanaryController.cs`

#### Why the canary exists

CodeQL queries are updated over time. A query can be removed from the `security-extended` suite, renamed, or its taint model changed so that a particular pattern is no longer detected. Without a canary, such regressions are invisible — scans keep running and the Security tab stays empty, which looks like success but might just mean the scanner has stopped detecting a class of vulnerability.

The canary is a self-contained .NET 9 ASP.NET Core project. Every endpoint contains one intentional vulnerability that maps to a specific CodeQL rule. The `verify-canary` CI job builds and scans this project and asserts that every expected rule fires.

#### Pattern design rationale

Each vulnerability pattern in the canary was specifically designed to be reliably detected by CodeQL. This required several iterations:

| Fix | Reason |
|---|---|
| XSS uses `"<h1>Hello " + name + "</h1>"` not `$"<h1>Hello {name}</h1>"` | C# compiler synthesises intermediate variables for string interpolation; CodeQL can lose taint flow through them. Direct concatenation keeps the taint graph as a single edge. |
| `Login` uses `[FromQuery]` parameters not `[FromBody] record` | Positional record properties in .NET may not be modelled as HTTP-tainted sources in all CodeQL versions. `[FromQuery]` has a well-established taint model. |
| A02 uses both `MD5.Create()` and `SHA1.Create()` | Guards against single-instance misses; if one instance is missed the other provides a backstop. |
| A08 uses XPath injection not XXE | `cs/xml-injection` is XPath injection (user input in `SelectSingleNode`). XXE requires `Request.Body` as a taint source, which is not modelled in `security-extended`. |

#### Vulnerability catalogue

| Endpoint | Rule | Pattern (simplified) |
|---|---|---|
| `GET _sast-canary/a01/file` | `cs/path-injection` | `File.ReadAllText(Path.Combine(base, fileName))` where `fileName` comes from `[FromQuery]` |
| `DELETE _sast-canary/a01/admin-delete/{id}` | `cs/web/missing-function-level-access-control` | HTTP DELETE action on a class with no `[Authorize]` attribute |
| `POST _sast-canary/a02/hash` | `cs/use-of-broken-or-weak-cryptographic-algorithm` | `MD5.Create()` and `SHA1.Create()` |
| `GET _sast-canary/a02/connect` | `cs/hardcoded-credentials` | `new NetworkCredential("sa", "Hardcoded@Pass2025!")` |
| `GET _sast-canary/a03/search` | `cs/sql-injection` | `FromSqlRaw("... '" + term + "'")` |
| `GET _sast-canary/a03/ping` | `cs/command-line-injection` | `new ProcessStartInfo("cmd.exe", "/c ping -n 1 " + host)` |
| `GET _sast-canary/a03/greet` | `cs/web/xss` | `Content("<h1>Hello " + name + "</h1>", "text/html")` |
| `GET _sast-canary/a05/redirect` | `cs/web/unvalidated-url-redirect` | `Redirect(returnUrl)` |
| `POST _sast-canary/a07/login` | `cs/log-forging` | `LogInformation("... password={Pass}", username, password)` |
| `GET _sast-canary/a07/token-info` | `cs/log-forging` | `LogDebug("... {Token}", Request.Headers["Authorization"])` |
| `GET _sast-canary/a08/xpath` | `cs/xml-injection` | `doc.SelectSingleNode("//user[@id='" + id + "']")` |
| `GET _sast-canary/a09/log-path` | `cs/log-forging` | `LogInformation("Visited: {Path}", Request.Path.Value)` |

**Bonus patterns** (not counted in pass/fail; require `security-and-quality` or future CodeQL versions):

| Endpoint | Rule | Note |
|---|---|---|
| `GET a05/diagnostics` | `cs/stack-trace-exposure` | Requires `security-and-quality` suite |
| `POST a08/import-xml` | `cs/xml-external-entity` | `XmlUrlResolver` on `Request.Body`; stream not modelled as taint source in `security-extended` |
| `GET a10/fetch` | `cs/ssrf` | `HttpClient.GetStringAsync(url)`; not yet modelled in C# pack |

---

### 3.6 `verify-canary.py`

The verification script has two responsibilities:

**1. Assert coverage**

```python
EXPECTED: dict[str, tuple[str, str]] = {
    "cs/path-injection": ("A01", "Path Traversal"),
    "cs/command-line-injection": ("A03", "OS Command Injection"),
    # ... etc
}

found = load_rule_ids(sarif_path)  # set of rule IDs that fired

for rule_id in EXPECTED:
    if rule_id not in found:
        failed += 1  # → exit code 1 → CI job fails
```

The script reads the SARIF results file and extracts every `ruleId` that appears in at least one result. It then checks that every rule in `EXPECTED` appears in that set. If any are missing, the script exits with code 1, which fails the `verify-canary` CI job.

**2. Write a job summary**

The script writes a formatted Markdown table to `$GITHUB_STEP_SUMMARY`. This is a GitHub Actions environment variable pointing to a file that GitHub renders as the job summary in the Actions UI:

```
## SAST Canary — OWASP Top 10:2025 Coverage
| OWASP 2025 | Vulnerability Class    | CodeQL Rule             | Status      |
|------------|------------------------|-------------------------|-------------|
| A01        | Path Traversal         | cs/path-injection       | ✅ Detected |
| A03        | SQL Injection          | cs/sql-injection        | ✅ Detected |
...
10/10 required vulnerability classes detected — scanner is healthy.
```

---

### 3.7 `allure-testops-sync.py`

This script bridges the gap between GitHub's security tooling and Allure TestOps' test management platform. It is called with one of two modes:

- `--scan-type application` — runs from the `analyze` job; checks that production code has zero findings per OWASP class
- `--scan-type canary` — runs from the `verify-canary` job; checks that expected CodeQL rules fired

#### Authentication

```python
def _exchange_token(self, api_token: str) -> str:
    resp = requests.post(
        f"{self.base}/api/uaa/oauth/token",
        data={"grant_type": "apitoken", "scope": "openid", "token": api_token},
    )
    return resp.json()["access_token"]
```

The Allure TestOps API uses short-lived JWT tokens. The script exchanges the long-lived `ALLURE_TESTOPS_API_TOKEN` for a JWT Bearer token at startup. Every subsequent API call uses this JWT in the `Authorization: Bearer ...` header.

#### Idempotency

The script never creates duplicate records. Each time it runs it follows a "find-or-create" pattern:

```
get_or_create_project()   → search by name → create only if not found
get_or_create_test_cases() → search by name → create only if not found
get_or_create_test_plan()  → search by name → create only if not found
create_launch()            → always new (one per CI run)
```

This means the same project and 10 OWASP test cases are reused across every run. Only the launch (recording of a specific scan) is new each time.

#### OWASP test case catalogue

The script defines 10 test cases (`OWASP_TEST_CASES`) hardcoded to the CodeQL C# rules that the canary verifies. Each has an `externalId`, `name`, OWASP category, rule ID, severity, tags, and description. These are the objects created in Allure TestOps and kept in sync across runs.

#### Application scan pass/fail logic

```python
EXCLUDED_PATH_PATTERNS = (
    "OwaspV2ValidationController",
    "SastCanaryController",
    "canary/Controllers",
    # ...
)

def parse_application_scan(sarif_path):
    # Returns rule_id → list of production findings
    # Findings in EXCLUDED_PATH_PATTERNS are silently dropped
```

When scanning an application repository, findings in test controllers and the canary itself are excluded so they do not cause false failures. A finding in production code causes `status: "failed"` for that OWASP test case in Allure; zero findings means `status: "passed"`.

#### Launch lifecycle

```
create_launch()  → creates an open launch in Allure TestOps
upload_results() → uploads Allure 2 JSON result files to the launch
link_to_plan()   → associates the launch with the test plan for this branch
close_launch()   → closes the launch (marks it complete)
```

The upload supports two endpoint patterns (Allure TestOps has had multiple API versions) and falls back gracefully if upload fails — the launch remains visible in Allure TestOps with the test plan linkage even without uploaded results.

#### Result file format

Each result is written as an [Allure 2](https://allurereport.org/docs/how-it-works/) JSON file:

```json
{
  "uuid":               "<unique per run>",
  "historyId":          "codeql-cs-command-injection",  // stable across runs
  "name":               "A03 — OS Command Injection (cs/command-line-injection)",
  "status":             "passed",
  "labels": [
    { "name": "suite",    "value": "A03:2025 Injection" },
    { "name": "severity", "value": "critical" },
    { "name": "tag",      "value": "OWASP-A03" }
  ],
  "links": [
    { "name": "OWASP A03:2025", "url": "https://owasp.org/...", "type": "issue" },
    { "name": "GitHub Actions Run", "url": "...", "type": "tms" }
  ]
}
```

The `historyId` is stable across runs (it is the `externalId`), which allows Allure TestOps to track history and calculate trend data.

---

## 4. DevOps Engineer Guide

### 4.1 Prerequisites

Before onboarding a repository, confirm the following:

| Prerequisite | How to verify |
|---|---|
| GitHub Advanced Security (GHAS) is enabled on the repository | Repo → Settings → Security → Code security → Code scanning |
| The repository is owned by the `latrobehealth` org | Check the repo URL |
| `exp-sast-security-workflows` is accessible to the repo's runners | If the app repo is private and this repo is also private, `canary-token` secret is required |
| Python 3.10+ is available on the runner | Default for `ubuntu-latest` GitHub-hosted runners — no action required |
| .NET SDK is available on the runner (for .NET projects) | Default for `ubuntu-latest` via `actions/setup-dotnet` — no action required |

### 4.2 GitHub Repository Settings

Enable the following in the application repository before the first scan:

**1. Code Scanning (GitHub Advanced Security)**

```
Settings → Security → Code security and analysis
  → Code scanning → Enable
```

This must be enabled before SARIF uploads will succeed. Without it, the `Upload SARIF to GitHub Advanced Security` step fails silently on public repos and throws an error on private repos.

**2. Dependabot (for ongoing supply chain monitoring)**

Create `.github/dependabot.yml` in the application repository:

```yaml
version: 2
updates:
  - package-ecosystem: nuget        # or npm, pip, etc.
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 10
```

This runs weekly and opens PRs when dependencies have updates. `dependency-review-reusable.yml` then checks those PRs for CVEs.

**3. Branch protection rules (recommended)**

Add the following to the `main` branch protection rule:

```
Settings → Branches → main
  → Require status checks to pass before merging
    ✓ CodeQL / analyze (javascript-typescript)   ← adjust to your languages
    ✓ CodeQL / analyze (csharp)
    ✓ Dependency Review / dependency-review
```

This prevents merging code that introduces new security findings.

### 4.3 Secrets and Variables

Configure these at the **organisation** level in GitHub (preferred — inherited by all repos) or at the repository level.

**Organisation secrets (Settings → Secrets and variables → Actions):**

| Secret name | Value | Required for |
|---|---|---|
| `ALLURE_TESTOPS_URL` | `https://your-allure-instance.com` | Allure sync |
| `ALLURE_TESTOPS_API_TOKEN` | API token from Allure TestOps | Allure sync |

**Repository-level secret (only for private repos that call verify-canary):**

| Secret name | Value | Required for |
|---|---|---|
| `SECURITY_WORKFLOWS_PAT` | GitHub PAT with `contents:read` on `exp-sast-security-workflows` | Canary checkout when this repo is private |

### 4.4 Onboarding Checklist

Use this checklist for each repository being onboarded.

```
Repository: ____________________________
Language(s): ____________________________
Date: ____________________________
Engineer: ____________________________

PRE-CHECKS
[ ] GitHub Advanced Security enabled in repository settings
[ ] Dependabot enabled (dependabot.yml created)
[ ] Organisation secrets ALLURE_TESTOPS_URL and ALLURE_TESTOPS_API_TOKEN confirmed set

WORKFLOW FILES
[ ] .github/workflows/security-sast.yml created with correct languages array
[ ] .github/workflows/security-deps.yml created
[ ] First CI run completed successfully (both workflows green)

ALERTS
[ ] Security → Code scanning tab shows alerts (or "No code scanning alerts")
[ ] OWASP tags (e.g. A05:2025) appear on at least one alert (confirms enrichment ran)

ALLURE TESTOPS (if applicable)
[ ] allure-project-name set correctly in security-sast.yml
[ ] Allure TestOps project visible with 10 OWASP test cases created
[ ] First launch visible in the test plan

BRANCH PROTECTION (recommended)
[ ] Code scanning checks added to main branch protection rules

SIGN-OFF
[ ] App team tech lead notified: security findings are now visible in Security tab
[ ] Triage session scheduled with tech lead for any existing alerts
```

---

## 5. Software Engineer Guide

This section covers what you need to add to each type of project. You will be adding **two workflow files** to your repository — nothing else changes in your codebase.

### 5.1 .NET C# — Azure API App

Azure API Apps are standard ASP.NET Core Web API applications. CodeQL analyses them as C# with `build-mode: autobuild`, which works for the vast majority of projects.

**Create `.github/workflows/security-sast.yml`:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: "0 3 * * 1"     # weekly Monday 03:00 UTC — catches new rules

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages:           '["csharp"]'
      build-mode:          autobuild
      allure-project-name: my-api-service   # replace with your service name
    secrets:
      ALLURE_TESTOPS_URL:       ${{ secrets.ALLURE_TESTOPS_URL }}
      ALLURE_TESTOPS_API_TOKEN: ${{ secrets.ALLURE_TESTOPS_API_TOKEN }}
```

**Create `.github/workflows/security-deps.yml`:**

```yaml
name: Security — Dependency Review

on:
  pull_request:
    branches: [main, develop]

jobs:
  dependency-review:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/dependency-review-reusable.yml@main
    secrets: inherit
```

**When build-mode: manual is needed:**

Use `manual` if any of these are true:
- Your solution has a custom pre-build step (code generation, protobuf, T4 templates)
- You use a non-standard project structure or a makefile
- `autobuild` runs but CodeQL reports zero C# results

```yaml
    with:
      languages:  '["csharp"]'
      build-mode: manual
```

The workflow's `manual` step runs `dotnet build --configuration Release /p:UseSharedCompilation=false`. If your project needs a different build command, you will need a fork or an extension of the reusable workflow. Contact Security Engineering.

**Common findings in .NET API Apps and how to fix them:**

| Alert | Root cause | Fix |
|---|---|---|
| `cs/sql-injection` | `FromSqlRaw("... " + value)` or `ExecuteSqlRaw` with concatenation | Use parameterised queries: `FromSqlRaw("SELECT * FROM X WHERE Name = {0}", value)` or LINQ |
| `cs/command-line-injection` | `ProcessStartInfo` with user-controlled arguments | Validate and allowlist input; avoid shell invocations; use specific APIs instead of shelling out |
| `cs/path-injection` | `File.ReadAllText(Path.Combine(root, userInput))` | Canonicalise path and confirm it starts with the expected base: `Path.GetFullPath(result).StartsWith(expectedBase)` |
| `cs/web/xss` | `Content(userInput, "text/html")` or writing to response without encoding | Use `HtmlEncoder.Default.Encode(value)` or return `ObjectResult` which serialises as JSON |
| `cs/hardcoded-credentials` | `new NetworkCredential("user", "password123")` literal string | Move to Azure Key Vault or environment variables; retrieve at runtime |
| `cs/log-forging` | `_logger.LogInformation("...{input}", userInput)` | Sanitise log inputs: strip newlines and ANSI codes; do not log raw credentials or tokens |
| `cs/web/unvalidated-url-redirect` | `return Redirect(Request.Query["returnUrl"])` | Validate against an allowlist: `if (!Url.IsLocalUrl(returnUrl)) return BadRequest()` |
| `cs/use-of-broken-or-weak-cryptographic-algorithm` | `MD5.Create()`, `SHA1.Create()`, `DES.Create()` | Use `SHA256` for integrity; `PBKDF2` / `Argon2` for password hashing; `AES-256-GCM` for encryption |

---

### 5.2 .NET C# — Azure Functions

Azure Functions V4 (.NET isolated model) are structurally similar to ASP.NET Core — they are C# class libraries compiled with dotnet. CodeQL handles them identically to API Apps. The same `csharp` language identifier and `autobuild` build mode apply.

**Create `.github/workflows/security-sast.yml`:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages:           '["csharp"]'
      build-mode:          autobuild
      allure-project-name: my-function-app   # replace with your function app name
    secrets:
      ALLURE_TESTOPS_URL:       ${{ secrets.ALLURE_TESTOPS_URL }}
      ALLURE_TESTOPS_API_TOKEN: ${{ secrets.ALLURE_TESTOPS_API_TOKEN }}
```

**Create `.github/workflows/security-deps.yml`:**

```yaml
name: Security — Dependency Review

on:
  pull_request:
    branches: [main, develop]

jobs:
  dependency-review:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/dependency-review-reusable.yml@main
    secrets: inherit
```

**Function-specific vulnerability patterns to watch for:**

Azure Functions receive data from triggers (HTTP, Service Bus, Blob Storage, Event Hub, etc.). All trigger inputs are taint sources for CodeQL — meaning data flowing from any of these can trigger a finding.

| Trigger | Taint source | Common finding |
|---|---|---|
| HTTP trigger | `HttpRequestData`, query parameters, request body | SQL injection, command injection, XSS, path traversal |
| Blob trigger | Blob name from trigger metadata | Path traversal if blob name used in file I/O |
| Queue/Service Bus | Message body as string | SQL injection if message content used in queries |
| Timer trigger | No external input | Generally low risk; no user-controlled data |

**Example — secure HTTP trigger:**

```csharp
// ❌ Vulnerable — query parameter flows to SQL
[Function("SearchItems")]
public async Task<HttpResponseData> SearchItems(
    [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequestData req)
{
    var term = req.Query["term"];
    var results = _db.Items.FromSqlRaw("SELECT * FROM Items WHERE Name = '" + term + "'").ToList();
    // ...
}

// ✅ Fixed — parameterised query
[Function("SearchItems")]
public async Task<HttpResponseData> SearchItems(
    [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequestData req)
{
    var term = req.Query["term"];
    var results = _db.Items.Where(i => i.Name == term).ToList();
    // ...
}
```

---

### 5.3 Next.js — Azure Web App

Next.js applications are TypeScript/JavaScript. CodeQL scans them with the `javascript-typescript` language identifier and `build-mode: none` (no compilation needed — CodeQL extracts directly from source).

**Create `.github/workflows/security-sast.yml`:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["javascript-typescript"]'
      # build-mode defaults to "none" — correct for JS/TS
    secrets: inherit
```

> **Note:** Allure TestOps sync is currently only implemented for C# SARIF results. The `allure-project-name` input is ignored for non-csharp languages. If you need Allure sync for JavaScript findings, contact Security Engineering.

**Create `.github/workflows/security-deps.yml`:**

```yaml
name: Security — Dependency Review

on:
  pull_request:
    branches: [main, develop]

jobs:
  dependency-review:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/dependency-review-reusable.yml@main
    with:
      allow-licenses: "MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD"
    secrets: inherit
```

**Common findings in Next.js and how to fix them:**

| Alert | Root cause | Fix |
|---|---|---|
| `js/xss` | `dangerouslySetInnerHTML={{ __html: userInput }}` in React | Never use `dangerouslySetInnerHTML` with user content. Use React's default rendering which escapes automatically. |
| `js/sql-injection` | API routes using string concatenation with Prisma raw SQL or `pg.query("... " + value)` | Use parameterised queries: `prisma.$queryRaw\`SELECT * FROM X WHERE id = ${id}\`` or `pg.query("... $1", [value])` |
| `js/path-injection` | `fs.readFile(path.join(__dirname, req.query.file))` in API routes | Validate and resolve path: confirm resolved path is within expected directory |
| `js/server-side-unvalidated-url-redirect` | `res.redirect(req.query.returnUrl)` | Validate against allowlist or use relative paths only |
| `js/missing-rate-limiting` | API routes with no rate limiting | Add `express-rate-limit` or Azure API Management policy |
| `js/hard-coded-credentials` | `const apiKey = "sk-prod-abc123"` | Move to environment variables; use Azure Key Vault references for App Service |

**Next.js-specific patterns:**

```typescript
// ❌ Vulnerable — getServerSideProps with user-controlled redirect
export async function getServerSideProps(context) {
  const { returnUrl } = context.query;
  return { redirect: { destination: returnUrl } };  // Open redirect
}

// ✅ Fixed — validate against allowlist
export async function getServerSideProps(context) {
  const { returnUrl } = context.query;
  const allowedPaths = ['/dashboard', '/profile', '/home'];
  const destination = allowedPaths.includes(returnUrl) ? returnUrl : '/home';
  return { redirect: { destination } };
}
```

```typescript
// ❌ Vulnerable — API route with SQL string concatenation
// pages/api/search.ts
export default async function handler(req, res) {
  const { term } = req.query;
  const results = await prisma.$queryRawUnsafe(`SELECT * FROM items WHERE name = '${term}'`);
  res.json(results);
}

// ✅ Fixed — parameterised query
export default async function handler(req, res) {
  const { term } = req.query;
  const results = await prisma.items.findMany({ where: { name: term } });
  res.json(results);
}
```

**Azure Static Web Apps / Azure App Service — important note:**

When deploying Next.js to Azure, ensure environment variables containing secrets are set as **Application Settings** in the Azure portal (or via Bicep/ARM), not committed to the repository. CodeQL will flag any hardcoded API keys, connection strings, or credentials.

---

### 5.4 Blazor — Azure Web App

Blazor applications are compiled as C# — both Blazor Server (runs on server) and Blazor WebAssembly (runs in browser). CodeQL treats them identically to any other ASP.NET Core project and uses the `csharp` language identifier.

**Create `.github/workflows/security-sast.yml`:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages:           '["csharp"]'
      build-mode:          autobuild
      allure-project-name: my-blazor-app   # replace with your app name
    secrets:
      ALLURE_TESTOPS_URL:       ${{ secrets.ALLURE_TESTOPS_URL }}
      ALLURE_TESTOPS_API_TOKEN: ${{ secrets.ALLURE_TESTOPS_API_TOKEN }}
```

**Create `.github/workflows/security-deps.yml`:**

```yaml
name: Security — Dependency Review

on:
  pull_request:
    branches: [main, develop]

jobs:
  dependency-review:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/dependency-review-reusable.yml@main
    secrets: inherit
```

**Blazor-specific vulnerability patterns:**

Blazor's component model handles most XSS automatically through its rendering pipeline — `@variable` bindings are HTML-encoded by default. However, certain patterns bypass this protection:

| Pattern | Risk | Fix |
|---|---|---|
| `@((MarkupString)userInput)` | **XSS** — renders raw HTML from user-controlled value | Never cast user input to `MarkupString`. If rendering HTML is required, sanitise with `HtmlSanitizer` first. |
| `NavigationManager.NavigateTo(returnUrl)` | **Open redirect** if `returnUrl` comes from a query parameter | Validate: `if (!returnUrl.StartsWith("/")) return;` |
| `IJSRuntime.InvokeAsync("eval", userInput)` | **Script injection** | Never pass user input to JavaScript `eval`. |
| Calling backend API with credentials from `localStorage` | **XSS consequence** — if XSS is possible, attacker can read tokens | Use `HttpOnly` cookies for authentication tokens in Blazor Server. |

```razor
@* ❌ Vulnerable — raw HTML from user *@
@((MarkupString)comment.Content)

@* ✅ Fixed — plain text (auto-escaped by Blazor) *@
@comment.Content

@* ✅ Fixed — sanitised HTML if formatting is needed *@
@((MarkupString)_sanitizer.Sanitize(comment.Content))
```

```csharp
// ❌ Vulnerable — unvalidated redirect in code-behind
[Parameter]
[SupplyParameterFromQuery]
public string? ReturnUrl { get; set; }

protected override void OnInitialized()
{
    NavigationManager.NavigateTo(ReturnUrl ?? "/");
}

// ✅ Fixed — local paths only
protected override void OnInitialized()
{
    var target = ReturnUrl;
    if (string.IsNullOrEmpty(target) || !target.StartsWith("/") || target.StartsWith("//"))
        target = "/";
    NavigationManager.NavigateTo(target);
}
```

**Blazor WebAssembly — additional considerations:**

CodeQL analyses the C# source code that compiles to WebAssembly. Do not store secrets in Blazor WASM code — they are accessible to anyone who downloads the WASM bundle. All sensitive operations must go through a backend API that validates authentication.

---

## 6. Understanding and Resolving Security Alerts

### 6.1 Navigating the GitHub Security Tab

After the first scan completes, alerts appear in the application repository:

```
Repository → Security → Code scanning
```

Each alert shows:
- **Title** — the CodeQL rule name, e.g. "Uncontrolled command line"
- **Severity** — Critical / High / Medium / Low (set by CodeQL)
- **Branch** — which branch has the finding
- **Tags** — `correctness`, `security`, and the OWASP category e.g. `A05:2025` (injected by our enrichment)
- **Weaknesses** — CWE identifiers, e.g. `CWE-78`, `CWE-88` (populated by CodeQL)
- **Show more** — the rule description plus an OWASP reference link (injected by our enrichment)
- **Show paths** — the full data-flow path from the taint source (user input) to the sink (vulnerable call)

### 6.2 Reading the Data Flow Paths

Click **Show paths** on any alert to see the taint flow. For a SQL injection this might look like:

```
Source:  SearchController.cs:12  → string term = Request.Query["term"]
         ↓ (taint flows through)
Step 1:  SearchController.cs:14  → var query = "SELECT ... '" + term + "'"
         ↓
Sink:    SearchController.cs:15  → _db.Items.FromSqlRaw(query)
```

This tells you exactly where the user-controlled data enters, how it flows through the code, and where it reaches the dangerous sink. Fix the code at the source (validate/sanitise input) or at the sink (use parameterised APIs) — fixing at the sink is usually safer and simpler.

### 6.3 Triage Process

When new alerts appear, the following process applies:

**Step 1 — Is the finding a true positive?**

Read the code path shown in the alert. Ask:
- Does this code path actually execute with real user input?
- Could an attacker reach this endpoint without authentication?
- Is the vulnerable pattern in production code or test code?

Most CodeQL alerts for the `security-extended` suite are true positives. False positives are uncommon but do occur, particularly when input is validated in a way CodeQL cannot statically verify.

**Step 2 — Assess severity**

| Alert level | Response SLA |
|---|---|
| Critical | Fix before next production deployment |
| High | Fix within current sprint |
| Medium | Schedule for next sprint |
| Low | Backlog — address when in the area |

**Step 3 — Fix and verify**

Fix the code, push a commit or PR, and confirm the alert is automatically closed once the scan runs on the fixed code. GitHub will mark the alert as "Fixed" and associate it with the commit that resolved it.

### 6.4 Dismissing False Positives

If you are certain an alert is a false positive:

1. Click the alert → **Dismiss alert**
2. Select a reason:
   - **False positive** — the code is not actually exploitable
   - **Won't fix** — accepted risk, documented
   - **Used in tests** — the vulnerable pattern only appears in test code
3. Write a comment explaining why. This is audited by Security Engineering.

> **Do not dismiss without a comment.** Unexplained dismissals are flagged in our security compliance reporting.

### 6.5 Fix Patterns per OWASP Category

#### A01 — Broken Access Control

**Path traversal:**
```csharp
// ❌
var content = File.ReadAllText(Path.Combine("C:\\data", fileName));

// ✅
var safePath = Path.GetFullPath(Path.Combine("C:\\data", fileName));
if (!safePath.StartsWith(Path.GetFullPath("C:\\data")))
    return BadRequest("Invalid file path.");
var content = File.ReadAllText(safePath);
```

**Missing access control:**
```csharp
// ❌
[HttpDelete("admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) { ... }

// ✅
[Authorize(Roles = "Admin")]
[HttpDelete("admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) { ... }
```

#### A04 — Cryptographic Failures

```csharp
// ❌ — broken algorithms
using var md5 = MD5.Create();
using var sha1 = SHA1.Create();
using var des = DES.Create();

// ✅ — password hashing
var hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

// ✅ — data integrity / non-password hashing
using var sha256 = SHA256.Create();
var hash = sha256.ComputeHash(data);

// ✅ — symmetric encryption
using var aes = Aes.Create();
aes.KeySize = 256;
aes.Mode = CipherMode.GCM;   // Use AesGcm class in .NET 6+
```

#### A05 — Injection

```csharp
// ❌ SQL injection
var results = _db.FromSqlRaw("SELECT * FROM Items WHERE Name = '" + term + "'");

// ✅ Parameterised
var results = _db.Items.Where(i => i.Name == term).ToList();
// OR
var results = _db.FromSqlRaw("SELECT * FROM Items WHERE Name = {0}", term);

// ❌ Command injection
var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 1 " + host);

// ✅ No shell; explicit arguments array
var psi = new ProcessStartInfo("ping") { ArgumentList = { "-n", "1", host } };
// Better: validate host is a valid hostname/IP before passing it at all
if (!Uri.CheckHostName(host).Equals(UriHostNameType.Dns))
    return BadRequest("Invalid host.");
```

#### A07 — Authentication Failures

```csharp
// ❌ Hardcoded credential
var cred = new NetworkCredential("sa", "P@ssword123!");

// ✅ From Key Vault / configuration
var password = _configuration["DatabasePassword"];  // Set via Azure Key Vault reference
var cred = new NetworkCredential("sa", password);

// ❌ Logging credentials
_logger.LogInformation("Login: user={User} password={Pass}", username, password);

// ✅ Never log credentials; log only non-sensitive identity
_logger.LogInformation("Login attempt for user: {User}", username);
```

---

## 7. Allure TestOps Dashboard

### 7.1 What You Will See

After the first successful run with `allure-project-name` configured, your Allure TestOps instance will have:

**Project** (named after `allure-project-name`):
- 10 test cases, one per OWASP class the scanner covers
- Each test case tagged: `OWASP-A01`, `CodeQL`, `SAST`, `security-extended`
- Each test case linked to the OWASP reference URL

**Test Plan** (named `OWASP Security — main`):
- Created once per branch, reused on every run
- All 10 test cases linked to the plan

**Launches** (one per CI run):
- Named: `Application Security Scan — main — run #12345`
- Linked to the test plan
- Contains one result per OWASP class

### 7.2 Pass/Fail Logic

| Scenario | Allure result |
|---|---|
| Zero production `cs/sql-injection` findings in SARIF | A03 — SQL Injection: **PASSED** |
| One or more `cs/sql-injection` findings in production code | A03 — SQL Injection: **FAILED** with file path and line number in the failure message |
| Finding exists but it is in `SastCanaryController` or test code | Finding excluded; treated as zero findings → **PASSED** |
| Allure TestOps unreachable | Step completes with warning; GitHub SARIF upload still succeeds |

### 7.3 How to Use the Dashboard

**To see the current security health of a project:**
1. Open Allure TestOps → select the project
2. Go to **Test Plans** → open `OWASP Security — main`
3. The latest launch shows pass/fail per OWASP class
4. Click a failed test case to see the finding details (file, line, message)

**To track trends over time:**
1. Open a test case (e.g. `A03 — SQL Injection`)
2. Go to the **History** tab
3. See whether this class has been passing or failing across branches and time

**To compare branches:**
- Each branch has its own test plan (`OWASP Security — develop`, `OWASP Security — feature/xyz`)
- Compare test plans to see if a feature branch introduced new security findings

---

## 8. Maintaining the Solution

### 8.1 Updating the OWASP CWE Mapping

When OWASP publishes a new Top 10:
1. Fetch the new category pages from `owasp.org/Top10/{year}/`
2. Update `.github/codeql/cwe-to-owasp-2025.json`:
   - Add new CWEs to `cwe_map`
   - Update category names and URLs in `categories`
3. Update the inline comment block in `.github/workflows/codeql-reusable.yml`
4. Update the OWASP coverage table in `README.md`
5. Update the `OWASP_TEST_CASES` catalogue in `scripts/allure-testops-sync.py`
6. Update canary patterns in `canary/Controllers/SastCanaryController.cs` and `canary/scripts/verify-canary.py`

### 8.2 Adding a New Language

To add support for a new CodeQL language (e.g. Go, Python, Ruby):
1. Add the language identifier to the documentation in `README.md` and this guide
2. No changes to the workflow are needed — `codeql-reusable.yml` accepts any CodeQL language via the `languages` input
3. Test with a repository that uses the new language: set `languages: '["go"]'` and confirm the scan runs
4. Note: Allure sync currently only processes `csharp.sarif` — extend `allure-testops-sync.py` if sync is needed for other languages

### 8.3 When the Canary Fails

If the `Verify OWASP Canary` job fails, it means a CodeQL rule that was previously expected to fire did not fire. This is a scanner regression.

**Triage steps:**
1. Check the job summary table — which specific rule(s) failed?
2. Check if the `security-extended` query suite was updated (CodeQL publishes changelogs at [github.com/github/codeql](https://github.com/github/codeql))
3. Check if the canary pattern needs updating (the rule may still exist but require a different code pattern)
4. If the rule was intentionally removed from `security-extended`, remove it from `EXPECTED` in `verify-canary.py` and document why

Do not dismiss canary failures without understanding the cause. A silent scanner is more dangerous than one that finds false positives.

### 8.4 Versioning and Supply Chain

Currently, calling workflows reference this repo at `@main`. For production use, pin to a commit SHA:

```yaml
uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@a1b2c3d4
```

This prevents an unreviewed commit to this repo from affecting production CI runs. The trade-off is that teams must explicitly update the SHA to receive fixes and improvements. Choose the right balance for your organisation's risk profile.

---

*This guide is maintained by the Security Engineering team. For questions, raise an issue in `latrobehealth/exp-sast-security-workflows` or contact the Security Engineering team directly.*
