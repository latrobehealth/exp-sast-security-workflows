# Security Workflows

Reusable GitHub Actions workflows for static application security testing (SAST), centrally maintained by the Security Engineering team and consumed by application repositories across the organisation.

> **Org:** `latrobehealth` · **Repo:** `exp-sast-security-workflows`

---

## Contents

- [Quick Start](#quick-start)
- [OWASP Top 10:2025 Coverage](#owasp-top-102025-coverage)
- [Workflow Reference](#workflow-reference)
  - [codeql-reusable.yml](#codeql-reusableyml--codeql-analysis)
  - [dependency-review-reusable.yml](#dependency-review-reusableyml--dependency-review)
- [SARIF Enrichment](#sarif-enrichment--owasp-tags-in-github)
- [SAST Canary](#sast-canary)
- [Allure TestOps Integration](#allure-testops-integration)
- [Complementary Controls](#complementary-controls)
- [Repository Structure](#repository-structure)
- [Adding New Workflows](#adding-new-workflows)
- [Security & Compliance](#security--compliance)

---

## Quick Start

Add two workflow files to your application repository. Replace the `languages` value with the languages your project uses.

### Step 1 — CodeQL (SAST scan on every push and PR)

Create `.github/workflows/security-sast.yml` in your application repo:

**JavaScript / TypeScript project:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"   # weekly, Monday 03:00 UTC

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["javascript-typescript"]'
    secrets: inherit
```

**.NET / C# project:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
    secrets: inherit
```

**Java / Kotlin project:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["java-kotlin"]'
      build-mode: autobuild
    secrets: inherit
```

**Python project:**

```yaml
name: Security — SAST

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["python"]'
    secrets: inherit
```

**Multi-language project:**

```yaml
jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp", "javascript-typescript"]'
      build-mode: autobuild
    secrets: inherit
```

> After the workflow runs, findings appear in your repo under **Security → Code scanning**. Each alert will show the OWASP Top 10:2025 category tag (e.g. `A05:2025`) and a clickable OWASP reference link in the rule detail panel.

---

### Step 2 — Dependency Review (supply chain scan on every PR)

Create `.github/workflows/security-deps.yml` in your application repo:

```yaml
name: Security — Dependency Review

on:
  pull_request:
    branches: [main]

jobs:
  dependency-review:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/dependency-review-reusable.yml@main
    secrets: inherit
```

This blocks PRs that introduce dependencies with known high or critical CVEs and posts a summary comment on the PR.

---

### Full security pipeline (both workflows together)

```yaml
# .github/workflows/security.yml
name: Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
    secrets: inherit

  dependency-review:
    if: github.event_name == 'pull_request'
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/dependency-review-reusable.yml@main
    secrets: inherit
```

---

## OWASP Top 10:2025 Coverage

The table below maps each [OWASP Top 10:2025](https://owasp.org/Top10/2025/) category to the workflow(s) that provide coverage. SARIF enrichment automatically tags every GitHub code-scanning alert with the matching OWASP category ID.

| # | Category | CodeQL | Dep Review | Notes |
|---|---|:---:|:---:|---|
| A01 | [Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) | Partial | — | Path traversal, missing access control, open redirect, SSRF (CWE-918). Logic-based access control requires manual review. |
| A02 | [Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) | Partial | — | Code-level insecure defaults and stack-trace exposure caught by CodeQL. IaC misconfigurations require Checkov / Trivy. |
| A03 | [Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) | — | **Yes** | CVE detection on added/changed dependencies. Pair with Dependabot for automated updates. |
| A04 | [Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) | **Yes** | Partial | Weak algorithms (MD5/SHA1), insecure RNG, hardcoded secrets. Dependency Review flags deps with crypto CVEs. |
| A05 | [Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) | **Yes** | — | SQL, OS command, XSS, path, template, LDAP, XML injection. Core CodeQL strength. |
| A06 | [Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/) | — | — | Architectural weakness — requires threat modelling and design review. Not detectable via SAST. |
| A07 | [Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) | Partial | — | Hardcoded credentials, log forging (credential/token exposure). Runtime auth logic requires manual review. |
| A08 | [Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/) | Partial | Partial | XXE, unsafe deserialization (CodeQL). Vulnerable dependency versions (Dependency Review). |
| A09 | [Security Logging & Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | Partial | — | Log injection / forging (sensitive data written to logs). Runtime monitoring requires a SIEM. |
| A10 | [Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) | Partial | — | Information leakage via exceptions and stack traces. |

**Legend:** **Yes** = primary coverage · Partial = some but not full coverage · — = not applicable

---

## Workflow Reference

### `codeql-reusable.yml` — CodeQL Analysis

Runs [GitHub CodeQL](https://codeql.github.com/) static analysis, enriches the SARIF output with OWASP Top 10:2025 tags and references, then uploads to GitHub Advanced Security.

#### Inputs

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| `languages` | `string` | **Yes** | — | JSON array of CodeQL language identifiers, e.g. `'["csharp","javascript-typescript"]'` |
| `build-mode` | `string` | No | `none` | `none` (interpreted), `autobuild`, or `manual` |
| `runner` | `string` | No | `ubuntu-latest` | GitHub-hosted or self-hosted runner label |
| `query-suite` | `string` | No | `security-extended` | `security-extended`, `security-and-quality`, or a path to a custom `.qls` suite |
| `verify-canary` | `boolean` | No | `false` | Run the SAST canary to verify OWASP Top 10:2025 detection coverage (see [SAST Canary](#sast-canary)) |
| `allure-project-name` | `string` | No | `""` | Allure TestOps project name for the calling repo (e.g. `exp-membership-service`). Leave empty to skip Allure sync entirely (see [Allure TestOps Integration](#allure-testops-integration)) |

#### Secrets

| Secret | Required | Description |
|---|---|---|
| `canary-token` | No | PAT with `contents:read` on `exp-sast-security-workflows`. Required only if the repo is private. Omit for internal/public repos. |
| `ALLURE_TESTOPS_URL` | No | Allure TestOps base URL, e.g. `https://allure.example.com`. Omit to skip Allure sync. |
| `ALLURE_TESTOPS_API_TOKEN` | No | Allure TestOps API token for authentication. Omit to skip Allure sync. |

#### Permissions granted by this workflow

| Permission | Level | Reason |
|---|---|---|
| `contents` | `read` | Check out source code |
| `security-events` | `write` | Upload SARIF to GitHub Advanced Security |
| `packages` | `read` | Pull CodeQL bundles |

#### Supported language identifiers

| Language | Identifier |
|---|---|
| C# / .NET | `csharp` |
| JavaScript / TypeScript | `javascript-typescript` |
| Java / Kotlin | `java-kotlin` |
| Python | `python` |
| Go | `go` |
| Ruby | `ruby` |
| C / C++ | `cpp` |
| Swift | `swift` |

#### Build mode guide

| Mode | When to use |
|---|---|
| `none` | Interpreted languages (JavaScript, Python, Ruby, Go). CodeQL does not require a build step. |
| `autobuild` | Compiled languages (.NET, Java, Kotlin) where CodeQL can infer the build command. Start here. |
| `manual` | Compiled languages with custom build steps. The workflow runs `dotnet build` for C#; extend for other toolchains. |

#### Advanced examples

**Highest coverage query suite (`security-and-quality`):**

```yaml
jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
      query-suite: security-and-quality
    secrets: inherit
```

**Self-hosted runner:**

```yaml
jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["java-kotlin"]'
      build-mode: autobuild
      runner: self-hosted-linux-large
    secrets: inherit
```

**With SAST canary coverage check:**

```yaml
jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
      verify-canary: true
    secrets: inherit
```

**With Allure TestOps sync:**

```yaml
jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
      allure-project-name: my-repo-name
    secrets:
      ALLURE_TESTOPS_URL:       ${{ secrets.ALLURE_TESTOPS_URL }}
      ALLURE_TESTOPS_API_TOKEN: ${{ secrets.ALLURE_TESTOPS_API_TOKEN }}
```

---

### `dependency-review-reusable.yml` — Dependency Review

Scans dependency manifest changes introduced by a pull request for known CVEs and licence policy violations using [actions/dependency-review-action](https://github.com/actions/dependency-review-action). Covers **A03** (Supply Chain Failures) from OWASP Top 10:2025.

> **Note:** Only runs on pull request events. It has no effect on direct pushes to a branch.

#### Inputs

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| `fail-on-severity` | `string` | No | `high` | Minimum CVE severity to fail the check: `critical`, `high`, `moderate`, `low` |
| `allow-licenses` | `string` | No | `""` | Comma-separated SPDX licence identifiers to permit; empty = allow all |
| `deny-packages` | `string` | No | `""` | Comma-separated `ecosystem:name` packages to block unconditionally |
| `comment-summary-in-pr` | `string` | No | `always` | When to post a summary comment on the PR: `always`, `on-failure`, `never` |

#### Permissions granted

| Permission | Level | Reason |
|---|---|---|
| `contents` | `read` | Read dependency manifests |
| `pull-requests` | `write` | Post review summary comment on the PR |

#### Examples

**Enforce licence policy and block specific packages:**

```yaml
jobs:
  dependency-review:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/dependency-review-reusable.yml@main
    with:
      fail-on-severity: moderate
      allow-licenses: "MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC"
      deny-packages: "npm:event-stream, npm:node-ipc"
    secrets: inherit
```

---

## SARIF Enrichment — OWASP Tags in GitHub

After CodeQL analysis, the `.github/scripts/enrich-sarif-owasp.py` script automatically enriches the SARIF file before it is uploaded to GitHub Advanced Security. No configuration is required — this runs transparently inside `codeql-reusable.yml`.

**What it adds to each alert in the GitHub Security tab:**

| Field | Added value | Where it appears |
|---|---|---|
| **Tags** | OWASP category ID e.g. `A05:2025` | Tags chip row on the alert detail page |
| **Rule help** | Markdown block with category name and clickable OWASP URL | "Show more" panel on the alert detail page |

The enrichment is driven by `.github/codeql/cwe-to-owasp-2025.json`, which maps 160+ CWE identifiers to their OWASP Top 10:2025 category sourced directly from [owasp.org/Top10/2025](https://owasp.org/Top10/2025/).

**Example — `cs/command-line-injection` (CWE-78, CWE-88) before and after enrichment:**

| | Before | After |
|---|---|---|
| Tags | `correctness` `security` | `correctness` `security` `A05:2025` |
| Help text | CodeQL docs link only | CodeQL docs link + OWASP A05:2025 Injection reference |

---

## SAST Canary

The canary is a self-contained .NET 9 project (`canary/`) containing **one intentional vulnerability per OWASP class** detectable by the CodeQL `security-extended` query suite. It is never deployed — it exists solely to verify that the scanner is healthy.

### How the canary works

1. When a caller sets `verify-canary: true`, the `verify-canary` job in `codeql-reusable.yml` checks out this repository and runs CodeQL against `canary/`.
2. Results are uploaded to the calling repo's Security tab under the distinct category `/language:csharp/sast-canary` so canary alerts are clearly separated from real findings.
3. `canary/scripts/verify-canary.py` reads the SARIF output and asserts every expected rule fired. It writes a coverage table to the GitHub Actions job summary and exits with code `1` if any class was missed — failing the CI job.

### Rules verified by the canary

| OWASP Class | CodeQL Rule | Vulnerability Pattern |
|---|---|---|
| A01 | `cs/path-injection` | User-controlled filename passed to `File.ReadAllText` |
| A01 | `cs/web/missing-function-level-access-control` | Admin endpoint with no `[Authorize]` attribute |
| A04 | `cs/use-of-broken-or-weak-cryptographic-algorithm` | `MD5.Create()` / `SHA1.Create()` — two independent instances |
| A04 | `cs/hardcoded-credentials` | `NetworkCredential` with a literal password |
| A05 | `cs/sql-injection` | EF Core `FromSqlRaw` with string concatenation |
| A05 | `cs/command-line-injection` | `ProcessStartInfo` with user-controlled argument |
| A05 | `cs/web/xss` | User input concatenated (not interpolated) into raw HTML response |
| A05 | `cs/web/unvalidated-url-redirect` | `Redirect(returnUrl)` without allowlist check |
| A07/A09 | `cs/log-forging` | Credentials and bearer tokens written to log via `[FromQuery]` parameters |
| A08 | `cs/xml-injection` | XPath injection — user input in `doc.SelectSingleNode("//user[@id='"+id+"']")` |

> **Bonus rules** (not counted in pass/fail — require `security-and-quality` suite or depend on CodeQL model version):
> `cs/stack-trace-exposure` (A02), `cs/xml-external-entity` (A08 — XXE), `cs/ssrf` (A10)

### Enabling the canary in your pipeline

```yaml
jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
      verify-canary: true
    secrets: inherit
    # For private repos only — omit if exp-sast-security-workflows is internal/public:
    # secrets:
    #   canary-token: ${{ secrets.SECURITY_WORKFLOWS_PAT }}
```

The canary job summary appears in the GitHub Actions run alongside the main scan:

```
## SAST Canary — OWASP Top 10:2025 Coverage
| OWASP 2025 | Vulnerability Class       | CodeQL Rule                    | Status       |
|------------|---------------------------|--------------------------------|--------------|
| A01        | Path Traversal            | cs/path-injection              | ✅ Detected  |
| A05        | SQL Injection             | cs/sql-injection               | ✅ Detected  |
| A05        | OS Command Injection      | cs/command-line-injection      | ✅ Detected  |
...
10/10 required vulnerability classes detected — scanner is healthy.
```

---

## Allure TestOps Integration

[Allure TestOps](https://qameta.io/) provides a test management layer on top of CI results. Security findings are tracked, triaged, and trended alongside functional test results in a single dashboard. The integration is built into `codeql-reusable.yml` via `scripts/allure-testops-sync.py` — no manual upload steps required in calling repos.

### How it works

`scripts/allure-testops-sync.py` runs automatically inside the `analyze` job (for C# scans) and the `verify-canary` job. It:

1. **Idempotently creates or finds** the Allure TestOps project (by `allure-project-name`), OWASP test cases, and a test plan per branch/version — so repeated runs never duplicate records.
2. **Creates a new launch** per GitHub Actions run ID, linked to the test plan, and records a result per OWASP class:
   - `application` scan: **PASS** = zero production findings for that OWASP class; **FAIL** = findings found in production code.
   - `canary` scan: **PASS** = expected CodeQL rule fired; **FAIL** = rule missed (scanner regression).
3. **Never blocks CI** — all Allure sync steps use `continue-on-error: true`. Missing credentials or network failures are logged to the GitHub Actions summary without failing the scan.

### Setup

Configure these secrets and variables at the **organisation** or **repository** level in GitHub:

| Name | Where | Description |
|---|---|---|
| `ALLURE_TESTOPS_URL` | Secret | Your Allure TestOps base URL, e.g. `https://allure.yourorg.com` |
| `ALLURE_TESTOPS_API_TOKEN` | Secret | API token from Allure TestOps → Profile → API Tokens |

### Enable in your workflow

Pass `allure-project-name` with the name of your Allure TestOps project (it will be created automatically if it does not exist):

```yaml
# .github/workflows/security-sast.yml
name: Security — SAST

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"

jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
      allure-project-name: exp-membership-service   # matches your Allure project name
    secrets:
      ALLURE_TESTOPS_URL:       ${{ secrets.ALLURE_TESTOPS_URL }}
      ALLURE_TESTOPS_API_TOKEN: ${{ secrets.ALLURE_TESTOPS_API_TOKEN }}
```

Omit `allure-project-name` (or leave it empty) to skip the Allure sync entirely — no secrets are required in that case.

### With canary enabled

When `verify-canary: true` is also set, a second Allure sync runs for the canary results under the fixed project name `exp-sast-security-workflows`, keeping scanner-health history separate from application security results:

```yaml
jobs:
  codeql:
    uses: latrobehealth/exp-sast-security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: autobuild
      allure-project-name: exp-membership-service
      verify-canary: true
    secrets:
      ALLURE_TESTOPS_URL:       ${{ secrets.ALLURE_TESTOPS_URL }}
      ALLURE_TESTOPS_API_TOKEN: ${{ secrets.ALLURE_TESTOPS_API_TOKEN }}
```

### What appears in Allure TestOps

| Allure concept | What it maps to |
|---|---|
| **Project** | Your repo / `allure-project-name` value |
| **Test cases** | One per OWASP Top 10:2025 class (A01–A10), tagged `OWASP-A0x`, `CodeQL`, `SAST` |
| **Test plan** | One per branch (e.g. `main`, `feature/auth-rewrite`) |
| **Launch** | One per GitHub Actions run — linked to the test plan |
| **Test result** | PASS / FAIL per OWASP class based on whether findings exist in production code |

---

## Complementary Controls

The following OWASP Top 10:2025 categories require controls outside this repository:

| Category | Recommended control |
|---|---|
| **A02 Security Misconfiguration** | [Checkov](https://www.checkov.io/) or [Trivy](https://github.com/aquasecurity/trivy) for IaC scanning (Terraform, Helm, Dockerfiles). GitHub's [Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) for CI/CD config. |
| **A03 Supply Chain Failures** | Enable [Dependabot version updates](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates) alongside `dependency-review-reusable.yml` to keep dependencies patched continuously. |
| **A06 Insecure Design** | Threat modelling (STRIDE / PASTA) at design time. Not detectable via automated tooling. |
| **A09 Logging & Alerting Failures** | Runtime log aggregation and alerting (Splunk, Datadog, Azure Sentinel). |

---

## Repository Structure

```
.
├── .github/
│   ├── codeql/
│   │   └── cwe-to-owasp-2025.json         # CWE → OWASP 2025 mapping (160+ CWEs)
│   ├── scripts/
│   │   └── enrich-sarif-owasp.py          # Injects OWASP tags into SARIF before upload
│   └── workflows/
│       ├── codeql-reusable.yml            # CodeQL SAST + SARIF enrichment + Allure sync + canary
│       └── dependency-review-reusable.yml # Dependency CVE and licence scan
├── canary/
│   ├── Controllers/
│   │   └── SastCanaryController.cs        # Intentional vulnerabilities (one per OWASP class)
│   ├── Data/
│   │   └── CanaryDbContext.cs             # EF Core InMemory context
│   ├── scripts/
│   │   └── verify-canary.py              # Asserts all expected CodeQL rules fired
│   ├── Program.cs
│   └── Sast.Canary.csproj
├── scripts/
│   └── allure-testops-sync.py            # Idempotent SARIF → Allure TestOps sync
└── README.md
```

---

## Adding New Workflows

1. Create `.github/workflows/<tool>-reusable.yml` using `on: workflow_call` with typed `inputs` and `secrets` blocks.
2. Grant only the minimum `permissions` required.
3. Add an inline comment block listing which OWASP Top 10:2025 categories the workflow covers (follow the format in `codeql-reusable.yml`).
4. Update `cwe-to-owasp-2025.json` if the new workflow surfaces additional CWE → OWASP mappings.
5. Update this README: add the workflow to the OWASP coverage table, add a Workflow Reference sub-section, and update the Repository Structure tree.

---

## Security & Compliance

- Findings appear in **Security → Code scanning** in each consuming repository.
- GitHub Advanced Security (GHAS) must be enabled on the consuming repository. GHAS is included for all public repositories and for organisations with a GHAS licence.
- Pinning the workflow reference to a commit SHA (e.g. `@a1b2c3d`) instead of `@main` provides supply-chain integrity and is recommended for production use.
- The OWASP coverage table and CWE mapping (`cwe-to-owasp-2025.json`) are reviewed and updated with each new OWASP Top 10 release.

---

## Contributing

Raise a pull request or GitHub Issue to propose a new workflow, report a false-positive in the canary, or update the OWASP mapping. Tag the Security Engineering team for review.
