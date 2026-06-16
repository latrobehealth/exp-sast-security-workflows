# Security Workflows

Reusable GitHub Actions workflows for static application security testing (SAST) — centrally maintained and consumed by application repositories across the organisation.

---

## Overview

This repository provides a library of reusable, parameterised security scanning workflows. Application teams call these workflows from their own CI pipelines without needing to own or maintain the underlying tooling configuration. All SARIF results are uploaded to GitHub Advanced Security so findings appear in the **Security** tab of each consuming repository.

---

## OWASP Top 10 2025 Coverage

The table below maps each [OWASP Top 10:2025](https://owasp.org/Top10/2025/) category to the workflow(s) in this repository that provide coverage, and notes where complementary controls outside CI are required.

| # | Category | CodeQL | Dependency Review | Notes |
|---|---|:---:|:---:|---|
| A01 | Broken Access Control | Partial | — | Path traversal, injection-based bypasses. Logic-based access control requires manual review. |
| A02 | Security Misconfiguration | Partial | — | Code-level insecure defaults caught by CodeQL. IaC misconfigurations require Checkov / Trivy. |
| A03 | Software Supply Chain Failures | — | **Yes** | CVE detection on added/changed dependencies. Pair with Dependabot for automated updates. |
| A04 | Cryptographic Failures | **Yes** | Partial | Weak algorithms, insecure RNG, hardcoded secrets. Dependency Review flags deps with crypto CVEs. |
| A05 | Injection | **Yes** | — | SQL, command, XSS, path, template, LDAP injection. Core CodeQL strength. |
| A06 | Insecure Design | — | — | Architectural weakness; requires threat modelling and design review — not detectable via SAST. |
| A07 | Authentication Failures | Partial | — | Hardcoded credentials and weak authentication patterns. Runtime auth logic needs manual review. |
| A08 | Software or Data Integrity Failures | Partial | Partial | Unsafe deserialization (CodeQL). Vulnerable dependency versions (Dependency Review). |
| A09 | Security Logging & Alerting Failures | — | — | Runtime concern; not detectable via SAST. Requires log aggregation and alerting platform. |
| A10 | Mishandling of Exceptional Conditions | Partial | — | Information leakage via exceptions. Full coverage requires runtime testing. |

**Legend:** **Yes** = primary tool for this category · Partial = some but not full coverage · — = not applicable

---

## Workflows

### `codeql-reusable.yml` — CodeQL Analysis

Runs [GitHub CodeQL](https://codeql.github.com/) static analysis against one or more languages using a matrix strategy. Covers **A01, A04, A05, A07, A08, A10** from OWASP Top 10:2025.

#### Inputs

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| `languages` | `string` | Yes | — | JSON array of CodeQL language identifiers, e.g. `'["javascript","python"]'` |
| `build-mode` | `string` | No | `none` | CodeQL build mode: `none`, `autobuild`, or `manual` |
| `runner` | `string` | No | `ubuntu-latest` | GitHub-hosted or self-hosted runner label |
| `query-suite` | `string` | No | `security-extended` | CodeQL query suite: `security-extended`, `security-and-quality`, or a custom suite path |

#### Permissions granted

| Permission | Level | Reason |
|---|---|---|
| `contents` | `read` | Checkout source code |
| `security-events` | `write` | Upload SARIF results to GitHub Advanced Security |
| `packages` | `read` | Pull CodeQL bundles from GitHub Packages |

#### Supported languages

Any language supported by CodeQL: `javascript`, `typescript`, `python`, `java`, `kotlin`, `csharp`, `cpp`, `c`, `go`, `ruby`, `swift`.

#### Build modes

| Mode | When to use |
|---|---|
| `none` | Interpreted languages (JavaScript, Python, Ruby, Go). CodeQL extracts without a build. |
| `autobuild` | Compiled languages where CodeQL can infer the build command automatically. |
| `manual` | Compiled languages with custom build requirements. The workflow includes a conditional step for .NET (`dotnet build`); extend it for other toolchains. |

#### Usage

**Minimal (interpreted language):**

```yaml
# .github/workflows/codeql.yml — in your application repo
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"   # weekly, Monday 03:00 UTC

jobs:
  codeql:
    uses: org/security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["javascript", "python"]'
    secrets: inherit
```

**Compiled language (.NET, manual build):**

```yaml
jobs:
  codeql:
    uses: org/security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["csharp"]'
      build-mode: manual
      query-suite: security-and-quality
    secrets: inherit
```

**Self-hosted runner with custom query suite:**

```yaml
jobs:
  codeql:
    uses: org/security-workflows/.github/workflows/codeql-reusable.yml@main
    with:
      languages: '["java", "kotlin"]'
      build-mode: autobuild
      runner: self-hosted-linux-large
      query-suite: ./.github/codeql/custom-queries.qls
    secrets: inherit
```

---

### `dependency-review-reusable.yml` — Dependency Review

Scans dependency changes introduced by a pull request for known CVEs and licence policy violations using [actions/dependency-review-action](https://github.com/actions/dependency-review-action). Covers **A03** (Supply Chain Failures) and contributes to **A04** and **A08** from OWASP Top 10:2025.

> **Note:** This workflow only runs on pull requests. It compares the dependency manifest between the base and head commits, so it has no effect on direct pushes to a branch.

#### Inputs

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| `fail-on-severity` | `string` | No | `high` | Minimum severity to fail the check: `critical`, `high`, `moderate`, `low` |
| `allow-licenses` | `string` | No | `""` | Comma-separated SPDX licence identifiers to permit; empty = allow all |
| `deny-packages` | `string` | No | `""` | Comma-separated `ecosystem:name` package identifiers to block unconditionally |
| `comment-summary-in-pr` | `string` | No | `always` | When to post a summary comment: `always`, `on-failure`, `never` |

#### Permissions granted

| Permission | Level | Reason |
|---|---|---|
| `contents` | `read` | Read dependency manifests |
| `pull-requests` | `write` | Post dependency review summary comment on the PR |

#### Usage

**Default (block high+ CVEs, all licences allowed):**

```yaml
# .github/workflows/dependency-review.yml — in your application repo
name: Dependency Review

on:
  pull_request:
    branches: [main]

jobs:
  dependency-review:
    uses: org/security-workflows/.github/workflows/dependency-review-reusable.yml@main
    secrets: inherit
```

**Enforce licence policy and block specific packages:**

```yaml
jobs:
  dependency-review:
    uses: org/security-workflows/.github/workflows/dependency-review-reusable.yml@main
    with:
      fail-on-severity: moderate
      allow-licenses: "MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC"
      deny-packages: "npm:event-stream, npm:node-ipc"
    secrets: inherit
```

---

## Complementary Controls (outside this repository)

The following OWASP Top 10:2025 categories are not fully addressed by SAST alone and require additional controls:

| Category | Recommended complementary control |
|---|---|
| **A02 Security Misconfiguration** | [Checkov](https://www.checkov.io/) or [Trivy](https://github.com/aquasecurity/trivy) for IaC scanning (Terraform, Helm, Dockerfiles). GitHub's [Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) for CI/CD misconfiguration. |
| **A03 Supply Chain Failures** | Enable [Dependabot version updates](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates) alongside `dependency-review-reusable.yml` to keep dependencies patched continuously. |
| **A06 Insecure Design** | Threat modelling (STRIDE / PASTA) and architecture review as part of the design phase. Not detectable via automated tooling. |
| **A09 Logging & Alerting Failures** | Runtime log aggregation, alerting thresholds, and incident response runbooks. Consider SIEM integration (Splunk, Datadog, Azure Sentinel). |

---

## Repository Structure

```
.
├── .github/
│   └── workflows/
│       ├── codeql-reusable.yml            # CodeQL SAST (A01, A04, A05, A07, A08, A10)
│       └── dependency-review-reusable.yml # Dependency CVE scan (A03, A04, A08)
└── README.md
```

---

## Adding New Workflows

1. Create a new file under `.github/workflows/` named `<tool>-reusable.yml`.
2. Use `on: workflow_call` with typed `inputs` and `secrets` blocks.
3. Grant only the minimum permissions required.
4. Add an inline comment block listing which OWASP Top 10:2025 categories the workflow covers (see existing workflows for the format).
5. Document the workflow in this README: add it to the OWASP coverage table, add a **Workflows** sub-section with an inputs table and usage examples, and update the repository structure tree.

---

## Security & Compliance

- Results are surfaced in the **Security > Code scanning** tab of each consuming repository.
- SARIF uploads require the consuming repository to have GitHub Advanced Security enabled (included for all public repositories and for organisations with a GHAS licence).
- Pinning the workflow reference to a commit SHA (`@<sha>`) rather than a branch provides supply-chain integrity for production use.
- These workflows target **OWASP Top 10:2025**. The coverage table above is reviewed and updated with each new OWASP release.

---

## Contributing

This repository is under active development. To propose a new workflow or report an issue, open a pull request or raise a GitHub Issue.
