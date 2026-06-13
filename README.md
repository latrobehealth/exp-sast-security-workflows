# Security Workflows

Reusable GitHub Actions workflows for static application security testing (SAST) — centrally maintained and consumed by application repositories across the organisation.

---

## Overview

This repository provides a library of reusable, parameterised security scanning workflows. Application teams call these workflows from their own CI pipelines without needing to own or maintain the underlying tooling configuration. All SARIF results are uploaded to GitHub Advanced Security so findings appear in the **Security** tab of each consuming repository.

---

## Workflows

### `codeql-reusable.yml` — CodeQL Analysis

Runs [GitHub CodeQL](https://codeql.github.com/) static analysis against one or more languages using a matrix strategy. Designed to be called from any repository that wants code-scanning coverage without duplicating workflow boilerplate.

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
# .github/workflows/codeql.yml  — in your application repo
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

## Repository Structure

```
.
├── .github/
│   └── workflows/
│       └── codeql-reusable.yml   # CodeQL reusable workflow
└── README.md
```

---

## Adding New Workflows

1. Create a new file under `.github/workflows/` named `<tool>-reusable.yml`.
2. Use `on: workflow_call` with typed `inputs` and `secrets` blocks.
3. Grant only the minimum permissions required.
4. Document the workflow in this README under a new **Workflows** sub-section, including an inputs table and usage examples.

---

## Security & Compliance

- Results are surfaced in the **Security > Code scanning** tab of each consuming repository.
- SARIF uploads require the consuming repository to have GitHub Advanced Security enabled (included for all public repositories and for organisations with a GHAS licence).
- Pinning the workflow reference to a SHA (`@<sha>`) rather than a branch provides supply-chain integrity for production use.

---

## Contributing

This repository is under active development. To propose a new workflow or report an issue, open a pull request or raise a GitHub Issue.
