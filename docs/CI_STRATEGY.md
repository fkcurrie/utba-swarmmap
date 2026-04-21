# Continuous Integration Strategy

This document outlines the CI/CD strategy for the UTBA Swarm Map project, documenting current checks, identifying gaps, and proposing an extensibility framework.

## 1. Current State (as of April 2026)

The project currently employs a robust set of CI checks via GitHub Actions, primarily defined in `.github/workflows/pr-checks.yaml`.

### 1.1 Backend (Go)

- **Linting:** `go fmt`, `go vet`, `golangci-lint`.
- **Security:** `gosec`, `govulncheck`.
- **Testing:** `go test` with race detector.
- **Dependency Management:** `go mod tidy` and `go mod verify` checks.
- **Coverage:** Coverage profile generated (`coverage.out`).

### 1.2 Frontend (JS/HTML/CSS)

- **Linting:** `eslint`, `stylelint`, `htmlhint`, `prettier`.
- **Security:** `npm audit` (high level).

### 1.3 General & Infrastructure

- **Security:** `detect-secrets`.
- **Workflows:** `actionlint`.
- **Configuration:** `yamllint`, `shellcheck`.
- **Content:** `markdownlint`, `misspell`.
- **Process:** `commitlint`.

### 1.4 E2E Validation

- **Startup Check:** A basic docker-compose based smoke test (`.github/workflows/e2e-startup.yaml`) that verifies container health and basic endpoint connectivity via `curl`.

---

## 2. Gap Analysis & Recommendations

While the current suite is comprehensive, several high-value additions can further improve quality and prevent regressions.

### 2.1 Backend Improvements

- **Coverage Enforcement:** (CRITICAL) Implement a check to fail PRs if code coverage falls below a defined threshold (e.g., 80%).
- **Mutation Testing:** Introduce `go-mutesting` to evaluate test suite effectiveness.
- **Static Analysis Depth:** Enable more aggressive linters in `golangci-lint` (e.g., `cyclop`, `gocognit`).

### 2.2 Frontend Improvements

- **Unit Testing:** Introduce Jest or Vitest for frontend logic testing.
- **Visual Regression:** Use Playwright's screenshot comparison to detect unintended UI changes.
- **Lighthouse Scoring:** Automate Lighthouse audits for performance, accessibility, and SEO.
- **Bundle Size Monitoring:** Use `bundlesize` or similar to prevent bloating.

### 2.3 Infrastructure & DevOps

- **Dockerfile Linting:** Integrate `hadolint` to ensure Docker best practices.
- **IaC Scanning:** Use `trivy` or `checkov` to scan `cloudbuild.yaml` and other infrastructure configurations.
- **Advanced Dependency Scanning:** Transition to GitHub CodeQL or Snyk for continuous vulnerability monitoring.

---

## 3. Extensibility Framework

To ensure the CI pipeline remains maintainable and easy to expand, we follow these principles:

### 3.1 Modular Jobs

Each major component (Backend, Frontend, Infrastructure) should have its own dedicated job. This allows for parallel execution and clear failure attribution.

### 3.2 Standardized Tooling

Where possible, use established GitHub Actions from reputable sources (e.g., `reviewdog`, `actions/`).

### 3.3 The "Bolt-On" Process

To add a new CI check:

1. **Identify the tool:** Choose a tool that supports CI/CD (e.g., outputs SARIF or exit codes).
2. **Local Validation:** Ensure the tool runs successfully on a developer machine.
3. **Workflow Integration:**
   - For a single-file check (e.g., a new linter), add a step to the `general` job in `pr-checks.yaml`.
   - For a new service or complex check, create a new job.
4. **Failure Policy:** Decide if the check should be "soft" (report only) or "hard" (fail the build). Use `continue-on-error: true` for soft launches.

### 3.4 Future-Proofing

If `pr-checks.yaml` exceeds 500 lines, it should be refactored into modular workflow files using `workflow_call`.

---

## 4. Implementation Roadmap

- [x] Document CI Strategy.
- [x] Implement Go test coverage enforcement (Threshold: 25% initial).
- [x] Integrate Playwright E2E tests into PR checks.
- [x] Add Dockerfile linting (hadolint).
- [ ] Implement Visual Regression testing.
- [ ] Add Lighthouse automated audits.
