# DevSecOps Pipeline

A production-ready **security scanning pipeline** for CI/CD workflows. Runs SAST, dependency vulnerability checks, secret detection, and container scanning — and blocks the pipeline on findings.

## What's Included

- **Python CLI** (`scanner.py`) — run individual or all security scans locally
- **GitHub Actions pipeline** — automated security gate on every PR and push
- **Terraform** — provisions S3 for report storage + IAM role for keyless GitHub Actions auth

---

## Quick Start

```bash
git clone https://github.com/abhisheksawant52/devsecops-pipeline.git
cd devsecops-pipeline

pip install -r src/requirements.txt

# Run all security scans
python src/scanner.py scan-all --target src/ --requirements src/requirements.txt

# Or run individual checks
python src/scanner.py sast --target src/ --severity MEDIUM
python src/scanner.py dependency-check --requirements src/requirements.txt
python src/scanner.py check-secrets --target .
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.11+ | [python.org](https://www.python.org) |
| bandit | 1.7.9 | `pip install bandit` |
| pip-audit | 2.7.3 | `pip install pip-audit` |
| detect-secrets | 1.5.0 | `pip install detect-secrets` |

---

## Python CLI Commands

### `sast` — Static Application Security Testing

```bash
python src/scanner.py sast --target ./src --severity MEDIUM --fail-on HIGH
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | `.` | Directory to scan |
| `--severity` | `LOW` | Minimum severity to report |
| `--fail-on` | `HIGH` | Exit non-zero above this severity |
| `--output` | none | Write JSON results to file |

### `dependency-check` — Vulnerable Dependencies

```bash
python src/scanner.py dependency-check --requirements requirements.txt
```

### `check-secrets` — Hardcoded Secret Detection

```bash
python src/scanner.py check-secrets --target .
```

### `scan-all` — Full Security Scan

```bash
python src/scanner.py scan-all \
  --target . \
  --requirements requirements.txt \
  --output security-report.json
```

---

## GitHub Actions Pipeline

### Jobs

| Job | Tool | Description |
|-----|------|-------------|
| `sast` | Bandit | Static code analysis |
| `dependency-check` | pip-audit | Known CVEs in dependencies |
| `secret-detection` | Gitleaks | Hardcoded secrets in git history |
| `container-scan` | Trivy | Container image vulnerabilities |
| `security-gate` | scanner.py | Unified report + pipeline gate |

### Pipeline Flow

```
PR/Push → SAST ──┐
               ├──→ Security Gate → Pass/Fail
Dep Check ─────┤
Secret Scan ───┘
```

### Required Secrets (GitHub Actions)

No secrets needed for basic SAST/dependency/secret scanning — these run with `GITHUB_TOKEN` only.

For Terraform (S3 reports bucket) and Gitleaks Pro, add:

| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS credentials for S3 upload |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_REGION` | AWS region |

---

## Terraform — Infrastructure

Sets up S3 bucket for report storage and IAM role for GitHub Actions OIDC (keyless auth).

```bash
cd terraform
terraform init
terraform apply \
  -var="github_org=abhisheksawant52" \
  -var="github_repo=devsecops-pipeline"
```

---

## Security Report Format

The unified report (`security-report.json`) contains:

```json
{
  "timestamp": "2026-06-14T00:00:00Z",
  "target": "src/",
  "sast": { "issues": [...] },
  "dependencies": { "vulnerabilities": [...] },
  "secrets": { "findings": {}, "total": 0 },
  "summary": { "pass": true, "blocking_issues": 0 }
}
```

---

## Cleanup

```bash
cd terraform
terraform destroy
```
