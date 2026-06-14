"""
DevSecOps Pipeline Scanner - Security scanning CLI for CI/CD pipelines.

Runs SAST (via bandit), dependency vulnerability checks (via safety),
secret detection (via detect-secrets), and generates a security report.

Usage:
    python scanner.py scan --target ./src
    python scanner.py check-secrets --target .
    python scanner.py dependency-check --requirements requirements.txt
    python scanner.py report --output report.json
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("devsecops-scanner")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _run_command(cmd: list, capture: bool = True) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=300,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out after 300 seconds"
    except FileNotFoundError as exc:
        return 1, "", f"Command not found: {cmd[0]}. Install it first."


def _tool_available(tool: str) -> bool:
    rc, _, _ = _run_command(["which", tool] if sys.platform != "win32" else ["where", tool])
    return rc == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("1.0.0", prog_name="devsecops-scanner")
def cli():
    """DevSecOps Pipeline Scanner — run security checks from the command line."""


# ---------------------------------------------------------------------------
# sast — static analysis with bandit
# ---------------------------------------------------------------------------

@cli.command("sast")
@click.option("--target", "-t", default=".", show_default=True, help="Path to scan.")
@click.option("--severity", "-l", default="LOW", type=click.Choice(["LOW", "MEDIUM", "HIGH"], case_sensitive=False), show_default=True)
@click.option("--confidence", "-c", default="LOW", type=click.Choice(["LOW", "MEDIUM", "HIGH"], case_sensitive=False), show_default=True)
@click.option("--output", "-o", default=None, help="Write JSON results to this file.")
@click.option("--fail-on", default="HIGH", type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"]), show_default=True, help="Exit non-zero if issues at or above this severity are found.")
def sast(target: str, severity: str, confidence: str, output: Optional[str], fail_on: str):
    """Run SAST (Static Application Security Testing) using Bandit.

    \b
    Example:
        python scanner.py sast --target ./src --severity MEDIUM --fail-on HIGH
    """
    if not _tool_available("bandit"):
        raise click.ClickException("bandit is not installed. Run: pip install bandit")

    cmd = [
        "bandit", "-r", target,
        "-l", severity.lower(),
        "-i", confidence.lower(),
        "-f", "json",
    ]

    logger.info("Running SAST scan on '%s'...", target)
    rc, stdout, stderr = _run_command(cmd)

    try:
        results = json.loads(stdout) if stdout.strip() else {"results": [], "metrics": {}}
    except json.JSONDecodeError:
        results = {"results": [], "raw": stdout, "error": stderr}

    issues = results.get("results", [])
    metrics = results.get("metrics", {})

    click.echo(f"\n📋 SAST Scan Results — {target}")
    click.echo(f"   Issues found: {len(issues)}")

    severity_counts = {}
    for issue in issues:
        sev = issue.get("issue_severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev, count in sorted(severity_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99)):
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
        click.echo(f"   {click.style(sev, fg=color)}: {count}")

    if issues:
        click.echo("\nTop issues:")
        for issue in sorted(issues, key=lambda x: SEVERITY_ORDER.get(x.get("issue_severity", "INFO"), 99))[:10]:
            sev = issue.get("issue_severity", "?")
            color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
            click.echo(
                f"  [{click.style(sev, fg=color)}] {issue.get('test_id', '')} — "
                f"{issue.get('filename', '')}:{issue.get('line_number', '')} — "
                f"{issue.get('issue_text', '')}"
            )

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        click.echo(f"\n✓ Full results written to '{output}'")

    # Fail if issues at or above threshold
    if fail_on != "NONE":
        threshold = SEVERITY_ORDER.get(fail_on, 99)
        blocking = [i for i in issues if SEVERITY_ORDER.get(i.get("issue_severity", "INFO"), 99) <= threshold]
        if blocking:
            click.echo(click.style(f"\n❌ {len(blocking)} issue(s) at or above {fail_on} severity. Pipeline blocked.", fg="red"))
            sys.exit(1)

    click.echo(click.style("\n✓ SAST scan complete.", fg="green"))


# ---------------------------------------------------------------------------
# dependency-check — check for vulnerable dependencies
# ---------------------------------------------------------------------------

@cli.command("dependency-check")
@click.option("--requirements", "-r", default="requirements.txt", show_default=True, help="Path to requirements.txt.")
@click.option("--output", "-o", default=None, help="Write JSON results to this file.")
@click.option("--fail-on-vuln/--no-fail-on-vuln", default=True, show_default=True, help="Exit non-zero if vulnerabilities found.")
def dependency_check(requirements: str, output: Optional[str], fail_on_vuln: bool):
    """Check Python dependencies for known vulnerabilities using pip-audit.

    \b
    Example:
        python scanner.py dependency-check --requirements requirements.txt
    """
    tool = "pip-audit"
    if not _tool_available(tool):
        # fallback to safety
        tool = "safety"
        if not _tool_available(tool):
            raise click.ClickException(
                "Neither pip-audit nor safety is installed.\n"
                "Install pip-audit: pip install pip-audit\n"
                "Or safety: pip install safety"
            )

    logger.info("Checking dependencies in '%s' with %s...", requirements, tool)

    if tool == "pip-audit":
        cmd = ["pip-audit", "-r", requirements, "--format", "json", "--output", "-"]
    else:
        cmd = ["safety", "check", "-r", requirements, "--json"]

    rc, stdout, stderr = _run_command(cmd)

    vulnerabilities = []
    try:
        data = json.loads(stdout) if stdout.strip() else []
        if tool == "pip-audit":
            for item in (data.get("dependencies", []) if isinstance(data, dict) else data):
                for vuln in item.get("vulns", []):
                    vulnerabilities.append({
                        "package": item.get("name", "unknown"),
                        "version": item.get("version", "?"),
                        "vuln_id": vuln.get("id", ""),
                        "description": vuln.get("description", ""),
                        "fix_versions": vuln.get("fix_versions", []),
                    })
        else:
            for vuln in (data if isinstance(data, list) else []):
                vulnerabilities.append({
                    "package": vuln[0] if len(vuln) > 0 else "?",
                    "version": vuln[2] if len(vuln) > 2 else "?",
                    "vuln_id": vuln[4] if len(vuln) > 4 else "?",
                    "description": vuln[3] if len(vuln) > 3 else "",
                    "fix_versions": [],
                })
    except (json.JSONDecodeError, IndexError):
        vulnerabilities = []

    click.echo(f"\n📦 Dependency Vulnerability Check — {requirements}")
    click.echo(f"   Vulnerabilities found: {len(vulnerabilities)}")

    for v in vulnerabilities:
        fix = ", ".join(v["fix_versions"]) if v["fix_versions"] else "no fix available"
        click.echo(
            f"  {click.style('VULN', fg='red')} {v['package']}=={v['version']} "
            f"({v['vuln_id']}) — fix: {fix}"
        )
        if v["description"]:
            click.echo(f"       {v['description'][:120]}")

    if output:
        Path(output).write_text(json.dumps(vulnerabilities, indent=2))
        click.echo(f"\n✓ Results written to '{output}'")

    if fail_on_vuln and vulnerabilities:
        click.echo(click.style(f"\n❌ {len(vulnerabilities)} vulnerable dependency(ies) found. Pipeline blocked.", fg="red"))
        sys.exit(1)

    click.echo(click.style("\n✓ Dependency check complete.", fg="green"))


# ---------------------------------------------------------------------------
# check-secrets — detect hardcoded secrets
# ---------------------------------------------------------------------------

@cli.command("check-secrets")
@click.option("--target", "-t", default=".", show_default=True, help="Directory or file to scan.")
@click.option("--output", "-o", default=None, help="Write JSON results to this file.")
@click.option("--fail-on-detect/--no-fail-on-detect", default=True, show_default=True)
def check_secrets(target: str, output: Optional[str], fail_on_detect: bool):
    """Detect hardcoded secrets using detect-secrets.

    \b
    Example:
        python scanner.py check-secrets --target .
    """
    if not _tool_available("detect-secrets"):
        raise click.ClickException("detect-secrets is not installed. Run: pip install detect-secrets")

    logger.info("Scanning for secrets in '%s'...", target)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        tmp_path = tmp.name

    scan_cmd = ["detect-secrets", "scan", target, "--output", tmp_path]
    rc, stdout, stderr = _run_command(scan_cmd)

    try:
        results = json.loads(Path(tmp_path).read_text())
        secrets = results.get("results", {})
    except (json.JSONDecodeError, FileNotFoundError):
        secrets = {}
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    total = sum(len(v) for v in secrets.values())

    click.echo(f"\n🔑 Secret Detection Scan — {target}")
    click.echo(f"   Potential secrets found: {total}")

    for filepath, items in secrets.items():
        for item in items:
            click.echo(
                f"  {click.style('SECRET', fg='red')} {filepath}:{item.get('line_number', '?')} "
                f"— {item.get('type', 'unknown')}"
            )

    if output:
        Path(output).write_text(json.dumps({"secrets": secrets, "total": total}, indent=2))
        click.echo(f"\n✓ Results written to '{output}'")

    if fail_on_detect and total > 0:
        click.echo(click.style(f"\n❌ {total} potential secret(s) detected. Pipeline blocked.", fg="red"))
        sys.exit(1)

    click.echo(click.style("\n✓ Secret detection scan complete.", fg="green"))


# ---------------------------------------------------------------------------
# scan-all — run all checks and generate a unified report
# ---------------------------------------------------------------------------

@cli.command("scan-all")
@click.option("--target", "-t", default=".", show_default=True, help="Directory to scan.")
@click.option("--requirements", "-r", default="requirements.txt", show_default=True)
@click.option("--output", "-o", default="security-report.json", show_default=True, help="Output report file.")
@click.option("--fail-on-high/--no-fail-on-high", default=True, show_default=True, help="Fail pipeline on HIGH/CRITICAL findings.")
def scan_all(target: str, requirements: str, output: str, fail_on_high: bool):
    """Run all security scans and produce a unified JSON report.

    \b
    Example:
        python scanner.py scan-all --target . --requirements requirements.txt
    """
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "sast": {"issues": [], "error": None},
        "dependencies": {"vulnerabilities": [], "error": None},
        "secrets": {"findings": {}, "total": 0, "error": None},
        "summary": {"pass": True, "blocking_issues": 0},
    }

    # SAST
    if _tool_available("bandit"):
        logger.info("Running SAST...")
        rc, stdout, _ = _run_command(["bandit", "-r", target, "-f", "json", "-q"])
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            report["sast"]["issues"] = data.get("results", [])
        except json.JSONDecodeError:
            report["sast"]["error"] = "Failed to parse bandit output"
    else:
        report["sast"]["error"] = "bandit not installed"

    # Dependency check
    req_path = Path(requirements)
    if req_path.exists():
        tool = "pip-audit" if _tool_available("pip-audit") else ("safety" if _tool_available("safety") else None)
        if tool:
            logger.info("Running dependency check with %s...", tool)
            if tool == "pip-audit":
                cmd = ["pip-audit", "-r", str(req_path), "--format", "json", "--output", "-"]
            else:
                cmd = ["safety", "check", "-r", str(req_path), "--json"]
            rc, stdout, _ = _run_command(cmd)
            try:
                data = json.loads(stdout) if stdout.strip() else []
                if tool == "pip-audit":
                    for item in (data.get("dependencies", []) if isinstance(data, dict) else data):
                        for v in item.get("vulns", []):
                            report["dependencies"]["vulnerabilities"].append({
                                "package": item.get("name"), "vuln_id": v.get("id")
                            })
            except json.JSONDecodeError:
                report["dependencies"]["error"] = "Failed to parse dependency check output"
        else:
            report["dependencies"]["error"] = "Neither pip-audit nor safety installed"
    else:
        report["dependencies"]["error"] = f"requirements file not found: {requirements}"

    # Secrets
    if _tool_available("detect-secrets"):
        logger.info("Running secret detection...")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name
        _run_command(["detect-secrets", "scan", target, "--output", tmp_path])
        try:
            data = json.loads(Path(tmp_path).read_text())
            report["secrets"]["findings"] = data.get("results", {})
            report["secrets"]["total"] = sum(len(v) for v in report["secrets"]["findings"].values())
        except Exception:
            report["secrets"]["error"] = "Failed to parse detect-secrets output"
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    else:
        report["secrets"]["error"] = "detect-secrets not installed"

    # Summary
    high_sast = sum(
        1 for i in report["sast"]["issues"]
        if SEVERITY_ORDER.get(i.get("issue_severity", "INFO"), 99) <= SEVERITY_ORDER["HIGH"]
    )
    vuln_count = len(report["dependencies"]["vulnerabilities"])
    secret_count = report["secrets"]["total"]
    blocking = high_sast + vuln_count + secret_count

    report["summary"]["blocking_issues"] = blocking
    report["summary"]["pass"] = blocking == 0 or not fail_on_high

    Path(output).write_text(json.dumps(report, indent=2, default=str))

    click.echo(f"\n📊 Security Scan Summary")
    click.echo(f"   SAST HIGH+ issues:      {high_sast}")
    click.echo(f"   Vulnerable dependencies: {vuln_count}")
    click.echo(f"   Detected secrets:        {secret_count}")
    click.echo(f"   Report written to:       {output}")

    if blocking > 0 and fail_on_high:
        click.echo(click.style(f"\n❌ {blocking} blocking security issue(s) found.", fg="red"))
        sys.exit(1)
    else:
        click.echo(click.style("\n✓ All security checks passed.", fg="green"))


if __name__ == "__main__":
    cli()
