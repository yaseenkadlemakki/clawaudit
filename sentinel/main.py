"""ClawAudit Sentinel CLI entrypoint."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from sentinel.config import get_config, load_config
from sentinel.analyzer.skill_analyzer import SkillAnalyzer
from sentinel.analyzer.config_auditor import ConfigAuditor
from sentinel.reporter.compliance import ComplianceReporter
from sentinel.reporter.delta import load_findings_from_jsonl
from sentinel.policy.engine import PolicyEngine
from sentinel.alerts.engine import AlertEngine
from sentinel.models.event import Event

app = typer.Typer(
    name="sentinel",
    help="ClawAudit Sentinel — real-time security monitoring for OpenClaw",
    add_completion=True,
)
console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange3",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


def _severity_color(s: str) -> str:
    return SEVERITY_COLORS.get(s, "white")


@app.command()
def audit(
    fix: bool = typer.Option(False, "--fix", help="Attempt auto-remediation (v2)"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown or json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save report to file"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Sentinel config file"),
) -> None:
    """Run a full one-shot ClawAudit security scan."""
    cfg = load_config(config_path)
    reporter = ComplianceReporter(cfg)

    with console.status("[bold green]Running security audit..."):
        run_id, findings = reporter.run_full_audit()

    if not findings:
        console.print("[green]✓ No findings — all checks passed![/green]")
        raise typer.Exit(0)

    # Display summary table
    table = Table(title=f"ClawAudit Findings — Run {run_id[:8]}", show_lines=True)
    table.add_column("Check", style="bold")
    table.add_column("Severity")
    table.add_column("Result")
    table.add_column("Title")
    table.add_column("Location", overflow="fold")

    for f in sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity) if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
        color = _severity_color(f.severity)
        result_style = "red" if f.result == "FAIL" else "green" if f.result == "PASS" else "yellow"
        table.add_row(
            f.check_id,
            f"[{color}]{f.severity}[/{color}]",
            f"[{result_style}]{f.result}[/{result_style}]",
            f.title[:60],
            f.location[:50],
        )

    console.print(table)

    # Counts
    fails = sum(1 for f in findings if f.result == "FAIL")
    passes = sum(1 for f in findings if f.result == "PASS")
    console.print(f"\n[red]FAIL: {fails}[/red]  [green]PASS: {passes}[/green]  Total: {len(findings)}")

    # Save findings
    findings_file = cfg.findings_file
    findings_file.parent.mkdir(parents=True, exist_ok=True)
    with findings_file.open("a") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict()) + "\n")

    if output:
        from sentinel.reporter.renderer import render_markdown, render_json
        if format == "json":
            output.write_text(render_json(findings, run_id))
        else:
            output.write_text(render_markdown(findings, run_id))
        console.print(f"[dim]Report saved to {output}[/dim]")

    if fix:
        console.print("[yellow]⚠ Auto-fix is a Phase 2 feature. Manual remediation required.[/yellow]")

    raise typer.Exit(1 if fails > 0 else 0)


@app.command()
def watch(
    interval: int = typer.Option(60, "--interval", "-i", help="Scan interval in seconds"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Start continuous monitoring daemon."""
    cfg = load_config(config_path)
    cfg.scan_interval = interval

    console.print(f"[bold green]🛡  ClawAudit Sentinel watching — interval {interval}s[/bold green]")

    from sentinel.collector.config_collector import ConfigCollector
    from sentinel.collector.skill_collector import SkillCollector
    from sentinel.collector.session_collector import SessionCollector
    from sentinel.collector.cron_collector import CronCollector
    from sentinel.collector.log_collector import LogCollector
    from sentinel.policy.engine import PolicyEngine
    from sentinel.alerts.engine import AlertEngine

    policy_engine = PolicyEngine(cfg.policies_dir)
    alert_engine = AlertEngine(cfg)

    def on_event(event: Event) -> None:
        decision = policy_engine.evaluate(event)
        event.action_taken = decision.action
        event.policy_refs = decision.policy_ids
        color = _severity_color(event.severity)
        console.print(f"[{color}][{event.severity}][/{color}] {event.event_type} — {event.entity}")
        if decision.action in ("ALERT", "BLOCK"):
            from sentinel.models.finding import Finding
            from datetime import datetime
            # Convert event to a temporary finding for alert routing
            f = Finding(
                check_id=event.source,
                domain="runtime",
                title=event.event_type,
                description=event.evidence,
                severity=event.severity,
                result="FAIL",
                evidence=event.evidence,
                location=event.entity,
                remediation="",
                run_id=str(uuid.uuid4()),
            )
            alert_engine.send(f, decision)

    async def run_all() -> None:
        config_col = ConfigCollector(cfg, on_event)
        session_col = SessionCollector(cfg, on_event)
        cron_col = CronCollector(cfg, on_event)
        log_col = LogCollector(cfg, on_event)
        skill_col = SkillCollector(cfg, on_event)
        skill_col.start()

        await asyncio.gather(
            config_col.run(),
            session_col.run(),
            cron_col.run(),
            log_col.run(),
        )

    try:
        asyncio.run(run_all())
    except KeyboardInterrupt:
        console.print("\n[dim]Sentinel stopped.[/dim]")


@app.command()
def skills(
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Show details for a specific skill"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """List skills with trust scores."""
    cfg = load_config(config_path)
    analyzer = SkillAnalyzer()
    profiles = []

    for skills_dir in [cfg.skills_dir, cfg.workspace_skills_dir]:
        if skills_dir.exists():
            for skill_md in skills_dir.rglob("SKILL.md"):
                with console.status(f"Analyzing {skill_md.parent.name}..."):
                    profile = analyzer.analyze(skill_md)
                    profiles.append(profile)

    if name:
        match = next((p for p in profiles if p.name == name), None)
        if not match:
            console.print(f"[red]Skill '{name}' not found[/red]")
            raise typer.Exit(1)
        _print_skill_detail(match)
        return

    table = Table(title="Skill Trust Scores", show_lines=True)
    table.add_column("Skill")
    table.add_column("Trust Score")
    table.add_column("Score")
    table.add_column("Shell")
    table.add_column("Injection Risk")
    table.add_column("Credentials")

    trust_colors = {"TRUSTED": "green", "CAUTION": "yellow", "UNTRUSTED": "orange3", "QUARANTINE": "red"}

    for p in sorted(profiles, key=lambda x: x.trust_score_value):
        tc = trust_colors.get(p.trust_score, "white")
        table.add_row(
            p.name,
            f"[{tc}]{p.trust_score}[/{tc}]",
            str(p.trust_score_value),
            "⚠️" if p.shell_access else "✓",
            p.injection_risk,
            "🔴" if p.credential_exposure else "✓",
        )

    console.print(table)


def _print_skill_detail(profile: "SkillProfile") -> None:
    """Print detailed skill profile."""
    from sentinel.models.skill import SkillProfile
    trust_colors = {"TRUSTED": "green", "CAUTION": "yellow", "UNTRUSTED": "orange3", "QUARANTINE": "red"}
    tc = trust_colors.get(profile.trust_score, "white")

    console.print(f"\n[bold]Skill: {profile.name}[/bold]")
    console.print(f"Path: {profile.path}")
    console.print(f"Trust Score: [{tc}]{profile.trust_score} ({profile.trust_score_value}/100)[/{tc}]")
    console.print(f"Author: {profile.author or 'unknown'}")
    console.print(f"Shell Access: {'Yes — ' + ', '.join(profile.shell_evidence[:3]) if profile.shell_access else 'No'}")
    console.print(f"Injection Risk: {profile.injection_risk}")
    console.print(f"Credential Exposure: {'Yes' if profile.credential_exposure else 'No'}")
    console.print(f"Outbound Domains: {', '.join(profile.outbound_domains[:5]) or 'none declared'}")

    if profile.findings:
        console.print("\n[bold]Findings:[/bold]")
        for f in profile.findings:
            color = _severity_color(f.severity)
            console.print(f"  [{color}][{f.severity}][/{color}] {f.check_id}: {f.title}")


@app.command()
def policies(
    list_: bool = typer.Option(False, "--list", "-l", help="List loaded policies"),
    validate: bool = typer.Option(False, "--validate", help="Validate policy files"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Manage and inspect policies."""
    cfg = load_config(config_path)
    engine = PolicyEngine(cfg.policies_dir)

    if list_ or (not validate):
        table = Table(title="Loaded Policy Rules")
        table.add_column("ID")
        table.add_column("Domain")
        table.add_column("Check")
        table.add_column("Severity")
        table.add_column("Action")

        for rule in engine.rules:
            color = _severity_color(rule.severity)
            table.add_row(
                rule.id,
                rule.domain,
                rule.check,
                f"[{color}]{rule.severity}[/{color}]",
                rule.action,
            )
        console.print(table)
        console.print(f"[dim]{len(engine.rules)} rules loaded from {cfg.policies_dir}[/dim]")

    if validate:
        console.print("[green]✓ Policy validation complete[/green]")


@app.command()
def alerts(
    last: int = typer.Option(20, "--last", "-n", help="Number of recent alerts to show"),
    ack: Optional[str] = typer.Option(None, "--ack", help="Acknowledge alert by ID"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """View recent alerts."""
    cfg = load_config(config_path)
    channels_cfg = cfg.alert_channels
    file_cfg = channels_cfg.get("file", {})
    alerts_path = Path(file_cfg.get("path", "~/.openclaw/sentinel/alerts.jsonl")).expanduser()

    if not alerts_path.exists():
        console.print("[dim]No alerts recorded yet.[/dim]")
        return

    records = []
    for line in alerts_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    records = records[-last:]

    table = Table(title=f"Recent Alerts (last {last})", show_lines=True)
    table.add_column("Time")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("Action")
    table.add_column("Message", overflow="fold")

    for r in records:
        color = _severity_color(r.get("severity", "INFO"))
        table.add_row(
            r.get("ts", "")[:19],
            f"[{color}]{r.get('severity','?')}[/{color}]",
            r.get("check_id", ""),
            r.get("action", ""),
            r.get("message", "")[:80],
        )

    console.print(table)


@app.command()
def baseline(
    create: bool = typer.Option(False, "--create", help="Create baseline from current config"),
    diff: bool = typer.Option(False, "--diff", help="Show diff from baseline"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Manage config baselines."""
    cfg = load_config(config_path)

    if create:
        import hashlib, json
        baseline_file = cfg.baseline_file
        baseline_file.parent.mkdir(parents=True, exist_ok=True)

        config_data = {}
        if cfg.config_file.exists():
            config_data = json.loads(cfg.config_file.read_text())

        baseline_record = {
            "created_at": __import__("datetime").datetime.utcnow().isoformat(),
            "config_hash": hashlib.sha256(json.dumps(config_data, sort_keys=True).encode()).hexdigest(),
            "config": config_data,
        }
        baseline_file.write_text(json.dumps(baseline_record, indent=2))
        console.print(f"[green]✓ Baseline created: {baseline_file}[/green]")

    elif diff:
        if not cfg.baseline_file.exists():
            console.print("[yellow]No baseline found. Run: sentinel baseline --create[/yellow]")
            return
        console.print("[dim]Diff feature — full implementation in Phase 2[/dim]")
    else:
        console.print("[dim]Use --create or --diff[/dim]")


@app.command()
def report(
    format: str = typer.Option("markdown", "--format", "-f", help="markdown or json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save to file"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Generate a compliance report."""
    cfg = load_config(config_path)
    reporter = ComplianceReporter(cfg)

    with console.status("[bold green]Generating report..."):
        content = reporter.generate(format=format, output=output)

    if output:
        console.print(f"[green]✓ Report saved to {output}[/green]")
    else:
        console.print(content)


if __name__ == "__main__":
    app()
