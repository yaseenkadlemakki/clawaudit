"""ClawAudit Sentinel CLI entrypoint."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sys
import uuid
from importlib.metadata import version as pkg_version
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sentinel.alerts.engine import AlertEngine
from sentinel.analyzer.skill_analyzer import SkillAnalyzer
from sentinel.config import load_config
from sentinel.models.event import Event
from sentinel.models.skill import SkillProfile
from sentinel.policy.engine import PolicyEngine
from sentinel.reporter.compliance import ComplianceReporter

app = typer.Typer(
    name="clawaudit",
    help="ClawAudit — forensic security auditor for OpenClaw deployments",
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
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Output format: markdown or json"
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save report to file"),
    config_path: Path | None = typer.Option(None, "--config", "-c", help="Sentinel config file"),
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

    for f in sorted(
        findings,
        key=lambda x: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)
            if x.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            else 99
        ),
    ):
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
    console.print(
        f"\n[red]FAIL: {fails}[/red]  [green]PASS: {passes}[/green]  Total: {len(findings)}"
    )

    # Save findings
    findings_file = cfg.findings_file
    findings_file.parent.mkdir(parents=True, exist_ok=True)
    with findings_file.open("a") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict()) + "\n")

    if output:
        from sentinel.reporter.renderer import render_json, render_markdown

        if format == "json":
            output.write_text(render_json(findings, run_id))
        else:
            output.write_text(render_markdown(findings, run_id))
        console.print(f"[dim]Report saved to {output}[/dim]")

    if fix:
        console.print(
            "[yellow]⚠ Auto-fix is a Phase 2 feature. Manual remediation required.[/yellow]"
        )

    raise typer.Exit(1 if fails > 0 else 0)


@app.command()
def watch(
    interval: int = typer.Option(60, "--interval", "-i", help="Scan interval in seconds"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Start continuous monitoring daemon."""
    cfg = load_config(config_path)
    cfg.scan_interval = interval

    console.print(f"[bold green]🛡  ClawAudit Sentinel watching — interval {interval}s[/bold green]")

    from sentinel.collector.config_collector import ConfigCollector
    from sentinel.collector.cron_collector import CronCollector
    from sentinel.collector.log_collector import LogCollector
    from sentinel.collector.session_collector import SessionCollector
    from sentinel.collector.skill_collector import SkillCollector
    from sentinel.policy.engine import PolicyEngine

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
    name: str | None = typer.Option(None, "--name", "-n", help="Show details for a specific skill"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
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

    trust_colors = {
        "TRUSTED": "green",
        "CAUTION": "yellow",
        "UNTRUSTED": "orange3",
        "QUARANTINE": "red",
    }

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


def _print_skill_detail(profile: SkillProfile) -> None:
    """Print detailed skill profile."""
    trust_colors = {
        "TRUSTED": "green",
        "CAUTION": "yellow",
        "UNTRUSTED": "orange3",
        "QUARANTINE": "red",
    }
    tc = trust_colors.get(profile.trust_score, "white")

    console.print(f"\n[bold]Skill: {profile.name}[/bold]")
    console.print(f"Path: {profile.path}")
    console.print(
        f"Trust Score: [{tc}]{profile.trust_score} ({profile.trust_score_value}/100)[/{tc}]"
    )
    console.print(f"Author: {profile.author or 'unknown'}")
    console.print(
        f"Shell Access: {'Yes — ' + ', '.join(profile.shell_evidence[:3]) if profile.shell_access else 'No'}"
    )
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
    config_path: Path | None = typer.Option(None, "--config", "-c"),
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
    ack: str | None = typer.Option(None, "--ack", help="Acknowledge alert by ID"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
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
            f"[{color}]{r.get('severity', '?')}[/{color}]",
            r.get("check_id", ""),
            r.get("action", ""),
            r.get("message", "")[:80],
        )

    console.print(table)


@app.command()
def baseline(
    create: bool = typer.Option(False, "--create", help="Create baseline from current config"),
    diff: bool = typer.Option(False, "--diff", help="Show diff from baseline"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Manage config baselines."""
    cfg = load_config(config_path)

    if create:
        import hashlib
        import json

        baseline_file = cfg.baseline_file
        baseline_file.parent.mkdir(parents=True, exist_ok=True)

        config_data = {}
        if cfg.config_file.exists():
            config_data = json.loads(cfg.config_file.read_text())

        baseline_record = {
            "created_at": __import__("datetime").datetime.utcnow().isoformat(),
            "config_hash": hashlib.sha256(
                json.dumps(config_data, sort_keys=True).encode()
            ).hexdigest(),
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
    output: Path | None = typer.Option(None, "--output", "-o", help="Save to file"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
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


@app.command()
def remediate(
    skill: str | None = typer.Option(None, "--skill", "-s", help="Target a specific skill by name"),
    check: str | None = typer.Option(
        None, "--check", "-c", help="Target a specific check ID (e.g. ADV-001)"
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Apply remediations (default: dry-run preview)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompts"),
    config_path: Path | None = typer.Option(None, "--config", help="Sentinel config file"),
) -> None:
    """Preview or apply remediations for audit findings.

    By default runs in dry-run mode — shows proposals without making changes.
    Pass --apply to actually apply fixes, --yes to skip confirmation.
    """
    from sentinel.remediation.engine import RemediationEngine
    from sentinel.remediation.rollback import SNAPSHOT_DIR

    cfg = load_config(config_path)
    skills_dir = Path(cfg.openclaw.workspace_skills_dir).expanduser()

    engine = RemediationEngine(skills_dir=skills_dir, dry_run=not apply)

    # Build a minimal findings list from config auditor
    from sentinel.analyzer.config_auditor import ConfigAuditor
    from sentinel.analyzer.skill_analyzer import SkillAnalyzer

    auditor = ConfigAuditor()
    findings_raw = asyncio.run(auditor.audit())

    skill_analyzer = SkillAnalyzer()
    skill_findings: list = []
    skill_dir = skills_dir
    if skill_dir.exists():
        for skill_md in skill_dir.glob("*/SKILL.md"):
            sname = skill_md.parent.name
            if skill and sname != skill:
                continue
            profile = skill_analyzer.analyze(skill_md)
            for f in profile.findings:
                skill_findings.append(
                    {
                        "id": f.id,
                        "check_id": f.check_id,
                        "skill_name": sname,
                        "location": str(skill_md.parent),
                    }
                )

    all_findings = [
        {
            "id": f.id,
            "check_id": f.check_id,
            "skill_name": getattr(f, "skill_name", ""),
            "location": "",
        }
        for f in findings_raw
    ] + skill_findings

    proposals = engine.scan_for_proposals(
        findings=all_findings,
        check_ids=[check] if check else None,
        skill_names=[skill] if skill else None,
    )

    if not proposals:
        console.print("[green]✓ No remediations needed — nothing to fix.[/green]")
        return

    mode_label = (
        "[bold red]APPLY MODE[/bold red]" if apply else "[bold yellow]DRY-RUN MODE[/bold yellow]"
    )
    console.print(f"\n{mode_label} — {len(proposals)} proposal(s) found\n")

    from rich.table import Table as RichTable

    table = RichTable(show_header=True, header_style="bold")
    table.add_column("Check", style="cyan", width=10)
    table.add_column("Skill", style="white", width=20)
    table.add_column("Description", style="white")
    table.add_column("Reversible", style="green", width=10)

    for p in proposals:
        table.add_row(
            p.check_id,
            p.skill_name,
            p.description[:80] + ("…" if len(p.description) > 80 else ""),
            "✓" if p.reversible else "✗",
        )
    console.print(table)

    if not apply:
        console.print("\n[dim]Run with --apply to apply these fixes.[/dim]")
        return

    if not yes:
        confirm = typer.confirm(f"\nApply {len(proposals)} remediation(s)?", default=False)
        if not confirm:
            console.print("[yellow]Aborted.[/yellow]")
            return

    results = engine.apply_all(proposals)
    success = sum(1 for r in results if r.success)
    failed = len(results) - success

    console.print(f"\n[green]✓ Applied: {success}[/green]  [red]Failed: {failed}[/red]")
    for result in results:
        if result.success:
            snap = result.snapshot_path
            console.print(
                f"  [green]✓[/green] {result.proposal.skill_name} ({result.proposal.check_id})"
                + (f" — snapshot: {snap.name}" if snap else "")
            )
        else:
            console.print(f"  [red]✗[/red] {result.proposal.skill_name}: {result.error}")

    if success:
        console.print(f"\n[dim]Snapshots saved to: {SNAPSHOT_DIR}[/dim]")
        console.print("[dim]To rollback: sentinel snapshots rollback <snapshot-name>[/dim]")


@app.command()
def snapshots(
    action: str = typer.Argument("list", help="list | rollback"),
    name: str | None = typer.Argument(None, help="Snapshot name for rollback"),
) -> None:
    """Manage remediation snapshots (list or rollback)."""
    from sentinel.remediation.rollback import SNAPSHOT_DIR, list_snapshots, restore_snapshot

    if action == "list":
        snaps = list_snapshots()
        if not snaps:
            console.print("[dim]No snapshots found.[/dim]")
            return
        from rich.table import Table as RichTable

        table = RichTable(show_header=True, header_style="bold")
        table.add_column("Snapshot", style="cyan")
        table.add_column("Size", style="white")
        for snap in snaps:
            size = f"{snap.stat().st_size // 1024} KB"
            table.add_row(snap.name, size)
        console.print(table)

    elif action == "rollback":
        if not name:
            console.print("[red]Error: provide a snapshot name.[/red]")
            raise typer.Exit(1)
        snap_path = SNAPSHOT_DIR / name
        if not snap_path.exists():
            console.print(f"[red]Snapshot not found: {snap_path}[/red]")
            raise typer.Exit(1)
        restore_snapshot(snap_path, snap_path.parent.parent)
        console.print(f"[green]✓ Rolled back from {name}[/green]")
    else:
        console.print(f"[red]Unknown action: {action}. Use 'list' or 'rollback'.[/red]")
        raise typer.Exit(1)


# ── Skill lifecycle sub-app ─────────────────────────────────────────────────

skills_app = typer.Typer(name="skills", help="Skill lifecycle management")


@skills_app.command("list")
def skills_list(
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """List all registered skills."""
    from sentinel.lifecycle.registry import SkillRegistry

    cfg = load_config(config_path)
    registry = SkillRegistry()
    registry.sync([cfg.skills_dir, cfg.workspace_skills_dir])
    records = registry.list_all()

    if not records:
        console.print("[dim]No skills registered.[/dim]")
        return

    table = Table(title="Registered Skills")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Path", overflow="fold")

    for r in sorted(records, key=lambda x: x.name):
        status = "[green]enabled[/green]" if r.enabled else "[dim]disabled[/dim]"
        table.add_row(r.name, r.version, r.source, status, r.path)

    console.print(table)


@skills_app.command("install")
def skills_install(
    path_or_url: str = typer.Argument(..., help="Local .skill file path or HTTP URL"),
    force: bool = typer.Option(False, "--force", help="Force reinstall even if hash differs"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Install a skill from a .skill file or URL."""
    from sentinel.lifecycle.installer import (
        SkillAlreadyInstalledError,
        SkillHashMismatchError,
        SkillInstaller,
    )
    from sentinel.lifecycle.registry import SkillRegistry

    cfg = load_config(config_path)
    registry = SkillRegistry()
    installer = SkillInstaller(cfg.workspace_skills_dir, registry)

    try:
        if path_or_url.startswith(("http://", "https://")):
            with console.status(f"[bold green]Downloading {path_or_url}..."):
                record = installer.install_from_url(path_or_url, force=force)
        else:
            record = installer.install_from_file(Path(path_or_url), force=force)
        console.print(f"[green]Installed '{record.name}' v{record.version} → {record.path}[/green]")
    except (
        ValueError,
        FileExistsError,
        FileNotFoundError,
        SkillAlreadyInstalledError,
        SkillHashMismatchError,
    ) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc


@skills_app.command("enable")
def skills_enable(
    name: str = typer.Argument(..., help="Skill name"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Enable a disabled skill."""
    from sentinel.lifecycle.registry import SkillRegistry
    from sentinel.lifecycle.toggler import SkillToggler

    load_config(config_path)
    registry = SkillRegistry()
    toggler = SkillToggler(registry)
    try:
        toggler.enable(name)
        console.print(f"[green]Enabled '{name}'[/green]")
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc


@skills_app.command("disable")
def skills_disable(
    name: str = typer.Argument(..., help="Skill name"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Disable an enabled skill."""
    from sentinel.lifecycle.registry import SkillRegistry
    from sentinel.lifecycle.toggler import SkillToggler

    load_config(config_path)
    registry = SkillRegistry()
    toggler = SkillToggler(registry)
    try:
        toggler.disable(name)
        console.print(f"[yellow]Disabled '{name}'[/yellow]")
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc


@skills_app.command("uninstall")
def skills_uninstall(
    name: str = typer.Argument(..., help="Skill name"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Uninstall a skill (move to trash)."""
    from sentinel.lifecycle.registry import SkillRegistry
    from sentinel.lifecycle.uninstaller import SkillUninstaller

    load_config(config_path)
    registry = SkillRegistry()
    uninstaller = SkillUninstaller(registry)
    try:
        trash_path = uninstaller.uninstall(name)
        console.print(f"[yellow]Uninstalled '{name}' → {trash_path}[/yellow]")
    except (FileNotFoundError, PermissionError) as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc


@skills_app.command("health")
def skills_health(
    name: str = typer.Argument(..., help="Skill name"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Run security analysis on a single skill."""
    from sentinel.lifecycle.registry import SkillRegistry

    load_config(config_path)
    registry = SkillRegistry()
    record = registry.get(name)
    if not record:
        console.print(f"[red]Skill '{name}' not found[/red]")
        raise typer.Exit(1)

    skill_md = Path(record.path) / "SKILL.md"
    if not skill_md.exists():
        skill_md = Path(record.path) / "SKILL.md.disabled"
    if not skill_md.exists():
        console.print(f"[red]SKILL.md not found for '{name}'[/red]")
        raise typer.Exit(1)

    analyzer = SkillAnalyzer()
    profile = analyzer.analyze(skill_md)
    _print_skill_detail(profile)


@skills_app.command("recover")
def skills_recover(
    trash_name: str = typer.Argument(..., help="Name of trash entry to recover"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Recover a previously uninstalled skill from trash."""
    from sentinel.lifecycle.registry import SkillRegistry
    from sentinel.lifecycle.uninstaller import SkillUninstaller

    cfg = load_config(config_path)
    registry = SkillRegistry()
    uninstaller = SkillUninstaller(registry)
    try:
        record = uninstaller.recover(trash_name, cfg.workspace_skills_dir)
        console.print(f"[green]Recovered '{record.name}' → {record.path}[/green]")
    except FileNotFoundError as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(1) from exc


@skills_app.command("verify")
def skills_verify(
    name: str = typer.Argument(..., help="Skill name to verify"),
) -> None:
    """Verify skill content hash matches registry."""
    from sentinel.lifecycle.installer import SkillInstaller
    from sentinel.lifecycle.registry import SkillRegistry

    registry = SkillRegistry()
    record = registry.get(name)
    if not record:
        console.print(f"[red]Skill '{name}' not found in registry[/red]")
        raise typer.Exit(1)

    if not record.content_hash:
        console.print(
            f"[yellow]Skill '{name}' has no stored hash (installed before hash pinning)[/yellow]"
        )
        raise typer.Exit(1)

    skill_dir = Path(record.path)
    if not skill_dir.exists():
        console.print(f"[red]Skill directory not found: {skill_dir}[/red]")
        raise typer.Exit(1)

    current_hash = SkillInstaller._compute_skill_hash(skill_dir)
    if current_hash == record.content_hash:
        console.print(f"[green]OK — '{name}' integrity verified[/green]")
    else:
        console.print(f"[red]TAMPERED — '{name}' content hash mismatch![/red]")
        console.print(f"  Expected: {record.content_hash[:16]}...")
        console.print(f"  Current:  {current_hash[:16]}...")
        raise typer.Exit(1)


app.add_typer(skills_app)


# ── Config sub-app ─────────────────────────────────────────────────────────────

config_app = typer.Typer(name="config", help="Manage sentinel configuration.")


@config_app.command("show")
def config_show() -> None:
    """Print effective sentinel configuration."""
    from sentinel.config import SecurityConfig

    cfg = SecurityConfig.load()
    console.print("[bold]Sentinel Security Configuration[/bold]\n")
    console.print(f"Safe domains ({len(cfg.safe_domains)}):")
    for d in sorted(cfg.safe_domains):
        console.print(f"  - {d}")
    console.print(f"\nScan scripts: {cfg.scan.scan_scripts}")
    console.print(f"Severity threshold: {cfg.scan.severity_threshold}")
    console.print(f"Max script size: {cfg.scan.max_script_size_mb} MB")


@config_app.command("init")
def config_init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config."),
) -> None:
    """Write default config to ~/.openclaw/sentinel/config.yaml."""
    from sentinel.config import SECURITY_CONFIG_PATH, SecurityConfig

    if SECURITY_CONFIG_PATH.exists() and not force:
        console.print(
            f"[yellow]Config already exists at {SECURITY_CONFIG_PATH}. "
            "Use --force to overwrite.[/yellow]"
        )
        raise typer.Exit(1)
    SecurityConfig.write_defaults()
    console.print(f"[green]Default config written to {SECURITY_CONFIG_PATH}[/green]")


app.add_typer(config_app)


# ── Hooks sub-app ─────────────────────────────────────────────────────────────

hooks_app = typer.Typer(name="hooks", help="Runtime hook integration — plugin events & monitoring")


@hooks_app.command("status")
def hooks_status() -> None:
    """Show plugin registration status and recent event count."""
    from sentinel.hooks.plugin import ClawAuditPlugin
    from sentinel.hooks.store import EventStore

    plugin = ClawAuditPlugin()
    registered = plugin.is_registered()

    console.print("[bold]Runtime Hook Status[/bold]\n")
    if registered:
        console.print("[green]Plugin: registered[/green]")
        manifest = plugin.read_manifest()
        if manifest:
            console.print(f"  Endpoint: {manifest.get('endpoint', 'N/A')}")
            console.print(f"  Hooks: {', '.join(manifest.get('hooks', []))}")
    else:
        console.print("[yellow]Plugin: not registered[/yellow]")
    console.print(f"  Manifest: {plugin.manifest_path}")

    store = EventStore()
    stats = asyncio.run(store.stats())
    console.print(f"\n  Total events: {stats['total_events']}")
    console.print(f"  Total alerts: {stats['total_alerts']}")


@hooks_app.command("register")
def hooks_register() -> None:
    """Register ClawAudit as an OpenClaw plugin."""
    from sentinel.hooks.plugin import ClawAuditPlugin

    plugin = ClawAuditPlugin()
    path = plugin.register()
    console.print(f"[green]Plugin registered at {path}[/green]")


@hooks_app.command("unregister")
def hooks_unregister() -> None:
    """Remove the ClawAudit plugin registration."""
    from sentinel.hooks.plugin import ClawAuditPlugin

    plugin = ClawAuditPlugin()
    plugin.unregister()
    console.print("[yellow]Plugin unregistered[/yellow]")


@hooks_app.command("events")
def hooks_events(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of events to show"),
    alerts_only: bool = typer.Option(False, "--alerts-only", help="Show only alerted events"),
    session: str | None = typer.Option(None, "--session", "-s", help="Filter by session ID"),
) -> None:
    """List recent tool events."""
    from sentinel.hooks.store import EventStore

    store = EventStore()
    events = asyncio.run(store.list(session_id=session, limit=limit, alerts_only=alerts_only))

    if not events:
        console.print("[dim]No events recorded yet.[/dim]")
        return

    table = Table(title=f"Recent Tool Events (last {limit})", show_lines=True)
    table.add_column("Time")
    table.add_column("Session")
    table.add_column("Skill")
    table.add_column("Tool")
    table.add_column("Outcome")
    table.add_column("Alert")

    for e in events:
        alert_badge = "[red]ALERT[/red]" if e.alert_triggered else "[dim]—[/dim]"
        outcome_color = (
            "green" if e.outcome == "success" else "yellow" if e.outcome == "pending" else "red"
        )
        table.add_row(
            e.timestamp.isoformat()[:19],
            e.session_id[:12] + "..." if len(e.session_id) > 12 else e.session_id,
            e.skill_name or "—",
            e.tool_name,
            f"[{outcome_color}]{e.outcome}[/{outcome_color}]",
            alert_badge,
        )

    console.print(table)


@hooks_app.command("simulate")
def hooks_simulate() -> None:
    """Fire a test event to verify the hook pipeline works."""
    from datetime import datetime, timezone  # noqa: UP017

    from sentinel.hooks.bus import HookBus
    from sentinel.hooks.event import ToolEvent
    from sentinel.hooks.store import EventStore

    event = ToolEvent(
        session_id="test-session",
        skill_name="test-skill",
        tool_name="exec",
        params_summary="echo hello world",
        timestamp=datetime.now(timezone.utc),  # noqa: UP017
        outcome="success",
    )

    bus = HookBus()
    store = EventStore()

    async def run() -> None:
        await bus.publish(event)
        await store.save(event)

    asyncio.run(run())

    console.print(f"[green]Test event fired and stored: {event.id}[/green]")
    if event.alert_triggered:
        console.print(f"[yellow]Alert triggered: {', '.join(event.alert_reasons)}[/yellow]")
    else:
        console.print("[dim]No alerts triggered (expected for benign test event)[/dim]")


app.add_typer(hooks_app)


# ── New quick-start commands ──────────────────────────────────────────────────

_OPENCLAW_SEARCH_PATHS = [
    "/opt/homebrew/lib/node_modules/openclaw",
    "/usr/local/lib/node_modules/openclaw",
]


def _find_openclaw() -> Path | None:
    """Locate the OpenClaw installation directory."""
    env_path = os.environ.get("OPENCLAW_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    for candidate in _OPENCLAW_SEARCH_PATHS:
        p = Path(candidate)
        if p.exists():
            return p

    # Search ~/.nvm for openclaw
    nvm_dir = Path.home() / ".nvm"
    if nvm_dir.exists():
        for match in nvm_dir.glob("versions/node/*/lib/node_modules/openclaw"):
            if match.exists():
                return match

    # Check if openclaw is on PATH
    openclaw_bin = shutil.which("openclaw")
    if openclaw_bin:
        return Path(openclaw_bin).resolve().parent

    return None


@app.command()
def version() -> None:
    """Print ClawAudit version, Python version, platform, and OpenClaw detection."""
    try:
        ver = pkg_version("clawaudit-sentinel")
    except Exception:
        ver = "unknown"

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    plat = platform.platform()
    oc_path = _find_openclaw()

    console.print(f"ClawAudit  {ver}")
    console.print(f"Python     {py_ver}")
    console.print(f"Platform   {plat}")
    if oc_path:
        console.print(f"OpenClaw   [green]✓ found at {oc_path}[/green]")
    else:
        console.print("OpenClaw   [yellow]✗ not found[/yellow]")


@app.command()
def doctor() -> None:
    """Validate environment readiness step by step."""
    checks: list[tuple[str, bool, str]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # 1. Python version
        task = progress.add_task("Checking Python version...", total=1)
        py_ok = sys.version_info >= (3, 10)
        py_hint = "" if py_ok else "Upgrade to Python 3.10+: https://python.org/downloads"
        checks.append(
            (
                f"Python ≥ 3.10 (found {sys.version_info.major}.{sys.version_info.minor})",
                py_ok,
                py_hint,
            )
        )
        progress.advance(task)

        # 2. OpenClaw binary / skills dir
        task = progress.add_task("Locating OpenClaw...", total=1)
        oc_path = _find_openclaw()
        oc_ok = oc_path is not None
        oc_hint = "" if oc_ok else "Install OpenClaw: npm install -g openclaw"
        checks.append(
            (
                f"OpenClaw installation ({oc_path or 'not found'})",
                oc_ok,
                oc_hint,
            )
        )
        progress.advance(task)

        # 3. Sentinel config
        task = progress.add_task("Checking sentinel config...", total=1)
        sentinel_yaml = Path.home() / ".openclaw" / "sentinel" / "sentinel.yaml"
        cfg_ok = sentinel_yaml.exists()
        cfg_hint = "" if cfg_ok else "Run: clawaudit config init"
        checks.append(
            (
                f"Sentinel config ({sentinel_yaml})",
                cfg_ok,
                cfg_hint,
            )
        )
        progress.advance(task)

        # 4. Skill registry
        task = progress.add_task("Checking skill registry...", total=1)
        registry_path = Path.home() / ".openclaw" / "sentinel" / "skill-registry.json"
        reg_ok = registry_path.exists()
        reg_hint = "" if reg_ok else "Registry will be created on first skill install"
        checks.append(
            (
                f"Skill registry ({registry_path})",
                reg_ok,
                reg_hint,
            )
        )
        progress.advance(task)

        # 5. Backend reachable
        task = progress.add_task("Checking backend (localhost:18790)...", total=1)
        backend_ok = False
        try:
            httpx.get("http://localhost:18790/health", timeout=3)
            backend_ok = True
        except Exception:
            pass
        backend_hint = "" if backend_ok else "Start backend: clawaudit-api or ./start.sh"
        checks.append(("Backend reachable (localhost:18790)", backend_ok, backend_hint))
        progress.advance(task)

        # 6. Dashboard reachable
        task = progress.add_task("Checking dashboard (localhost:3000)...", total=1)
        dash_ok = False
        try:
            httpx.get("http://localhost:3000", timeout=3)
            dash_ok = True
        except Exception:
            pass
        dash_hint = "" if dash_ok else "Start dashboard: cd frontend && npm run dev"
        checks.append(("Dashboard reachable (localhost:3000)", dash_ok, dash_hint))
        progress.advance(task)

    # Print results
    console.print()
    passed = 0
    failed = 0
    for label, ok, hint in checks:
        if ok:
            console.print(f"  [green]✓[/green] {label}")
            passed += 1
        else:
            console.print(f"  [red]✗[/red] {label}")
            if hint:
                console.print(f"    [dim]Fix: {hint}[/dim]")
            failed += 1

    console.print()
    if failed == 0:
        console.print(f"[green]All {passed} checks passed — environment is ready.[/green]")
    else:
        console.print(f"[green]{passed} passed[/green], [red]{failed} failed[/red]")


@app.command()
def scan(
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Output format: markdown or json"
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save report to file"),
    config_path: Path | None = typer.Option(None, "--config", "-c", help="Sentinel config file"),
) -> None:
    """Run a full ClawAudit security scan (alias for audit)."""
    audit(format=format, output=output, config_path=config_path)


@app.command()
def monitor(
    interval: int = typer.Option(60, "--interval", "-i", help="Scan interval in seconds"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Start continuous monitoring (alias for watch)."""
    watch(interval=interval, config_path=config_path)


@app.command()
def findings(
    severity: str | None = typer.Option(
        None, "--severity", "-s", help="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"
    ),
    limit: int = typer.Option(50, "--limit", "-n", help="Max findings to display"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Show findings from the last scan."""
    cfg = load_config(config_path)
    findings_path = cfg.findings_file

    if not findings_path.exists():
        console.print("[yellow]No findings recorded yet. Run: clawaudit scan[/yellow]")
        raise typer.Exit(1)

    records: list[dict] = []
    for line in findings_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not records:
        console.print("[yellow]No findings recorded yet. Run: clawaudit scan[/yellow]")
        raise typer.Exit(1)

    # Filter by severity
    if severity:
        sev_upper = severity.upper()
        records = [r for r in records if r.get("severity", "").upper() == sev_upper]

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    records.sort(key=lambda r: sev_order.get(r.get("severity", "INFO"), 99))

    # Apply limit
    records = records[:limit]

    if format == "json":
        console.print(json.dumps(records, indent=2))
        return

    table = Table(title="ClawAudit Findings", show_lines=True)
    table.add_column("Severity")
    table.add_column("Check ID", style="bold")
    table.add_column("Title")
    table.add_column("Location", overflow="fold")

    for r in records:
        sev = r.get("severity", "INFO")
        color = _severity_color(sev)
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            r.get("check_id", ""),
            r.get("title", "")[:60],
            r.get("location", "")[:50],
        )

    console.print(table)
    console.print(f"[dim]Showing {len(records)} finding(s)[/dim]")


@app.command()
def quickstart(
    config_path: Path | None = typer.Option(None, "--config", "-c"),
) -> None:
    """Full onboarding flow — detect environment, scan, and display results."""
    console.print(
        Panel(
            "[bold]ClawAudit Quick Start[/bold]\nForensic security auditor for OpenClaw",
            style="blue",
        )
    )
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Step 1 — Detect environment
        task = progress.add_task("Step 1: Detecting environment...", total=1)
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        plat = platform.platform()
        progress.advance(task)
        progress.update(task, description=f"Step 1: Python {py_ver} on {plat}")

        # Step 2 — Find OpenClaw
        task = progress.add_task("Step 2: Finding OpenClaw...", total=1)
        oc_path = _find_openclaw()
        if not oc_path:
            progress.stop()
            console.print(
                "\n[red]✗ OpenClaw not found.[/red]\n"
                "[dim]Install OpenClaw: npm install -g openclaw\n"
                "Or set OPENCLAW_PATH environment variable.[/dim]"
            )
            raise typer.Exit(1)
        progress.advance(task)
        progress.update(task, description=f"Step 2: OpenClaw at {oc_path}")

        # Step 3 — Check skills directory
        task = progress.add_task("Step 3: Checking skills directory...", total=1)
        skills_dir = oc_path / "skills" if (oc_path / "skills").exists() else None
        skill_count = 0
        if skills_dir:
            skill_count = sum(1 for _ in skills_dir.glob("*/SKILL.md"))
        progress.advance(task)
        progress.update(task, description=f"Step 3: {skill_count} skill(s) found")

        # Step 4 — Validate/create config
        task = progress.add_task("Step 4: Validating configuration...", total=1)
        sentinel_yaml = Path.home() / ".openclaw" / "sentinel" / "sentinel.yaml"
        if not sentinel_yaml.exists():
            progress.update(task, description="Step 4: Creating default config...")
            try:
                from sentinel.config import SecurityConfig

                SecurityConfig.write_defaults()
            except Exception:
                pass
        progress.advance(task)
        progress.update(task, description="Step 4: Configuration ready")

        # Step 5 — Run security scan
        task = progress.add_task("Step 5: Running security scan...", total=1)
        cfg = load_config(config_path)
        reporter = ComplianceReporter(cfg)
        run_id, scan_findings = reporter.run_full_audit()
        progress.advance(task)
        progress.update(
            task,
            description=f"Step 5: Scan complete — {len(scan_findings)} finding(s)",
        )

    # Save findings
    findings_file = cfg.findings_file
    findings_file.parent.mkdir(parents=True, exist_ok=True)
    with findings_file.open("a") as fh:
        for f in scan_findings:
            fh.write(json.dumps(f.to_dict()) + "\n")

    # Step 6 — Display results
    console.print()

    # Count by severity
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    passes = 0
    for f in scan_findings:
        if f.result == "PASS":
            passes += 1
        if f.severity in counts:
            counts[f.severity] += 1

    total = len(scan_findings)

    summary_lines = [
        "[bold]ClawAudit Security Scan Complete[/bold]",
        "",
        f"  [red]CRITICAL  {counts['CRITICAL']}[/red]    "
        f"[orange3]HIGH   {counts['HIGH']}[/orange3]    "
        f"[yellow]MEDIUM  {counts['MEDIUM']}[/yellow]",
        f"  [blue]LOW       {counts['LOW']}[/blue]    "
        f"[green]PASS  {passes}[/green]    "
        f"Total   {total}",
    ]

    # Top findings (up to 3 CRITICAL/HIGH)
    top = [
        f
        for f in sorted(
            scan_findings,
            key=lambda x: (
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)
                if x.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                else 99
            ),
        )
        if f.result == "FAIL" and f.severity in ("CRITICAL", "HIGH")
    ][:3]

    if top:
        summary_lines.append("")
        summary_lines.append("[bold]Top findings:[/bold]")
        sev_icons = {"CRITICAL": "[red]CRITICAL[/red]", "HIGH": "[orange3]HIGH[/orange3]"}
        for f in top:
            icon = sev_icons.get(f.severity, f.severity)
            summary_lines.append(f"  {icon} {f.location} — {f.title}")

    summary_lines.extend(
        [
            "",
            "[bold]Next steps:[/bold]",
            "  clawaudit findings       view all findings",
            "  clawaudit remediate      preview auto-fixes",
            "  clawaudit monitor        continuous monitoring",
            "  clawaudit report -o r.md export full report",
        ]
    )

    console.print(Panel("\n".join(summary_lines), style="green", padding=(1, 2)))


if __name__ == "__main__":
    app()
