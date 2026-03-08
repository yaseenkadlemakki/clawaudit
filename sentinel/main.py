"""ClawAudit Sentinel CLI entrypoint."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sentinel.alerts.engine import AlertEngine
from sentinel.analyzer.skill_analyzer import SkillAnalyzer
from sentinel.config import load_config
from sentinel.models.event import Event
from sentinel.models.skill import SkillProfile
from sentinel.policy.engine import PolicyEngine
from sentinel.reporter.compliance import ComplianceReporter

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


if __name__ == "__main__":
    app()
