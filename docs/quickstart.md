# ClawAudit Quick Start Guide

## Prerequisites

- **Python 3.10+** (3.11+ recommended)
- **OpenClaw** installed (`npm install -g openclaw`)
- **pip** (included with Python)

## Installation

```bash
git clone https://github.com/yaseenkadlemakki/clawaudit.git
cd clawaudit
pip install -e .
```

## One-Command Start

```bash
clawaudit quickstart
```

This single command will:
1. Detect your Python version and platform
2. Locate your OpenClaw installation
3. Discover installed skills
4. Validate or create the sentinel configuration
5. Run a full security scan
6. Display a results summary with next steps

## Step-by-Step Manual Flow

If you prefer to run each step individually:

### 1. Check your environment

```bash
clawaudit doctor
```

This validates Python version, OpenClaw installation, config files, and service connectivity.

### 2. Run a security scan

```bash
clawaudit scan
```

Runs all 43 checks across 6 security domains. Add `--format json --output report.json` to export.

### 3. Review findings

```bash
clawaudit findings
clawaudit findings --severity CRITICAL
clawaudit findings --format json
```

### 4. Preview and apply remediations

```bash
clawaudit remediate              # dry-run: list proposals
clawaudit remediate --apply      # apply fixes (creates snapshots)
```

### 5. Start continuous monitoring

```bash
clawaudit monitor                # default 60s interval
clawaudit monitor --interval 30  # custom interval
```

### 6. Generate a compliance report

```bash
clawaudit report -o report.md
clawaudit report --format json -o report.json
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `clawaudit quickstart` | Full onboarding flow |
| `clawaudit version` | Show version, Python, platform, OpenClaw status |
| `clawaudit doctor` | Validate environment readiness |
| `clawaudit scan` | Run a full security scan |
| `clawaudit findings` | View findings from the last scan |
| `clawaudit monitor` | Start continuous monitoring daemon |
| `clawaudit audit` | Run audit (original command) |
| `clawaudit watch` | Start monitoring (original command) |
| `clawaudit skills` | List skills with trust scores |
| `clawaudit skills list` | List all registered skills |
| `clawaudit skills install` | Install a skill from file or URL |
| `clawaudit skills enable` | Enable a disabled skill |
| `clawaudit skills disable` | Disable a skill |
| `clawaudit skills uninstall` | Uninstall a skill (to trash) |
| `clawaudit skills recover` | Recover from trash |
| `clawaudit skills health` | Security analysis on a single skill |
| `clawaudit remediate` | Preview or apply remediations |
| `clawaudit report` | Generate compliance report |
| `clawaudit policies --list` | List loaded policy rules |
| `clawaudit alerts` | View recent alerts |
| `clawaudit baseline` | Manage config baselines |
| `clawaudit snapshots` | Manage remediation snapshots |
| `clawaudit config show` | Print effective configuration |
| `clawaudit config init` | Write default config file |
| `clawaudit hooks status` | Show plugin registration status |

## Common Use Cases

### CI Integration

Add ClawAudit to your CI pipeline to catch security issues before deployment:

```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    pip install -e .
    clawaudit scan --format json --output security-report.json
```

The `scan` command exits with code 1 when findings with `FAIL` results are detected, making it suitable for CI gates.

### Scheduled Scans

Use `clawaudit monitor` for continuous monitoring, or schedule periodic scans:

```bash
# crontab -e
0 */6 * * * cd /path/to/clawaudit && clawaudit scan --format json -o /var/log/clawaudit/scan-$(date +\%Y\%m\%d-\%H\%M).json
```

### Remediation Workflow

```bash
# 1. Scan to identify issues
clawaudit scan

# 2. Review findings
clawaudit findings --severity CRITICAL

# 3. Preview proposed fixes
clawaudit remediate

# 4. Apply fixes with confirmation
clawaudit remediate --apply

# 5. Verify fixes
clawaudit scan

# 6. Rollback if needed
clawaudit snapshots list
clawaudit snapshots rollback <snapshot-name>
```
