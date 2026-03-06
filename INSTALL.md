# Installing ClawAudit into an OpenClaw Deployment

## Requirements

- **OpenClaw** ≥ 1.0.0
- **Platform:** macOS (primary), Linux (supported — adjust install path for Method 1)
- **Permissions:** Read access to the OpenClaw config file and skills directory. No write permissions required.

## Method 1: Copy to OpenClaw Skills Directory (Recommended)

```bash
cp -r /path/to/clawaudit /opt/homebrew/lib/node_modules/openclaw/skills/clawaudit
```

Then restart OpenClaw:
```bash
openclaw gateway restart
```

Invoke with:
```
/clawaudit
```

## Method 2: Workspace-local (Current Setup)

ClawAudit is already present in `~/.openclaw/workspace/clawaudit/`.
The agent can invoke it by reading `SKILL.md` directly.

## Method 3: Package as .skill file

From the workspace root:
```bash
# If skill-creator init_skill.py is available:
python3 /opt/homebrew/lib/node_modules/openclaw/skills/skill-creator/scripts/package_skill.py \
  ~/.openclaw/workspace/clawaudit
```

Distribute the resulting `clawaudit.skill` file. Users install via OpenClaw dashboard or CLI.

## Verification

After install, confirm ClawAudit is recognized:
```
/skills list
```

Should show `clawaudit 🔍` in the list.

## Permissions Required

ClawAudit requires only read-access tools:
- `Read` (file reading)
- `gateway config.get` (live config access)
- `session_status` (timestamp)
- `memory_search` / `memory_get` (optional — for prior audit context)

It does **not** require `exec`, `Write`, `Edit`, or any messaging tool.

## Scheduling Periodic Audits

```bash
# Weekly audit every Monday at 09:00 — adjust timezone to your local zone
openclaw cron add \
  --name "clawaudit:weekly" \
  --schedule "cron:0 9 * * MON America/New_York" \
  --payload "agentTurn:/clawaudit" \
  --delivery "announce:discord"
```

Replace `America/New_York` with your local IANA timezone (e.g., `Europe/London`, `Asia/Tokyo`).
Run `openclaw cron list` to confirm the scheduled job was registered.
