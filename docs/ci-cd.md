# CI/CD Pipeline

ClawAudit uses two GitHub Actions workflows.

## `test.yml` — Test Suite

Runs on every push and PR to `master`.

```
lint-yaml
    │
    ├──► unit-tests (Python 3.10 / 3.11 / 3.12)
    │        │
    │        ├──► functional-tests ──┐
    │        └──► integration-tests ─┤
    │                                ▼
    │                           coverage (80% gate)
    └──► backend-tests
    └──► sentinel-tests
                                      │
                                      ▼
                               all-tests-passed (gate)
```

| Job | Purpose |
|-----|---------|
| `lint-yaml` | yamllint on `data/` and `.github/workflows/` |
| `unit-tests` | `tests/unit/` across Python 3.10/3.11/3.12 |
| `functional-tests` | `tests/functional/` |
| `integration-tests` | `tests/integration/` (fail-fast: `-x`) |
| `coverage` | Full suite, 80% gate, uploads HTML + XML artifacts |
| `backend-tests` | `tests/backend/` with full backend deps |
| `sentinel-tests` | Sentinel unit + integration tests |
| `all-tests-passed` | Final status gate (required for merge) |

---

## `build.yml` — Build & Publish

Runs on every push and PR to `master`, and on version tags (`v*.*.*`).

```
audit-python  audit-node
    │              │
    ▼              ▼
lint-python    build-frontend
    │
    ▼
build-backend
    │
    └──► build-complete (gate)
```

| Job | Purpose |
|-----|---------|
| `audit-python` | `pip-audit` — checks Python deps for known CVEs |
| `audit-node` | `npm audit --audit-level=high` |
| `lint-python` | `ruff check` + `ruff format --check` on `backend/` and `sentinel/` |
| `build-backend` | Builds `docker/Dockerfile.backend`; pushes to GHCR on merge |
| `build-frontend` | Builds `docker/Dockerfile.frontend`; pushes to GHCR on merge |
| `build-complete` | Final status gate |

### Image Tags

Images are published to `ghcr.io/yaseenkadlemakki/clawaudit-{backend,frontend}` with:
- Branch name (e.g., `master`)
- PR reference (e.g., `pr-14`)
- Semver on tags (e.g., `1.2.3`, `1.2`)
- Short SHA (e.g., `sha-abc1234`)

Images are only pushed on non-PR runs (i.e., after merge to `master` or on tag push). PRs only trigger a build to verify the Dockerfile is valid.

---

## Adding a New Required Check

1. Add your job to the appropriate workflow
2. Add the job name to the `needs:` list of the gate job (`all-tests-passed` or `build-complete`)
3. Add the result check to the gate job's shell script:
   ```yaml
   if [[ "${{ needs.my-new-job.result }}" != "success" || ...
   ```
