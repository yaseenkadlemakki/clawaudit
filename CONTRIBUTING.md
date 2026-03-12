# Contributing to ClawAudit

Thank you for taking the time to contribute! ClawAudit is a community-driven project, and every contribution — code, docs, bug reports, or ideas — makes it better. 🎉

---

## Table of Contents

- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Development Setup](#development-setup)
- [Branch Naming](#branch-naming)
- [Commit Messages](#commit-messages)
- [Code Style](#code-style)
- [Running Tests](#running-tests)
- [Pull Request Requirements](#pull-request-requirements)

---

## Reporting Bugs

Found a bug? Please [open a GitHub Issue](https://github.com/yaseenkadlemakki/clawaudit/issues/new?template=bug_report.yml) and fill in the bug report template. Include:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Your environment (OS, Python version, Docker vs local, ClawAudit version)
- Relevant logs or stack traces

> **Security vulnerabilities** — do NOT file public issues. See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## Suggesting Features

Have an idea? [Open a feature request issue](https://github.com/yaseenkadlemakki/clawaudit/issues/new?template=feature_request.yml). Describe the problem you're trying to solve and why the proposed solution makes sense. We love opinionated proposals.

---

## Development Setup

### Requirements

- **Python 3.10+** (3.11 recommended)
- **Node.js 18+**
- **Docker + Docker Compose** (optional, for the full stack)

### Local Setup

```bash
# Clone the repo
git clone https://github.com/yaseenkadlemakki/clawaudit.git
cd clawaudit

# Install Python dependencies (backend + dev extras)
pip install -e ".[backend,dev]"

# Install frontend dependencies
cd frontend && npm install && cd ..

# Copy env example
cp docker/.env.example docker/.env
# Edit docker/.env — set POSTGRES_PASSWORD and any other required vars

# Start the backend
uvicorn backend.main:app --host 0.0.0.0 --port 18790 --reload

# In another terminal, start the frontend
cd frontend && npm run dev
```

### Docker Setup

```bash
cp docker/.env.example docker/.env
# Edit docker/.env

docker compose --env-file docker/.env -f docker/docker-compose.yml up --build
```

The full stack will be available at:
- Dashboard: http://localhost:3000
- API: http://localhost:18790
- API Docs: http://localhost:18790/docs

---

## Branch Naming

Use a consistent prefix for every branch:

| Prefix | Use for |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `chore/` | Maintenance, deps, tooling |
| `test/` | Tests only (no production code changes) |
| `docs/` | Documentation only |

Examples: `feat/policy-engine`, `fix/issue-74-chunk-paths`, `chore/update-deps`

---

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

[optional body]

[optional footer: Closes #123]
```

| Type | Use for |
|------|---------|
| `feat:` | A new feature |
| `fix:` | A bug fix |
| `test:` | Adding or updating tests |
| `chore:` | Build process, tooling, deps |
| `docs:` | Documentation changes |
| `refactor:` | Code change that neither fixes a bug nor adds a feature |
| `style:` | Formatting, linting (no logic change) |

---

## Code Style

We use [Ruff](https://docs.astral.sh/ruff/) for both linting and formatting.

```bash
# Check for lint errors
ruff check .

# Auto-fix lint errors
ruff check --fix .

# Format code
ruff format .

# Check formatting without modifying (CI mode)
ruff format --check .
```

Configuration is in `pyproject.toml`. Line length is 100. Target Python is 3.11.

---

## Running Tests

### Python tests (pytest)

```bash
# Run the full test suite with coverage
pytest --cov=sentinel --cov=backend --cov-report=term-missing

# Run only unit tests
pytest -m unit

# Run only backend tests
pytest -m backend

# Run a specific test file
pytest tests/test_policy_engine.py -v
```

The coverage gate is **80%** — PRs that drop coverage below this threshold will fail CI.

### End-to-end / Playwright tests

```bash
cd frontend
npm run test:e2e
```

Playwright tests require the backend and frontend to be running. Use Docker Compose for a stable environment.

---

## Pull Request Requirements

Before opening a PR, please ensure:

- [ ] **All tests pass** — `pytest` must pass with ≥80% coverage
- [ ] **Ruff is clean** — `ruff check .` and `ruff format --check .` must return no errors
- [ ] **One concern per PR** — don't bundle unrelated changes
- [ ] **Tests included** — new features and bug fixes should come with tests
- [ ] **No regressions** — existing behavior must not break
- [ ] **PR description filled out** — use the PR template

We review PRs promptly. If you don't hear back within a few days, feel free to ping in the issue or discussion thread.

---

## Thank You

Every contribution matters — from typo fixes to major features. We appreciate you spending your time to make ClawAudit better for everyone. 🙏
