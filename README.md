# Free push-triggered security scan (v2)

Scans a repo on every push to `main` and on manual runs, then opens **one GitHub issue per new finding** (deduplicated, never reopened if you close it). 100% free: no AI model key, card, or third-party account. Standard GitHub-hosted runners are [free for public repositories](https://docs.github.com/en/actions/concepts/billing-and-usage).

Findings are leads for review, not confirmed vulnerabilities. Issues link to the flagged line and scan run; they do not copy source snippets.

## What v2 checks (20-point web-app checklist)

| # | Checklist item | Covered by |
|---|---|---|
| 1 | SQL / command injection, unsafe queries | Semgrep `security-audit`, `owasp-top-ten`, `nodejs`, `python` |
| 2 | Missing input validation, unsafe eval | Semgrep JS/TS/Python packs |
| 3 | XSS, unsafe HTML rendering | Semgrep `javascript`, `typescript`, `react` |
| 4 | Unsafe file uploads, path traversal | Semgrep `expressjs`, `owasp-top-ten` |
| 5 | Weak password hashing / weak crypto | Semgrep `security-audit`, `python` |
| 6 | JWT mistakes (none alg, hardcoded secrets) | Semgrep `jwt` |
| 7 | Rate limiting on login / OTP | `hygiene_checks.py` (Express apps without a rate-limit package) |
| 8 | Missing access control, insecure auth | Semgrep `owasp-top-ten`, `expressjs` |
| 9 | Password reset / session flaws | Semgrep `owasp-top-ten` (partial; needs human review) |
| 10 | HTTPS / HSTS | `header_check.py` (optional live URL) |
| 11 | Security headers (CSP, X-Frame-Options, nosniff) | `header_check.py`; `hygiene_checks.py` flags missing `helmet` |
| 12 | CORS misconfiguration | `header_check.py`; `hygiene_checks.py` |
| 13 | CSRF | Semgrep `owasp-top-ten`, `expressjs` |
| 14 | Secrets in code | Semgrep `secrets`; committed `.env` / key files; `.env` not in `.gitignore` |
| 15 | Keys that touched a repo need rotating | Issue text on secret findings; rotation is manual |
| 16 | Sensitive data at rest | Semgrep crypto rules (partial) |
| 17 | Vulnerable dependencies | `dependency_audit.py`: `npm audit` (high/critical, prod deps) and `pip-audit` |
| 18 | Verbose errors / stack traces | Semgrep `expressjs`, `python` (partial) |
| 19 | Logging of logins and admin actions | Not automatable; review by hand |
| 20 | Backups with tested restore | Not automatable; review by hand |

Items marked partial or by hand cannot be proven by static scanning. Docker: Semgrep `dockerfile` pack plus a root-user check.

## Add it to any repo (public or private)

This repo's workflow is reusable. In the other repo, create `.github/workflows/security-scan.yml` with the contents of [`examples/caller-workflow.yml`](examples/caller-workflow.yml):

```yaml
name: Security scan
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
  issues: write
jobs:
  scan:
    uses: sourav-bwn/free-security-scanner/.github/workflows/security-scan.yml@main
    permissions:
      contents: read
      issues: write
    # with:
    #   header_url: https://your-site.example.com   # optional live header/HTTPS check
```

Requirements:
- Issues and Actions enabled on the target repo.
- Settings > Actions > General > Workflow permissions allows the workflow token to create issues (the `permissions` block above requests it).
- A **private** repo can call this public reusable workflow. Private repos use your free Actions minutes (2,000/month on the Free plan), so each scan counts against that. Issues are created in the scanned repo, not here.
- Pass `allowed_owner` if the repo is owned by someone other than `sourav-bwn`.

## Notes

- Semgrep CE, checkout and setup-python are pinned; review upstream releases before bumping. Registry rule packs are fetched on each run and can change.
- Anonymous Semgrep CE may omit stable fingerprints. Dedup then uses rule + file + line, so moved code can open a new issue.
- A failed or partial scan creates no issues.
- `npm audit` needs a `package-lock.json`; `pip-audit` reads `requirements.txt`.
- [Strix](https://github.com/usestrix/strix/blob/main/README.md) and [Alibaba OpenCodeReview](https://github.com/alibaba/open-code-review/blob/main/action.yml) are not enabled: they need an LLM key.
