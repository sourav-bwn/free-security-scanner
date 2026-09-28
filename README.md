# Free push-triggered security scan

This example scans a public GitHub repository on every push to `main` and on manual runs. It uses [Semgrep CE](https://semgrep.dev/docs/cli-reference) and the [security-audit rule pack](https://semgrep.dev/p/security-audit). It needs no AI model key, card, or third-party account. Standard GitHub-hosted Actions runners are [free for public repositories](https://docs.github.com/en/actions/concepts/billing-and-usage).

A successful scan opens one issue per *new* Semgrep finding. Findings are leads for review, not confirmed vulnerabilities. The issue links to the flagged line and scan run; it does not copy source snippets. Existing issues, even if closed as false positives, are not reopened. Anonymous Semgrep CE scans may omit a stable fingerprint; then deduplication uses rule, file, and line, so moving affected code can create a new issue. This does not scan private repos or other repos by itself.

## Use it in another public repo

Copy `.github/workflows/security-scan.yml` and `scripts/security_issues.py` into that repository. Change the `push.branches` list if the default branch is not `main`, and change the repository-owner condition if you aren't `sourav-bwn`. Ensure Issues and Actions are enabled and the repository's Actions settings permit workflow `GITHUB_TOKEN` to create issues. No personal access token is needed.

The workflow pins checkout, setup-python, and Semgrep. Keep these updated after reviewing upstream releases. It has a 20-minute timeout, and a failed scan does not create issues from incomplete results. Registry rules are downloaded during each scan; the rule pack can evolve. Review every generated issue before making a change.

[Strix](https://github.com/usestrix/strix/blob/main/README.md) and [Alibaba OpenCodeReview](https://github.com/alibaba/open-code-review/blob/main/action.yml) are not enabled: their self-hosted CI examples need an LLM endpoint/key. Strix's managed service advertises a free signup, but its ongoing usage terms would need checking before promising free scans on every push. This version deliberately uses no metered model.
