# jean-claude-van-damme

A Claude skill for security review and secure coding. It covers the OWASP Top 10, ASVS, LLM/agent risks, secrets, supply chain and insecure defaults, with diff-based review and false-positive triage. It is read-only by default: it reports findings and proposes fixes without editing code unless asked.

## Install

### Claude Code (plugin marketplace)

```
/plugin marketplace add as-one/jean-claude-van-damme
/plugin install jean-claude-van-damme@as-one
```

### Claude Code (manual)

Personal install:

```
git clone https://github.com/as-one/jean-claude-van-damme.git
cp -r jean-claude-van-damme/skills/jean-claude-van-damme ~/.claude/skills/
```

Per project: copy the same folder to `.claude/skills/` inside your repository.

### Claude.ai / Claude Desktop

Zip the `skills/jean-claude-van-damme` folder and upload it under Settings > Capabilities > Skills.

To update the plugin:

```
claude plugin marketplace update as-one
claude plugin update jean-claude-van-damme@as-one
```

Restart Claude Code to apply the update.

## Usage

Just ask. The skill loads on security requests, in English or Portuguese:

| You want to | Ask something like |
|---|---|
| Review your changes | "review my changes for security issues" |
| Check one thing before merging | "is this safe to ship?" |
| Audit a project | "audit this repo" |
| Take a fast look | "quick security look at the auth code" |
| Check infrastructure | "is this GitHub Actions workflow safe?" |
| Review an agent | "check this MCP server for prompt injection risks" |
| Write code securely | "add a file upload endpoint, securely" |
| Perguntar em português | "isso aqui tem alguma vulnerabilidade?" |

To call it explicitly in Claude Code (plugin install):

```
/jean-claude-van-damme:jean-claude-van-damme review the changes in this branch
```

With a manual install, use `/jean-claude-van-damme`.

### Scopes

| Scope | Covers |
|---|---|
| diff | Changed files and their callers and callees |
| quick | Entry points, auth, secrets and injection sinks |
| full | The whole repository |

If you do not name one, it uses diff when there is a Git diff and quick otherwise.

### What you get

Findings ordered by severity, each with the path from input to sink, followed by what was not reviewed. Illustrative example:

```
### [High] Any user can read any invoice  (CWE-639, A01:2025 Broken Access Control, confidence: High)
- Location: api/invoices.py:42
- Path: invoice_id (URL) -> get_invoice() -> SELECT without owner filter
- Impact: a logged-in user reads other customers' invoices
- Fix: filter by owner_id of the current user
```

It does not edit code unless you ask, and it does not run code from the project under review without your explicit request. It is a model-driven review, not a scanner: pair it with tools such as Semgrep, gitleaks and your package manager's audit.

## Layout

```
.claude-plugin/
  plugin.json
  marketplace.json
skills/
  jean-claude-van-damme/
    SKILL.md               # workflow, triage rubric, report format
    reference/             # read only when the review needs it
      review-checklist.md  # coverage checklist by topic
      owasp-codes.md       # short index of OWASP and ASVS IDs
      owasp-top10.md       # Top 10:2025 in detail, with examples
      asvs.md              # ASVS 5.0 requirements by chapter and level
      owasp-ai.md          # LLM and Agentic Top 10 (2026) in detail
      languages.md         # pitfalls and examples for 19 language groups, SSRF, uploads, secrets
      iac-and-ci.md        # CI/CD, lockfiles, SBOM and signing, containers, cloud, headers, with examples
evals/                     # test cases for `claude plugin eval`
```

## Evals

The command compares results with the skill against a baseline without it. It calls real models and is charged to your account, so set a ceiling with `--max-cost-usd`.

```bash
claude plugin eval . --no-publish --max-cost-usd 5
```

Run them before and after changing the skill. Results are written to `evals/results/`, which is ignored by Git.

## Updating the codes

OWASP editions change over time. Once a year, check the sources listed in `reference/owasp-codes.md`, update `owasp-codes.md`, `owasp-top10.md`, `asvs.md`, `owasp-ai.md` and their check dates, review the IDs cited in `review-checklist.md`, and bump the plugin version.

## License

MIT (see [LICENSE](LICENSE)), except for the reference files that summarize OWASP material (OWASP and ASVS names and IDs belong to the OWASP Foundation):

| File in `reference/` | Terms |
|---|---|
| `asvs.md`, `owasp-ai.md` | CC BY-SA 4.0 |
| `owasp-top10.md` | Summaries of OWASP Top 10 material, which is CC BY 3.0; attribution required |
| `owasp-codes.md` | Names and IDs from the sources listed in the file, under their licenses |
