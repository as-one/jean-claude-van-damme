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

## Usage

Ask Claude for a security review, for example "review my changes for security issues" or "audit this repo". The skill picks a scope (diff, quick or full) and reports triaged findings.

## Layout

```
.claude-plugin/
  plugin.json
  marketplace.json
skills/
  jean-claude-van-damme/
    SKILL.md               # workflow, triage rubric, report format
    reference/             # read only when the review needs it
      owasp-codes.md       # OWASP Top 10, LLM, Agentic and ASVS IDs
      languages.md         # pitfalls per language
      iac-and-ci.md        # CI/CD, dependencies, containers, Kubernetes, Terraform
evals/                     # test cases for `claude plugin eval`
```

## Evals

The command compares results with the skill against a baseline without it. It calls real models and is charged to your account, so set a ceiling with `--max-cost-usd`.

```bash
claude plugin eval . --no-publish --max-cost-usd 5
```

Run them before and after changing the skill. Results are written to `evals/results/`, which is ignored by Git.

## Updating the codes

OWASP editions change over time. Once a year, check the sources listed in `reference/owasp-codes.md`, update the tables and the "last checked" date, and bump the plugin version.

## Credits

The split into on-demand reference files, the eval approach and the "every step is possible for the attacker" triage rule were inspired by [agamm/claude-code-owasp](https://github.com/agamm/claude-code-owasp) (MIT). The text here was written for this project. OWASP and ASVS names and IDs belong to the OWASP Foundation; see `reference/owasp-codes.md` for sources and licenses.

## License

MIT. See [LICENSE](LICENSE).
