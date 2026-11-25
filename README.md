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
    SKILL.md
```

## License

MIT. See [LICENSE](LICENSE).
