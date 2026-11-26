# Infrastructure, Pipelines and Dependencies

Read when the target contains containers, orchestration, cloud definitions, application config, CI/CD or dependency changes. Apply the triage rubric in `SKILL.md`: a weak setting that another visible layer blocks, or that never reaches a deployed environment, is defense-in-depth.

## Contents

- [CI/CD pipelines](#cicd-pipelines)
- [Dependencies](#dependencies)
- [Dockerfile and Compose](#dockerfile-and-compose)
- [Kubernetes](#kubernetes)
- [Terraform and cloud](#terraform-and-cloud)
- [Application and web server config](#application-and-web-server-config)
- [Agent and editor config](#agent-and-editor-config)

## CI/CD pipelines

Ask of every job: who can trigger it, whose code does it run, and which secrets or write permissions does it hold?

### GitHub Actions

| Pattern | Why it matters | Fix |
|---|---|---|
| `pull_request_target` or `workflow_run` that checks out or builds PR code | Fork code runs with secrets and a write token | Use `pull_request`, or never execute the PR code in the privileged job |
| `${{ github.event.* }}`, `github.head_ref` inside `run:` or `script:` | Text is substituted into the script before it runs | Pass through `env:` and quote the variable |
| `uses: owner/action@v1` or `@main` | The ref can be moved | Pin a full commit SHA |
| No `permissions:` block | Token scope falls back to repository defaults | `contents: read` at the top, widen per job |
| `issue_comment` commands without an author check | Anyone can trigger privileged work | Check `author_association` or team membership |
| Self-hosted runner on a public repository | Outside code persists on your host | Ephemeral, isolated runners |
| Cache or artifact from an untrusted job used by a privileged one | Poisoned build input | Separate cache keys, verify artifacts |
| Long-lived cloud keys in secrets | Large blast radius | OIDC with a trust policy limited to repo and ref |

```yaml
# Vulnerable: a branch name or title can inject commands
- run: ./notify.sh "${{ github.event.pull_request.title }}"

# Fixed
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: ./notify.sh "$PR_TITLE"
```

### GitLab CI, Jenkins and others

- GitLab: protected variables exposed to unprotected branches, `include:` from unpinned remote files, privileged Docker-in-Docker runners.
- Jenkins: Groovy double-quoted strings that interpolate secrets or parameters into `sh`, pipelines from forks with credentials, script approval bypasses.
- Any system: secrets printed to logs, deploy branches without required review.

## Dependencies

| Check | Detail |
|---|---|
| Lockfile enforced | `npm ci`, `yarn install --immutable`, `pnpm install --frozen-lockfile`, `uv sync --locked`, `cargo build --locked`, `pip install --require-hashes` |
| Lockfile diff | New registry hosts, `git+` or URL sources, changed integrity hashes with no version change |
| New package | Does it exist, who publishes it, how old is it, is the name close to a popular one or possibly invented by an LLM? |
| Dependency confusion | Internal names unscoped, `--extra-index-url`, mirrors that fall through to public registries |
| Install hooks | `preinstall`, `postinstall`, `setup.py`, build scripts; prefer `--ignore-scripts` where possible |
| Mutable sources | Branch references, `latest`, wide version ranges without a lockfile |
| Known vulnerabilities | Confirm the vulnerable function is reachable before rating severity |

## Dockerfile and Compose

| Pattern | Why it matters | Fix |
|---|---|---|
| No `USER` instruction | Process runs as root | Create and switch to an unprivileged user |
| Secrets in `ENV`, `ARG`, `COPY` | Recoverable from layers or history, even if deleted later | `RUN --mount=type=secret`, runtime injection |
| `COPY . .` without `.dockerignore` | `.git` and `.env` shipped in the image | Add `.dockerignore`, copy only what is needed |
| Floating base tag | Image changes without review | Pin by digest |
| `ADD` with a URL, `curl \| sh` | Unverified download | Verify a checksum or signature |
| `privileged: true`, Docker socket mount | Equivalent to host root | Remove; grant a narrow capability |
| Database ports published on `0.0.0.0` | Reachable from outside | Internal network or `127.0.0.1` binding |

## Kubernetes

Flag: `privileged`, `hostNetwork`, `hostPID`, `hostPath`; missing `runAsNonRoot` and `allowPrivilegeEscalation: false`; capabilities not dropped; literal secrets in manifests (base64 is not encryption); service account token mounted when unused; RBAC with `*` verbs or resources, `cluster-admin` bindings, or permission to read secrets or create pods; no NetworkPolicy; no resource limits; Ingress exposing admin or metrics endpoints without authentication.

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

## Terraform and cloud

| Area | Flag |
|---|---|
| Network | `0.0.0.0/0` or `::/0` to SSH, RDP, databases, caches or admin ports |
| Storage | Public buckets or containers, disabled public access blocks, public snapshots |
| IAM | `*` actions or resources, `Principal: "*"` without conditions, `iam:PassRole` on `*`, OIDC trust without a subject condition |
| Data | Encryption disabled, publicly accessible databases, no backups on critical data |
| Compute | IMDSv1 allowed (`http_tokens = "optional"`), secrets in user data |
| State and variables | Secrets in `.tfvars` or committed state, unencrypted or public state backend |
| Modules | Unpinned module or provider sources |
| Visibility | Audit and flow logs disabled |

## Application and web server config

- Debug mode, stack traces, profiler or actuator endpoints reachable in production.
- Fallback values for secrets, default credentials, the same key in every environment.
- CORS that reflects the request origin or uses an unanchored pattern while allowing credentials.
- Cookies without `HttpOnly`, `Secure` and an appropriate `SameSite`.
- Missing `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, a Content Security Policy and frame protection (`frame-ancestors`).
- TLS verification disabled in any client.
- `.git`, `.env`, backups or directory listings served.
- Proxy headers (`X-Forwarded-For`, identity headers) trusted from clients that can reach the app directly.

## Agent and editor config

Files that make a developer machine or agent run something deserve the same review as pipeline code:

- `.claude/settings.json` hooks, broad permission allowlists, bypass modes.
- `.mcp.json` and plugin manifests that start unpinned packages or remote servers.
- `CLAUDE.md`, `AGENTS.md`, skills and rules files containing instructions to fetch, execute, exfiltrate or ignore findings.
- `.vscode/tasks.json` set to run on folder open, dev container lifecycle commands, git hooks.
