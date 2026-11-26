# LLM and Agentic Risks in Detail

For code that calls a model or runs an agent. Read the items that match the design. Apply the triage rubric in `SKILL.md`.

This file summarizes the OWASP Top 10 for LLM Applications 2026 (https://genai.owasp.org/top-10-for-llm-applications-2026/) and the OWASP Top 10 for Agentic Applications 2026 (https://genai.owasp.org/top-10-for-agentic-applications-2026/), checked 2026-11-26, with added review guidance. It is shared under CC BY-SA 4.0.

## Contents

- Start here: [First questions](#first-questions)
- LLM: [01](#llm01-prompt-injection) · [02](#llm02-sensitive-information-disclosure) · [03](#llm03-excessive-agency) · [04](#llm04-supply-chain) · [05](#llm05-data-and-model-poisoning) · [06](#llm06-unbounded-consumption) · [07](#llm07-misinformation) · [08](#llm08-hidden-context-exposure) · [09](#llm09-vector-and-embedding-weaknesses) · [10](#llm10-improper-output-handling)
- Agentic: [01](#asi01-agent-goal-hijack) · [02](#asi02-tool-misuse-and-exploitation) · [03](#asi03-identity-and-privilege-abuse) · [04](#asi04-agentic-supply-chain-vulnerabilities) · [05](#asi05-unexpected-code-execution-rce) · [06](#asi06-memory--context-poisoning) · [07](#asi07-insecure-inter-agent-communication) · [08](#asi08-cascading-failures) · [09](#asi09-human-agent-trust-exploitation) · [10](#asi10-rogue-agents)

## First questions

1. What text, files and tool results enter the context, and who can write them?
2. What can the model reach: data, tools, credentials, network?
3. Where does its output go: a screen, a query, a shell, another agent, memory?
4. What requires a human, and does the approval show the real action?

A useful design check: avoid giving one context all three of untrusted input, access to sensitive data, and the ability to change state or send data out. When all three are needed, require human approval.

Choosing between close items: injection into one response is LLM01; a changed agent goal is ASI01; a permitted tool used harmfully is ASI02; gaining access is ASI03; running code is ASI05; stored corruption is ASI06; spread between components is ASI08.

## LLM01 Prompt Injection

Any input the model reads can change its behavior, because instructions and data are not separated. There is no reliable prevention, so the defense is architectural.

**Look for:** retrieved pages, email, tickets, repository files, tool or MCP results, images, audio or memory placed in a context that also has tools or secrets; rendering that loads image URLs automatically.

**Attacks:** direct override; indirect instructions in content; invisible Unicode or encoded text; payloads in images or audio; poisoned memory that acts in later sessions.

**Mitigate:** keep credentials and state changes in ordinary code with least privilege; validate output structure; label content origin and strip invisible characters; require confirmation for privileged actions; treat memory writes as privileged; test adversarially. Prompt wording and delimiters help only partially.

```python
# Vulnerable: untrusted text and a powerful tool share one context
agent.run(f"Handle this email:\\n{email}", tools=[read_crm, send_email])

# Better: the reader has no tools and returns constrained data
intent = llm.classify(email, labels=["refund", "question", "other"])
handlers[intent](ticket)  # ordinary code decides what happens
```

## LLM02 Sensitive Information Disclosure

Confidential data leaves through an unauthorized channel: answers, tool arguments, reasoning traces, logs, embeddings or side channels.

**Look for:** retrieval without per-user authorization; full prompts sent to logging or analytics; secrets or personal data in context; caches shared between users; training on unscrubbed data.

**Attacks:** extracting memorized data; asking for retrieved chunks; cross-user leakage; embedding inversion; exfiltration through hidden outbound requests; recovering text under a visual-only redaction.

**Mitigate:** authorize before retrieval; minimize and scrub data before indexing, prompting and logging; per-user query budgets; for regulated data add trace redaction, audit logs and stronger privacy techniques.

## LLM03 Excessive Agency

The system can do damage because it has more functions, permissions or autonomy than the task needs, whatever makes the model misbehave.

**Look for:** generic shell, SQL or HTTP tools; unused tools still registered; shared admin identity; write access for read tasks; irreversible actions without approval.

**Mitigate:** fewer and narrower tools with strict input schemas; run in the user's context with minimal scopes, also through chained agents; authorize in code; human approval for high-impact actions; monitoring, rate limits and circuit breakers.

```python
# Vulnerable
tools = [run_sql]            # any statement, service account

# Better
tools = [get_order_status]   # one parameterized read, scoped to the caller
```

## LLM04 Supply Chain

Models, adapters, datasets, conversion services or serving platforms are compromised.

**Look for:** pickle-based model files; mutable tags or names resolved from public hubs; unsigned artifacts; unpinned models; packages suggested by an assistant and installed without checking.

**Attacks:** malicious weights or adapters; backdoors that survive safe formats; parser bugs in model loaders; reused hub namespaces; registering package names that models invent.

**Mitigate:** pin by immutable digest and verify signatures; maintain SBOM and model inventories; vet suppliers and their terms; re-test after any change, including quantization; isolate shared model environments.

## LLM05 Data and Model Poisoning

Training, tuning, embedding or model files are manipulated to plant bias or backdoors. The model may look normal, and the fix may require retraining.

**Look for:** user feedback or scraped content flowing into training or indexes without review; broad write access to datasets; chat templates, tokenizer configs and adapters loaded from untrusted places.

**Attacks:** trigger phrases; a few crafted documents; removing refusals through tuning data; slow drift through feedback loops.

**Mitigate:** track lineage and version data for rollback; validate and sandbox new sources; restrict writes; rate-limit feedback; probe for triggers after tuning; review templates and configs as code.

## LLM06 Unbounded Consumption

Uncontrolled inference causes outages, runaway cost or model theft. Request-rate limits alone are not enough, because one cheap request can be very expensive.

**Look for:** no token or cost limits; no cap on agent steps or depth; large uploads or contexts accepted; exposed log probabilities; unlimited egress.

**Attacks:** output explosion; denial of wallet; prompts that trap reasoning in loops; heavy media; model extraction; tools that force recursion.

**Mitigate:** limits on tokens and spend per user and period, with hard caps; estimate and check size before calling; step, depth, time and cost limits with loop detection; queue limits and graceful degradation; harden inference servers.

```python
# Vulnerable
while not done:
    done = agent.step()

# Better
for _ in range(MAX_STEPS):
    if budget.exhausted() or agent.step():
        break
```

## LLM07 Misinformation

Plausible but wrong output drives a decision or an action, by accident or by attacker influence.

**Look for:** output used to approve, pay, configure or install without verification; actions based on the model's claim that a condition holds or a task finished.

**Mitigate:** ground answers in current authoritative sources; separate proposing from executing; check preconditions against live state; require structured fields; verify at runtime and approve high-impact actions; log claims with evidence.

## LLM08 Hidden Context Exposure

System prompts, developer instructions, policy text, tool schemas and guardrail rules can be extracted.

**Look for:** keys or connection strings in prompts; roles and permission rules that only the prompt enforces; sensitive logic in tool descriptions.

**Severity** follows content: informational if nothing matters; medium for internal rules that help attacks; high or critical for credentials, or when access control depends on secrecy.

**Mitigate:** assume readable; no secrets; enforce authorization and critical filters in code outside the model; split duties by privilege.

## LLM09 Vector and Embedding Weaknesses

The embedding and similarity layer is attacked, in RAG, agent memory, semantic caches and deduplication.

**Look for:** tenant filtering after the search; one index for mixed trust levels; raw similarity scores returned; embeddings that outlive deleted documents; unprotected vector backups.

**Attacks:** cross-tenant retrieval; recovering text from vectors; documents placed near target queries; blocker documents that silence answers; cache threshold abuse.

**Mitigate:** scope tenant inside the index query or use separate indexes; chunk-level access control; normalize input and record provenance; rate-limit embedding endpoints; delete derived vectors; re-embed everything when the model changes.

```python
# Vulnerable: filtered after ranking across all tenants
hits = [h for h in index.search(q, k=10) if h.tenant == user.tenant]

# Better: the tenant is part of the query, taken from the server session
hits = index.search(q, k=10, namespace=user.tenant)
```

## LLM10 Improper Output Handling

Output reaches another component without validation or encoding. Treat it like input from an untrusted user.

**Look for:** output passed to shell, `eval`, SQL, file paths, HTML, Markdown renderers, email templates, terminals, logs or server-side fetches; generated code deployed without review.

**Attacks:** script injection; command execution; SSRF; terminal escape sequences that spoof text or write the clipboard; image links that leak data.

**Mitigate:** validate against a schema; encode per context; parameterize; strict CSP; strip control characters; disable or allowlist automatic fetching; sandbox and review generated code.

## ASI01 Agent Goal Hijack

An attacker changes what the agent is trying to do or how it decides.

**Look for:** external content that can redirect planning; email or calendar items processed automatically; system prompts editable without change control.

**Mitigate:** treat all natural language as untrusted; least privilege; approval for goal changes and sensitive actions; validate intent at run time and pause on drift; sanitize connected sources; log goals and compare with a baseline.

## ASI02 Tool Misuse and Exploitation

The agent harms with tools it is allowed to use.

**Look for:** tools that combine read with delete or send; unrestricted egress; chains from internal data to external delivery; unqualified tool names; unlimited paid calls.

**Mitigate:** per-tool scopes, rate and egress limits as policy; check intent and arguments before execution; dry-run and confirmation for destructive actions; sandbox; short-lived credentials; pinned, fully qualified tool names; immutable logs.

## ASI03 Identity and Privilege Abuse

Agents gain access through delegation, inherited roles, cached credentials or confused identity.

**Look for:** a parent passing its full rights to sub-agents; credentials reused across users or sessions; permission checked only at workflow start; unauthenticated agent registration.

**Mitigate:** distinct agent identities with short-lived, task-scoped tokens; isolate and wipe state between tasks; re-check each privileged step centrally; bind tokens to purpose and audience; approval for escalation.

## ASI04 Agentic Supply Chain Vulnerabilities

Tools, plugins, prompts, MCP or agent-to-agent servers, registries or update channels are malicious or altered. Composition happens at run time, so review is not only about the manifest.

**Look for:** prompts or tool definitions fetched remotely; unpinned MCP servers (`npx package@latest`); look-alike tool names; coding agents installing packages on their own.

**Mitigate:** allowlist and pin by content hash; sign and verify definitions; keep inventories; sandbox; mutual authentication; re-check at run time; keep a way to revoke a tool or prompt quickly.

```json
// Vulnerable: whatever is published today runs with the developer's access
{ "command": "npx", "args": ["-y", "some-mcp-server@latest"] }
```

## ASI05 Unexpected Code Execution (RCE)

Text becomes execution through generated code, tool chains, deserialization or `eval`.

**Look for:** model-written code run on the host; auto-approved commands; agents with production access; package installation during a task.

**Mitigate:** sandbox without root, with limited filesystem and network; separate generation from execution with validation and static analysis; no `eval`; version-controlled allowlist for automatic commands; approval for elevated runs; monitoring.

## ASI06 Memory & Context Poisoning

Stored context is corrupted and biases later reasoning, across sessions.

**Look for:** memory writes without validation; the agent re-ingesting its own output; shared memory across users or tenants; summaries built from untrusted turns.

**Mitigate:** check writes before commit; provenance and trust scores that decay; per-tenant namespaces; expiry for unverified items; snapshots and rollback; human verification before high-impact memories are used.

## ASI07 Insecure Inter-Agent Communication

Messages between agents can be read, spoofed, altered, replayed or misread.

**Look for:** unauthenticated buses or endpoints; unsigned messages; no nonce or timestamp; fallback to old protocols; open discovery; free-text messages treated as commands.

**Mitigate:** mutual authentication and encryption; sign payload and context; anti-replay; pin protocol versions; authenticated registries and signed agent descriptions; typed schemas with an explicit audience.

## ASI08 Cascading Failures

One fault spreads and grows across agents and tools. Use this item for propagation, and the origin item for the cause.

**Look for:** executors that run plans unchecked; automatic fan-out of actions or releases; no limits between components; approvals granted in bulk.

**Mitigate:** separate planning from execution with a policy check; validate before results propagate; quotas, rate limits and circuit breakers; isolation; detect drift; test policy changes by replay; tamper-evident logs.

## ASI09 Human-Agent Trust Exploitation

People approve harmful actions because the agent seems confident or friendly. The audit trail then shows a human action.

**Look for:** approvals that show a summary instead of the real command or diff; "preview" steps with side effects; recommendations without source; instructions the user is told to paste and run.

**Mitigate:** show exact effects and confirm in steps for sensitive actions; keep preview free of side effects; show provenance and risk cues; log recommendations and approvals; let users report suspicious behavior; train staff.

## ASI10 Rogue Agents

A compromised or drifting agent acts outside its purpose; each step may look legitimate.

**Look for:** agents that can create other agents or change their own permissions; no way to stop or revoke one agent; signing keys held by the agent itself.

**Mitigate:** per-agent identity and signed behavior manifests; trust zones; immutable logs; behavioral monitoring; kill switch, credential revocation and quarantine; fresh verification and approval before reintegration.
