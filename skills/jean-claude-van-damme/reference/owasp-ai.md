# LLM and Agentic Risks in Detail

For code that calls a model or runs an agent. Read the items that match the design. Apply the triage rubric in `SKILL.md`.

This file summarizes the OWASP Top 10 for LLM Applications 2026 (https://genai.owasp.org/top-10-for-llm-applications-2026/) and the OWASP Top 10 for Agentic Applications 2026 (https://genai.owasp.org/top-10-for-agentic-applications-2026/), checked 2026-11-26, with added review guidance and examples. It is shared under CC BY-SA 4.0.

Code examples are fragments that show a pattern. Names such as `llm`, `policy` and `audit` stand for the application's own components.

## Contents

- Start here: [First questions](#first-questions) · [Tracing a path](#tracing-a-path) · [Rating severity](#rating-severity)
- LLM: [01](#llm01-prompt-injection) · [02](#llm02-sensitive-information-disclosure) · [03](#llm03-excessive-agency) · [04](#llm04-supply-chain) · [05](#llm05-data-and-model-poisoning) · [06](#llm06-unbounded-consumption) · [07](#llm07-misinformation) · [08](#llm08-hidden-context-exposure) · [09](#llm09-vector-and-embedding-weaknesses) · [10](#llm10-improper-output-handling)
- Agentic: [01](#asi01-agent-goal-hijack) · [02](#asi02-tool-misuse-and-exploitation) · [03](#asi03-identity-and-privilege-abuse) · [04](#asi04-agentic-supply-chain-vulnerabilities) · [05](#asi05-unexpected-code-execution-rce) · [06](#asi06-memory--context-poisoning) · [07](#asi07-insecure-inter-agent-communication) · [08](#asi08-cascading-failures) · [09](#asi09-human-agent-trust-exploitation) · [10](#asi10-rogue-agents)
- [MCP servers and tool definitions](#mcp-servers-and-tool-definitions)

## First questions

1. What text, files and tool results enter the context, and who can write them?
2. What can the model reach: data, tools, credentials, network?
3. Where does its output go: a screen, a query, a shell, another agent, memory?
4. What requires a human, and does the approval show the real action?
5. What stops it: limits on steps and spend, and a way to revoke access?

A useful design check: avoid giving one context all three of untrusted input, access to sensitive data, and the ability to change state or send data out. When all three are needed, require human approval.

Choosing between close items: injection into one response is LLM01; a changed agent goal is ASI01; a permitted tool used harmfully is ASI02; gaining access is ASI03; running code is ASI05; stored corruption is ASI06; spread between components is ASI08.

## Tracing a path

Treat the model as a component that an attacker may fully steer through any untrusted text it reads. Then trace two hops:

1. **Into the context:** who can write the text? A public ticket, a web page, a shared document, a dependency's README, a tool response.
2. **Out of the model:** which action or sink consumes the result, with whose permissions, and what checks it in ordinary code?

A finding needs both hops. If outsiders cannot write to the context, say who can. If the output reaches nothing but the same user's screen, rendered as plain text, the impact is usually low.

System prompt instructions, delimiters, a second model acting as a judge and keyword filters lower the success rate of attacks. Do not count them as the control that blocks the path.

## Rating severity

| Situation | Typical rating |
|---|---|
| Outsider text can trigger code execution, money movement or bulk data export with no approval | Critical |
| Outsider text can read or change another user's data, or send private data out | High |
| Same, but a human approves an exact and readable action first | Medium |
| The user can only affect their own session and data | Low or not a finding |
| Prompt wording could be stronger, with no reachable impact | Hardening note |

## LLM01 Prompt Injection

Any input the model reads can change its behavior, because instructions and data are not separated. There is no reliable prevention, so the defense is architectural.

**Look for:** retrieved pages, email, tickets, repository files, tool or MCP results, images, audio or memory placed in a context that also has tools or secrets; rendering that loads image URLs automatically; text from other users concatenated into a prompt; filenames, metadata and error messages that reach the model.

**Attacks:** direct override; indirect instructions in content; invisible Unicode or encoded text; payloads in images or audio; instructions split across several documents; fake conversation turns or tool results inside content; poisoned memory that acts in later sessions.

**Mitigate:** keep credentials and state changes in ordinary code with least privilege; validate output structure; label content origin and strip invisible characters; require confirmation for privileged actions; treat memory writes as privileged; remove a tool or the network once untrusted content has been read; test adversarially. Prompt wording and delimiters help only partially.

```python
# Vulnerable: untrusted text and a powerful tool share one context
agent.run(f"Handle this email:\n{email}", tools=[read_crm, send_email])

# Better: the reader has no tools and returns constrained data
LABELS = {"refund", "question", "other"}
label = llm.complete(CLASSIFY_PROMPT, untrusted=email, tools=[]).strip()
handlers[label if label in LABELS else "other"](ticket)  # code decides what happens
```

```python
# Removes format characters often used to hide instructions (tag characters,
# zero-width and bidirectional controls). Reduces one technique only.
def strip_hidden(text: str) -> str:
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
```

Removing all format characters also breaks some scripts and emoji sequences, so adjust for the content you accept.

**Test:** plant a harmless instruction in each untrusted source ("reply with the word CANARY") and check whether it changes tool calls or output.

## LLM02 Sensitive Information Disclosure

Confidential data leaves through an unauthorized channel: answers, tool arguments, reasoning traces, logs, embeddings or side channels.

**Look for:** retrieval without per-user authorization; full prompts sent to logging or analytics; secrets or personal data in context; whole records passed when two fields are needed; caches shared between users; conversation IDs that are guessable or not checked against the owner; training on unscrubbed data; third-party model providers receiving data they should not.

**Attacks:** extracting memorized data; asking for retrieved chunks; cross-user leakage; embedding inversion; exfiltration through hidden outbound requests, such as a Markdown image whose URL carries data; recovering text under a visual-only redaction.

**Mitigate:** authorize before retrieval; minimize and scrub data before indexing, prompting and logging; scope caches and history by user and tenant; per-user query budgets; for regulated data add trace redaction, audit logs and stronger privacy techniques.

```python
# Vulnerable: the whole record enters the context and the log
context = json.dumps(customer.to_dict())
log.info("prompt=%s", context)

# Better: only the fields the task needs, and metadata in logs
context = json.dumps({"plan": customer.plan, "open_invoices": customer.open_invoices})
log.info("llm_call customer=%s chars=%d", customer.id, len(context))
```

```python
# Vulnerable: a cached answer for one tenant can be served to another
key = hash_text(question)

# Better: everything that changes the answer is part of the key
key = hash_text(json.dumps([tenant_id, user_role, model_id, prompt_version, question]))
```

## LLM03 Excessive Agency

The system can do damage because it has more functions, permissions or autonomy than the task needs, whatever makes the model misbehave.

**Look for:** generic shell, SQL or HTTP tools; unused tools still registered; shared admin identity; write access for read tasks; tool arguments that name the user or tenant; irreversible actions without approval.

**Attacks:** any successful injection, hallucinated call or ambiguous request turns spare capability into impact.

**Mitigate:** fewer and narrower tools with strict input schemas; run in the user's context with minimal scopes, also through chained agents; take identity from the session; authorize in code; human approval for high-impact actions; monitoring, rate limits and circuit breakers.

```python
# Vulnerable
tools = [run_sql]            # any statement, service account

# Better
tools = [get_order_status]   # one parameterized read, scoped to the caller
```

```python
# Vulnerable: the model chooses whose data is read
def get_order(customer_id: str, order_id: str): ...

# Better: identity is bound by the server, outside the tool schema
def make_get_order(session):
    def get_order(order_id: str):
        return orders.find(id=order_id, customer_id=session.user_id)
    return get_order
```

**Not a finding:** a broad tool in a local developer assistant that asks for confirmation on every call and runs with only that developer's rights. Check that confirmation cannot be switched off by repository files.

## LLM04 Supply Chain

Models, adapters, datasets, conversion services or serving platforms are compromised.

**Look for:** pickle-based model files; loaders that execute repository code (`trust_remote_code=True`); mutable tags or names resolved from public hubs; unsigned artifacts; unpinned models and prompt templates; packages suggested by an assistant and installed without checking; provider endpoints configurable by untrusted input.

**Attacks:** malicious weights or adapters; backdoors that survive safe formats; parser bugs in model loaders; reused hub namespaces; registering package names that models invent.

**Mitigate:** pin by immutable digest and verify signatures; prefer non-executable formats such as safetensors; maintain SBOM and model inventories; vet suppliers and their terms; re-test after any change, including quantization; isolate shared model environments.

```python
# Vulnerable: moving reference, and code from the repository runs on load
model = AutoModel.from_pretrained("someorg/model", trust_remote_code=True)

# Better
model = AutoModel.from_pretrained(
    "someorg/model",
    revision="<full-commit-sha>",
    trust_remote_code=False,
    use_safetensors=True,
)
```

## LLM05 Data and Model Poisoning

Training, tuning, embedding or model files are manipulated to plant bias or backdoors. The model may look normal, and the fix may require retraining.

**Look for:** user feedback or scraped content flowing into training or indexes without review; broad write access to datasets and buckets; ingestion that anyone can trigger; no record of where a document came from; chat templates, tokenizer configs and adapters loaded from untrusted places.

**Attacks:** trigger phrases; a few crafted documents; removing refusals through tuning data; slow drift through feedback loops.

**Mitigate:** track lineage and version data for rollback; validate and sandbox new sources; restrict writes; rate-limit feedback; probe for triggers after tuning; review templates and configs as code.

```python
# Vulnerable: anything uploaded becomes trusted knowledge
index.add(upload.text)

# Better: provenance is stored, and outside content waits for review
index.add(
    upload.text,
    metadata={
        "source": upload.source,
        "uploader": session.user_id,
        "sha256": hashlib.sha256(upload.text.encode()).hexdigest(),
        "trust": "reviewed" if upload.source in TRUSTED_SOURCES else "pending",
    },
)
hits = index.search(query, filter={"trust": "reviewed"})
```

**Rating:** depends on who can write to the data and what relies on the answers. A corpus only maintainers can change is a lower risk than a public upload form.

## LLM06 Unbounded Consumption

Uncontrolled inference causes outages, runaway cost or model theft. Request-rate limits alone are not enough, because one cheap request can be very expensive.

**Look for:** no token or cost limits; no cap on agent steps or depth; large uploads or contexts accepted; retries without a ceiling; anonymous access to a model endpoint; a provider key shipped to the client; exposed log probabilities; unlimited egress.

**Attacks:** output explosion; denial of wallet; prompts that trap reasoning in loops; heavy media; model extraction; tools that force recursion.

**Mitigate:** limits on tokens and spend per user and period, with hard caps; estimate and check size before calling; step, depth, time and cost limits with loop detection; queue limits and graceful degradation; keep provider keys on the server; harden inference servers.

```python
# Vulnerable
while not done:
    done = agent.step()

# Better
for _ in range(MAX_STEPS):
    if budget.exhausted() or agent.step():
        break
```

```python
# Check before spending: input size, a reservation per user, an output cap, a timeout
if len(prompt) > MAX_PROMPT_CHARS:
    raise TooLarge()
if not budget.reserve(user_id, estimate_cost(prompt, MAX_OUTPUT_TOKENS)):  # atomic
    raise QuotaExceeded()
reply = llm.complete(prompt, max_tokens=MAX_OUTPUT_TOKENS, timeout=30)
```

**Not a finding:** a missing limit on an internal batch job with fixed input, unless it can loop or be triggered by outsiders.

## LLM07 Misinformation

Plausible but wrong output drives a decision or an action, by accident or by attacker influence.

**Look for:** output used to approve, pay, configure or install without verification; actions based on the model's claim that a condition holds or a task finished; invented package names, citations, API parameters or identifiers passed onward.

**Mitigate:** ground answers in current authoritative sources; separate proposing from executing; check preconditions against live state; require structured fields; verify at runtime and approve high-impact actions; log claims with evidence.

```python
# Vulnerable: the model's word decides
if llm.ask("Has this invoice been paid? yes/no") == "yes":
    release_goods(order)

# Better: the system of record decides
if payments.status(order.invoice_id) == "settled":
    release_goods(order)
```

```python
# A suggested dependency is checked against an approved list before installation
name = suggestion.package
if name not in APPROVED_PACKAGES:
    raise NeedsReview(name)
subprocess.run(["pip", "install", "--require-hashes", "-r", LOCKED[name]], check=True)
```

**Not a finding:** wrong answers in a chat where nothing acts on them and the user is told to verify. Mention it only if the domain makes errors harmful.

## LLM08 Hidden Context Exposure

System prompts, developer instructions, policy text, tool schemas and guardrail rules can be extracted.

**Look for:** keys or connection strings in prompts; roles and permission rules that only the prompt enforces; sensitive logic in tool descriptions; hidden context returned in error messages, debug endpoints or client-side code.

**Attacks:** asking the model to repeat or translate its instructions; extracting them piece by piece; reading tool schemas from network traffic.

**Severity** follows content: informational if nothing matters; medium for internal rules that help attacks; high or critical for credentials, or when access control depends on secrecy.

**Mitigate:** assume readable; no secrets; enforce authorization and critical filters in code outside the model; split duties by privilege.

```python
# Vulnerable: a secret and an access rule live in the prompt
system = f"API key: {API_KEY}. Only admins may issue refunds."

# Better: the key stays in the tool, and code enforces the rule
system = "You help with order questions."

def issue_refund(session, order_id: str):
    if not session.has_role("admin"):
        raise PermissionError("refunds require the admin role")
    return payments.refund(order_id, api_key=API_KEY)
```

**Not a finding:** a recoverable system prompt that holds only tone and formatting instructions.

## LLM09 Vector and Embedding Weaknesses

The embedding and similarity layer is attacked, in RAG, agent memory, semantic caches and deduplication.

**Look for:** tenant filtering after the search; one index for mixed trust levels; permissions copied at indexing time and never refreshed; raw similarity scores returned; embeddings that outlive deleted documents; unprotected vector backups and admin ports.

**Attacks:** cross-tenant retrieval; recovering text from vectors; documents placed near target queries; blocker documents that silence answers; cache threshold abuse.

**Mitigate:** scope tenant inside the index query or use separate indexes; chunk-level access control checked at query time; normalize input and record provenance; rate-limit embedding endpoints; delete derived vectors; re-embed everything when the model changes.

```python
# Vulnerable: filtered after ranking across all tenants
hits = [h for h in index.search(q, k=10) if h.tenant == user.tenant]

# Better: the tenant is part of the query, taken from the server session
hits = index.search(q, k=10, namespace=user.tenant)
```

```python
# Permissions change after indexing, so confirm against the source before use
hits = index.search(q, k=20, namespace=user.tenant)
allowed = [h for h in hits if documents.can_read(user, h.document_id)]

def delete_document(document_id):
    documents.delete(document_id)
    index.delete(filter={"document_id": document_id})
    answer_cache.invalidate(document_id)
```

## LLM10 Improper Output Handling

Output reaches another component without validation or encoding. Treat it like input from an untrusted user.

**Look for:** output passed to shell, `eval`, SQL, file paths, HTML, Markdown renderers, email templates, terminals, logs or server-side fetches; JSON parsed without a schema; generated code deployed without review.

**Attacks:** script injection; command execution; SSRF; path traversal; terminal escape sequences that spoof text or write the clipboard; image links that leak data.

**Mitigate:** validate against a schema; encode per context; parameterize; strict CSP; strip control characters; disable or allowlist automatic fetching; sandbox and review generated code.

```python
# Vulnerable
os.system(llm.complete(f"Command to show disk usage for {path}"))

# Better: the model selects from fixed choices; code builds the command
class Request(BaseModel):
    action: Literal["disk_usage", "list_files"]

request = Request.model_validate_json(llm.complete(prompt))
COMMANDS = {"disk_usage": ["du", "-sh"], "list_files": ["ls", "-l"]}
subprocess.run([*COMMANDS[request.action], "--", str(validated_path)], check=True)
```

```js
// Vulnerable: model Markdown becomes live HTML, including remote images
element.innerHTML = marked.parse(reply);

// Better: sanitize, with an explicit list that excludes images
element.innerHTML = DOMPurify.sanitize(marked.parse(reply), {
  ALLOWED_TAGS: ["p", "br", "strong", "em", "ul", "ol", "li", "code", "pre"],
  ALLOWED_ATTR: [],
});
```

## ASI01 Agent Goal Hijack

An attacker changes what the agent is trying to do or how it decides.

**Look for:** external content that can redirect planning; email, calendar or issue items processed automatically; goals rebuilt from conversation history; system prompts and instruction files editable without change control.

**Attacks:** a document that adds a new task; a meeting invite that reorders priorities; repository instruction files that redirect a coding agent.

**Mitigate:** treat all natural language as untrusted; least privilege; fix the goal and allowed tools when the task starts; approval for goal changes and sensitive actions; validate intent at run time and pause on drift; sanitize connected sources; log goals and compare with a baseline.

```python
# The permitted scope comes from the authenticated request, not from anything read later
task = Task(goal=user_request, tools=frozenset({"search_docs", "draft_reply"}))

for call in agent.plan(task):
    if call.tool not in task.tools:
        audit.record("out_of_scope_tool", task.id, call.tool)
        raise PolicyViolation(call.tool)
    run(call)
```

A tool allowlist does not catch harmful arguments to an allowed tool. Check those under ASI02.

## ASI02 Tool Misuse and Exploitation

The agent harms with tools it is allowed to use.

**Look for:** tools that combine read with delete or send; unrestricted egress; chains from internal data to external delivery; free-form arguments such as paths, URLs and queries; unqualified tool names; unlimited paid calls.

**Attacks:** mailing internal records to an outside address; deleting with a broad filter; encoding data into a DNS lookup or URL; calling a costly API in a loop.

**Mitigate:** per-tool scopes, rate and egress limits as policy; check intent and arguments before execution; dry-run and confirmation for destructive actions; sandbox; short-lived credentials; pinned, fully qualified tool names; immutable logs.

```python
def send_email(session, to: str, body: str, approval: Approval | None = None):
    local, _, domain = to.rpartition("@")
    if not local or domain.lower() not in session.allowed_domains:
        # An approval is valid only for this exact recipient and body
        if approval is None or not approval.matches("send_email", to=to, body=body):
            raise ApprovalRequired(to)
    rate_limit.check(session.user_id, "send_email")
    mailer.send(to=[to], body=body)
```

Validate the address with a real parser as well, so one string cannot name several recipients.

## ASI03 Identity and Privilege Abuse

Agents gain access through delegation, inherited roles, cached credentials or confused identity.

**Look for:** a parent passing its full rights to sub-agents; credentials reused across users or sessions; a service account acting for whoever asks; permission checked only at workflow start; tokens passed through to another service without audience checks; unauthenticated agent registration.

**Attacks:** a low-privilege user asking a high-privilege agent to act; reusing a cached token; a fake internal agent receiving delegated work.

**Mitigate:** distinct agent identities with short-lived, task-scoped tokens; isolate and wipe state between tasks; re-check each privileged step centrally; bind tokens to purpose and audience; approval for escalation.

```python
# Vulnerable: the sub-agent inherits everything
sub_agent.run(task, credentials=parent.credentials)

# Better: a narrower token for one purpose, checked again at the resource
token = auth.exchange(
    subject=session.user_token,
    audience="billing-api",
    scopes=["invoices:read"],
    ttl_seconds=300,
)
sub_agent.run(task, credentials=token)
```

## ASI04 Agentic Supply Chain Vulnerabilities

Tools, plugins, prompts, skills, MCP or agent-to-agent servers, registries or update channels are malicious or altered. Composition happens at run time, so review is not only about the manifest.

**Look for:** prompts or tool definitions fetched remotely; unpinned MCP servers (`npx package@latest`); auto-updating plugins from unreviewed sources; look-alike tool names; skills or hooks that download and run scripts; coding agents installing packages on their own.

**Attacks:** a trusted server changing a tool description after approval; a typosquatted server; a malicious update to a plugin.

**Mitigate:** allowlist and pin by version and content hash; sign and verify definitions; keep inventories; sandbox; mutual authentication; re-check at run time; keep a way to revoke a tool or prompt quickly.

```json
{
  "mcpServers": {
    "risky": { "command": "npx", "args": ["-y", "some-mcp-server@latest"] },
    "pinned": { "command": "npx", "args": ["--no", "--", "some-mcp-server"] }
  }
}
```

The first entry runs whatever is published today with the developer's access. The second runs only what the project's lockfile already installed.

```python
# Stop when a tool definition differs from the reviewed one
def verify(tool) -> None:
    definition = json.dumps(
        [tool.name, tool.description, tool.input_schema], sort_keys=True
    )
    digest = hashlib.sha256(definition.encode()).hexdigest()
    if APPROVED_TOOLS.get(tool.name) != digest:
        raise UntrustedTool(tool.name)
```

## ASI05 Unexpected Code Execution (RCE)

Text becomes execution through generated code, tool chains, deserialization, templates or `eval`.

**Look for:** model-written code run on the host; auto-approved commands, including allowlists that match by prefix; agents with production access; package installation during a task; notebooks or test runners executing generated files.

**Attacks:** a command appended to an allowed one; a dependency with an install script; code that reads environment variables and sends them out.

**Mitigate:** sandbox without root, with limited filesystem and network; separate generation from execution with validation and static analysis; no `eval`; version-controlled allowlist matching the whole command; approval for elevated runs; monitoring.

```python
# Vulnerable: host process, host credentials, open network
exec(generated_code)

# Better: a disposable container with nothing worth taking
subprocess.run(
    ["docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
     "--security-opt=no-new-privileges", "--user=65534:65534",
     "--memory=256m", "--cpus=1", "--pids-limit=64",
     f"--name={run_id}", "-i", SANDBOX_IMAGE, "python", "-I", "-"],
    input=generated_code.encode(), timeout=20, check=False,
)
```

The timeout stops the client, not necessarily the container: remove it by name when the timeout fires. For hostile code, prefer stronger isolation such as a microVM.

## ASI06 Memory & Context Poisoning

Stored context is corrupted and biases later reasoning, across sessions.

**Look for:** memory writes without validation; instructions saved as facts; the agent re-ingesting its own output; shared memory across users or tenants; summaries built from untrusted turns; no way to inspect or delete an entry.

**Attacks:** a page that asks the agent to remember a new payee; slow accumulation of false facts; one user's entry influencing another.

**Mitigate:** check writes before commit; provenance and trust scores that decay; per-tenant namespaces; expiry for unverified items; snapshots and rollback; human verification before high-impact memories are used.

```python
# Vulnerable
memory.save(agent_output)

# Better: scoped, attributed, expiring, and never authoritative for sensitive actions
memory.save(
    namespace=(session.tenant_id, session.user_id),
    text=fact,
    source=origin,               # "user", "web", "tool"
    verified=origin == "user",
    expires_at=now() + (LONG_TTL if origin == "user" else SHORT_TTL),
)
```

## ASI07 Insecure Inter-Agent Communication

Messages between agents can be read, spoofed, altered, replayed or misread.

**Look for:** unauthenticated buses or endpoints; unsigned messages; no nonce or timestamp; fallback to old protocols; open discovery; free-text messages treated as commands; a message's claim about who approved something taken as true.

**Mitigate:** mutual authentication and encryption; sign payload and context; anti-replay; pin protocol versions; authenticated registries and signed agent descriptions; typed schemas with an explicit audience.

```python
def accept(raw: bytes, signature: str, sender_key: bytes) -> Message:
    expected = hmac.new(sender_key, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode(), signature.encode()):
        raise Rejected("bad signature")
    message = Message.model_validate_json(raw)  # strict schema, extra fields refused
    if message.audience != MY_AGENT_ID or abs(time.time() - message.sent_at) > 60:
        raise Rejected("wrong audience or stale")
    if not nonces.add_if_new(message.nonce, ttl=120):
        raise Rejected("replay")
    return message  # authenticates the sender; it does not grant permission
```

## ASI08 Cascading Failures

One fault spreads and grows across agents and tools. Use this item for propagation, and the origin item for the cause.

**Look for:** executors that run plans unchecked; automatic fan-out of actions or releases; retries at several layers; agents that trigger each other; no limits between components; approvals granted in bulk.

**Mitigate:** separate planning from execution with a policy check; validate before results propagate; quotas, rate limits and circuit breakers; isolation; detect drift; test policy changes by replay; tamper-evident logs.

```python
def dispatch(actions, context):
    if context.depth > MAX_DEPTH or len(actions) > MAX_FAN_OUT:
        raise Halt("delegation limit")
    for action in actions:
        if breaker.is_open(action.target):
            raise Halt("circuit open")
        policy.check(action, context)  # each action, not just the plan
        execute(action, context.child())
```

## ASI09 Human-Agent Trust Exploitation

People approve harmful actions because the agent seems confident or friendly. The audit trail then shows a human action.

**Look for:** approvals that show a summary instead of the real command or diff; text from the model used as the description of its own action; "preview" steps with side effects; "always allow" offered for risky tools; recommendations without source; instructions the user is told to paste and run.

**Mitigate:** show exact effects and confirm in steps for sensitive actions; build the prompt from the actual parameters; keep preview free of side effects; show provenance and risk cues; log recommendations and approvals; let users report suspicious behavior; train staff.

```python
# Vulnerable: the model describes what it is about to do
confirm(agent.summary)

# Better: the screen shows the real call, and approval is bound to it
call = agent.next_call()
approval = confirm(render(call.tool, call.arguments))  # escape control characters
execute(call, approval)  # refuses if the call no longer matches what was shown
```

## ASI10 Rogue Agents

A compromised or drifting agent acts outside its purpose; each step may look legitimate.

**Look for:** agents that can create other agents, schedule jobs or change their own permissions, instructions or logs; no way to stop or revoke one agent; signing keys held by the agent itself; no owner or inventory.

**Mitigate:** per-agent identity and signed behavior manifests; trust zones; immutable logs; behavioral monitoring; kill switch, credential revocation and quarantine; fresh verification and approval before reintegration.

```python
# The check runs in the gateway that executes tools, where the agent cannot change it
def authorize(agent_id: str, call) -> None:
    if registry.is_revoked(agent_id):
        raise Revoked(agent_id)
    if call.tool not in registry.manifest(agent_id).tools:
        quarantine(agent_id)
        raise PolicyViolation(call.tool)
    audit.append(agent_id, call.tool, call.arguments_digest)
```

## MCP servers and tool definitions

When the target is a server or a client that connects to one, check:

| Area | Look for |
|---|---|
| Authentication | Remote servers without it; tokens accepted that were issued for another audience, or forwarded downstream |
| Authorization | Each tool call checked against the calling user, not only the connection |
| Local transport | HTTP servers bound to all interfaces, or without `Origin` validation (DNS rebinding) |
| Arguments | Paths, URLs, SQL and shell built from them: apply the injection and SSRF checks |
| Tool metadata | Instructions hidden in descriptions or schemas; names that shadow other tools; definitions that change after approval |
| Results | Untrusted content returned to the model as if it were trusted |
| Secrets | Keys in configuration files committed to the repository, or echoed in errors and results |
| Launch | Unpinned packages, remote install scripts, broad environment variables passed to the server |

Map findings to the closest item: argument injection to ASI02 or ASI05, token misuse to ASI03, changed or hostile definitions to ASI04.
