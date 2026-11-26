# OWASP and ASVS Codes

Short index of IDs for tagging findings. Always write the ID together with its name. For depth, see `owasp-top10.md`, `owasp-ai.md` and `asvs.md`.

**Last checked against official sources: 2026-11-26.** Refresh once a year, or sooner when OWASP publishes a new edition.

## Contents

- [Top 10:2025](#top-102025)
- [Top 10 for LLM Applications 2026](#top-10-for-llm-applications-2026)
- [Top 10 for Agentic Applications 2026](#top-10-for-agentic-applications-2026)
- [ASVS 5.0](#asvs-50)
- [Sources and licenses](#sources-and-licenses)

## Top 10:2025

| ID | Name | Typical CWEs |
|---|---|---|
| A01:2025 | Broken Access Control | 22, 200, 352, 601, 639, 862, 863, 918 |
| A02:2025 | Security Misconfiguration | 16, 260, 611, 614, 1004 |
| A03:2025 | Software Supply Chain Failures | 1035, 1104, 1329, 1357, 1395 |
| A04:2025 | Cryptographic Failures | 319, 321, 327, 338, 759, 916 |
| A05:2025 | Injection | 77, 78, 79, 89, 94, 917 |
| A06:2025 | Insecure Design | 256, 269, 434, 501, 522, 657 |
| A07:2025 | Authentication Failures | 287, 295, 306, 307, 384, 798 |
| A08:2025 | Software or Data Integrity Failures | 345, 426, 494, 502, 829, 915 |
| A09:2025 | Security Logging and Alerting Failures | 117, 221, 223, 532, 778 |
| A10:2025 | Mishandling of Exceptional Conditions | 209, 234, 274, 476, 636, 703, 755 |

Placement that is easy to get wrong:

- SSRF (CWE-918) is under A01.
- XXE (CWE-611) is under A02, not A05.
- Unsafe deserialization (CWE-502) is under A08.
- Fail-open logic (CWE-636) is under A10.

## Top 10 for LLM Applications 2026

| ID | Name | What to check | 2025 ID |
|---|---|---|---|
| LLM01 | Prompt Injection | Can untrusted text, files, images or tool output steer the model? | LLM01 |
| LLM02 | Sensitive Information Disclosure | Can the model reach data the current user may not see? | LLM02 |
| LLM03 | Excessive Agency | Are there more tools, permissions or autonomy than the task needs? | LLM06 |
| LLM04 | Supply Chain | Are models, adapters and datasets pinned and from a verified origin? | LLM03 |
| LLM05 | Data and Model Poisoning | Who can write to training, tuning or indexing data? | LLM04 |
| LLM06 | Unbounded Consumption | Are there caps on tokens, steps, tool calls, time and spend? | LLM10 |
| LLM07 | Misinformation | Is ungrounded output used for code, config or decisions? | LLM09 |
| LLM08 | Hidden Context Exposure | Do secrets or access rules live in the system prompt or tool schemas? | LLM07 (System Prompt Leakage) |
| LLM09 | Vector and Embedding Weaknesses | Is retrieval filtered by tenant and user permissions? | LLM08 |
| LLM10 | Improper Output Handling | Does model output reach SQL, shell, HTML, code or URLs unchecked? | LLM05 |

The 2026 edition reordered the list, so a bare `LLM06` is ambiguous. Cite 2026 IDs with names.

## Top 10 for Agentic Applications 2026

Use together with the LLM list when the system plans, calls tools or keeps memory.

| ID | Name | What to check |
|---|---|---|
| ASI01 | Agent Goal Hijack | Can injected content change what the agent is trying to do? |
| ASI02 | Tool Misuse and Exploitation | Can a legitimate tool be called with harmful arguments or in a harmful chain? |
| ASI03 | Identity and Privilege Abuse | Does the agent hold broad, long-lived or borrowed credentials? |
| ASI04 | Agentic Supply Chain Vulnerabilities | Are MCP servers, plugins, skills and hooks pinned and reviewed? |
| ASI05 | Unexpected Code Execution (RCE) | Does generated or retrieved content get executed outside a sandbox? |
| ASI06 | Memory & Context Poisoning | Can untrusted content persist in memory or the index and act later? |
| ASI07 | Insecure Inter-Agent Communication | Can one agent spoof, replay or alter what another agent receives? |
| ASI08 | Cascading Failures | Are there limits on retries, fan-out and error propagation? |
| ASI09 | Human-Agent Trust Exploitation | Does the approval prompt show the real action being approved? |
| ASI10 | Rogue Agents | Can a misbehaving agent be detected and stopped? |

## ASVS 5.0

IDs from ASVS 4.0 do not carry over to 5.0. Cite 5.0 IDs only. If a requirement is not in `asvs.md`, name the chapter instead of guessing a number, or look it up in the official source.

**Levels:** L1 is the minimum (about 20% of requirements). L2 is the target for most applications (about 70% cumulative). L3 adds the rest, for the highest assurance.

### Chapters

| ID | Chapter | ID | Chapter |
|---|---|---|---|
| V1 | Encoding and Sanitization | V10 | OAuth and OIDC |
| V2 | Validation and Business Logic | V11 | Cryptography |
| V3 | Web Frontend Security | V12 | Secure Communication |
| V4 | API and Web Service | V13 | Configuration |
| V5 | File Handling | V14 | Data Protection |
| V6 | Authentication | V15 | Secure Coding and Architecture |
| V7 | Session Management | V16 | Security Logging and Error Handling |
| V8 | Authorization | V17 | WebRTC |
| V9 | Self-contained Tokens | | |

Requirement IDs and levels are in `asvs.md`.

## Sources and licenses

Names and IDs belong to the OWASP Foundation and its project teams. The summaries and checks in this file are this project's own wording.

| Standard | Source | License stated by the source |
|---|---|---|
| Top 10:2025 | https://top10.owasp.org/2025 | CC BY 3.0 |
| ASVS 5.0 | https://github.com/OWASP/ASVS/tree/master/5.0/en | CC BY-SA 4.0 |
| LLM Applications 2026 | https://genai.owasp.org/top-10-for-llm-applications-2026/ | CC BY-SA 4.0 (site default) |
| Agentic Applications 2026 | https://genai.owasp.org/top-10-for-agentic-applications-2026/ | CC BY-SA 4.0 (site default) |
