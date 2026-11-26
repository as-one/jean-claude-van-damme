# OWASP and ASVS Codes

Use these IDs when tagging findings. Always write the ID together with its name.

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

IDs from ASVS 4.0 do not carry over to 5.0. Cite 5.0 IDs only. If a requirement is not listed below, name the chapter instead of guessing a number, or look it up in the official source.

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

### Requirements most often cited in reviews

| Requirement | Level | Summary |
|---|---|---|
| 1.2.1 | L1 | Output encoding fits the HTTP, HTML or XML context |
| 1.2.2 | L1 | URLs built from untrusted data are encoded and limited to safe protocols |
| 1.2.3 | L1 | Data placed in JavaScript or JSON is encoded |
| 1.2.4 | L1 | Database queries are parameterized |
| 1.2.5 | L1 | OS calls are protected against command injection |
| 1.3.2 | L1 | No `eval` or similar dynamic code execution |
| 1.5.1 | L1 | XML parsers disable external entities |
| 1.5.2 | L2 | Deserialization of untrusted data is restricted to safe types and mechanisms |
| 2.2.1 | L1 | Input is validated against what the business logic expects |
| 2.2.2 | L1 | Validation happens in a trusted server-side layer |
| 2.3.1 | L1 | Business flows cannot skip or reorder steps |
| 3.5.1 | L1 | Sensitive cross-origin requests are verified (CSRF) when preflight does not block them |
| 5.2.1 | L1 | Accepted file sizes cannot cause denial of service |
| 5.3.2 | L1 | File paths use trusted data, or strictly validated user input |
| 6.2.1 | L1 | Passwords have at least 8 characters (15 recommended) |
| 6.2.4 | L1 | Reject new passwords found in a list of the 3000 or more most common |
| 6.2.5 | L1 | No character-composition rules |
| 6.2.12 | L2 | New passwords are checked against breached passwords |
| 6.3.1 | L1 | Credential stuffing and brute force are controlled |
| 6.3.2 | L1 | No active default accounts |
| 6.3.3 | L2 | Multi-factor access (L3 requires a phishing-resistant hardware factor) |
| 7.2.1 | L1 | Session tokens are verified by a trusted backend |
| 7.2.3 | L1 | Opaque session tokens are random (CSPRNG, 128 bits or more) |
| 7.2.4 | L1 | Authentication issues a new token and ends the previous one |
| 7.4.1 | L1 | A terminated session cannot be reused |
| 8.2.1 | L1 | Function access requires explicit permission |
| 8.2.2 | L1 | Data access is checked per object (IDOR, BOLA) |
| 8.3.1 | L1 | Authorization is enforced server-side |
| 9.1.1 | L1 | Token signature or MAC is verified before the content is trusted |
| 9.1.2 | L1 | Token algorithms are allowlisted and `none` is rejected |
| 9.2.1 | L1 | Token validity window is enforced |
| 11.3.1 | L1 | No ECB or weak padding |
| 11.3.2 | L1 | Encryption sticks to approved algorithms and modes (AES-GCM, for example) |
| 11.4.2 | L2 | Passwords use a slow, approved password hash |
| 11.5.1 | L2 | Unguessable values come from a CSPRNG with 128 bits; UUIDs do not qualify |
| 12.1.1 | L1 | Only current TLS versions are enabled |
| 12.2.1 | L1 | External HTTP traffic uses TLS with no plaintext fallback |
| 12.2.2 | L1 | External services use publicly trusted certificates |
| 13.3.1 | L2 | Backend secrets are in a secrets manager, never in source or artifacts |
| 13.4.1 | L1 | Version control metadata is not exposed in deployments |
| 14.2.1 | L1 | Sensitive data never goes in URLs or query strings |
| 16.3.1 | L2 | Successful and failed authentication is logged |
| 16.3.2 | L2 | Failed authorization is logged (L3: all authorization decisions) |
| 16.5.1 | L2 | Error responses are generic and leak no internals |
| 16.5.3 | L2 | Failures are handled securely, never fail-open |

## Sources and licenses

Names and IDs belong to the OWASP Foundation and its project teams. The summaries and checks in this file are this project's own wording.

| Standard | Source | License stated by the source |
|---|---|---|
| Top 10:2025 | https://top10.owasp.org/2025 | CC BY 3.0 |
| ASVS 5.0 | https://github.com/OWASP/ASVS/tree/master/5.0/en | CC BY-SA 4.0 |
| LLM Applications 2026 | https://genai.owasp.org/top-10-for-llm-applications-2026/ | CC BY-SA 4.0 (site default) |
| Agentic Applications 2026 | https://genai.owasp.org/top-10-for-agentic-applications-2026/ | CC BY-SA 4.0 (site default) |
