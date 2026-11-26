---
description: Tags agent risks with the bundled 2026 IDs.
tags: [review, llm, agentic]
model: sonnet
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---
Security review this agent step. Tag findings with the relevant OWASP IDs.

```python
import subprocess

def run_step(llm, ticket_text):
    command = llm.complete(
        "Write one shell command that resolves this support ticket:\n" + ticket_text
    )
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
```
